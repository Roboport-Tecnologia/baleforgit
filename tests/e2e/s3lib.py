"""S3 mode for the baleforgit e2e harness.

Pure-stdlib helpers that pair with `run.py` to drive `baleforgit-server`
against a MinIO sidecar instead of the local-filesystem `BlobStore`.

Exports:
    Network                 — per-run podman network (server + MinIO share it)
    MinioGuard              — MinIO container lifecycle + `mc` introspection
    S3StorageView           — bucket-level analogue of `ServerHandle.disk_*_bytes`
    s3_server_env(...)      — BALE_S3_* env-dict for `start_container(extra_env=…)`
    s3_run_args(...)        — `--network <net> --add-host …` for extra_run_args
    phase_s3_basic                                  — push+clone roundtrip
    phase_s3_dedup                                  — chunk-level dedup against
                                                      MinIO object counts
    phase_s3_failure_server_kill_mid_upload         — kills the server while it's
                                                      mid-PUT to MinIO; user-side
                                                      retry must converge
    phase_s3_failure_connection_drop_mid_upload     — drops the server↔MinIO
                                                      TCP link mid-PUT via a
                                                      host-side TcpProxy

Each phase scopes its writes under a unique `BALE_S3_PREFIX` so they share
one MinIO bucket without cross-contamination — same isolation the fs phases
get from per-phase `data_root` directories.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


def _host_ip() -> str:
    """Return the host's primary outbound IP — the address the kernel
    would use to send a packet to the public internet. Doesn't actually
    open a connection (UDP `connect` is just a routing decision).

    This IP is reachable from BOTH the host (it's the host's own
    interface IP, so the kernel loopbacks) AND from a podman container
    (it routes to the host via the bridge). MinIO bound on 0.0.0.0 +
    this IP as the endpoint URL is the only way the presigned URLs the
    server signs work for the host-side client — the server-only DNS
    name `bale-e2e-minio-<hex>` won't resolve outside the network.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 1))
        return s.getsockname()[0]
    finally:
        s.close()

# We deliberately import from run.py rather than re-implementing — keeps the
# fs and S3 suites in lock-step on container plumbing, JWT minting, git
# driving, payload generation, and the worktree/pointer verifiers.
from run import (
    BIG_FILE_BYTES,
    E2E_HUB_TOKEN,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_USER,
    JWT_TTL_YEARS,
    SIZE_TOLERANCE_BYTES,
    ClientEnv,
    Runtime,
    ServerHandle,
    TcpProxy,
    TestFailure,
    Timings,
    _start_push_background,
    _wait_push,
    deterministic_payload,
    fail_fast_xet_env,
    fetch_repo_usage,
    fmt_bytes,
    git,
    info,
    init_repo_for_clone,
    init_repo_for_push,
    mint_bale_jwt,
    pick_free_port,
    sha256_bytes,
    skip,
    staging_files,
    start_container,
    verify_pointer_at,
    verify_worktree,
)


# =============================================================================
# Constants
# =============================================================================

MINIO_IMAGE = "quay.io/minio/minio:RELEASE.2025-01-20T14-49-07Z"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"
MINIO_BUCKET = "bale-e2e"
# Generous: covers a cold image pull on a fresh runner. Matches the Rust-side
# minio.rs READY_TIMEOUT.
MINIO_READY_TIMEOUT_S = 180
MINIO_INTERNAL_PORT = 9000

# Throttle for the server↔MinIO proxy in the S3-conndrop phase. ~2 MiB/s is
# slow enough that the kill reliably lands mid-stream on fast machines while
# still finishing the 35 MiB payload in under 20s on retry.
S3_PROXY_THROTTLE_BPS = 2 * 1024 * 1024


# =============================================================================
# Per-run podman network
# =============================================================================


@dataclass
class Network:
    rt: Runtime
    name: str

    @classmethod
    def create(cls, rt: Runtime) -> "Network":
        name = f"bale-e2e-net-{secrets.token_hex(4)}"
        completed = subprocess.run(
            rt.cmd("network", "create", name), capture_output=True, check=False
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"podman network create failed: "
                f"{completed.stderr.decode('utf-8', 'replace')}"
            )
        info(f"created podman network {name}")
        return cls(rt, name)

    def destroy(self) -> None:
        # Best-effort: containers attached to the net will block removal until
        # they're stopped. Each MinioGuard/ServerHandle teardown precedes this.
        subprocess.run(
            self.rt.cmd("network", "rm", self.name),
            capture_output=True, check=False,
        )


# =============================================================================
# MinIO sidecar
# =============================================================================


class MinioGuard:
    """Single-node MinIO container + `mc` introspection helpers.

    Lifecycle mirrors `crates/bale-server-storage-s3/tests/minio.rs`'s
    MinioGuard: launch, poll `/minio/health/ready`, provision the bucket
    via `mc mb -p` (idempotent), tear down on `stop()`.

    Two URL forms matter:
      - `shared_url`    — http://<host_primary_ip>:<host_port>. Used by
                          BOTH the server (reaches it via bridge → host)
                          AND the host-side client (presigned URLs the
                          server signs embed this hostname; the client
                          must be able to resolve+connect to the same
                          string for the signature to validate). Solves
                          the chicken/egg of "server in container vs.
                          client on host need to agree on MinIO's URL".
      - `host_url`      — http://127.0.0.1:<host_port>. Used by the
                          host-side TcpProxy upstream in the S3-conndrop
                          phase (the host loopbacks faster than going
                          out to its own primary IP).

    MinIO binds on 0.0.0.0:<host_port>:9000 so both URL forms work — the
    legacy 127.0.0.1-only bind would only let the host reach it, not
    the container via the bridge.
    """

    def __init__(
        self,
        rt: Runtime,
        network: Network,
        container: str,
        host_port: int,
        host_ip: str,
    ) -> None:
        self.rt = rt
        self.network = network
        self.container = container
        self.host_port = host_port
        self.host_ip = host_ip

    @classmethod
    def start(cls, rt: Runtime, network: Network) -> "MinioGuard":
        host_port = pick_free_port()
        host_ip = _host_ip()
        container = f"bale-e2e-minio-{secrets.token_hex(4)}"
        info(
            f"launching {MINIO_IMAGE} as {container} on 0.0.0.0:{host_port} "
            f"(shared URL http://{host_ip}:{host_port})"
        )
        completed = subprocess.run(
            rt.cmd(
                "run",
                "-d",
                "--rm",
                "--name", container,
                "--network", network.name,
                # 0.0.0.0 (default when no bind address) so the published
                # port is reachable both via the host's loopback (for the
                # host-side TcpProxy + mc admin) AND via the host's
                # primary IP (for containers on the shared bridge).
                "-p", f"{host_port}:{MINIO_INTERNAL_PORT}",
                "-e", f"MINIO_ROOT_USER={MINIO_ACCESS_KEY}",
                "-e", f"MINIO_ROOT_PASSWORD={MINIO_SECRET_KEY}",
                MINIO_IMAGE,
                "server", "/data",
            ),
            capture_output=True, check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"podman run minio failed:\n"
                f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
            )
        guard = cls(rt, network, container, host_port, host_ip)
        try:
            guard.wait_ready()
            guard.provision_bucket()
        except Exception:
            guard.stop()
            raise
        return guard

    @property
    def shared_url(self) -> str:
        """The endpoint URL both the server (in container) and the
        client (on host) use. host_ip is the host's primary outbound IP
        — kernel loopbacks for the host, the bridge routes for the
        container, both end up at the same MinIO."""
        return f"http://{self.host_ip}:{self.host_port}"

    @property
    def host_url(self) -> str:
        """The host-loopback URL. Used by the host-side TcpProxy
        upstream in the S3-conndrop phase (loopback is faster + simpler
        than re-routing through the host's primary IP)."""
        return f"http://127.0.0.1:{self.host_port}"

    def wait_ready(self) -> None:
        url = f"{self.host_url}/minio/health/ready"
        deadline = time.monotonic() + MINIO_READY_TIMEOUT_S
        last_err: Optional[str] = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    if resp.status == 200:
                        info(f"minio ready at {self.host_url}")
                        return
                    last_err = f"status {resp.status}"
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                last_err = str(e)
            time.sleep(0.3)
        raise TestFailure(
            f"minio did not become ready within {MINIO_READY_TIMEOUT_S}s "
            f"(last error: {last_err})"
        )

    def provision_bucket(self) -> None:
        # `mc` ships in the minio/minio image; alias set + mb -p covers the
        # "already exists" case without SigV4 plumbing on the host.
        self._mc(
            "alias", "set", "local",
            f"http://127.0.0.1:{MINIO_INTERNAL_PORT}",
            MINIO_ACCESS_KEY, MINIO_SECRET_KEY,
        )
        # mc mb -p is the idempotent form ("ignore already exists" + parent
        # creation). Without -p, a second run aborts with "Bucket already
        # owned" which would make stop+restart flow brittle.
        self._mc("mb", "-p", f"local/{MINIO_BUCKET}")

    def stop(self) -> None:
        subprocess.run(
            self.rt.cmd("rm", "-f", self.container),
            capture_output=True, check=False,
        )

    # ---- `mc` subprocess helpers ----------------------------------------

    def _mc(self, *args: str, capture: bool = True) -> subprocess.CompletedProcess:
        cmd = self.rt.cmd("exec", self.container, "mc", *args)
        completed = subprocess.run(cmd, capture_output=capture, check=False)
        if completed.returncode != 0:
            raise TestFailure(
                f"`mc {' '.join(args)}` failed (exit {completed.returncode}):\n"
                f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
            )
        return completed

    def list_objects(self, prefix: str) -> list[tuple[str, int]]:
        """Returns [(key, size), ...] for every object under `prefix`.

        `prefix` is bucket-relative, e.g. "basic/xorbs/" — matches the
        layout the server writes (BALE_S3_PREFIX + "xorbs/"/<aa>/<bb>/<hex>).
        Returns an empty list when the prefix has no objects; `mc ls` doesn't
        error on missing prefixes, it just emits nothing.
        """
        completed = subprocess.run(
            self.rt.cmd(
                "exec", self.container, "mc", "ls",
                "--recursive", "--json",
                f"local/{MINIO_BUCKET}/{prefix}",
            ),
            capture_output=True, check=False,
        )
        out: list[tuple[str, int]] = []
        for raw in completed.stdout.decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # mc ls error entries carry status="error"; skip them. Missing
            # prefixes don't produce errors either, just no output.
            if obj.get("status") and obj["status"] != "success":
                continue
            key = obj.get("key")
            size = obj.get("size")
            if not key or size is None:
                continue
            out.append((str(key), int(size)))
        return out

    def total_bytes(self, prefix: str) -> int:
        return sum(sz for _key, sz in self.list_objects(prefix))

    def get_object(self, prefix_key: str) -> bytes:
        """Read an object's bytes via `mc cat` inside the container.

        `prefix_key` is bucket-relative (e.g. "basic/xorbs/aa/bb/<hex>").
        """
        completed = subprocess.run(
            self.rt.cmd(
                "exec", self.container, "mc", "cat",
                f"local/{MINIO_BUCKET}/{prefix_key}",
            ),
            capture_output=True, check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"`mc cat {prefix_key}` failed: "
                f"{completed.stderr.decode('utf-8', 'replace')}"
            )
        return completed.stdout


# =============================================================================
# StorageView (bucket-level analogue of ServerHandle.disk_*_bytes)
# =============================================================================


@dataclass
class S3StorageView:
    """Inspect a phase's S3 footprint by prefix.

    A phase passes its `BALE_S3_PREFIX` (e.g. "dedup/") and gets back the
    same shape as `ServerHandle.disk_xorb_bytes()` / `disk_total_bytes()`,
    but answered by `mc ls` against the bucket. Used in the dedup phase to
    assert chunk-level CDC reuse, and in the kill phase to wait for
    progress on the MinIO side.
    """

    minio: MinioGuard
    prefix: str

    def xorb_bytes(self) -> int:
        return self.minio.total_bytes(f"{self.prefix}xorbs/")

    def shard_bytes(self) -> int:
        return self.minio.total_bytes(f"{self.prefix}shards/")

    def total_bytes(self) -> int:
        return self.xorb_bytes() + self.shard_bytes()


# =============================================================================
# Env + run-arg helpers for start_container(extra_env=…, extra_run_args=…)
# =============================================================================


def s3_server_env(
    minio: MinioGuard,
    *,
    prefix: str,
    endpoint_override: Optional[str] = None,
) -> dict[str, str]:
    """BALE_S3_* env dict the server reads (see
    crates/bale-server-bin/src/main.rs:97-160). `endpoint_override` lets
    the S3-conndrop phase point at a proxy instead of MinIO directly.
    """
    return {
        "BALE_S3_BUCKET": MINIO_BUCKET,
        "BALE_S3_ENDPOINT_URL": endpoint_override or minio.shared_url,
        # MinIO speaks path-style only (no virtual-host addressing).
        "BALE_S3_FORCE_PATH_STYLE": "1",
        # MinIO SSE-S3 requires a KMS key; the throwaway test bucket has none.
        "BALE_S3_DISABLE_SSE": "1",
        "BALE_S3_ACCESS_KEY_ID": MINIO_ACCESS_KEY,
        "BALE_S3_SECRET_ACCESS_KEY": MINIO_SECRET_KEY,
        # us-east-1 is what the AWS SDK assumes by default and what
        # minio.rs uses; either way the actual choice is moot for MinIO.
        "BALE_S3_REGION": "us-east-1",
        # Per-phase prefix — equivalent to the fs suite's per-phase data_root.
        # Trailing "/" matters: keys become "<prefix>xorbs/aa/bb/<hex>".
        "BALE_S3_PREFIX": prefix,
    }


def s3_run_args(network: Network) -> list[str]:
    """Attach the server container to the shared network so it can
    resolve MinIO by container DNS — and also so its bridge route gets
    it to the host's primary IP (where MinIO publishes on 0.0.0.0:<host
    _port>). No `--add-host=…:host-gateway` here: on macOS rootless
    podman `host-gateway` sometimes fails resolution, so we side-step
    the whole magic-name layer by using the host's primary IP directly
    (`MinioGuard.shared_url`).
    """
    return ["--network", network.name]


# =============================================================================
# Local helpers
# =============================================================================


def _wait_storage_progress(
    progress_fn: Callable[[], int],
    *,
    min_bytes: int,
    timeout_s: float = 30.0,
) -> int:
    """Poll `progress_fn` until it returns >= min_bytes. Mirrors run.py's
    `wait_for_server_progress` but storage-agnostic — used here to poll the
    MinIO bucket (the S3 server doesn't have a local xorbs/ dir).

    Longer default timeout than the fs version because each call shells
    `mc ls` inside the container (~50ms per probe) and MinIO has to commit
    the object before it's listable.
    """
    deadline = time.monotonic() + timeout_s
    last = 0
    while time.monotonic() < deadline:
        last = progress_fn()
        if last >= min_bytes:
            return last
        time.sleep(0.2)
    raise TestFailure(
        f"storage bytes did not reach {min_bytes} within {timeout_s}s "
        f"(stalled at {last})"
    )


def _mint_admin_jwt(jwt_secret_hex: str, repo: str) -> str:
    return mint_bale_jwt(
        secret=bytes.fromhex(jwt_secret_hex),
        sub=E2E_USER,
        repo_type="model",
        repo_id=f"{E2E_OWNER}/{repo}",
        revision="main",
        scope="write",
        ttl_secs=JWT_TTL_YEARS * 365 * 24 * 3600,
    )


def _start_s3_server(
    *,
    rt: Runtime,
    image_tag: str,
    data_root: Path,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    ssh_public_key: str,
    test_repos: list[str],
    admin_token_hex: str,
    name_suffix: str,
    minio: MinioGuard,
    network: Network,
    prefix: str,
    endpoint_override: Optional[str] = None,
    public_host_url_override: Optional[str] = None,
    cas_port: Optional[int] = None,
    ssh_port: Optional[int] = None,
) -> ServerHandle:
    """Wrap start_container with the S3 env + network plumbing. Every S3
    phase boots its server through this — keeps the BALE_S3_* +
    --network wiring in one place. `cas_port`/`ssh_port` are forwarded
    so phases that put a TcpProxy in front of the server can target the
    exact port the container publishes."""
    run_args = s3_run_args(network)
    return start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret_hex,
        transfer_secret_hex=transfer_secret_hex,
        ssh_public_key=ssh_public_key,
        test_repos=test_repos,
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=name_suffix,
        public_host_url_override=public_host_url_override,
        extra_env=s3_server_env(
            minio, prefix=prefix, endpoint_override=endpoint_override
        ),
        extra_run_args=run_args,
    )


# =============================================================================
# Phase: basic push + clone roundtrip against S3
# =============================================================================


def phase_s3_basic(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
    minio: MinioGuard,
    network: Network,
) -> None:
    """Stage → commit → push → clone → checkout, all against an S3-backed
    server. Asserts the bucket actually receives xorbs (server isn't
    silently falling back to fs) and the cold smudge on the clone side
    reconstructs the right bytes via /v1/reconstructions/ (which presigns
    against MinIO under the hood)."""
    phase_root = work_root / "s3-basic"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    prefix = "basic/"
    storage = S3StorageView(minio, prefix=prefix)

    server = _start_s3_server(
        rt=rt, image_tag=image_tag, data_root=data_root,
        jwt_secret_hex=jwt_secret, transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix="s3-basic",
        minio=minio, network=network, prefix=prefix,
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO, name="s3-basic-client",
        )
        payload = deterministic_payload(64 * 1024, seed=b"s3-basic")
        payload_sha = sha256_bytes(payload)
        (repo / "smallish.bin").write_bytes(payload)

        with timings.measure("s3-basic: stage + commit", bytes_moved=len(payload)):
            git(["add", "smallish.bin"], cwd=repo, env=env)
            verify_pointer_at(
                repo, env, spec=":smallish.bin",
                expected_sha=payload_sha, expected_size=len(payload),
                label="s3-basic:after-stage",
            )
            git(["commit", "-m", "s3-basic"], cwd=repo, env=env)

        if storage.total_bytes() != 0:
            raise TestFailure(
                f"s3-basic: bucket prefix {prefix!r} non-empty before push: "
                f"{fmt_bytes(storage.total_bytes())}"
            )
        with timings.measure(
            "s3-basic: push (drains staging into S3)", bytes_moved=len(payload)
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure("s3-basic: staging not drained after push")
        if storage.total_bytes() <= 0:
            raise TestFailure(
                "s3-basic: bucket still empty after push — the server may "
                "have fallen back to the fs blob store"
            )
        info(f"  s3-basic: bucket grew to {fmt_bytes(storage.total_bytes())}")

        # Cold clone in a fresh worktree — the smudge has to traverse
        # /v1/reconstructions/ AND the resulting presigned URL has to fetch
        # the right bytes back from MinIO. Both ends matter.
        with timings.measure("s3-basic: cold clone + checkout", bytes_moved=len(payload)):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root, client=client, server=server,
                owner=E2E_OWNER, repo=E2E_REPO, name="s3-basic-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "smallish.bin",
            expected_sha=payload_sha, expected_size=len(payload),
            label="s3-basic:after-clone",
        )
    finally:
        server.stop()


# =============================================================================
# Phase: chunk-level dedup against S3
# =============================================================================


def phase_s3_dedup(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
    minio: MinioGuard,
    network: Network,
) -> None:
    """Push a 35 MiB binary at THREE revisions with small edits (v1 →
    8-byte poke → 1 MiB region swap), mirroring the fs `bigfile` phase.

    Each revision has a distinct sha256 — so the server registers three
    file_hash entries and `raw_bytes` ≈ 3 × BIG_FILE_BYTES. The CDC
    chunks overlap heavily across revisions, so the bucket grows only
    by the edit delta on v2/v3 and `stored_bytes` stays close to one
    payload's worth. `dedup_savings_bytes = raw - stored` shows the
    savings story.

    Note: a duplicate file (same content, different path) at the same
    commit does NOT exercise this — the server collapses identical
    file_hashes at the metadata layer (`register_files` is content-
    addressed), so raw_bytes wouldn't grow. The 3-revision shape is the
    only one that exercises chunk-level dedup at the accounting layer.
    """
    phase_root = work_root / "s3-dedup"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    prefix = "dedup/"
    storage = S3StorageView(minio, prefix=prefix)

    server = _start_s3_server(
        rt=rt, image_tag=image_tag, data_root=data_root,
        jwt_secret_hex=jwt_secret, transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO_2}"],
        admin_token_hex=admin_token_hex,
        name_suffix="s3-dedup",
        minio=minio, network=network, prefix=prefix,
    )
    admin_jwt = _mint_admin_jwt(jwt_secret, E2E_REPO_2)
    try:
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_2, name="s3-dedup-client",
        )

        # ---- v1: baseline 35 MiB ----------------------------------------
        payload_v1 = deterministic_payload(BIG_FILE_BYTES, seed=b"s3-dedup-v1")
        sha_v1 = sha256_bytes(payload_v1)
        (repo / "bigfile.bin").write_bytes(payload_v1)
        with timings.measure(
            "s3-dedup: v1 stage+commit+push", bytes_moved=BIG_FILE_BYTES
        ):
            git(["add", "bigfile.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-dedup v1"], cwd=repo, env=env)
            before_v1 = storage.total_bytes()
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        after_v1 = storage.total_bytes()
        grew_v1 = after_v1 - before_v1
        # Full payload upload; compression keeps it below raw size.
        if grew_v1 < BIG_FILE_BYTES // 2:
            raise TestFailure(
                f"s3-dedup v1: bucket grew only {fmt_bytes(grew_v1)} — "
                f"expected ≥ {fmt_bytes(BIG_FILE_BYTES // 2)}"
            )
        info(f"  s3-dedup v1: bucket +{fmt_bytes(grew_v1)} (full payload)")

        # ---- v2: 8-byte poke at the middle ------------------------------
        # CDC keeps the edit localized: at most a handful of chunks need
        # re-uploading. Tolerance is generous to absorb chunk-boundary
        # variance.
        v2_offset = BIG_FILE_BYTES // 2
        payload_v2 = (
            payload_v1[:v2_offset]
            + b"\xde\xad\xbe\xef\x01\x02\x03\x04"
            + payload_v1[v2_offset + 8:]
        )
        sha_v2 = sha256_bytes(payload_v2)
        if sha_v2 == sha_v1:
            raise TestFailure("s3-dedup v2: sha256 unchanged after poke")
        (repo / "bigfile.bin").write_bytes(payload_v2)
        with timings.measure(
            "s3-dedup: v2 stage+commit+push (8-byte poke)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            git(["add", "bigfile.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-dedup v2: 8-byte poke"], cwd=repo, env=env)
            git(["push", "origin", "main"], cwd=repo, env=env)
        after_v2 = storage.total_bytes()
        grew_v2 = after_v2 - after_v1
        # Tolerance: a handful of 64 KiB chunks (each is ~64 KiB
        # uncompressed) plus the new shard. 2 MiB is a generous cap.
        v2_max_growth = 2 * 1024 * 1024
        if grew_v2 > v2_max_growth:
            raise TestFailure(
                f"s3-dedup v2: bucket grew by {fmt_bytes(grew_v2)} for an "
                f"8-byte edit — expected ≤ {fmt_bytes(v2_max_growth)} "
                "(CDC chunk-level dedup not engaging)"
            )
        info(f"  s3-dedup v2: bucket +{fmt_bytes(grew_v2)} (8-byte edit)")

        # ---- v3: 1 MiB region replacement -------------------------------
        v3_offset = BIG_FILE_BYTES // 4
        v3_len = 1024 * 1024
        v3_region = deterministic_payload(v3_len, seed=b"s3-dedup-v3-region")
        payload_v3 = (
            payload_v2[:v3_offset] + v3_region + payload_v2[v3_offset + v3_len:]
        )
        sha_v3 = sha256_bytes(payload_v3)
        if sha_v3 in (sha_v1, sha_v2):
            raise TestFailure("s3-dedup v3: sha256 collision with earlier rev")
        (repo / "bigfile.bin").write_bytes(payload_v3)
        with timings.measure(
            "s3-dedup: v3 stage+commit+push (1 MiB region)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            git(["add", "bigfile.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-dedup v3: 1 MiB region"], cwd=repo, env=env)
            git(["push", "origin", "main"], cwd=repo, env=env)
        after_v3 = storage.total_bytes()
        grew_v3 = after_v3 - after_v2
        # ~1 MiB of new content plus boundary chunks; cap at 3 MiB.
        v3_max_growth = 3 * 1024 * 1024
        if grew_v3 > v3_max_growth:
            raise TestFailure(
                f"s3-dedup v3: bucket grew by {fmt_bytes(grew_v3)} for a "
                f"1 MiB edit — expected ≤ {fmt_bytes(v3_max_growth)}"
            )
        info(f"  s3-dedup v3: bucket +{fmt_bytes(grew_v3)} (1 MiB edit)")

        # ---- /v1/usage cross-check --------------------------------------
        # raw_bytes counts each (commit, file_path) registration, so
        # three distinct file_hashes (v1/v2/v3) yield ≈ 3 × BIG_FILE_BYTES.
        # stored_bytes is on-disk xorb cost (chunk-deduped) — should stay
        # close to one payload's worth despite three revisions.
        # savings = raw - stored should be ≈ 2 × BIG_FILE_BYTES.
        usage = fetch_repo_usage(
            server, token=admin_jwt, owner=E2E_OWNER, repo=E2E_REPO_2,
        )
        info(f"  s3-dedup: /v1/usage repo response = {usage}")
        raw = int(usage["raw_bytes"])
        stored = int(usage["stored_bytes"])
        savings = int(usage["dedup_savings_bytes"])

        # raw ≥ 2× (be lenient; the precise multiplier depends on whether
        # carried-forward pointers count as new registrations).
        if raw < 2 * BIG_FILE_BYTES:
            raise TestFailure(
                f"s3-dedup: /v1/usage raw_bytes={raw} < expected ≥ "
                f"{2 * BIG_FILE_BYTES} — accounting isn't counting the "
                "three revisions distinctly"
            )
        # stored ≤ 1.5× one payload — chunks dedup across revisions.
        if stored > BIG_FILE_BYTES * 3 // 2:
            raise TestFailure(
                f"s3-dedup: /v1/usage stored_bytes={stored} > expected "
                f"≤ {BIG_FILE_BYTES * 3 // 2} — chunk-level dedup isn't "
                "reaching the accounting layer"
            )
        if savings != raw - stored:
            raise TestFailure(
                f"s3-dedup: /v1/usage dedup_savings_bytes={savings} != "
                f"raw_bytes - stored_bytes = {raw - stored}"
            )
        if savings <= 0:
            raise TestFailure(
                f"s3-dedup: /v1/usage dedup_savings_bytes={savings} ≤ 0 — "
                "no savings recorded across three revisions"
            )
        info(
            f"  s3-dedup: raw={fmt_bytes(raw)}, stored={fmt_bytes(stored)}, "
            f"savings={fmt_bytes(savings)} "
            f"({100.0 * savings / raw:.1f}% of raw)"
        )

        # ---- Cold-clone history verification ----------------------------
        # Every revision must check out to the right sha256 — proves the
        # CDC-deduped chunks reassemble correctly per-revision from S3.
        clone_path, clone_env, _ = init_repo_for_clone(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_2, name="s3-dedup-clone",
        )
        with timings.measure(
            "s3-dedup: cold clone HEAD (v3)", bytes_moved=BIG_FILE_BYTES,
        ):
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "bigfile.bin",
            expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
            label="s3-dedup:clone:v3",
        )
    finally:
        server.stop()


# =============================================================================
# Phase: server killed mid-upload, S3 backend
# =============================================================================


def phase_s3_failure_server_kill_mid_upload(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
    minio: MinioGuard,
    network: Network,
) -> None:
    """Same shape as the fs `failure-kill` phase but with S3 storage.

    A throttled TcpProxy slows the client→server leg so the harness can
    kill the server container after at least one xorb has landed in MinIO.
    The client push fails; restart the server (same data_root for meta.db
    + git-home, same BALE_S3_PREFIX so the same bucket subtree); retry
    push — must converge via content-addressed idempotency.
    """
    phase_root = work_root / "s3-failure-kill"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    prefix = "kill/"
    storage = S3StorageView(minio, prefix=prefix)
    # 4 MiB payload — matches the fs failure-kill phase. Large enough
    # that the throttled proxy gives a multi-second window to land the
    # kill mid-stream, small enough that the suite stays fast.
    kill_payload_size = 4 * 1024 * 1024

    cas_port = pick_free_port()
    ssh_port = pick_free_port()
    proxy_port = pick_free_port()
    # Proxy on the client→server leg, throttled so the kill lands during
    # the request body upload. We trigger the kill on proxy bytes
    # forwarded (client→server), NOT on bucket growth: MinIO bytes only
    # appear after the server has parsed and verified the whole xorb
    # body, which is way too late in the pipeline to count as mid-upload.
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=cas_port,
        throttle_bytes_per_sec=1024 * 1024,
    )
    proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    server = _start_s3_server(
        rt=rt, image_tag=image_tag, data_root=data_root,
        jwt_secret_hex=jwt_secret, transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        cas_port=cas_port, ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix="s3-kill",
        minio=minio, network=network, prefix=prefix,
        public_host_url_override=proxy_url,
    )
    new_server: Optional[ServerHandle] = None
    try:
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO, name="s3-kill-client",
        )
        # Trim xet retry budget so a deliberately-broken upstream surfaces
        # as a push failure in ~1s rather than ~30s.
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(kill_payload_size, seed=b"s3-kill")
        payload_sha = sha256_bytes(payload)
        (repo / "killtest.bin").write_bytes(payload)
        with timings.measure(
            "s3-failure-kill: stage + commit", bytes_moved=kill_payload_size
        ):
            git(["add", "killtest.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-kill mid-upload"], cwd=repo, env=env)

        with timings.measure("s3-failure-kill: push then kill"):
            proc = _start_push_background(repo, env)
            try:
                # Wait for the proxy to forward 64 KiB — proves the
                # upload is mid-stream on the client→server leg. (We
                # don't wait for MinIO bytes here: those only appear
                # after the server has fully parsed + hashed the xorb
                # body, which would mean the upload is already past the
                # mid-stream window we want to kill in.)
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.02)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"s3-failure-kill: proxy never saw ≥64 KiB within 15s "
                        f"(seen {proxy.bytes_forwarded})"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise
            info("  killing server container mid-upload")
            server.stop()
            rc = _wait_push(proc, timeout_s=30.0)
            if rc == 0:
                raise TestFailure(
                    "s3-failure-kill: push subprocess unexpectedly succeeded "
                    "despite mid-upload server kill"
                )
        if not staging_files(repo):
            raise TestFailure(
                "s3-failure-kill: staging dir empty after killed push — "
                "client lost its pending xorbs"
            )

        # Restart on the SAME data_root and SAME S3 prefix. meta.db survives
        # in /data; whatever xorbs already made it into the bucket stay
        # there. Retry push converges by content-addressed idempotency.
        with timings.measure("s3-failure-kill: restart server"):
            new_server = _start_s3_server(
                rt=rt, image_tag=image_tag, data_root=data_root,
                jwt_secret_hex=jwt_secret, transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
                cas_port=cas_port, ssh_port=ssh_port,
                admin_token_hex=admin_token_hex,
                name_suffix="s3-kill-restart",
                minio=minio, network=network, prefix=prefix,
                public_host_url_override=proxy_url,
            )
        with timings.measure(
            "s3-failure-kill: retry push after restart",
            bytes_moved=kill_payload_size,
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "s3-failure-kill: staging dir not drained after successful retry"
            )

        # Cold-clone in a fresh worktree — proves the file genuinely
        # reconstructs from server-side state (S3 + meta.db), not a
        # hot-cache illusion in the original push client.
        with timings.measure(
            "s3-failure-kill: cold clone after recovery",
            bytes_moved=kill_payload_size,
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root, client=client, server=new_server,
                owner=E2E_OWNER, repo=E2E_REPO, name="s3-kill-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "killtest.bin",
            expected_sha=payload_sha, expected_size=kill_payload_size,
            label="s3-failure-kill:after-recovery-clone",
        )
    finally:
        proxy.kill()
        if new_server is not None:
            new_server.stop()
        else:
            server.stop()


# =============================================================================
# Phase: S3 connection drop mid-upload (server↔MinIO, NOT client↔server)
# =============================================================================


def phase_s3_failure_connection_drop_mid_upload(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
    minio: MinioGuard,
    network: Network,
) -> None:
    """Drop the server↔MinIO TCP connection mid-PUT.

    Distinct from the fs `failure-conndrop` phase, which drops client↔server.
    Here a host-side TcpProxy sits between the server (inside its container)
    and MinIO (inside its container). The server reaches the proxy via
    `host.containers.internal:<proxy_port>` (BALE_S3_ENDPOINT_URL), the
    proxy forwards to `127.0.0.1:<minio.host_port>` on the host.

    `proxy.kill()` slams every socket without FIN, mimicking a sudden
    upstream drop from the AWS SDK's perspective. The SDK retries
    transient connection errors (RetryConfig::standard, up to 2 retries),
    so we hold the proxy down for 2s and then bring it back: the test
    tolerates both "SDK swallowed the drop" and "SDK gave up, client must
    retry" outcomes. Either way, the file must be recoverable on disk
    afterwards and the bucket must hold one copy of the payload.
    """
    phase_root = work_root / "s3-failure-conndrop"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    prefix = "s3drop/"
    storage = S3StorageView(minio, prefix=prefix)

    proxy_port = pick_free_port()
    # bind_host="0.0.0.0" so the proxy is reachable from the server
    # container via host.containers.internal. Throttle is set so the
    # 35 MiB upload doesn't complete before the kill fires.
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=minio.host_port,
        throttle_bytes_per_sec=S3_PROXY_THROTTLE_BPS,
        bind_host="0.0.0.0",
    )
    proxy.start()

    # Server reaches the proxy at the same host IP MinIO is published
    # on. From the container's POV that IP is "the host" (routed via
    # the bridge); from the proxy's POV its bind is 0.0.0.0:<proxy_port>
    # so any incoming address is accepted.
    proxy_url = f"http://{minio.host_ip}:{proxy_port}"
    info(f"  server→S3 proxy URL: {proxy_url}")

    server = _start_s3_server(
        rt=rt, image_tag=image_tag, data_root=data_root,
        jwt_secret_hex=jwt_secret, transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix="s3-conndrop",
        minio=minio, network=network, prefix=prefix,
        endpoint_override=proxy_url,
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO, name="s3-conndrop-client",
        )
        # Fast-fail xet so a server-side error (cascading from the dropped
        # S3 connection) doesn't burn 30s of retries before the push exits.
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(BIG_FILE_BYTES, seed=b"s3-conndrop")
        payload_sha = sha256_bytes(payload)
        (repo / "s3drop.bin").write_bytes(payload)
        with timings.measure(
            "s3-failure-conndrop: stage + commit", bytes_moved=BIG_FILE_BYTES
        ):
            git(["add", "s3drop.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3 mid-upload drop"], cwd=repo, env=env)

        with timings.measure("s3-failure-conndrop: push then drop"):
            proc = _start_push_background(repo, env)
            try:
                # Wait until the proxy is actually forwarding — proves the
                # server is mid-PUT to MinIO, not still parsing the request.
                deadline = time.monotonic() + 30.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.05)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"s3-failure-conndrop: proxy never forwarded ≥64 KiB "
                        f"within 30s (seen {proxy.bytes_forwarded}) — the "
                        "server may not be using the BALE_S3_ENDPOINT_URL "
                        "override"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise

            info("  dropping server→MinIO connections via proxy.kill()")
            proxy.kill()
            # Hold the link down long enough that aws-sdk-s3's standard
            # retry policy (≈3 attempts, exponential backoff from ~100ms)
            # has time to exhaust before the proxy comes back. Without this
            # gap, the SDK swallows the drop and the test no longer
            # exercises the failure path.
            time.sleep(3.0)
            proxy.start()
            info("  proxy restarted; awaiting push exit")
            rc = _wait_push(proc, timeout_s=120.0)
            push_succeeded_first_try = rc == 0

        if push_succeeded_first_try:
            # SDK retried internally past the dead-proxy window. Still
            # valid: the file should be fully on disk and the bucket
            # should hold one copy.
            info("  push survived the drop via aws-sdk-s3 retries")
        else:
            info("  push failed mid-drop; retrying (proxy is back up)")
            if not staging_files(repo):
                raise TestFailure(
                    "s3-failure-conndrop: staging dir empty after failed push — "
                    "client lost its pending xorbs"
                )
            with timings.measure(
                "s3-failure-conndrop: retry push", bytes_moved=BIG_FILE_BYTES
            ):
                git(["push", "-u", "origin", "main"], cwd=repo, env=env)
            if staging_files(repo):
                raise TestFailure(
                    "s3-failure-conndrop: staging dir not drained after "
                    "successful retry"
                )

        # Cold clone proves the file genuinely lives in MinIO. Also probes
        # the reconstruction path (server presigns against MinIO, client
        # fetches via the host-published port — that traffic doesn't go
        # through our dropped proxy).
        with timings.measure(
            "s3-failure-conndrop: cold clone after recovery",
            bytes_moved=BIG_FILE_BYTES,
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root, client=client, server=server,
                owner=E2E_OWNER, repo=E2E_REPO, name="s3-conndrop-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "s3drop.bin",
            expected_sha=payload_sha, expected_size=BIG_FILE_BYTES,
            label="s3-failure-conndrop:after-recovery-clone",
        )

        # No-double-counting: stored bytes should be roughly one copy of
        # the payload, not two. A retry that re-uploaded into a fresh
        # prefix would show up here as ~2× the expected size.
        stored = storage.xorb_bytes()
        if stored > BIG_FILE_BYTES * 3 // 2:
            raise TestFailure(
                f"s3-failure-conndrop: stored xorb bytes {fmt_bytes(stored)} "
                f"exceeds 1.5× payload ({fmt_bytes(BIG_FILE_BYTES)}) — retry "
                "may have double-written"
            )
        info(f"  s3-failure-conndrop: final stored xorb bytes = {fmt_bytes(stored)}")
    finally:
        proxy.kill()
        server.stop()
