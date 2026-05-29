"""S3 backend plumbing for the e2e harness (MinIO sidecar + bucket views).

This module holds everything needed to run the harness against an S3
`BlobStore` *without* depending on `run`/`s3lib` — so `server.py` can import
it to make `start_container` backend-aware without a circular import. The
bespoke S3 phases in `s3lib.py` re-export these names for backwards compat.

Two ways the S3 backend is wired in:

  - `run.py --backend s3` sets a process-global `ActiveS3Backend` (mirrors
    the `covstate` coverage global). Every `start_container` call — the
    shared one and each phase's private one — then auto-injects the
    BALE_S3_* env + shared-network args and derives a per-`data_root` bucket
    prefix, so the *full* fs phase registry runs against MinIO unchanged.
  - `s3lib.py`'s standalone phases pass `s3_server_env(...)` /
    `s3_run_args(...)` explicitly and never set the global.

Each server's writes are scoped under a unique `BALE_S3_PREFIX` derived from
its `data_root` — the bucket-level analogue of the fs suite's per-phase
`data_root` directories. The derivation is *stable* per `data_root` so a
restart on the same dir (failure-kill, offline-restart) lands on the same
bucket subtree, and *distinct* across phases so they don't cross-contaminate.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from baleharness.logutil import TestFailure, info
from baleharness.proc import host_primary_ip, pick_free_port
from baleharness.runtime import Runtime


# =============================================================================
# Constants
# =============================================================================

MINIO_IMAGE = "quay.io/minio/minio:RELEASE.2025-01-20T14-49-07Z"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"
MINIO_BUCKET = "bale-e2e"
# Generous: covers a cold image pull on a fresh runner.
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
            capture_output=True,
            check=False,
        )


# =============================================================================
# MinIO sidecar
# =============================================================================


class MinioGuard:
    """Single-node MinIO container + `mc` introspection helpers.

    Lifecycle: launch, poll `/minio/health/ready`, provision the bucket
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
        host_ip = host_primary_ip()
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
                "--name",
                container,
                "--network",
                network.name,
                # 0.0.0.0 (default when no bind address) so the published
                # port is reachable both via the host's loopback (for the
                # host-side TcpProxy + mc admin) AND via the host's
                # primary IP (for containers on the shared bridge).
                "-p",
                f"{host_port}:{MINIO_INTERNAL_PORT}",
                "-e",
                f"MINIO_ROOT_USER={MINIO_ACCESS_KEY}",
                "-e",
                f"MINIO_ROOT_PASSWORD={MINIO_SECRET_KEY}",
                MINIO_IMAGE,
                "server",
                "/data",
            ),
            capture_output=True,
            check=False,
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
            "alias",
            "set",
            "local",
            f"http://127.0.0.1:{MINIO_INTERNAL_PORT}",
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
        )
        # mc mb -p is the idempotent form ("ignore already exists" + parent
        # creation). Without -p, a second run aborts with "Bucket already
        # owned" which would make stop+restart flow brittle.
        self._mc("mb", "-p", f"local/{MINIO_BUCKET}")

    def stop(self) -> None:
        subprocess.run(
            self.rt.cmd("rm", "-f", self.container),
            capture_output=True,
            check=False,
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
        """Returns [(key, size), ...] for every object under `prefix`, with
        each key normalized to BUCKET-relative.

        `prefix` is bucket-relative, e.g. "basic/xorbs/" — matches the
        layout the server writes (BALE_S3_PREFIX + "xorbs/"/<aa>/<bb>/<hex>).
        `mc ls --json` reports each `key` relative to the listed prefix (e.g.
        "<aa>/<bb>/<hex>"), so we re-prepend `prefix` to get a key usable with
        `mc cat`/`mc pipe`. (Guarded so a mc build that already returns
        bucket-relative keys isn't double-prefixed.) Returns an empty list
        when the prefix has no objects; `mc ls` emits nothing, not an error.
        """
        completed = subprocess.run(
            self.rt.cmd(
                "exec",
                self.container,
                "mc",
                "ls",
                "--recursive",
                "--json",
                f"local/{MINIO_BUCKET}/{prefix}",
            ),
            capture_output=True,
            check=False,
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
            key = str(key)
            if not key.startswith(prefix):
                key = prefix + key
            out.append((key, int(size)))
        return out

    def total_bytes(self, prefix: str) -> int:
        return sum(sz for _key, sz in self.list_objects(prefix))

    def get_object(self, prefix_key: str) -> bytes:
        """Read an object's bytes via `mc cat` inside the container.

        `prefix_key` is bucket-relative (e.g. "basic/xorbs/aa/bb/<hex>").
        """
        completed = subprocess.run(
            self.rt.cmd(
                "exec",
                self.container,
                "mc",
                "cat",
                f"local/{MINIO_BUCKET}/{prefix_key}",
            ),
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"`mc cat {prefix_key}` failed: "
                f"{completed.stderr.decode('utf-8', 'replace')}"
            )
        return completed.stdout

    def put_object(self, prefix_key: str, data: bytes) -> None:
        """Overwrite an object's bytes via `mc pipe` (stdin) inside the
        container. The bucket-level analogue of writing a file under the
        fs `data_root` — used by the tampered-xorb phase to corrupt a
        stored xorb and then restore it."""
        completed = subprocess.run(
            self.rt.cmd(
                "exec",
                "-i",
                self.container,
                "mc",
                "pipe",
                f"local/{MINIO_BUCKET}/{prefix_key}",
            ),
            input=data,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"`mc pipe {prefix_key}` failed: "
                f"{completed.stderr.decode('utf-8', 'replace')}"
            )


# =============================================================================
# StorageView (bucket-level analogue of ServerHandle.disk_*_bytes)
# =============================================================================


@dataclass
class S3StorageView:
    """Inspect a server's S3 footprint by prefix.

    A server's `BALE_S3_PREFIX` (e.g. "dedup/") gets the same shape as
    `ServerHandle.disk_xorb_bytes()` / `disk_total_bytes()`, but answered
    by `mc ls` against the bucket. `ServerHandle` holds one of these in
    S3 mode and delegates its `disk_*_bytes` to it.
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
        # us-east-1 is what the AWS SDK assumes by default; the actual choice
        # is moot for MinIO.
        "BALE_S3_REGION": "us-east-1",
        # Per-server prefix — equivalent to the fs suite's per-phase data_root.
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


def prefix_for_data_root(data_root: Path, anchor: Path) -> str:
    """Derive a stable, distinct bucket prefix from a server's `data_root`.

    `anchor` is the run's tmpdir (an ancestor of every server's data_root),
    so the relative path is unique per server and identical across a restart
    on the same dir. Falls back to the basename only if `data_root` somehow
    sits outside the anchor.
    """
    try:
        rel = data_root.resolve().relative_to(anchor.resolve())
        key = str(rel)
    except ValueError:
        key = data_root.name
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", key).strip("-")
    return f"{safe or 'root'}/"


# =============================================================================
# Active S3 backend (process-global; mirrors covstate for coverage mode)
# =============================================================================


@dataclass
class ActiveS3Backend:
    """The S3 backend in force for the whole run, set by `run.py --backend s3`.

    Held process-global (like the coverage config) so `start_container` picks
    it up for every container without threading a flag through every phase
    signature. `prefix_anchor` is the run's tmpdir; `start_container` derives
    each server's bucket prefix relative to it.
    """

    minio: MinioGuard
    network: Network
    prefix_anchor: Path


_ACTIVE_S3: Optional[ActiveS3Backend] = None


def set_active_s3_backend(backend: Optional[ActiveS3Backend]) -> None:
    global _ACTIVE_S3
    _ACTIVE_S3 = backend


def get_active_s3_backend() -> Optional[ActiveS3Backend]:
    return _ACTIVE_S3
