"""S3 backend plumbing for the e2e harness (MinIO sidecar + bucket views).

Kept free of `run`/`s3lib` imports so `server.py` can use it without a cycle.
`run.py --backend s3` sets a process-global `ActiveS3Backend` and every
`start_container` injects BALE_S3_* + the shared network, so the full phase
registry runs on MinIO unchanged; `s3lib.py`'s coverage phases pass
`s3_server_env`/`s3_run_args` explicitly instead.

Each server's `BALE_S3_PREFIX` derives from its `data_root`: distinct so phases
don't cross-contaminate, stable so a restart on the same dir (failure-kill,
offline-restart) lands on the same subtree.
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

from baleharness.logutil import TestFailure, info
from baleharness.proc import host_primary_ip, pick_free_port
from baleharness.runtime import Runtime

MINIO_IMAGE = "quay.io/minio/minio:RELEASE.2025-01-20T14-49-07Z"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"
MINIO_BUCKET = "bale-e2e"
# Covers a cold image pull on a fresh runner.
MINIO_READY_TIMEOUT_S = 180
MINIO_INTERNAL_PORT = 9000

# failure-s3-conndrop's server↔MinIO proxy: slow enough that the kill lands
# mid-stream on fast machines, fast enough that the 35 MiB retry takes < 20s.
S3_PROXY_THROTTLE_BPS = 2 * 1024 * 1024


@dataclass
class Network:
    rt: Runtime
    name: str

    @classmethod
    def create(cls, rt: Runtime) -> Network:
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
        # Best-effort: attached containers block removal, so tear them down first.
        subprocess.run(
            self.rt.cmd("network", "rm", self.name),
            capture_output=True,
            check=False,
        )


class MinioGuard:
    """Single-node MinIO container + `mc` introspection helpers.

    Published on 0.0.0.0 so both the host loopback (`host_url`) and the
    containers on the bridge (`shared_url`, via the host's primary IP) reach it.
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
    def start(cls, rt: Runtime, network: Network) -> MinioGuard:
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
                # No bind address = 0.0.0.0; see the class docstring.
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
        """One URL for the server (in container) and the client (on host):
        presigned URLs embed the host name, so both must reach the same string
        for the signature to validate."""
        return f"http://{self.host_ip}:{self.host_port}"

    @property
    def host_url(self) -> str:
        """Host-loopback URL, for host-side health polling."""
        return f"http://127.0.0.1:{self.host_port}"

    def wait_ready(self) -> None:
        url = f"{self.host_url}/minio/health/ready"
        deadline = time.monotonic() + MINIO_READY_TIMEOUT_S
        last_err: str | None = None
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
        # `mc` ships in the image, so no SigV4 plumbing is needed on the host.
        self._mc(
            "alias",
            "set",
            "local",
            f"http://127.0.0.1:{MINIO_INTERNAL_PORT}",
            MINIO_ACCESS_KEY,
            MINIO_SECRET_KEY,
        )
        # -p: idempotent; without it a rerun fails with "Bucket already owned".
        self._mc("mb", "-p", f"local/{MINIO_BUCKET}")

    def stop(self) -> None:
        subprocess.run(
            self.rt.cmd("rm", "-f", self.container),
            capture_output=True,
            check=False,
        )

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
        """[(bucket-relative key, size)] under bucket-relative `prefix`.

        `mc ls --json` keys are relative to the listed prefix, so `prefix` is
        re-prepended (unless already present) to make them usable with
        `get_object`/`put_object`. A missing prefix yields [], not an error.
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
        """`prefix_key` is bucket-relative (e.g. "basic/xorbs/aa/bb/<hex>")."""
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
        """Overwrite an object (adversarial phases corrupt, then restore, xorbs)."""
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


@dataclass
class S3StorageView:
    """Bucket-side backing for `ServerHandle.disk_*_bytes` in S3 mode."""

    minio: MinioGuard
    prefix: str

    def xorb_bytes(self) -> int:
        return self.minio.total_bytes(f"{self.prefix}xorbs/")

    def shard_bytes(self) -> int:
        return self.minio.total_bytes(f"{self.prefix}shards/")

    def total_bytes(self) -> int:
        return self.xorb_bytes() + self.shard_bytes()


def s3_server_env(
    minio: MinioGuard,
    *,
    prefix: str,
    endpoint_override: str | None = None,
) -> dict[str, str]:
    """BALE_S3_* env (read in crates/bale-server-bin/src/main.rs)."""
    return {
        "BALE_S3_BUCKET": MINIO_BUCKET,
        "BALE_S3_ENDPOINT_URL": endpoint_override or minio.shared_url,
        # MinIO speaks path-style only (no virtual-host addressing).
        "BALE_S3_FORCE_PATH_STYLE": "1",
        # MinIO SSE-S3 requires a KMS key; the throwaway test bucket has none.
        "BALE_S3_DISABLE_SSE": "1",
        "BALE_S3_ACCESS_KEY_ID": MINIO_ACCESS_KEY,
        "BALE_S3_SECRET_ACCESS_KEY": MINIO_SECRET_KEY,
        # Moot for MinIO; the SDK just needs one.
        "BALE_S3_REGION": "us-east-1",
        # Trailing "/" matters: keys become "<prefix>xorbs/aa/bb/<hex>".
        "BALE_S3_PREFIX": prefix,
    }


def s3_run_args(network: Network) -> list[str]:
    """No `--add-host=…:host-gateway`: it sometimes fails to resolve on macOS
    rootless podman, so MinIO is reached via the host's primary IP instead
    (`MinioGuard.shared_url`).
    """
    return ["--network", network.name]


def prefix_for_data_root(data_root: Path, anchor: Path) -> str:
    """Keyed on `data_root` relative to the run tmpdir `anchor`: unique per
    server, identical across a restart on the same dir."""
    try:
        rel = data_root.resolve().relative_to(anchor.resolve())
        key = str(rel)
    except ValueError:
        key = data_root.name
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", key).strip("-")
    return f"{safe or 'root'}/"


@dataclass
class ActiveS3Backend:
    """Process-global so `start_container` applies it to every container
    without threading a flag through each phase. `prefix_anchor` is the run's
    tmpdir (see `prefix_for_data_root`).
    """

    minio: MinioGuard
    network: Network
    prefix_anchor: Path


_ACTIVE_S3: ActiveS3Backend | None = None


def set_active_s3_backend(backend: ActiveS3Backend | None) -> None:
    global _ACTIVE_S3
    _ACTIVE_S3 = backend


def get_active_s3_backend() -> ActiveS3Backend | None:
    return _ACTIVE_S3
