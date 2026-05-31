"""baleforgit-server + sshd container lifecycle."""

from __future__ import annotations

import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from baleharness.config import (
    BROWSER_DL_JWT,
    CONTAINER_NAME_PREFIX,
    E2E_HUB_TOKEN,
    E2E_OWNER,
    E2E_REPO_2,
    E2E_USER,
    HEALTHZ_TIMEOUT_S,
    SSH_READY_TIMEOUT_S,
)
from baleharness.covstate import get_coverage
from baleharness.logutil import TestFailure, info
from baleharness.proc import dir_size_bytes, pick_free_port
from baleharness.runtime import Runtime, host_mount_path
from baleharness.pgbackend import (
    db_for_data_root,
    get_active_postgres_backend,
)
from baleharness.s3backend import (
    S3StorageView,
    get_active_s3_backend,
    prefix_for_data_root,
    s3_server_env,
)


@dataclass
class ServerHandle:
    rt: Runtime
    name: str
    cas_port: int
    ssh_port: int
    data_root: Path
    public_host_url: str
    # Set in S3 mode: a bucket-prefix view that answers disk_*_bytes from
    # MinIO instead of the (empty) local data_root/xorbs tree.
    s3_view: Optional[S3StorageView] = None

    @property
    def healthz_url(self) -> str:
        return f"{self.public_host_url}/healthz"

    def stop(self) -> None:
        # In coverage mode SIGKILL (`rm -f`) prevents the server's atexit
        # hook from flushing .profraw files. Send SIGTERM first so the
        # axum graceful-shutdown path runs, LLVM atexit writes profiles,
        # then `--rm` on `podman run` auto-removes the container. Prod
        # mode skips this for speed.
        if get_coverage() is not None:
            subprocess.run(
                self.rt.cmd("stop", "-t", "10", self.name),
                capture_output=True,
                check=False,
            )
        subprocess.run(
            self.rt.cmd("rm", "-f", self.name), capture_output=True, check=False
        )

    def logs(self) -> str:
        completed = subprocess.run(
            self.rt.cmd("logs", self.name), capture_output=True, check=False
        )
        return completed.stdout.decode("utf-8", "replace") + completed.stderr.decode(
            "utf-8", "replace"
        )

    def is_healthy(self) -> bool:
        """Quiet one-shot `/healthz` probe (no retry, no logging). A crashed
        server's container exits under `--rm`, so this goes false the moment
        the process dies — the per-push crash detector the churn phase needs."""
        try:
            with urllib.request.urlopen(self.healthz_url, timeout=2) as resp:
                return resp.status == 200
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
            return False

    def disk_xorb_bytes(self) -> int:
        if self.s3_view is not None:
            return self.s3_view.xorb_bytes()
        return dir_size_bytes(self.data_root / "xorbs")

    def disk_shard_bytes(self) -> int:
        if self.s3_view is not None:
            return self.s3_view.shard_bytes()
        return dir_size_bytes(self.data_root / "shards")

    def disk_total_bytes(self) -> int:
        return self.disk_xorb_bytes() + self.disk_shard_bytes()


def start_container(
    rt: Runtime,
    *,
    image_tag: str,
    data_root: Path,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    ssh_public_key: str,
    test_repos: list[str],
    cas_port: Optional[int] = None,
    ssh_port: Optional[int] = None,
    quota_bytes: Optional[int] = None,
    admin_token_hex: Optional[str] = None,
    name_suffix: Optional[str] = None,
    public_host_url_override: Optional[str] = None,
    extra_env: Optional[dict[str, str]] = None,
    extra_run_args: Optional[list[str]] = None,
) -> ServerHandle:
    cas_port = cas_port or pick_free_port()
    ssh_port = ssh_port or pick_free_port()
    # public_host_url is the URL the SSH forge-auth script hands back to the
    # client. The connection-drop phase points it at an in-process TCP proxy
    # instead of the container's port so it can sever connections mid-upload
    # while the server itself stays running.
    public_host_url = public_host_url_override or f"http://127.0.0.1:{cas_port}"
    name = f"{CONTAINER_NAME_PREFIX}-{name_suffix or secrets.token_hex(4)}"
    bale_grants = ",".join(f"{E2E_HUB_TOKEN}:{E2E_USER}:{r}:write" for r in test_repos)
    # The browser-download phase presents a forge-style JWT instead of the
    # opaque hub token, so register it as a read grant on repo2 wherever repo2
    # is hosted (static authz matches the bearer verbatim).
    repo2_id = f"{E2E_OWNER}/{E2E_REPO_2}"
    if repo2_id in test_repos:
        bale_grants += f",{BROWSER_DL_JWT}:{E2E_USER}:{repo2_id}:read"

    env_kvs = [
        "BALE_LISTEN=0.0.0.0:8080",
        "BALE_DATA_ROOT=/data",
        f"BALE_PUBLIC_URL={public_host_url}",
        f"BALE_PUBLIC_HOST_URL={public_host_url}",
        f"BALE_JWT_SECRET_HEX={jwt_secret_hex}",
        f"BALE_TRANSFER_SECRET_HEX={transfer_secret_hex}",
        f"BALE_GRANTS={bale_grants}",
        f"E2E_HUB_TOKEN={E2E_HUB_TOKEN}",
        f"SSH_AUTHORIZED_KEY={ssh_public_key}",
        f"TEST_REPOS={' '.join(test_repos)}",
        "RUST_LOG=info",
    ]
    if quota_bytes is not None:
        env_kvs.append(f"BALE_DEFAULT_QUOTA_BYTES={quota_bytes}")
    if admin_token_hex is not None:
        env_kvs.append(f"BALE_ADMIN_TOKEN_HEX={admin_token_hex}")

    # `run.py --backend s3` and/or `--meta postgres` set process-global backends;
    # when active, auto-inject their env + the shared-network arg for every
    # container so the full fs phase registry runs against MinIO / Postgres
    # unchanged. A caller's explicit extra_env (the bespoke s3lib / coverage
    # phases) wins on key conflicts. Both backends share one podman network, so
    # the `--network` arg is added exactly once even when both are active.
    s3_view: Optional[S3StorageView] = None
    networks: list[str] = []
    s3_backend = get_active_s3_backend()
    if s3_backend is not None:
        prefix = prefix_for_data_root(data_root, s3_backend.prefix_anchor)
        merged = s3_server_env(s3_backend.minio, prefix=prefix)
        if extra_env:
            merged.update(extra_env)
        extra_env = merged
        s3_view = S3StorageView(s3_backend.minio, extra_env["BALE_S3_PREFIX"])
        networks.append(s3_backend.network.name)

    # Postgres metadata store: derive a per-data_root database (the metadata
    # analogue of the S3 per-data_root bucket prefix), create it, and point the
    # server at it. The fs/s3 blob store is unaffected — only the MetadataStore
    # changes.
    pg_backend = get_active_postgres_backend()
    if pg_backend is not None:
        dbname = db_for_data_root(data_root, pg_backend.prefix_anchor)
        pg_backend.guard.ensure_database(dbname)
        merged = {"BALE_POSTGRES_URL": pg_backend.guard.url_for_db(dbname)}
        if extra_env:
            merged.update(extra_env)
        extra_env = merged
        if pg_backend.network.name not in networks:
            networks.append(pg_backend.network.name)

    if networks:
        with_net = list(extra_run_args or [])
        for net in networks:
            with_net += ["--network", net]
        extra_run_args = with_net

    # extra_env carries the BALE_S3_* wiring (from the active backend above, or
    # explicitly from the coverage s3 phases). Existing fs call sites pass None
    # and behave exactly as before.
    if extra_env:
        for k, v in extra_env.items():
            env_kvs.append(f"{k}={v}")

    # Bind-mount `<data_root>/git-home` too so the bare git repos under
    # /home/git survive a container restart. Without this, the restart
    # persistence phase brings up a fresh container with empty repos and the
    # post-restart clone has no refs to check out.
    git_home_root = data_root.parent / "git-home"
    git_home_root.mkdir(exist_ok=True)
    cmd: list[str] = [
        rt.exe,
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{cas_port}:8080",
        "-p",
        f"127.0.0.1:{ssh_port}:2222",
        "-v",
        f"{host_mount_path(data_root)}:/data",
        "-v",
        f"{host_mount_path(git_home_root)}:/home/git",
    ]
    # In --coverage mode every container shares the same host profile dir,
    # bind-mounted as /coverage. The in-container `bale` user writes
    # .profraw files there; entrypoint.sh propagates LLVM_PROFILE_FILE.
    if get_coverage() is not None:
        cmd.extend(["-v", f"{host_mount_path(get_coverage().profile_dir)}:/coverage"])
        env_kvs.append(f"LLVM_PROFILE_FILE={get_coverage().container_profile_template}")
    for kv in env_kvs:
        cmd.extend(["-e", kv])
    # extra_run_args attaches the container to the shared podman network in S3 /
    # Postgres mode (set above from the active backend, or by the coverage s3
    # phases) so server→MinIO / server→Postgres traffic resolves.
    if extra_run_args:
        cmd.extend(extra_run_args)
    cmd.append(image_tag)

    info(
        f"starting container {name} (cas=:{cas_port}, ssh=:{ssh_port}, "
        f"data={data_root})"
    )
    completed = _run_container_start(rt, cmd, name)
    if completed.returncode != 0:
        raise TestFailure(
            "container start failed:\n"
            f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
        )
    handle = ServerHandle(
        rt, name, cas_port, ssh_port, data_root, public_host_url, s3_view
    )
    wait_for_healthz(handle)
    wait_for_ssh(handle)
    return handle


def _is_port_bind_conflict(stderr: str) -> bool:
    s = stderr.lower()
    return (
        "address already in use" in s
        or "couldn't listen on requested" in s
        or ("pasta failed" in s and "listen failed" in s)
    )


def _run_container_start(rt: Runtime, cmd: list[str], name: str):
    # podman-on-Windows occasionally can't bind a host port that
    # pick_free_port just saw as free: pasta's teardown of a prior --rm'd
    # container lags, so its host-side forward still holds the port. The
    # port is load-bearing (restart phases bake the ssh port into the git
    # remote URL), so we can't re-pick — wait for the stale forward to clear
    # and retry the same command, clearing any half-created container first.
    attempts = 6
    completed = subprocess.run(cmd, capture_output=True, check=False)
    for i in range(1, attempts):
        if completed.returncode == 0:
            return completed
        if not _is_port_bind_conflict(completed.stderr.decode("utf-8", "replace")):
            return completed
        subprocess.run(rt.cmd("rm", "-f", name), capture_output=True, check=False)
        time.sleep(0.5 * i)
        completed = subprocess.run(cmd, capture_output=True, check=False)
    return completed


def wait_for_healthz(handle: ServerHandle) -> None:
    deadline = time.monotonic() + HEALTHZ_TIMEOUT_S
    last_err: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(handle.healthz_url, timeout=2) as resp:
                if resp.status == 200:
                    info("server healthz: ok")
                    return
                last_err = f"status {resp.status}"
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
            last_err = str(e)
        time.sleep(0.3)
    raise TestFailure(
        f"baleforgit-server did not become healthy within {HEALTHZ_TIMEOUT_S}s "
        f"(last error: {last_err})\n"
        f"--- container logs ---\n{handle.logs()}"
    )


def wait_for_ssh(handle: ServerHandle) -> None:
    deadline = time.monotonic() + SSH_READY_TIMEOUT_S
    last_err: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(
                ("127.0.0.1", handle.ssh_port), timeout=2
            ) as s:
                banner = s.recv(64)
                if banner.startswith(b"SSH-"):
                    info(f"sshd banner: {banner.strip().decode('ascii', 'replace')}")
                    return
                last_err = f"non-SSH banner: {banner!r}"
        except (OSError, ConnectionError, TimeoutError) as e:
            last_err = str(e)
        time.sleep(0.3)
    raise TestFailure(
        f"sshd inside the container did not respond on :{handle.ssh_port} "
        f"within {SSH_READY_TIMEOUT_S}s (last error: {last_err})\n"
        f"--- container logs ---\n{handle.logs()}"
    )
