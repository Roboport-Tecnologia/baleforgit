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
from baleharness.pgbackend import (
    db_for_data_root,
    get_active_postgres_backend,
)
from baleharness.proc import dir_size_bytes, pick_free_port
from baleharness.runtime import Runtime, host_mount_path
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
    # S3 mode: answers disk_*_bytes from MinIO, since data_root/xorbs is empty.
    s3_view: S3StorageView | None = None

    @property
    def healthz_url(self) -> str:
        return f"{self.public_host_url}/healthz"

    def stop(self) -> None:
        # `rm -f` SIGKILLs, so LLVM's atexit never flushes .profraw; in
        # coverage mode SIGTERM first for a graceful exit.
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
        """One-shot `/healthz` probe, no retry or logging. Under `--rm` a crashed
        server's container is gone, so this is false as soon as it dies."""
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

    def read_data_file(self, path: Path) -> bytes:
        # Files are `bale`-owned 0600 and the harness is a different host UID
        # (a subuid under rootless podman), so read via a root `exec`.
        rel = path.relative_to(self.data_root).as_posix()
        completed = subprocess.run(
            self.rt.cmd("exec", self.name, "cat", f"/data/{rel}"),
            capture_output=True,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"failed to read /data/{rel} in container: "
                + completed.stderr.decode("utf-8", "replace")
            )
        return completed.stdout

    def write_data_file(self, path: Path, data: bytes) -> None:
        # Same permission workaround as read_data_file.
        rel = path.relative_to(self.data_root).as_posix()
        completed = subprocess.run(
            self.rt.cmd(
                "exec", "-i", self.name, "sh", "-c", 'cat > "$0"', f"/data/{rel}"
            ),
            input=data,
            capture_output=True,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"failed to write /data/{rel} in container: "
                + completed.stderr.decode("utf-8", "replace")
            )


def start_container(
    rt: Runtime,
    *,
    image_tag: str,
    data_root: Path,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    ssh_public_key: str,
    test_repos: list[str],
    cas_port: int | None = None,
    ssh_port: int | None = None,
    quota_bytes: int | None = None,
    admin_token_hex: str | None = None,
    name_suffix: str | None = None,
    public_host_url_override: str | None = None,
    extra_env: dict[str, str] | None = None,
    extra_run_args: list[str] | None = None,
) -> ServerHandle:
    cas_port = cas_port or pick_free_port()
    ssh_port = ssh_port or pick_free_port()
    # The URL the SSH forge-auth script hands the client. Failure phases point
    # it at an in-process TCP proxy to sever connections with the server up.
    public_host_url = public_host_url_override or f"http://127.0.0.1:{cas_port}"
    name = f"{CONTAINER_NAME_PREFIX}-{name_suffix or secrets.token_hex(4)}"
    bale_grants = ",".join(f"{E2E_HUB_TOKEN}:{E2E_USER}:{r}:write" for r in test_repos)
    # The browser-download phase presents a forge-style JWT; static authz
    # matches bearers verbatim, so grant it read on repo2.
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

    # `--backend s3` / `--meta postgres` set process-global backends; inject
    # their env + network into every container so all phases run on them
    # unchanged. An explicit extra_env (s3lib phases) wins on conflicts. Both
    # backends share one podman network, so `--network` is added once.
    s3_view: S3StorageView | None = None
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

    # One database per data_root, like the S3 per-data_root prefix.
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

    if extra_env:
        for k, v in extra_env.items():
            env_kvs.append(f"{k}={v}")

    # Bare repos under /home/git must survive a restart, or the restart
    # phases' post-restart clone finds no refs.
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
    # All containers share one host profile dir; entrypoint.sh re-exports
    # LLVM_PROFILE_FILE for the server.
    if get_coverage() is not None:
        cmd.extend(["-v", f"{host_mount_path(get_coverage().profile_dir)}:/coverage"])
        env_kvs.append(f"LLVM_PROFILE_FILE={get_coverage().container_profile_template}")
    for kv in env_kvs:
        cmd.extend(["-e", kv])
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
    # podman-on-Windows: pasta's teardown of a prior --rm'd container lags, so
    # its host-side forward still holds a port pick_free_port saw as free.
    # Restart phases bake the ssh port into the remote URL, so retry the same
    # port rather than re-pick, removing any half-created container first.
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
    last_err: str | None = None
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
    last_err: str | None = None
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
