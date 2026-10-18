"""Failure-recovery phases + shared background-push helpers."""

from __future__ import annotations

import os
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    BIG_FILE_BYTES,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_CPUT_A,
    E2E_REPO_CPUT_B,
    E2E_REPO_WRITEFAIL,
    FS_CPUT_BYTES,
    FS_WRITEFAIL_BYTES,
)
from baleharness.gitutil import git, verify_pointer_at, verify_worktree
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.mocks import TcpProxy, hold_db_writer_lock
from baleharness.payloads import deterministic_payload
from baleharness.pgbackend import get_active_postgres_backend
from baleharness.proc import pick_free_port, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.s3backend import S3_PROXY_THROTTLE_BPS, get_active_s3_backend
from baleharness.server import ServerHandle, start_container
from baleharness.storage import staging_files
from baleharness.timing import Timings


def _dir_entry_count(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(len(files) for _cur, _dirs, files in os.walk(root))


def _start_push_background(repo: Path, env: dict) -> subprocess.Popen:
    return subprocess.Popen(
        ["git", "push", "-u", "origin", "main"],
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def fail_fast_xet_env(env: dict) -> dict:
    """Trim xet's retry budget so a deliberately broken upstream fails the push
    in ~1s instead of the default ~30–360s of backoff."""
    env = dict(env)
    env["HF_XET_CLIENT_RETRY_MAX_ATTEMPTS"] = "1"
    env["HF_XET_CLIENT_RETRY_BASE_DELAY"] = "100ms"
    env["HF_XET_CLIENT_RETRY_MAX_DURATION"] = "2s"
    return env


def _wait_push(proc: subprocess.Popen, timeout_s: float) -> int:
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)
        raise TestFailure(
            f"git push subprocess did not exit within {timeout_s}s; killed"
        )
    return proc.returncode


def phase_failure_server_kill_mid_upload(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """SIGKILL the server mid-upload, restart it, and a re-run `git push` must
    recover. A throttled proxy in front of the CAS port widens the upload to
    seconds (a 4 MiB localhost push otherwise finishes in milliseconds), so
    the kill lands mid-stream and push-pending must fail without draining
    staging."""
    phase_root = work_root / "failure-kill"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    cas_port = pick_free_port()
    ssh_port = pick_free_port()
    proxy_port = pick_free_port()
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=cas_port,
        # ~1 MiB/s: ~4s for the 4 MiB payload.
        throttle_bytes_per_sec=1024 * 1024,
    )
    proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=f"kill-mid-upload-{secrets.token_hex(3)}",
        public_host_url_override=proxy_url,
    )
    new_server: ServerHandle | None = None
    payload_size = 4 * 1024 * 1024
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="kill-mid-upload-client",
        )
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(payload_size, seed=b"kill-mid-upload")
        payload_sha = sha256_bytes(payload)
        (repo / "killtest.bin").write_bytes(payload)
        with timings.measure("failure-kill: stage + commit", bytes_moved=payload_size):
            git(["add", "killtest.bin"], cwd=repo, env=env)
            git(["commit", "-m", "kill mid-upload"], cwd=repo, env=env)
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:killtest.bin",
            expected_sha=payload_sha,
            expected_size=payload_size,
            label="failure-kill:after-commit",
        )

        # Once 64 KiB has flowed, the throttle leaves seconds before the body
        # fully lands; `server.stop()` is `podman rm -f` (SIGKILL).
        with timings.measure("failure-kill: push then crash"):
            proc = _start_push_background(repo, env)
            try:
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.02)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"proxy never saw ≥64 KiB within 15s "
                        f"(seen {proxy.bytes_forwarded})"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise
            info("  killing server mid-upload")
            server.stop()
            # Otherwise xet keeps reconnecting through the still-listening
            # proxy until its retry budget runs out (a 30–60s hang).
            proxy.kill()
            rc = _wait_push(proc, timeout_s=30.0)
            if rc == 0:
                raise TestFailure(
                    "push subprocess unexpectedly succeeded despite mid-upload "
                    "server kill"
                )

        if not staging_files(repo):
            raise TestFailure(
                "failure-kill: staging dir empty after crashed push — "
                "push-pending drained staging before the upload finalized"
            )
        verify_worktree(
            repo,
            "killtest.bin",
            expected_sha=payload_sha,
            expected_size=payload_size,
            label="failure-kill:after-crashed-push",
        )
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:killtest.bin",
            expected_sha=payload_sha,
            expected_size=payload_size,
            label="failure-kill:after-crashed-push",
        )

        # Proxy first: start_container polls /healthz at public_host_url,
        # which is the proxy.
        proxy.start()
        with timings.measure("failure-kill: restart server"):
            new_server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
                cas_port=cas_port,
                ssh_port=ssh_port,
                admin_token_hex=admin_token_hex,
                name_suffix=f"kill-mid-upload-restart-{secrets.token_hex(3)}",
                public_host_url_override=proxy_url,
            )

        # Content-addressed: xorbs that landed before the crash re-POST as
        # `was_inserted=false`; a torn write left nothing, so it uploads fresh.
        with timings.measure(
            "failure-kill: retry push after restart", bytes_moved=payload_size
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "failure-kill: staging dir not drained after successful retry"
            )

        # Fresh clone: proves it reconstructs from server state, not the pusher's cache.
        with timings.measure(
            "failure-kill: cold clone after recovery", bytes_moved=payload_size
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=new_server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="kill-mid-upload-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "killtest.bin",
            expected_sha=payload_sha,
            expected_size=payload_size,
            label="failure-kill:after-recovery-clone",
        )
    finally:
        proxy.kill()
        if new_server is not None:
            new_server.stop()
        else:
            server.stop()


def phase_failure_connection_drop_mid_upload(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drop the client→server connection mid-upload while the server stays up:
    the advertised CAS URL is an in-process proxy whose kill() slams every
    socket without a FIN. After restarting the proxy, a retry must succeed
    with no server-side intervention."""
    phase_root = work_root / "failure-conndrop"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    cas_port = pick_free_port()
    ssh_port = pick_free_port()
    proxy_port = pick_free_port()
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=cas_port,
        throttle_bytes_per_sec=1024 * 1024,
    )
    proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    payload_size = 4 * 1024 * 1024
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=f"conndrop-{secrets.token_hex(3)}",
        # forge-auth hands the client BALE_PUBLIC_HOST_URL, so every CAS
        # request flows through the proxy.
        public_host_url_override=proxy_url,
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="conndrop-client",
        )
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(payload_size, seed=b"conndrop")
        payload_sha = sha256_bytes(payload)
        (repo / "conndrop.bin").write_bytes(payload)
        with timings.measure(
            "failure-conndrop: stage + commit", bytes_moved=payload_size
        ):
            git(["add", "conndrop.bin"], cwd=repo, env=env)
            git(["commit", "-m", "conndrop mid-upload"], cwd=repo, env=env)

        with timings.measure("failure-conndrop: push then drop"):
            proc = _start_push_background(repo, env)
            try:
                # Proves the upload is mid-stream, not still in client-side CDC.
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.05)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"proxy never forwarded ≥64 KiB within 15s "
                        f"(seen {proxy.bytes_forwarded})"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise
            info("  dropping all connections via proxy.kill()")
            proxy.kill()
            rc = _wait_push(proc, timeout_s=30.0)
            if rc == 0:
                raise TestFailure(
                    "push subprocess unexpectedly succeeded despite mid-upload "
                    "connection drop"
                )
        if not staging_files(repo):
            raise TestFailure("failure-conndrop: staging dir empty after dropped push")
        # Unlike failure-kill the server must still be up; hit the CAS port
        # directly since server.healthz_url goes through the dead proxy.
        direct_healthz = f"http://127.0.0.1:{server.cas_port}/healthz"
        with urllib.request.urlopen(direct_healthz, timeout=5) as resp:
            if resp.status != 200:
                raise TestFailure(
                    f"server unhealthy after connection drop: {resp.status}"
                )

        # No container restart: the retry runs against the same server.
        proxy.start()
        with timings.measure(
            "failure-conndrop: retry push after proxy restart",
            bytes_moved=payload_size,
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "failure-conndrop: staging dir not drained after successful retry"
            )
        with timings.measure(
            "failure-conndrop: cold clone after recovery", bytes_moved=payload_size
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="conndrop-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "conndrop.bin",
            expected_sha=payload_sha,
            expected_size=payload_size,
            label="failure-conndrop:after-recovery-clone",
        )
    finally:
        proxy.kill()
        server.stop()


def phase_failure_transient_db(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Hold the SQLite writer lock while a push is in flight: the push must
    still succeed, the server waiting it out via busy_timeout (30s). Push
    wallclock ≥ the hold proves the server really waited on the lock."""
    # Locks meta.db via a sidecar sqlite3 shell; Postgres has no meta.db.
    if get_active_postgres_backend() is not None:
        info("-- failure-dbbusy: SQLite busy_timeout test; skipping under postgres")
        return
    phase_root = work_root / "failure-dbbusy"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix=f"dbbusy-{secrets.token_hex(3)}",
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="dbbusy-client",
        )
        # Big enough for real DB writes, small enough that the lock hold
        # dominates the wallclock.
        payload_size = 1 * 1024 * 1024
        payload = deterministic_payload(payload_size, seed=b"dbbusy")
        payload_sha = sha256_bytes(payload)
        (repo / "dbbusy.bin").write_bytes(payload)
        with timings.measure(
            "failure-dbbusy: stage + commit", bytes_moved=payload_size
        ):
            git(["add", "dbbusy.bin"], cwd=repo, env=env)
            git(["commit", "-m", "dbbusy"], cwd=repo, env=env)

        hold_seconds = 2.0
        t0 = time.perf_counter()
        with timings.measure("failure-dbbusy: push while DB writer-locked"):
            with hold_db_writer_lock(server, hold_seconds=hold_seconds):
                git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        push_elapsed = time.perf_counter() - t0

        # Faster than the hold means the server never contended and the test
        # was vacuous. No upper bound: post-release writes serialize.
        if push_elapsed < hold_seconds * 0.8:
            raise TestFailure(
                f"failure-dbbusy: push finished in {push_elapsed:.2f}s but "
                f"lock was held for {hold_seconds:.2f}s — the server's "
                "writes didn't actually wait on the writer lock"
            )
        info(f"  push wallclock {push_elapsed:.2f}s (lock held {hold_seconds:.1f}s)")
        if staging_files(repo):
            raise TestFailure(
                "failure-dbbusy: staging not drained — push reported success "
                "but push-pending didn't finalize"
            )
        with timings.measure("failure-dbbusy: cold clone", bytes_moved=payload_size):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="dbbusy-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "dbbusy.bin",
            expected_sha=payload_sha,
            expected_size=payload_size,
            label="failure-dbbusy:after-clone",
        )
    finally:
        server.stop()


def phase_failure_s3_conndrop(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drop the server↔MinIO connection mid-PUT (`failure-conndrop` severs
    client↔server instead). S3-only.

    A host-side TcpProxy between server and MinIO (via a BALE_S3_ENDPOINT_URL
    override, which wins over the auto-injected endpoint) is killed for ~3s.
    The SDK may swallow the drop or give up and leave the client to retry;
    either way the file must reconstruct from MinIO with one stored copy."""
    backend = get_active_s3_backend()
    if backend is None:
        info("-- failure-s3-conndrop: server↔storage drop is S3-only; skipping")
        return
    minio = backend.minio

    phase_root = work_root / "failure-s3-conndrop"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()

    proxy_port = pick_free_port()
    # 0.0.0.0 so the container reaches it via the host's primary IP; throttled
    # so the upload can't finish before the kill lands.
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=minio.host_port,
        throttle_bytes_per_sec=S3_PROXY_THROTTLE_BPS,
        bind_host="0.0.0.0",
    )
    proxy.start()
    proxy_url = f"http://{minio.host_ip}:{proxy_port}"
    info(f"  server→S3 proxy URL: {proxy_url}")

    # disk_*_bytes still reads the bucket directly, not via the proxy.
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix="s3-conndrop",
        extra_env={"BALE_S3_ENDPOINT_URL": proxy_url},
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="s3-conndrop-client",
        )
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(BIG_FILE_BYTES, seed=b"s3-conndrop")
        payload_sha = sha256_bytes(payload)
        (repo / "s3drop.bin").write_bytes(payload)
        with timings.measure(
            "failure-s3-conndrop: stage + commit", bytes_moved=BIG_FILE_BYTES
        ):
            git(["add", "s3drop.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3 mid-upload drop"], cwd=repo, env=env)

        with timings.measure("failure-s3-conndrop: push then drop"):
            proc = _start_push_background(repo, env)
            try:
                # Proves the server is mid-PUT, not still parsing the request.
                deadline = time.monotonic() + 30.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.05)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"failure-s3-conndrop: proxy never forwarded ≥64 KiB "
                        f"within 30s (seen {proxy.bytes_forwarded}) — the server "
                        "may not be using the BALE_S3_ENDPOINT_URL override"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise

            info("  dropping server→MinIO connections via proxy.kill()")
            proxy.kill()
            # Long enough to usually exhaust aws-sdk-s3's retries; a shorter
            # drop is swallowed by the SDK and the client-retry path never runs.
            time.sleep(3.0)
            proxy.start()
            info("  proxy restarted; awaiting push exit")
            rc = _wait_push(proc, timeout_s=120.0)
            push_succeeded_first_try = rc == 0

        if push_succeeded_first_try:
            info("  push survived the drop via aws-sdk-s3 retries")
        else:
            info("  push failed mid-drop; retrying (proxy is back up)")
            if not staging_files(repo):
                raise TestFailure(
                    "failure-s3-conndrop: staging dir empty after failed push — "
                    "client lost its pending xorbs"
                )
            with timings.measure(
                "failure-s3-conndrop: retry push", bytes_moved=BIG_FILE_BYTES
            ):
                git(["push", "-u", "origin", "main"], cwd=repo, env=env)
            if staging_files(repo):
                raise TestFailure(
                    "failure-s3-conndrop: staging dir not drained after retry"
                )

        # Cold clone proves the file genuinely lives in MinIO and reconstructs
        # (the presigned download traffic doesn't go through the dropped proxy).
        with timings.measure(
            "failure-s3-conndrop: cold clone after recovery",
            bytes_moved=BIG_FILE_BYTES,
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="s3-conndrop-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "s3drop.bin",
            expected_sha=payload_sha,
            expected_size=BIG_FILE_BYTES,
            label="failure-s3-conndrop:after-recovery-clone",
        )

        # A retry that re-uploaded must still leave ~one copy, not two.
        stored = server.disk_xorb_bytes()
        if stored > BIG_FILE_BYTES * 3 // 2:
            raise TestFailure(
                f"failure-s3-conndrop: stored xorb bytes {fmt_bytes(stored)} "
                f"exceeds 1.5× payload ({fmt_bytes(BIG_FILE_BYTES)}) — retry may "
                "have double-written"
            )
        info(f"  failure-s3-conndrop: final stored xorb bytes = {fmt_bytes(stored)}")
    finally:
        proxy.kill()
        server.stop()


def phase_failure_s3_presign_unreachable(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Presigned download URLs on a host the client can't resolve must fail the
    checkout fast, not hang: xet-core treats "host not found" as retryable and
    parks in a base-squared backoff (~2.5h on the 2nd retry) unless the
    cold-path watchdog aborts.

    BALE_S3_PUBLIC_ENDPOINT_URL (presign-only) points at a bogus host while
    server writes still reach MinIO, so the push succeeds and a cold clone's
    checkout must die with the stall error under a short
    BALE_DOWNLOAD_STALL_SECS. S3-only."""
    backend = get_active_s3_backend()
    if backend is None:
        info("-- failure-s3-presign-unreachable: presigned URLs are S3-only; skipping")
        return

    phase_root = work_root / "failure-s3-presign-unreachable"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()

    stall_secs = 8
    # `.invalid` is reserved (RFC 6761): guaranteed NXDOMAIN.
    bogus_endpoint = "http://bale-presign-unreachable.invalid:9000"

    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix="presign-unreachable",
        extra_env={"BALE_S3_PUBLIC_ENDPOINT_URL": bogus_endpoint},
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="presign-unreachable-client",
        )
        payload = deterministic_payload(4 * 1024 * 1024, seed=b"presign-unreachable")
        (repo / "unreachable.bin").write_bytes(payload)
        with timings.measure(
            "failure-s3-presign-unreachable: push (server-side write)"
        ):
            git(["add", "unreachable.bin"], cwd=repo, env=env)
            git(["commit", "-m", "presign unreachable"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)

        # Empty chunk cache: smudge takes the cold path to the bogus host.
        clone_path, clone_env, _ = init_repo_for_clone(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="presign-unreachable-clone",
        )
        clone_env = dict(clone_env)
        clone_env["BALE_DOWNLOAD_STALL_SECS"] = str(stall_secs)

        with timings.measure("failure-s3-presign-unreachable: checkout fails fast"):
            start = time.monotonic()
            res = git(
                ["checkout", "main"],
                cwd=clone_path,
                env=clone_env,
                capture=True,
                expect_fail=True,
            )
            elapsed = time.monotonic() - start

        if res.returncode == 0:
            raise TestFailure(
                "failure-s3-presign-unreachable: checkout unexpectedly succeeded "
                "against an unreachable presign host"
            )
        stderr = res.stderr.decode("utf-8", "replace") if res.stderr else ""
        if "stalled: no data received" not in stderr:
            raise TestFailure(
                "failure-s3-presign-unreachable: checkout failed but without the "
                f"cold-path stall watchdog message; stderr was:\n{stderr}"
            )
        # Generous margin for slow CI; the failure mode is hours, not seconds.
        if elapsed > stall_secs + 30:
            raise TestFailure(
                f"failure-s3-presign-unreachable: checkout took {elapsed:.0f}s "
                f"(stall={stall_secs}s) — the watchdog did not abort promptly"
            )
        info(
            f"  failure-s3-presign-unreachable: checkout aborted in {elapsed:.0f}s "
            f"with the stall error (stall={stall_secs}s)"
        )
    finally:
        server.stop()


def phase_failure_fs_write_fail(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """A failed fs blob write must leave nothing behind: `write_atomic` writes
    `tmp/<uuid>`, fsyncs, then links it into place, and on a write/fsync error
    must remove the tmp and surface the error. ENOSPC can't be injected
    without putting tmp/ on another filesystem (breaking the same-fs link), so
    BALE_TEST_FS_WRITE_FAIL forces every blob write down the failure arm.

    The push must fail with xorbs/, shards/ and tmp/ empty; after a restart
    without the hook a re-push must round-trip, proving no poison was left.
    fs-only."""
    if get_active_s3_backend() is not None:
        info("-- failure-fs-writefail: fs BlobStore write path is S3-skipped")
        return
    phase_root = work_root / "failure-fs-writefail"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    repo_id = f"{E2E_OWNER}/{E2E_REPO_WRITEFAIL}"
    # Pinned so origin still resolves after the hook-off restart.
    cas_port = pick_free_port()
    ssh_port = pick_free_port()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[repo_id],
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=f"fs-writefail-{secrets.token_hex(3)}",
        extra_env={"BALE_TEST_FS_WRITE_FAIL": "1"},
    )
    new_server: ServerHandle | None = None
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_WRITEFAIL,
            name="fs-writefail-client",
        )
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(FS_WRITEFAIL_BYTES, seed=b"fs-writefail")
        payload_sha = sha256_bytes(payload)
        (repo / "wf.bin").write_bytes(payload)
        with timings.measure(
            "failure-fs-writefail: stage + commit", bytes_moved=FS_WRITEFAIL_BYTES
        ):
            git(["add", "wf.bin"], cwd=repo, env=env)
            git(["commit", "-m", "write-fail"], cwd=repo, env=env)

        with timings.measure("failure-fs-writefail: push (must fail)"):
            res = git(
                ["push", "-u", "origin", "main"],
                cwd=repo,
                env=env,
                capture=True,
                expect_fail=True,
            )
        if res.returncode == 0:
            raise TestFailure(
                "failure-fs-writefail: push succeeded despite forced write failure"
            )

        xorb_files = _dir_entry_count(data_root / "xorbs")
        shard_files = _dir_entry_count(data_root / "shards")
        tmp_files = _dir_entry_count(data_root / "tmp")
        if xorb_files or shard_files:
            raise TestFailure(
                f"failure-fs-writefail: write failed but blobs landed anyway "
                f"(xorbs={xorb_files}, shards={shard_files}) — half-write visible"
            )
        if tmp_files:
            raise TestFailure(
                f"failure-fs-writefail: {tmp_files} tmp file(s) leaked under "
                "tmp/ after a failed write — write_atomic didn't clean up"
            )
        info("  forced write failure stored nothing; tmp/ clean")

        server.stop()
        new_server = start_container(
            rt,
            image_tag=image_tag,
            data_root=data_root,
            jwt_secret_hex=jwt_secret,
            transfer_secret_hex=transfer_secret,
            ssh_public_key=ssh_public_key,
            test_repos=[repo_id],
            cas_port=cas_port,
            ssh_port=ssh_port,
            admin_token_hex=admin_token_hex,
            name_suffix=f"fs-writefail-recover-{secrets.token_hex(3)}",
        )
        with timings.measure(
            "failure-fs-writefail: re-push after clean restart",
            bytes_moved=FS_WRITEFAIL_BYTES,
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "failure-fs-writefail: staging not drained after recovery push"
            )
        with timings.measure(
            "failure-fs-writefail: cold clone after recovery",
            bytes_moved=FS_WRITEFAIL_BYTES,
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=new_server,
                owner=E2E_OWNER,
                repo=E2E_REPO_WRITEFAIL,
                name="fs-writefail-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "wf.bin",
            expected_sha=payload_sha,
            expected_size=FS_WRITEFAIL_BYTES,
            label="failure-fs-writefail:after-recovery-clone",
        )
    finally:
        if new_server is not None:
            new_server.stop()
        else:
            server.stop()


def phase_failure_fs_concurrent_put(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Two byte-identical pushes (to two repos, dodging a ref collision) race
    `write_atomic` on the same xorb paths and must converge: the loser hits the
    existence fast path or link(2)'s EEXIST, both `Ok(false)`. Both pushes must
    exit 0, stored xorb bytes stay ≈ one payload, tmp/ stays empty, and both
    repos clone back the original bytes. fs-only."""
    if get_active_s3_backend() is not None:
        info("-- failure-fs-cput: fs BlobStore write path is S3-skipped")
        return
    phase_root = work_root / "failure-fs-cput"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    repo_a = f"{E2E_OWNER}/{E2E_REPO_CPUT_A}"
    repo_b = f"{E2E_OWNER}/{E2E_REPO_CPUT_B}"
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[repo_a, repo_b],
        admin_token_hex=admin_token_hex,
        name_suffix=f"fs-cput-{secrets.token_hex(3)}",
    )
    try:
        payload = deterministic_payload(FS_CPUT_BYTES, seed=b"fs-cput")
        payload_sha = sha256_bytes(payload)
        repos = []
        for repo_name, suffix in ((E2E_REPO_CPUT_A, "a"), (E2E_REPO_CPUT_B, "b")):
            repo, env = init_repo_for_push(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=repo_name,
                name=f"fs-cput-{suffix}",
            )
            (repo / "c.bin").write_bytes(payload)
            git(["add", "c.bin"], cwd=repo, env=env)
            git(["commit", "-m", "concurrent put"], cwd=repo, env=env)
            repos.append((repo, env))

        with timings.measure(
            "failure-fs-cput: two concurrent pushes", bytes_moved=2 * FS_CPUT_BYTES
        ):
            procs = [_start_push_background(repo, env) for repo, env in repos]
            rcs = [_wait_push(p, timeout_s=120.0) for p in procs]
        if any(rc != 0 for rc in rcs):
            raise TestFailure(
                f"failure-fs-cput: a concurrent push failed (rcs={rcs}) — "
                "write_atomic didn't converge under a same-content race"
            )

        stored = server.disk_xorb_bytes()
        if stored > FS_CPUT_BYTES * 3 // 2:
            raise TestFailure(
                f"failure-fs-cput: stored xorb bytes {fmt_bytes(stored)} exceeds "
                f"1.5× payload ({fmt_bytes(FS_CPUT_BYTES)}) — the race double-wrote"
            )
        tmp_files = _dir_entry_count(data_root / "tmp")
        if tmp_files:
            raise TestFailure(
                f"failure-fs-cput: {tmp_files} tmp file(s) leaked after the race"
            )
        info(f"  concurrent pushes converged: stored {fmt_bytes(stored)}, tmp/ clean")

        for repo_name, suffix in ((E2E_REPO_CPUT_A, "a"), (E2E_REPO_CPUT_B, "b")):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=repo_name,
                name=f"fs-cput-clone-{suffix}",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
            verify_worktree(
                clone_path,
                "c.bin",
                expected_sha=payload_sha,
                expected_size=FS_CPUT_BYTES,
                label=f"failure-fs-cput:clone-{suffix}",
            )
    finally:
        server.stop()
