"""Failure-recovery phases + shared background-push helpers."""

from __future__ import annotations

import os
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Optional

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
from baleharness.proc import pick_free_port, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.pgbackend import get_active_postgres_backend
from baleharness.s3backend import S3_PROXY_THROTTLE_BPS, get_active_s3_backend
from baleharness.server import ServerHandle, start_container
from baleharness.storage import staging_files
from baleharness.timing import Timings


def _dir_entry_count(root: Path) -> int:
    """Count regular files anywhere under `root` (0 if `root` is absent)."""
    if not root.exists():
        return 0
    return sum(len(files) for _cur, _dirs, files in os.walk(root))


def _start_push_background(repo: Path, env: dict) -> subprocess.Popen:
    """Spawn `git push -u origin main` in the background so the harness can
    interrupt it while it's still streaming bytes. Stdout/stderr are captured
    so the failure mode can be inspected after the kill."""
    return subprocess.Popen(
        ["git", "push", "-u", "origin", "main"],
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def fail_fast_xet_env(env: dict) -> dict:
    """Trim xet-client's retry budget so a deliberately-broken upstream
    surfaces as a push error in ~1s instead of the default ~30–360s
    (5 attempts × exponential backoff from 3s base). Production clients
    want the generous default; the failure-recovery phases want to drive
    the failure deterministically and move on."""
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
    """Crash the server mid-upload, bring it back, and verify the user can
    re-run `git push` and recover. A throttled TCP proxy in front of the
    CAS port gives us a multi-second upload window on localhost (without
    it, a 4 MiB push to 127.0.0.1 finishes in tens of milliseconds and
    racing the kill is hopeless). When the proxy has seen the first byte
    of the request body we SIGKILL the container — guaranteeing the
    upload is mid-stream, the server-side put_xorb hasn't run, and
    push-pending must error out without draining staging."""
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
        # ~1 MiB/s. 4 MiB payload → ~4s upload, plenty of room to kill
        # mid-stream without making the suite uncomfortably slow.
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
    new_server: Optional[ServerHandle] = None
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

        # Start the push, wait for the proxy to start seeing upload bytes,
        # then SIGKILL the server (`podman rm -f` defaults to SIGKILL).
        # The threshold is tiny — once bytes are flowing, the throttle
        # gives us ample headroom before the request body fully lands.
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
            # Also slam the proxy: with the upstream dead, xet-data's
            # built-in retry loop would otherwise keep reconnecting
            # through the still-listening proxy until its retry budget
            # ran out — a 30–60s hang that masks the real failure.
            # Killing the proxy makes the next connect refuse instantly,
            # so the client surfaces a transport error promptly.
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

        # Restart the proxy BEFORE the container: start_container waits
        # for /healthz at the public_host_url, which we've overridden to
        # the proxy URL — so the proxy has to be listening (and able to
        # forward to the new container's cas_port) before that check can
        # succeed.
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

        # Retry. Content-addressed: any xorbs that landed before the crash
        # will be re-POSTed with `was_inserted=false` (or the server's
        # crash truncated the on-disk write, in which case the body is
        # missing and the re-upload writes the full bytes). Either way,
        # the final state has the full content available.
        with timings.measure(
            "failure-kill: retry push after restart", bytes_moved=payload_size
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "failure-kill: staging dir not drained after successful retry"
            )

        # Cold-clone in a fresh worktree to confirm the file genuinely
        # reconstructs from server-side state — not a hot-cache illusion
        # in the original push client.
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
    """Drop the client→server TCP connection mid-upload while the server
    itself stays running. Uses a small in-process TCP proxy as the
    advertised CAS URL: kill()ing the proxy slams every socket without a
    FIN, mimicking a sudden network drop. The proxy is then restarted and
    the retry must succeed, with no server-side intervention needed."""
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
        # BALE_PUBLIC_HOST_URL is what the SSH forge-auth script returns
        # to the client. Pointing it at the proxy means every CAS request
        # the client makes flows through us — so we can sever them.
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
                # Wait for the proxy to actually forward something — proves
                # the in-flight upload is mid-stream, not still in the
                # client's CDC pre-processing.
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
        # Confirm the server itself is still healthy — the whole point of
        # this phase versus the kill phase is the server stays up. Bypass
        # the (just-killed) proxy by hitting the container's mapped cas
        # port directly; server.healthz_url goes through the proxy URL.
        direct_healthz = f"http://127.0.0.1:{server.cas_port}/healthz"
        with urllib.request.urlopen(direct_healthz, timeout=5) as resp:
            if resp.status != 200:
                raise TestFailure(
                    f"server unhealthy after connection drop: {resp.status}"
                )

        # Bring the proxy back and retry. No container restart, no JWT
        # refresh — the previously-resolved token is still valid (JWTs
        # carry a 1-hour TTL by default) and the retry should reuse it.
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
    """Force SQLITE_BUSY transiently while a push is in flight. The user-side
    push should succeed: sqlx's busy_timeout (5s default) gives the server
    enough headroom to wait out the contention without surfacing an error.

    Uses a small file so the upload completes quickly once the lock is
    released — and asserts the wallclock is ≥ the lock-hold duration, which
    is what proves the server actually waited for the busy DB instead of
    racing past it on a separate connection."""
    # SQLite-specific: it locks the server's meta.db via a sidecar sqlite3
    # shell. Under --meta postgres there is no meta.db, and Postgres MVCC
    # doesn't need the busy_timeout this exercises, so skip cleanly.
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
        # Use a medium-sized payload (1 MiB): big enough to take real DB
        # writes (xorb_frames row, files row, file_terms rows), small enough
        # that the upload itself finishes fast and the wallclock is
        # dominated by the lock-hold window.
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
                # Lock is held NOW. Run push synchronously inside the
                # context so the server's DB writes hit SQLITE_BUSY and
                # rely on sqlx's busy_timeout to wait out the lock.
                git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        push_elapsed = time.perf_counter() - t0

        # The whole-push wallclock must be ≥ the lock-hold window — if it
        # finished faster, the server somehow didn't actually contend with
        # the sidecar lock and the test was vacuous. We don't bound the
        # upper end: SQLite serializes writers and the post-release work
        # can take real time.
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
        # Verify the file actually round-tripped: cold-clone in a fresh
        # worktree and check the bytes against the original.
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
    """Drop the server↔MinIO TCP connection mid-PUT — the one failure mode the
    rest of the suite can't reach. The fs `failure-conndrop` severs
    client↔server; this severs server↔storage, which only exists when the
    blob store is remote. S3-only: cleanly skips under the fs backend.

    A host-side TcpProxy sits between the server (in its container) and MinIO.
    The server reaches the proxy at the host's primary IP (BALE_S3_ENDPOINT_URL
    override, which wins over the backend's auto-injected endpoint); the proxy
    forwards to MinIO on the host loopback. `proxy.kill()` slams every socket
    without FIN — a sudden upstream drop from the AWS SDK's view. The SDK
    retries transient connection errors, so we hold the link down ~3s and bring
    it back: the test tolerates both "SDK swallowed the drop" and "SDK gave up,
    client retries". Either way the file must reconstruct from MinIO afterward
    and the bucket must hold one copy."""
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
    # bind 0.0.0.0 so the server container reaches the proxy via the host's
    # primary IP (routed over the bridge); throttle so a 35 MiB upload can't
    # finish before the kill lands.
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

    # The active backend makes start_container auto-wire BALE_S3_* + network;
    # the endpoint override points S3 writes at the proxy instead of MinIO
    # directly. disk_*_bytes still reads the bucket directly (not via proxy).
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
        # Fast-fail xet so a server error (cascading from the dropped S3
        # connection) doesn't burn 30s of retries before the push exits.
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
                # Wait until the proxy is forwarding — proves the server is
                # mid-PUT to MinIO, not still parsing the request.
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
            # Hold the link down long enough that aws-sdk-s3's standard retry
            # policy exhausts before the proxy returns — otherwise the SDK
            # swallows the drop and the failure path isn't exercised.
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

        # No double-counting: a retry that re-uploaded should still leave ~one
        # copy in the bucket, not two.
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
    """A blob store the *server* can reach but the *client* can't — presigned
    download URLs pointing at an unresolvable host — must fail the checkout fast,
    not hang. Without the cold-path watchdog, xet-core classifies the "host not
    found" DNS error as retryable and parks in a base-squared exponential backoff
    (~2.5h on the 2nd retry), hanging `git checkout` silently for hours.

    We point BALE_S3_PUBLIC_ENDPOINT_URL (presign-only) at a bogus host while the
    server keeps writing to the real MinIO via the auto-injected
    BALE_S3_ENDPOINT_URL, so push succeeds (server-side write) but a cold clone's
    checkout fetches an unreachable presigned URL. With a short
    BALE_DOWNLOAD_STALL_SECS the watchdog must abort promptly with its stall
    error. S3-only: presigned URLs don't exist under the fs backend."""
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
    # `.invalid` is reserved (RFC 6761) → guaranteed NXDOMAIN on the host where
    # the client runs, so the presigned fetch fails to connect.
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

        # Cold clone (separate worktree, empty chunk cache): the checkout's smudge
        # falls to the cold path, gets a presigned URL on the bogus host, stalls.
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
        # The whole point: fail near the stall window, not on xet-core's
        # multi-hour backoff. Generous margin for slow CI containers.
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
    """The fs analogue of `failure-s3-conndrop`: a blob *write* failure must
    leave nothing behind. `write_atomic` writes to `tmp/<uuid>`, fsyncs, then
    renames onto the content-addressed path. If the write/fsync fails it must
    remove the tmp file and surface the error — never leaving a half-written
    xorb at the addressed path nor a leaked tmp. That cleanup arm runs 0× in a
    healthy suite, and ENOSPC can't be injected without putting tmp/ on a
    different filesystem than xorbs/ (which would break the same-fs rename on
    the happy path too), so we drive it with the server-side
    BALE_TEST_FS_WRITE_FAIL hook: every blob write takes the failure arm.

    Push a file → it must fail with nothing stored (xorbs/ and tmp/ both empty).
    Then restart the server *without* the hook and re-push: the content-addressed
    path is still writable, the file round-trips, proving the failure left no
    poison behind. fs-backend only — under S3 the FsBlobStore isn't used."""
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
    # Pin the ports so the restarted (hook-off) server reuses them and the
    # repo's origin remote still resolves after the recovery restart.
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
    new_server: Optional[ServerHandle] = None
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

        # The load-bearing assertion: the rejected write left NOTHING — no
        # half-written blob at the addressed path, no leaked tmp.
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

        # Restart without the hook (same data_root) and prove recovery: the
        # content-addressed path is still writable and the file round-trips.
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
    """Two byte-identical pushes racing `write_atomic` on the same
    content-addressed dst must converge: both succeed, exactly one copy lands,
    no tmp leaks. Identical content → identical xorb hashes, so two concurrent
    pushes (to two repos, to dodge a git ref collision) POST the same xorb paths
    at the same instant. The loser hits either the pre-rename existence
    fast-path (`Ok(false)`) or the rename-replace — both content-preserving. (On
    Linux `rename(2)` over an existing file replaces atomically, so the
    `Err(_) if dst exists` race-loser arm is a non-Linux/Windows defensive guard
    and isn't expected to fire here; the property under test is convergence, not
    that specific arm.)

    Asserts both pushes exit 0, on-disk xorb bytes stay ≈ one payload (not 2×),
    tmp/ is empty, and both repos cold-clone to the original bytes. fs-only."""
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
        # Same payload bytes in both repos → same xorb hashes → same dst paths.
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

        # Fire both pushes at once and let write_atomic race on shared dsts.
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

        # Content-addressed dedup must hold under the race: ~one stored copy,
        # not two; and no tmp leaked from the losing writer.
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
