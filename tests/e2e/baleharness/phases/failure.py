"""Failure-recovery phases + shared background-push helpers."""

from __future__ import annotations

import secrets
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Optional

from baleharness.client import ClientEnv
from baleharness.config import BIG_FILE_BYTES, E2E_OWNER, E2E_REPO
from baleharness.gitutil import git, verify_pointer_at, verify_worktree
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.mocks import TcpProxy, hold_db_writer_lock
from baleharness.payloads import deterministic_payload
from baleharness.proc import pick_free_port, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.s3backend import S3_PROXY_THROTTLE_BPS, get_active_s3_backend
from baleharness.server import ServerHandle, start_container
from baleharness.storage import staging_files
from baleharness.timing import Timings


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
