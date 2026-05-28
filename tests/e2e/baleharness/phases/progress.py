"""Manual-only demo phase: watch the git-bale upload progress indicator.

Not part of any normal run — it's a hand-driven demo, registered as
`progress-demo` and gated so it only fires under `--only progress-demo`.
Its whole point is the *visual*: it runs `git push` with the harness's
output capture turned OFF, so git-bale's pre-push hook inherits this
process's stderr. When you launch the harness from an interactive
terminal, that's a TTY — which is exactly the condition git-bale checks
before drawing the progress bar (see crates/git-bale/src/progress.rs).

Two env knobs:
  FILE_TIMER  (default 1, decimals OK) — how many seconds the server should
              take to ingest each file. Realised as a client→server byte
              throttle on a TcpProxy that fronts the CAS port, so the
              upload stream (and thus the bar) advances over ~FILE_TIMER
              seconds per file instead of finishing in milliseconds on
              localhost. Set it below ~0.2 to watch the 200ms threshold
              suppress the bar; set it to 3–5 to watch the bar climb slowly.
  FILE_COUNT  (default 5) — how many distinct files to add + push. Each has
              unique (incompressible) content so none dedup away and every
              one contributes real upload bytes.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import E2E_OWNER, E2E_REPO
from baleharness.gitutil import git, verify_pointer_at, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.mocks import TcpProxy
from baleharness.payloads import deterministic_payload
from baleharness.proc import pick_free_port, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import start_container
from baleharness.storage import staging_files
from baleharness.timing import Timings

PER_FILE_BYTES = 4 * 1024 * 1024


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = float(raw)
    except ValueError:
        raise TestFailure(f"{name} must be a number, got {raw!r}")
    if v < 0:
        raise TestFailure(f"{name} must be >= 0, got {v}")
    return v


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = int(raw)
    except ValueError:
        raise TestFailure(f"{name} must be an integer, got {raw!r}")
    if v < 1:
        raise TestFailure(f"{name} must be >= 1, got {v}")
    return v


def phase_progress_demo(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    file_timer = _env_float("FILE_TIMER", 1.0)
    file_count = _env_int("FILE_COUNT", 5)

    # Throttle the client→server direction so each file's worth of bytes takes
    # ~FILE_TIMER seconds to upload; that's the window the bar is visible in.
    # FILE_TIMER=0 means "instant server" — no throttle, bar likely suppressed.
    throttle = int(PER_FILE_BYTES / file_timer) if file_timer > 0 else None

    phase_root = work_root / "progress-demo"
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
        throttle_bytes_per_sec=throttle,
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
        name_suffix=f"progress-demo-{os.getpid()}",
        public_host_url_override=proxy_url,
    )
    total_bytes = PER_FILE_BYTES * file_count
    info(
        f"progress-demo: FILE_COUNT={file_count} × {PER_FILE_BYTES // (1024 * 1024)} "
        f"MiB = {total_bytes // (1024 * 1024)} MiB, FILE_TIMER={file_timer}s/file "
        f"(throttle={'none' if throttle is None else f'{throttle} B/s'})"
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="progress-demo-client",
        )
        files: list[tuple[str, str]] = []  # (name, sha256)
        for i in range(file_count):
            payload = deterministic_payload(
                PER_FILE_BYTES, seed=f"progress-demo-{i}".encode()
            )
            name = f"data{i}.bin"
            (repo / name).write_bytes(payload)
            files.append((name, sha256_bytes(payload)))
        with timings.measure("progress-demo: stage + commit", bytes_moved=total_bytes):
            git(["add", "."], cwd=repo, env=env)
            git(["commit", "-m", f"add {file_count} files"], cwd=repo, env=env)
        for name, sha in files:
            verify_pointer_at(
                repo,
                env,
                spec=f"HEAD:{name}",
                expected_sha=sha,
                expected_size=PER_FILE_BYTES,
                label="progress-demo:after-commit",
            )

        info("progress-demo: pushing — watch for the upload bar below (TTY only)")
        # capture=False lets the pre-push hook's git-bale push-pending write its
        # progress bar straight to this terminal. expect_fail=True keeps run()
        # from trying to .decode() the (uncaptured, None) stdout on a bad exit.
        with timings.measure("progress-demo: git push", bytes_moved=total_bytes):
            res = git(
                ["push", "-u", "origin", "main"],
                cwd=repo,
                env=env,
                capture=False,
                expect_fail=True,
            )
        if res.returncode != 0:
            raise TestFailure(
                f"git push failed (exit {res.returncode}); see output above"
            )
        if staging_files(repo):
            raise TestFailure(
                "progress-demo: staging not drained after push — push-pending "
                "didn't finalize the upload"
            )

        # Prove the bytes actually reached the server: cold-clone (downloads are
        # not throttled) and re-materialize every file from reconstruction.
        with timings.measure("progress-demo: cold clone", bytes_moved=total_bytes):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="progress-demo-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        for name, sha in files:
            verify_worktree(
                clone_path,
                name,
                expected_sha=sha,
                expected_size=PER_FILE_BYTES,
                label="progress-demo:after-clone",
            )
        info("progress-demo: all files round-tripped through the server")
    finally:
        proxy.kill()
        server.stop()
