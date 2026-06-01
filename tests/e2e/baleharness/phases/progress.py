"""The git-bale upload progress indicator: a validation phase + a hand demo.

The phase runs in two modes, both on their own isolated container so they
never touch other phases' shared-server state:

  * Normal sweep (`from_only=False`) — validates the indicator without any
    env knobs. It pushes a couple of fixed variants through `git-bale
    push-pending` with stderr *captured*, and asserts the git-styled summary
    line it leaves behind. No TTY, no live bar drawn; we only check the final
    `Uploading bales: 100% (N/N), …, done.` line (and that the deduped variant
    reports the already-present bytes instead of an upload size). Nothing is
    printed to the screen.

  * `--only progress-demo` (`from_only=True`) — a hand-driven *visual* demo.
    It reads FILE_TIMER / FILE_COUNT and pushes with capture turned OFF so the
    pre-push hook inherits your terminal; on a TTY git-bale then draws the live
    bar. A throttle proxy in front of the CAS port stretches the upload so the
    bar is watchable. See `tests/e2e/README.md`.

Env knobs (only read in the `--only` demo):
  FILE_TIMER  (default 1, decimals OK) — seconds the server should "take" per
              file, realised as a client→server byte throttle. Under ~0.2 the
              200ms threshold suppresses the live bar (summary still prints);
              3–5 makes it climb slowly. 0 = no throttle.
  FILE_COUNT  (default 5) — distinct files to add + push, each unique
              (incompressible) so none dedup away.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import E2E_OWNER, E2E_REPO
from baleharness.gitutil import git, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.mocks import TcpProxy
from baleharness.payloads import deterministic_payload
from baleharness.proc import pick_free_port, run, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.storage import staging_files
from baleharness.timing import Timings

DEMO_FILE_BYTES = 4 * 1024 * 1024  # --only demo: big enough for a visible climb
VARIANT_FILE_BYTES = 256 * 1024  # sweep variants: small + fast


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
    from_only: bool,
) -> None:
    phase_root = work_root / "progress-demo"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    cas_port = pick_free_port()
    ssh_port = pick_free_port()

    # The live bar is only watchable if the upload is slowed down, so the demo
    # fronts the CAS port with a throttle proxy. The sweep variants don't draw a
    # bar (captured, non-TTY), so they talk to the server directly.
    proxy = None
    public_host_url_override = None
    if from_only:
        file_timer = _env_float("FILE_TIMER", 1.0)
        proxy_port = pick_free_port()
        throttle = int(DEMO_FILE_BYTES / file_timer) if file_timer > 0 else None
        proxy = TcpProxy(
            listen_port=proxy_port,
            upstream_host="127.0.0.1",
            upstream_port=cas_port,
            throttle_bytes_per_sec=throttle,
        )
        proxy.start()
        public_host_url_override = f"http://127.0.0.1:{proxy_port}"

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
        public_host_url_override=public_host_url_override,
    )
    try:
        if from_only:
            _interactive_demo(timings, server, client, work_root, file_timer)
        else:
            _validation_variants(timings, server, client, work_root)
    finally:
        if proxy is not None:
            proxy.kill()
        server.stop()


def _interactive_demo(
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    file_timer: float,
) -> None:
    file_count = _env_int("FILE_COUNT", 5)
    total_bytes = DEMO_FILE_BYTES * file_count
    info(
        f"progress-demo: FILE_COUNT={file_count} × {DEMO_FILE_BYTES // (1024 * 1024)} "
        f"MiB = {total_bytes // (1024 * 1024)} MiB, FILE_TIMER={file_timer}s/file"
    )
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
            DEMO_FILE_BYTES, seed=f"progress-demo-{i}".encode()
        )
        name = f"data{i}.bin"
        (repo / name).write_bytes(payload)
        files.append((name, sha256_bytes(payload)))
    with timings.measure("progress-demo: stage + commit", bytes_moved=total_bytes):
        git(["add", "."], cwd=repo, env=env)
        git(["commit", "-m", f"add {file_count} files"], cwd=repo, env=env)

    info("progress-demo: pushing — watch for the upload line below (TTY only)")
    # capture=False lets the pre-push hook's git-bale push-pending write its
    # progress line straight to this terminal. expect_fail=True keeps run()
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
        raise TestFailure(f"git push failed (exit {res.returncode}); see output above")
    if staging_files(repo):
        raise TestFailure("progress-demo: staging not drained after push")

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
            expected_size=DEMO_FILE_BYTES,
            label="progress-demo:after-clone",
        )
    info("progress-demo: all files round-tripped through the server")


def _validation_variants(
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    git_bale = str(client.git_bale_bin)
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="progress-validate-client",
    )

    # Variant 1: three fresh files → a real upload, so the summary carries the
    # size clause (`100% (3/3), <size>, done.`).
    fresh: list[tuple[str, str]] = []
    for i in range(3):
        payload = deterministic_payload(
            VARIANT_FILE_BYTES, seed=f"progress-variant-{i}".encode()
        )
        name = f"v{i}.bin"
        (repo / name).write_bytes(payload)
        fresh.append((name, sha256_bytes(payload)))
    git(["add", "."], cwd=repo, env=env)
    git(["commit", "-m", "3 fresh files"], cwd=repo, env=env)
    with timings.measure(
        "progress-demo: variant fresh", bytes_moved=3 * VARIANT_FILE_BYTES
    ):
        res = run([git_bale, "push-pending"], cwd=repo, env=env)
    _assert_summary(res.stderr, count=3, kind="uploaded", label="fresh")
    if staging_files(repo):
        raise TestFailure(
            "progress-demo[fresh]: staging not drained after push-pending"
        )

    # Variant 2: a byte-identical copy of v0 → fully deduped against content the
    # server already holds, so nothing is uploaded and the summary names the
    # already-present bytes (`100% (1/1), <size> already on server, done.`).
    (repo / "dup.bin").write_bytes((repo / "v0.bin").read_bytes())
    git(["add", "dup.bin"], cwd=repo, env=env)
    git(["commit", "-m", "duplicate of v0"], cwd=repo, env=env)
    with timings.measure("progress-demo: variant dedup"):
        res = run([git_bale, "push-pending"], cwd=repo, env=env)
    _assert_summary(res.stderr, count=1, kind="deduped", label="dedup")
    if staging_files(repo):
        raise TestFailure(
            "progress-demo[dedup]: staging not drained after push-pending"
        )

    # Confirm the uploaded bytes round-trip: push the refs, then cold-clone.
    git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    clone_path, clone_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="progress-validate-clone",
    )
    git(["checkout", "main"], cwd=clone_path, env=clone_env)
    for name, sha in fresh:
        verify_worktree(
            clone_path,
            name,
            expected_sha=sha,
            expected_size=VARIANT_FILE_BYTES,
            label="progress-demo:variant-clone",
        )
    info("progress-demo: fresh + deduped summary variants validated")


def _assert_summary(stderr_bytes: bytes, *, count: int, kind: str, label: str) -> None:
    """Validate the git-styled push-pending summary line.

    `kind` selects the expected remainder after `100% (N/N),`:
      * "uploaded" — a real upload: `<size>[ | <rate>][ (+ <size> deduped)], done.`
      * "deduped"  — nothing new (full dedup): `<size> already on server, done.`
    """
    text = stderr_bytes.decode("utf-8", "replace")
    line = next(
        (
            ln.strip()
            for ln in text.splitlines()
            if ln.strip().startswith("Uploading bales:")
        ),
        None,
    )
    if line is None:
        raise TestFailure(
            f"progress-demo[{label}]: no 'Uploading bales:' summary in "
            f"push-pending stderr:\n{text}"
        )
    prefix = f"Uploading bales: 100% ({count}/{count}),"
    if not line.startswith(prefix) or not line.endswith("done."):
        raise TestFailure(
            f"progress-demo[{label}]: summary line {line!r} doesn't match "
            f"{prefix!r} … 'done.'"
        )
    remainder = line[len(prefix) :].strip()
    if kind == "uploaded":
        pattern = r"[\d.]+ \w+( \| [\d.]+ \w+/s)?( \(\+ [\d.]+ \w+ deduped\))?, done\."
    elif kind == "deduped":
        pattern = r"[\d.]+ \w+ already on server, done\."
    else:
        raise TestFailure(f"progress-demo[{label}]: unknown summary kind {kind!r}")
    if not re.fullmatch(pattern, remainder):
        raise TestFailure(
            f"progress-demo[{label}]: summary remainder {remainder!r} doesn't "
            f"match expected {kind!r} shape {pattern!r}"
        )
