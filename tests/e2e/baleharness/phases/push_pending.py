"""push-pending drain edge cases (empty staging; failed re-translate)."""

from __future__ import annotations

from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    E2E_OWNER,
    E2E_REPO,
    GC_PAYLOAD_BYTES,
    SIZE_TOLERANCE_BYTES,
)
from baleharness.gitutil import git, pointer_hash_at
from baleharness.logutil import TestFailure, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import run
from baleharness.repo import init_repo_for_push
from baleharness.server import ServerHandle
from baleharness.storage import staged_markers, staging_files
from baleharness.timing import Timings


def phase_push_pending_noop(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """`git-bale push-pending` with nothing staged is a clean no-op.

    The pre-push hook runs push-pending on *every* push, including pushes
    that touched no bale-tracked file — those leave `.git/bale/staging/`
    absent. push-pending must short-circuit and exit 0, never error
    (which would block the push). This drives the `!staging.exists()`
    early return before any auth resolution or server contact."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="pp-noop",
    )
    staging = repo / ".git" / "bale" / "staging"
    if staging.exists():
        raise TestFailure(
            f"pp-noop: precondition violated — {staging} exists before any "
            "bale-tracked file was added"
        )
    with timings.measure("push-pending-noop: drain with no staging dir"):
        # check=True: a non-zero exit here is a real product bug (the hook
        # would block every push), so let `run` raise with the output.
        run([str(client.git_bale_bin), "push-pending"], cwd=repo, env=env)
    if staging.exists():
        raise TestFailure(
            "pp-noop: push-pending created a staging dir while draining nothing"
        )


def phase_push_pending_corrupt_staging(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """A failed re-translate must abort WITHOUT draining staging.

    push-pending reconstructs each staged file from `.git/bale/staging/`
    through a local download session, then re-cleans it through the online
    upload session. If the local reconstruct fails — staging corruption, or
    a `file-index/` marker outliving the xorb it points at — push-pending
    must error and leave the marker + remaining objects in place. The
    load-bearing property: it must never clear the marker (report the file
    as drained) when it couldn't actually upload it, or the staged bytes
    are silently lost.

    We simulate the corruption by deleting the staged xorb data after
    `git add` while keeping the marker, then assert push-pending fails at
    the local-reconstruct step, the marker survives, and nothing reached
    the server."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="pp-corrupt",
    )
    payload = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"pp-corrupt")
    (repo / "corrupt.bin").write_bytes(payload)
    # Clean is offline, so this stages xorbs/shards + a file-index marker
    # without any server contact.
    git(["add", "corrupt.bin"], cwd=repo, env=env)
    file_hex = pointer_hash_at(repo, env, ":corrupt.bin", label="pp-corrupt:staged")
    if file_hex not in staged_markers(repo):
        raise TestFailure(
            f"pp-corrupt: expected a staging marker for {file_hex} after add, "
            f"got {sorted(staged_markers(repo))}"
        )
    # Delete the xorb data (the bytes), keeping shards + marker: the marker
    # still advertises the file and the shard still resolves it to chunks,
    # but the chunks' backing xorb is gone — exactly the "marker outlives
    # its xorb" corruption. The local download session reads only from
    # staging (never bale.cacheDir or the server), so this is unrecoverable.
    xorbs = [p for p in staging_files(repo) if p.name.startswith("default.")]
    if not xorbs:
        raise TestFailure(
            f"pp-corrupt: `git add` of a {GC_PAYLOAD_BYTES}-byte file produced "
            "no staged xorb to delete — payload may be below the inline threshold"
        )
    info(f"  deleting {len(xorbs)} staged xorb(s), keeping shards + marker")
    for x in xorbs:
        x.unlink()

    disk_before = server.disk_total_bytes()
    with timings.measure("push-pending-corrupt: drain with missing xorb"):
        completed = run(
            [str(client.git_bale_bin), "push-pending"],
            cwd=repo,
            env=env,
            expect_fail=True,
        )
    stderr = completed.stderr.decode("utf-8", "replace")
    if completed.returncode == 0:
        raise TestFailure(
            "pp-corrupt: push-pending succeeded despite the staged xorb being "
            "deleted — it must fail the local reconstruct, not silently report "
            f"success.\nstderr:\n{stderr}"
        )
    if "local reconstruct" not in stderr:
        raise TestFailure(
            "pp-corrupt: push-pending failed, but not at the expected "
            f"local-reconstruct step.\nstderr:\n{stderr}"
        )
    if file_hex not in staged_markers(repo):
        raise TestFailure(
            f"pp-corrupt: marker {file_hex} was cleared after a FAILED "
            "push-pending — staging was drained for a file that never uploaded, "
            "so the staged bytes are now lost"
        )
    disk_after = server.disk_total_bytes()
    if disk_after - disk_before > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            f"pp-corrupt: server disk grew by {disk_after - disk_before} bytes "
            "during a push-pending that failed before any upload"
        )
