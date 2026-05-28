"""gc staging-reconciliation phases."""

from __future__ import annotations

from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    E2E_OWNER,
    E2E_REPO_GC1,
    E2E_REPO_GC2,
    E2E_REPO_GC3,
    GC_PAYLOAD_BYTES,
)
from baleharness.gitutil import git, pointer_hash_at, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import run, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.server import ServerHandle
from baleharness.storage import staged_markers, staging_files
from baleharness.timing import Timings


def phase_gc_abandon_checkout(
    *, timings: Timings, server: ServerHandle, client: ClientEnv, work_root: Path
) -> None:
    """The user-reported bug: stage a change, then abandon it entirely. The
    post-checkout hook's gc must sweep the orphaned staging.

    The baseline v1 is pushed first, so push-pending has already wiped its
    staging and v1 lives on the server. After abandoning v2 there is nothing
    left in git that references any staged bytes → gc does a full wipe."""
    with timings.measure("gc-abandon-checkout"):
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_GC1,
            name="gc-abandon",
        )
        rel = "big.bin"
        v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-abandon-v1")
        v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-abandon-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "add big v1"], cwd=repo, env=env)
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "[gc-abandon] precondition: push should have drained staging, "
                f"but xorbs/shards remain: {[str(p) for p in staging_files(repo)]}"
            )

        # Stage a change...
        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        if not staging_files(repo):
            raise TestFailure("[gc-abandon] git add should have staged v2 xorbs")
        if not staged_markers(repo):
            raise TestFailure("[gc-abandon] git add should have written a marker")

        # ...then abandon it: unstage, then discard the worktree edit. The
        # `git checkout` fires the post-checkout hook → `git-bale gc`.
        git(["reset"], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)

        leftover = staging_files(repo)
        if leftover:
            raise TestFailure(
                "[gc-abandon] staging not reclaimed after the change was "
                f"discarded; orphaned objects remain: {[str(p) for p in leftover]}"
            )
        if staged_markers(repo):
            raise TestFailure(
                f"[gc-abandon] stale markers survived the discard: {staged_markers(repo)}"
            )
        # Worktree is back to v1.
        verify_worktree(
            repo,
            rel,
            expected_sha=sha256_bytes(v1),
            expected_size=len(v1),
            label="gc-abandon",
        )
        info("[gc-abandon] orphaned staging swept; v1 worktree intact")


def phase_gc_keeps_unpushed(
    *, timings: Timings, server: ServerHandle, client: ClientEnv, work_root: Path
) -> None:
    """DATA-LOSS GUARD. Two stacked commits, neither pushed: C1 adds v1, C2
    changes it to v2. The branch tip references only v2, but a future `git
    push` uploads BOTH commits, so v1's staged bytes are still needed. A
    naive cleanup keyed on the worktree/tip would drop v1 and silently
    corrupt history; gc must keep it.

    Proof is end-to-end: after gc, push both commits, cold-clone, and check
    out every revision — if v1 had been dropped the server would lack it and
    the C1 checkout would fail or mismatch."""
    with timings.measure("gc-keeps-unpushed"):
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_GC2,
            name="gc-keep",
        )
        rel = "data.bin"
        v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-keep-v1")
        v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-keep-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "data v1"], cwd=repo, env=env)
        c1 = git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
        h1 = pointer_hash_at(repo, env, f"HEAD:{rel}", label="gc-keep")

        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "data v2"], cwd=repo, env=env)
        c2 = git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
        h2 = pointer_hash_at(repo, env, f"HEAD:{rel}", label="gc-keep")

        before = staged_markers(repo)
        if not {h1, h2} <= before:
            raise TestFailure(
                "[gc-keep] precondition: both unpushed versions should be "
                f"staged; want {{{h1[:8]}.., {h2[:8]}..}} have {before}"
            )

        # Manual gc — the tip only references v2, but v1 lives in unpushed C1.
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)

        after = staged_markers(repo)
        if not {h1, h2} <= after:
            raise TestFailure(
                "[gc-keep] DATA LOSS: gc dropped a marker for committed-but-"
                f"unpushed content. before={before} after={after}"
            )

        # Push both commits, cold-clone, verify EVERY revision reconstructs.
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        clone, cenv, _cache = init_repo_for_clone(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_GC2,
            name="gc-keep-clone",
        )
        git(["checkout", c1], cwd=clone, env=cenv)
        verify_worktree(
            clone,
            rel,
            expected_sha=sha256_bytes(v1),
            expected_size=len(v1),
            label="gc-keep@C1",
        )
        git(["checkout", c2], cwd=clone, env=cenv)
        verify_worktree(
            clone,
            rel,
            expected_sha=sha256_bytes(v2),
            expected_size=len(v2),
            label="gc-keep@C2",
        )
        info("[gc-keep] unpushed v1 survived gc; all revisions reconstruct")


def phase_gc_mixed(
    *, timings: Timings, server: ServerHandle, client: ClientEnv, work_root: Path
) -> None:
    """The mixed case: one committed-but-unpushed version (must survive) plus
    one staged-then-abandoned version (must be forgotten). gc keeps the live
    marker and drops only the dangling one; v1 stays pushable + reconstructable."""
    with timings.measure("gc-mixed"):
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_GC3,
            name="gc-mixed",
        )
        rel = "m.bin"
        v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-mixed-v1")
        v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-mixed-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "m v1"], cwd=repo, env=env)  # committed, NOT pushed
        h1 = pointer_hash_at(repo, env, f"HEAD:{rel}", label="gc-mixed")

        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)  # staged, never committed
        h2 = pointer_hash_at(repo, env, f":{rel}", label="gc-mixed")
        if h1 == h2:
            raise TestFailure("[gc-mixed] v1 and v2 unexpectedly hash-collided")

        git(["reset"], cwd=repo, env=env)  # unstage v2 (now dangling)
        git(["checkout", "--", rel], cwd=repo, env=env)  # restore v1; fires gc hook

        markers = staged_markers(repo)
        if h1 not in markers:
            raise TestFailure(
                "[gc-mixed] DATA LOSS: gc dropped the committed-but-unpushed "
                f"v1 marker {h1[:8]}..; markers={markers}"
            )
        if h2 in markers:
            raise TestFailure(
                "[gc-mixed] gc kept the abandoned (never-committed) v2 marker "
                f"{h2[:8]}..; markers={markers}"
            )

        # v1 still uploads and reconstructs after a cold clone.
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        clone, cenv, _cache = init_repo_for_clone(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_GC3,
            name="gc-mixed-clone",
        )
        git(["checkout", "main"], cwd=clone, env=cenv)
        verify_worktree(
            clone,
            rel,
            expected_sha=sha256_bytes(v1),
            expected_size=len(v1),
            label="gc-mixed",
        )
        info("[gc-mixed] live v1 kept, dangling v2 dropped, v1 reconstructs")
