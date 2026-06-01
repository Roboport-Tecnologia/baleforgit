"""Fully-local (no-server) mode phases. These never touch `server`."""

from __future__ import annotations

from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import LOCAL_PAYLOAD_BYTES
from baleharness.gitutil import git, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import run, sha256_bytes
from baleharness.repo import init_repo_local
from baleharness.storage import (
    local_store_objects,
    local_store_xorbs,
    per_repo_store,
    staged_markers,
)
from baleharness.timing import Timings


def phase_local_basic(*, timings: Timings, client: ClientEnv, work_root: Path) -> None:
    """init-local -> add + commit a big file -> fresh checkout reconstructs it,
    with no server anywhere in the loop."""
    with timings.measure("local-basic"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-basic"
        )
        rel = "big.bin"
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-basic")

        (repo / rel).write_bytes(payload)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "add big"], cwd=repo, env=env)

        store = per_repo_store(repo)
        if not local_store_objects(store):
            raise TestFailure("[local-basic] add wrote no objects to .git/bale/store")
        if not staged_markers(repo):
            raise TestFailure("[local-basic] add wrote no file-index marker")

        # Force a real smudge: drop the worktree file + caches, re-checkout.
        (repo / rel).unlink()
        run(["rm", "-rf", str(repo / ".git" / "bale" / "manifests")], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)

        verify_worktree(
            repo,
            rel,
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="local-basic",
        )
        info("[local-basic] reconstructed from .git/bale/store with no server")


def phase_local_gc_abandon(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Abandoned `git add` in a per-repo local store is swept by gc; a committed
    file survives."""
    with timings.measure("local-gc-abandon"):
        repo, env = init_repo_local(work_root=work_root, client=client, name="local-gc")
        rel = "big.bin"
        v1 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-gc-v1")
        v2 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-gc-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "v1"], cwd=repo, env=env)
        store = per_repo_store(repo)
        if not local_store_objects(store):
            raise TestFailure("[local-gc] commit left no objects")

        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        git(["reset"], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)  # fires post-checkout gc

        # v1 still committed -> its objects must remain and reconstruct.
        verify_worktree(
            repo,
            rel,
            expected_sha=sha256_bytes(v1),
            expected_size=len(v1),
            label="local-gc",
        )
        if not local_store_objects(store):
            raise TestFailure("[local-gc] gc wrongly swept the committed v1 objects")
        info("[local-gc] abandoned add reconciled; committed v1 intact")


def phase_local_shared_dedup(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Two repos on one shared store: the second add of identical content writes
    no new xorbs."""
    with timings.measure("local-shared-dedup"):
        shared = work_root / "shared-store"
        r1, e1 = init_repo_local(
            work_root=work_root, client=client, name="shared-a", shared_store=shared
        )
        rel = "big.bin"
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"shared")
        (r1 / rel).write_bytes(payload)
        git(["add", rel], cwd=r1, env=e1)
        git(["commit", "-m", "a"], cwd=r1, env=e1)
        after_first = len(local_store_xorbs(shared))

        r2, e2 = init_repo_local(
            work_root=work_root, client=client, name="shared-b", shared_store=shared
        )
        (r2 / rel).write_bytes(payload)
        git(["add", rel], cwd=r2, env=e2)
        git(["commit", "-m", "b"], cwd=r2, env=e2)
        after_second = len(local_store_xorbs(shared))

        if after_second != after_first:
            raise TestFailure(
                f"[shared-dedup] identical content re-stored: {after_first} -> {after_second} xorbs"
            )
        verify_worktree(
            r2,
            rel,
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="shared-dedup",
        )
        info(f"[shared-dedup] dedup held across repos ({after_first} xorbs)")


def phase_local_prune_shared(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """prune --shared keeps an object referenced by a second repo and removes a
    truly-orphaned one."""
    with timings.measure("local-prune-shared"):
        shared = work_root / "prune-store"
        keep_repo, ke = init_repo_local(
            work_root=work_root, client=client, name="prune-keep", shared_store=shared
        )
        orphan_repo, oe = init_repo_local(
            work_root=work_root, client=client, name="prune-orphan", shared_store=shared
        )
        keep_payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"prune-keep")
        orphan_payload = deterministic_payload(
            LOCAL_PAYLOAD_BYTES, seed=b"prune-orphan"
        )

        (keep_repo / "k.bin").write_bytes(keep_payload)
        git(["add", "k.bin"], cwd=keep_repo, env=ke)
        git(["commit", "-m", "keep"], cwd=keep_repo, env=ke)

        # Orphan: add then hard-reset so nothing references it (objects persist
        # in the shared store — gc is append-only in shared mode).
        (orphan_repo / "o.bin").write_bytes(orphan_payload)
        git(["add", "o.bin"], cwd=orphan_repo, env=oe)
        git(["reset", "--hard"], cwd=orphan_repo, env=oe)

        before = len(local_store_xorbs(shared))
        run([str(client.git_bale_bin), "prune", "--shared"], cwd=keep_repo, env=ke)
        after = len(local_store_xorbs(shared))

        if after >= before:
            raise TestFailure(
                f"[prune] expected reclamation: {before} -> {after} xorbs"
            )
        # The kept file must still reconstruct from the compacted store.
        (keep_repo / "k.bin").unlink()
        run(
            ["rm", "-rf", str(keep_repo / ".git" / "bale" / "manifests")],
            cwd=keep_repo,
            env=ke,
        )
        git(["checkout", "--", "k.bin"], cwd=keep_repo, env=ke)
        verify_worktree(
            keep_repo,
            "k.bin",
            expected_sha=sha256_bytes(keep_payload),
            expected_size=len(keep_payload),
            label="prune",
        )
        info(f"[prune] orphan reclaimed, kept file intact ({before} -> {after} xorbs)")
