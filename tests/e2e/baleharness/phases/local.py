"""Fully-local (no-server) mode phases. These never touch `server`."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import LOCAL_PAYLOAD_BYTES
from baleharness.gitutil import git, pointer_hash_at, verify_worktree
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

        # Drop the worktree file + manifest cache so checkout really smudges.
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


def phase_local_clean_gc_race(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """clean-vs-gc race: gc must not sweep a new xorb whose marker isn't written yet.

    file1 is added then unstaged (dead marker M1). A second `git add` is held
    between writing xorb X2 and marker M2 (BALE_TEST_CLEAN_MARKER_DELAY_MS) and
    gc fires in that window: an unprotected gc would drop M1, see zero markers
    and sweep X2. Clean holds the store lock across that window, so gc skips."""
    with timings.measure("local-clean-gc-race"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-race"
        )
        store = per_repo_store(repo)

        p1 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-race-1")
        (repo / "file1.bin").write_bytes(p1)
        git(["add", "file1.bin"], cwd=repo, env=env)
        if not local_store_xorbs(store):
            raise TestFailure("[local-race] step1: no xorbs after adding file1")
        if not staged_markers(repo):
            raise TestFailure("[local-race] step1: no markers after adding file1")

        # M1 becomes dead: its pointer is in no index, commit or reflog.
        git(["reset"], cwd=repo, env=env)

        baseline_xorbs = len(local_store_xorbs(store))

        p2 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-race-2")
        (repo / "file2.bin").write_bytes(p2)
        add_env = {**env, "BALE_TEST_CLEAN_MARKER_DELAY_MS": "3000"}
        proc = subprocess.Popen(
            ["git", "add", "file2.bin"],
            cwd=str(repo),
            env=add_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Window: X2 present (count above baseline) but M2 not yet written.
        deadline = time.monotonic() + 2.5
        window_hit = False
        while time.monotonic() < deadline:
            xorbs = local_store_xorbs(store)
            markers = staged_markers(repo)
            if len(xorbs) > baseline_xorbs and len(markers) == 1:
                info(
                    f"[local-race] vulnerable window: {len(xorbs)} xorb(s) "
                    f"(baseline={baseline_xorbs}), 1 (dead) marker, "
                    "M2 not yet written — firing gc"
                )
                window_hit = True
                break
            time.sleep(0.05)

        xorbs_before_gc = len(local_store_xorbs(store))
        markers_before_gc = len(staged_markers(repo))
        info(
            f"[local-race] before gc: {xorbs_before_gc} xorb(s), "
            f"{markers_before_gc} marker(s), window_hit={window_hit}"
        )

        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)

        xorbs_after_gc = len(local_store_xorbs(store))
        info(f"[local-race] after gc: {xorbs_after_gc} xorb(s)")

        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise TestFailure(
                f"[local-race] background git add failed (exit {proc.returncode}):\n"
                f"stdout:\n{stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{stderr.decode('utf-8', 'replace')}"
            )
        git(["commit", "-m", "file2"], cwd=repo, env=env)

        xorbs_after_add = len(local_store_xorbs(store))
        info(
            f"[local-race] after add finished: {xorbs_after_add} xorb(s), "
            f"{len(staged_markers(repo))} marker(s)"
        )

        if not local_store_xorbs(store):
            raise TestFailure(
                "[local-race] gc swept the store during the marker-delay window "
                f"(window_hit={window_hit}, xorbs before={xorbs_before_gc}, "
                f"after gc={xorbs_after_gc}, after add={xorbs_after_add}) — "
                "data loss: file2 cannot be reconstructed"
            )

        (repo / "file2.bin").unlink()
        run(
            ["rm", "-rf", str(repo / ".git" / "bale" / "manifests")],
            cwd=repo,
            env=env,
        )
        git(["checkout", "--", "file2.bin"], cwd=repo, env=env)
        verify_worktree(
            repo,
            "file2.bin",
            expected_sha=sha256_bytes(p2),
            expected_size=len(p2),
            label="local-race",
        )
        info("[local-race] clean/gc race did not lose data")


def phase_local_concurrent_stress(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Concurrent store mutations under natural timing: zero data loss, no deadlock.

    Part A: per-repo store, each round races a background `git add` against gc.
    Part B: shared store, adds in two repos interleaved with `prune --shared`,
    which holds the store lock for its whole run so a racing add blocks on it.
    """
    with timings.measure("local-concurrent-stress"):
        git_bale_bin = str(client.git_bale_bin)

        repo, env = init_repo_local(
            work_root=work_root, client=client, name="stress-perrepo"
        )

        committed: list[tuple[str, str, int]] = []

        for rnd in range(8):
            payload = deterministic_payload(
                LOCAL_PAYLOAD_BYTES, seed=f"stress-A-{rnd}".encode()
            )
            rel = f"f{rnd}.bin"
            (repo / rel).write_bytes(payload)

            proc = subprocess.Popen(
                ["git", "add", rel],
                cwd=str(repo),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            run([git_bale_bin, "gc"], cwd=repo, env=env)

            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                raise TestFailure(
                    f"[stress] round {rnd}: git add hung — possible deadlock"
                )
            if proc.returncode != 0:
                stdout = proc.stdout.read() if proc.stdout else b""
                stderr = proc.stderr.read() if proc.stderr else b""
                raise TestFailure(
                    f"[stress] round {rnd}: git add failed (exit {proc.returncode}):\n"
                    f"stdout:\n{stdout.decode('utf-8', 'replace')}\n"
                    f"stderr:\n{stderr.decode('utf-8', 'replace')}"
                )

            git(["commit", "-m", f"f{rnd}"], cwd=repo, env=env)
            committed.append((rel, sha256_bytes(payload), len(payload)))

        for rel, expected_sha, expected_size in committed:
            (repo / rel).unlink()
        run(
            ["rm", "-rf", str(repo / ".git" / "bale" / "manifests")],
            cwd=repo,
            env=env,
        )
        for rel, expected_sha, expected_size in committed:
            git(["checkout", "--", rel], cwd=repo, env=env)
            verify_worktree(
                repo,
                rel,
                expected_sha=expected_sha,
                expected_size=expected_size,
                label="stress-A",
            )

        run([git_bale_bin, "gc"], cwd=repo, env=env)
        run(
            ["rm", "-rf", str(repo / ".git" / "bale" / "manifests")],
            cwd=repo,
            env=env,
        )
        for rel, _sha, _sz in committed:
            (repo / rel).unlink()
        for rel, expected_sha, expected_size in committed:
            git(["checkout", "--", rel], cwd=repo, env=env)
            verify_worktree(
                repo,
                rel,
                expected_sha=expected_sha,
                expected_size=expected_size,
                label="stress-A-post-gc",
            )

        shared = work_root / "stress-shared"
        repo_a, env_a = init_repo_local(
            work_root=work_root, client=client, name="stress-sh-a", shared_store=shared
        )
        repo_b, env_b = init_repo_local(
            work_root=work_root, client=client, name="stress-sh-b", shared_store=shared
        )

        shared_committed: list[tuple[Path, dict, str, str, int]] = []

        # Round 0 races a background add with prune.
        for i in range(4):
            for repo_x, env_x, tag in (
                (repo_a, env_a, "A"),
                (repo_b, env_b, "B"),
            ):
                payload = deterministic_payload(
                    LOCAL_PAYLOAD_BYTES, seed=f"stress-B-{tag}-{i}".encode()
                )
                rel = f"f{tag}{i}.bin"
                (repo_x / rel).write_bytes(payload)

                if i == 0:
                    proc = subprocess.Popen(
                        ["git", "add", rel],
                        cwd=str(repo_x),
                        env=env_x,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    run(
                        [git_bale_bin, "prune", "--shared"],
                        cwd=repo_x,
                        env=env_x,
                    )
                    try:
                        proc.wait(timeout=120)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        raise TestFailure(
                            f"[stress] shared {tag}{i}: git add hung after prune — possible deadlock"
                        )
                    if proc.returncode != 0:
                        stdout = proc.stdout.read() if proc.stdout else b""
                        stderr = proc.stderr.read() if proc.stderr else b""
                        raise TestFailure(
                            f"[stress] shared {tag}{i}: git add failed (exit {proc.returncode}):\n"
                            f"stdout:\n{stdout.decode('utf-8', 'replace')}\n"
                            f"stderr:\n{stderr.decode('utf-8', 'replace')}"
                        )
                else:
                    git(["add", rel], cwd=repo_x, env=env_x)

                git(["commit", "-m", f"{tag}{i}"], cwd=repo_x, env=env_x)
                shared_committed.append(
                    (repo_x, env_x, rel, sha256_bytes(payload), len(payload))
                )

        run([git_bale_bin, "prune", "--shared"], cwd=repo_a, env=env_a)

        for repo_x, env_x, rel, _sha, _sz in shared_committed:
            (repo_x / rel).unlink()
        for repo_x, env_x, _rel, _sha, _sz in shared_committed:
            run(
                ["rm", "-rf", str(repo_x / ".git" / "bale" / "manifests")],
                cwd=repo_x,
                env=env_x,
            )
        for repo_x, env_x, rel, expected_sha, expected_size in shared_committed:
            git(["checkout", "--", rel], cwd=repo_x, env=env_x)
            verify_worktree(
                repo_x,
                rel,
                expected_sha=expected_sha,
                expected_size=expected_size,
                label="stress-B",
            )

        total = len(committed) + len(shared_committed)
        info(
            f"[stress] {total} files across per-repo + shared survived concurrent add/gc/prune"
        )


def phase_local_cache_hit_gc_race(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """cache-hit-clean vs gc race: gc must not sweep content a cache hit is re-emitting.

    f.bin is added then unstaged, leaving its clean-cache entry, marker and
    objects on disk but H unreferenced. The re-add's cache hit is held before
    emitting the pointer (BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS) and gc fires: a gc
    reading the stale index would sweep H and the committed pointer would point
    nowhere. The delay sits under the store lock, so gc skips."""
    with timings.measure("local-cache-hit-gc-race"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-cachehit"
        )
        store = per_repo_store(repo)

        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"cachehit")
        (repo / "f.bin").write_bytes(payload)
        git(["add", "f.bin"], cwd=repo, env=env)

        if not local_store_xorbs(store):
            raise TestFailure("[cachehit] no xorbs after initial add")
        if not staged_markers(repo):
            raise TestFailure("[cachehit] no markers after initial add")

        # Unstaging keeps the worktree file, marker, xorbs and cache entry.
        git(["reset", "--mixed"], cwd=repo, env=env)

        # Without a cache entry the re-add misses and re-writes objects itself.
        cache_dir = repo / ".git" / "bale" / "clean-cache"
        cache_entries = list(cache_dir.iterdir()) if cache_dir.exists() else []
        if not cache_entries:
            raise TestFailure(
                "[cachehit] precondition: clean-cache empty after reset — "
                "re-add would be a miss; test cannot exercise the cache-hit path"
            )
        if not local_store_xorbs(store):
            raise TestFailure("[cachehit] precondition: xorbs gone before gc ran")
        if not staged_markers(repo):
            raise TestFailure("[cachehit] precondition: marker gone before gc ran")

        add_env = {**env, "BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS": "3000"}
        proc = subprocess.Popen(
            ["git", "add", "f.bin"],
            cwd=str(repo),
            env=add_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Ensures gc fires inside the 3s delay (the filter reaches it in < 100 ms).
        time.sleep(0.5)

        if proc.poll() is not None:
            raise TestFailure(
                "[cachehit] git add finished before the 0.5 s window — "
                "filter may not have entered the cache-hit delay"
            )

        xorbs_before_gc = len(local_store_xorbs(store))
        markers_before_gc = staged_markers(repo)
        info(
            f"[cachehit] in delay window: {xorbs_before_gc} xorb(s), "
            f"{len(markers_before_gc)} marker(s) — firing gc"
        )

        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)

        xorbs_after_gc = len(local_store_xorbs(store))
        info(f"[cachehit] after gc: {xorbs_after_gc} xorb(s)")

        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise TestFailure(
                "[cachehit] background git add timed out — possible deadlock"
            )

        if proc.returncode != 0:
            stdout_b = proc.stdout.read() if proc.stdout else b""
            stderr_b = proc.stderr.read() if proc.stderr else b""
            raise TestFailure(
                f"[cachehit] background git add failed (exit {proc.returncode}):\n"
                f"stdout:\n{stdout_b.decode('utf-8', 'replace')}\n"
                f"stderr:\n{stderr_b.decode('utf-8', 'replace')}"
            )

        git(["commit", "-m", "readd"], cwd=repo, env=env)

        xorbs_after_add = len(local_store_xorbs(store))
        info(f"[cachehit] after add+commit: {xorbs_after_add} xorb(s)")

        # Smudge hard-errors if gc swept the objects during the delay.
        (repo / "f.bin").unlink()
        run(
            ["rm", "-rf", str(repo / ".git" / "bale" / "manifests")],
            cwd=repo,
            env=env,
        )
        checkout = git(
            ["checkout", "--", "f.bin"],
            cwd=repo,
            env=env,
            expect_fail=True,
        )
        if checkout.returncode != 0:
            raise TestFailure(
                f"[cachehit] reconstruction failed after cache-hit/gc race "
                f"(xorbs before gc={xorbs_before_gc}, after gc={xorbs_after_gc}, "
                f"after add={xorbs_after_add}) — "
                "data loss: gc swept the only object copy while the cache-hit "
                "emit was delayed"
            )

        verify_worktree(
            repo,
            "f.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="cachehit",
        )

        info("[cachehit] cache-hit clean/gc race did not lose data")


def phase_local_gc_grace(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """gc's reclaim grace protects a recently-cleaned-but-unreferenced marker
    (the backstop for the in-flight windows no lock can see), and reclaims it
    once it ages past the grace. Drives both directly via BALE_GC_GRACE_SECS."""
    with timings.measure("local-gc-grace"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-grace"
        )
        rel = "f.bin"
        v1 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"grace-v1")
        v2 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"grace-v2")

        # v2 staged then unstaged: a young unreferenced marker, the shape an
        # in-flight op transits.
        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "v1"], cwd=repo, env=env)
        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        git(["reset"], cwd=repo, env=env)

        markers_before = staged_markers(repo)
        if len(markers_before) < 2:
            raise TestFailure(
                f"[grace] expected v1+v2 markers after add/reset, got {markers_before}"
            )

        long_grace = {**env, "BALE_GC_GRACE_SECS": "600"}
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=long_grace)
        if staged_markers(repo) != markers_before:
            raise TestFailure(
                "[grace] gc with a 600s grace reclaimed a marker younger than the "
                f"grace: before={markers_before} after={staged_markers(repo)}"
            )

        no_grace = {**env, "BALE_GC_GRACE_SECS": "0"}
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=no_grace)
        after = staged_markers(repo)
        if len(after) >= len(markers_before):
            raise TestFailure(
                f"[grace] gc with grace=0 did not reclaim the orphan: "
                f"before={markers_before} after={after}"
            )

        (repo / rel).unlink()
        run(["rm", "-rf", str(repo / ".git" / "bale" / "manifests")], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)
        verify_worktree(
            repo,
            rel,
            expected_sha=sha256_bytes(v1),
            expected_size=len(v1),
            label="grace",
        )
        info("[grace] young orphan survived gc under grace; reclaimed once aged")


def phase_local_stash_reflog(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Reflog entries are live, as in git's gc: content reachable only from
    `stash@{1}` keeps its marker, so it still pops after `stash@{0}` is dropped."""
    with timings.measure("local-stash-reflog"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-stash"
        )
        rel = "s.bin"
        v1 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"stash-v1")
        v2 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"stash-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        h1 = pointer_hash_at(repo, env, f":{rel}", label="stash")
        git(["stash"], cwd=repo, env=env)
        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        h2 = pointer_hash_at(repo, env, f":{rel}", label="stash")
        git(["stash"], cwd=repo, env=env)

        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)
        markers = staged_markers(repo)
        if not {h1, h2} <= markers:
            raise TestFailure(
                "[stash] gc dropped the marker of content reachable only from "
                f"stash@{{1}}: want {{{h1[:8]}.., {h2[:8]}..}} have {markers}"
            )

        git(["stash", "drop", "stash@{0}"], cwd=repo, env=env)
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)
        markers = staged_markers(repo)
        if h1 not in markers:
            raise TestFailure(f"[stash] v1 marker lost after dropping v2: {markers}")
        if h2 in markers:
            raise TestFailure(f"[stash] dropped v2's marker survived gc: {markers}")

        git(["stash", "pop"], cwd=repo, env=env)
        verify_worktree(
            repo,
            rel,
            expected_sha=sha256_bytes(v1),
            expected_size=len(v1),
            label="stash",
        )
        info("[stash] stash@{1} content survived gc and pops intact")


def phase_local_worktree_gc(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """gc in the main worktree must see a linked worktree's staged content: all
    bookkeeping lives in the common git dir and liveness covers every
    worktree's index."""
    with timings.measure("local-worktree-gc"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-worktree"
        )
        wt = work_root / "local-worktree-linked"
        git(["worktree", "add", "-b", "linked", str(wt)], cwd=repo, env=env)

        pm = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"wt-main")
        pw = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"wt-linked")

        (repo / "m.bin").write_bytes(pm)
        git(["add", "m.bin"], cwd=repo, env=env)
        hm = pointer_hash_at(repo, env, ":m.bin", label="worktree")
        git(["reset"], cwd=repo, env=env)

        (wt / "w.bin").write_bytes(pw)
        git(["add", "w.bin"], cwd=wt, env=env)
        hw = pointer_hash_at(wt, env, ":w.bin", label="worktree")
        if not (wt / ".git").is_file():
            raise TestFailure("[worktree] linked worktree has no .git file")
        markers = staged_markers(repo)
        if not {hm, hw} <= markers:
            raise TestFailure(
                "[worktree] markers should all live in the common git dir: "
                f"want {{{hm[:8]}.., {hw[:8]}..}} have {markers}"
            )

        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)
        markers = staged_markers(repo)
        if hw not in markers:
            raise TestFailure(
                f"[worktree] main gc dropped the linked worktree's staged marker: {markers}"
            )
        if hm in markers:
            raise TestFailure(f"[worktree] main's abandoned marker survived: {markers}")

        def restore_and_verify(label: str) -> None:
            (wt / "w.bin").unlink()
            run(
                ["rm", "-rf", str(repo / ".git" / "bale" / "manifests")],
                cwd=repo,
                env=env,
            )
            git(["checkout", "--", "w.bin"], cwd=wt, env=env)
            verify_worktree(
                wt,
                "w.bin",
                expected_sha=sha256_bytes(pw),
                expected_size=len(pw),
                label=label,
            )

        restore_and_verify("worktree-staged")

        # Committed in the linked worktree only; gc from either side keeps it.
        git(["commit", "-m", "w"], cwd=wt, env=env)
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)
        run([str(client.git_bale_bin), "gc"], cwd=wt, env=env)
        restore_and_verify("worktree-committed")
        info("[worktree] linked worktree's content survived gc from both worktrees")


def phase_local_prune_cross_repo(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """prune --shared keeps content cleaned in B but referenced only by A (A
    fetched B's commit, so holds no marker): every repo's markers are tested
    against every repo."""
    with timings.measure("local-prune-cross-repo"):
        shared = work_root / "xrepo-store"
        a, ea = init_repo_local(
            work_root=work_root, client=client, name="xrepo-a", shared_store=shared
        )
        b, eb = init_repo_local(
            work_root=work_root, client=client, name="xrepo-b", shared_store=shared
        )
        px = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"xrepo-x")
        py = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"xrepo-y")

        (b / "x.bin").write_bytes(px)
        git(["add", "x.bin"], cwd=b, env=eb)
        git(["commit", "-m", "x"], cwd=b, env=eb)

        git(["fetch", str(b), "main"], cwd=a, env=ea)
        git(["checkout", "-b", "from-b", "FETCH_HEAD"], cwd=a, env=ea)
        verify_worktree(
            a,
            "x.bin",
            expected_sha=sha256_bytes(px),
            expected_size=len(px),
            label="xrepo-fetch",
        )

        # B forgets x entirely (commit, reflog, ORIG_HEAD) and abandons y.
        git(["reset", "--hard", "HEAD~1"], cwd=b, env=eb)
        git(["reflog", "expire", "--expire=now", "--all"], cwd=b, env=eb)
        (b / ".git" / "ORIG_HEAD").unlink(missing_ok=True)
        (b / "y.bin").write_bytes(py)
        git(["add", "y.bin"], cwd=b, env=eb)
        git(["reset", "--hard"], cwd=b, env=eb)

        before = len(local_store_xorbs(shared))
        run([str(client.git_bale_bin), "prune", "--shared"], cwd=b, env=eb)
        after = len(local_store_xorbs(shared))
        if after >= before:
            raise TestFailure(
                f"[xrepo] expected the orphan to be reclaimed: {before} -> {after} xorbs"
            )

        (a / "x.bin").unlink()
        run(["rm", "-rf", str(a / ".git" / "bale" / "manifests")], cwd=a, env=ea)
        git(["checkout", "--", "x.bin"], cwd=a, env=ea)
        verify_worktree(
            a,
            "x.bin",
            expected_sha=sha256_bytes(px),
            expected_size=len(px),
            label="xrepo-after-prune",
        )
        info(
            f"[xrepo] content referenced only by another repo survived prune ({before} -> {after} xorbs)"
        )


def phase_local_tampered_store(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Corrupted local-store xorbs fail the checkout instead of writing wrong bytes."""
    with timings.measure("local-tampered-store"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-tampered"
        )
        rel = "t.bin"
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"tampered")
        (repo / rel).write_bytes(payload)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "t"], cwd=repo, env=env)

        xorbs = local_store_xorbs(per_repo_store(repo))
        if not xorbs:
            raise TestFailure("[tampered] no xorbs to corrupt")
        for x in xorbs:
            data = bytearray(x.read_bytes())
            window = min(4096, len(data))
            start = (len(data) - window) // 2
            for i in range(start, start + window):
                data[i] ^= 0xFF
            x.chmod(0o644)  # xet stores objects read-only
            x.write_bytes(bytes(data))

        (repo / rel).unlink()
        run(["rm", "-rf", str(repo / ".git" / "bale" / "manifests")], cwd=repo, env=env)
        checkout = git(["checkout", "--", rel], cwd=repo, env=env, expect_fail=True)
        if checkout.returncode == 0:
            raise TestFailure(
                "[tampered] checkout of corrupted local-store content succeeded"
            )
        target = repo / rel
        if target.exists() and sha256_bytes(target.read_bytes()) != sha256_bytes(
            payload
        ):
            raise TestFailure("[tampered] wrong bytes were written to the worktree")
        info("[tampered] corrupted store content refused; worktree untouched")


def phase_local_autostash(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A `rebase --autostash` that stops on a conflict holds the user's
    uncommitted changes only in `rebase-merge/autostash` (no ref, no reflog,
    no `*.lock`). gc must keep that content and `rebase --continue` must
    restore it."""
    with timings.measure("local-autostash"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-autostash"
        )
        (repo / "other.txt").write_text("base\n")
        git(["add", "other.txt"], cwd=repo, env=env)
        git(["commit", "-m", "base"], cwd=repo, env=env)
        git(["checkout", "-b", "topic"], cwd=repo, env=env)
        (repo / "other.txt").write_text("topic\n")
        git(["commit", "-am", "topic"], cwd=repo, env=env)
        git(["checkout", "main"], cwd=repo, env=env)
        (repo / "other.txt").write_text("main\n")
        git(["commit", "-am", "main"], cwd=repo, env=env)
        git(["checkout", "topic"], cwd=repo, env=env)

        # The only bale content anywhere: staged, never committed.
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"autostash")
        (repo / "a.bin").write_bytes(payload)
        git(["add", "a.bin"], cwd=repo, env=env)
        h = pointer_hash_at(repo, env, ":a.bin", label="autostash")

        rebase = git(
            ["rebase", "--autostash", "main"], cwd=repo, env=env, expect_fail=True
        )
        if rebase.returncode == 0:
            raise TestFailure(
                "[autostash] rebase unexpectedly applied without conflict"
            )
        if not (repo / ".git" / "rebase-merge" / "autostash").exists():
            raise TestFailure("[autostash] rebase stopped without an autostash entry")

        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env, expect_fail=True)
        if h not in staged_markers(repo):
            raise TestFailure(
                f"[autostash] gc dropped the autostashed content's marker: {staged_markers(repo)}"
            )

        (repo / "other.txt").write_text("resolved\n")
        git(["add", "other.txt"], cwd=repo, env=env)
        git(
            ["-c", "core.editor=true", "rebase", "--continue"],
            cwd=repo,
            env={**env, "GIT_EDITOR": "true"},
        )
        verify_worktree(
            repo,
            "a.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="autostash",
        )
        info("[autostash] autostashed content survived gc and was restored")


def phase_local_prune_missing_repo(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Content a present repo reaches survives `prune --shared --force` even
    when the only marker for it lived in a registered repo that is now gone."""
    with timings.measure("local-prune-missing-repo"):
        shared = work_root / "missing-store"
        a, ea = init_repo_local(
            work_root=work_root, client=client, name="missing-a", shared_store=shared
        )
        b, eb = init_repo_local(
            work_root=work_root, client=client, name="missing-b", shared_store=shared
        )
        px = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"missing-x")
        py = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"missing-y")

        (a / "x.bin").write_bytes(px)
        git(["add", "x.bin"], cwd=a, env=ea)
        git(["commit", "-m", "x"], cwd=a, env=ea)
        git(["fetch", str(a), "main"], cwd=b, env=eb)
        git(["checkout", "-b", "from-a", "FETCH_HEAD"], cwd=b, env=eb)

        # An orphan in B so prune has something to reclaim.
        (b / "y.bin").write_bytes(py)
        git(["add", "y.bin"], cwd=b, env=eb)
        git(["reset", "--hard"], cwd=b, env=eb)

        run(["rm", "-rf", str(a)], cwd=work_root, env=eb)
        before = len(local_store_xorbs(shared))
        run([str(client.git_bale_bin), "prune", "--shared", "--force"], cwd=b, env=eb)
        after = len(local_store_xorbs(shared))
        if after >= before:
            raise TestFailure(
                f"[missing] expected the orphan to be reclaimed: {before} -> {after} xorbs"
            )

        (b / "x.bin").unlink()
        run(["rm", "-rf", str(b / ".git" / "bale" / "manifests")], cwd=b, env=eb)
        git(["checkout", "--", "x.bin"], cwd=b, env=eb)
        verify_worktree(
            b,
            "x.bin",
            expected_sha=sha256_bytes(px),
            expected_size=len(px),
            label="missing-after-prune",
        )
        info("[missing] content reached by a present repo survived prune --force")


def phase_local_store_owner(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A non-shared store belongs to one repo (gc sweeps it whole). A second
    repo pointed at it is refused by init-local, by clean and by gc — and its
    gc never sweeps the owner's objects."""
    with timings.measure("local-store-owner"):
        store = work_root / "owned-store"
        a = work_root / "owner-a"
        a.mkdir()
        ea = client.make_env()
        git(["init", "-b", "main", "."], cwd=a, env=ea)
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=a,
            env=ea,
        )
        run([str(client.git_bale_bin), "track", "*.bin"], cwd=a, env=ea)
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"owner-a")
        (a / "a.bin").write_bytes(payload)
        git(["add", ".gitattributes", "a.bin"], cwd=a, env=ea)
        git(["commit", "-m", "a"], cwd=a, env=ea)
        xorbs = local_store_xorbs(store)
        if not xorbs:
            raise TestFailure("[owner] repo A wrote no objects to its store")

        b = work_root / "owner-b"
        b.mkdir()
        eb = client.make_env()
        git(["init", "-b", "main", "."], cwd=b, env=eb)
        init = run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=b,
            env=eb,
            expect_fail=True,
        )
        if init.returncode == 0:
            raise TestFailure(
                "[owner] init-local accepted another repo's non-shared store"
            )

        for k, v in (
            ("filter.bale.process", "git-bale filter-process"),
            ("filter.bale.required", "true"),
            ("bale.local", "true"),
            ("bale.localStore", str(store)),
        ):
            git(["config", "--local", k, v], cwd=b, env=eb)
        gc = run([str(client.git_bale_bin), "gc"], cwd=b, env=eb, expect_fail=True)
        if gc.returncode == 0:
            raise TestFailure("[owner] gc in a non-owner repo did not refuse")
        if local_store_xorbs(store) != xorbs:
            raise TestFailure(
                "[owner] gc in a non-owner repo swept the owner's objects"
            )
        (b / ".gitattributes").write_text("*.bin filter=bale -text\n")
        (b / "b.bin").write_bytes(
            deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"owner-b")
        )
        add = git(["add", "b.bin"], cwd=b, env=eb, expect_fail=True)
        if add.returncode == 0:
            raise TestFailure(
                "[owner] clean wrote into another repo's non-shared store"
            )

        (a / "a.bin").unlink()
        git(["checkout", "--", "a.bin"], cwd=a, env=ea)
        verify_worktree(
            a,
            "a.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="owner",
        )
        info(
            "[owner] non-shared store refused to a second repo; owner's content intact"
        )


def phase_local_moved_shared_repo(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A repo moved after `init-local --shared` re-registers from its next gc,
    so `prune --shared --force` (which skips the stale old path) keeps its
    content."""
    with timings.measure("local-moved-shared-repo"):
        shared = work_root / "moved-store"
        a, ea = init_repo_local(
            work_root=work_root, client=client, name="moved-a", shared_store=shared
        )
        px = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"moved-x")
        py = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"moved-y")
        (a / "x.bin").write_bytes(px)
        git(["add", "x.bin"], cwd=a, env=ea)
        git(["commit", "-m", "x"], cwd=a, env=ea)
        (a / "y.bin").write_bytes(py)
        git(["add", "y.bin"], cwd=a, env=ea)
        git(["reset", "--hard"], cwd=a, env=ea)

        moved = work_root / "moved-a-renamed"
        a.rename(moved)
        run([str(client.git_bale_bin), "gc"], cwd=moved, env=ea)
        before = len(local_store_xorbs(shared))
        run(
            [str(client.git_bale_bin), "prune", "--shared", "--force"],
            cwd=moved,
            env=ea,
        )
        after = len(local_store_xorbs(shared))
        if after >= before:
            raise TestFailure(
                f"[moved] expected the orphan reclaimed: {before} -> {after}"
            )

        (moved / "x.bin").unlink()
        run(
            ["rm", "-rf", str(moved / ".git" / "bale" / "manifests")], cwd=moved, env=ea
        )
        git(["checkout", "--", "x.bin"], cwd=moved, env=ea)
        verify_worktree(
            moved,
            "x.bin",
            expected_sha=sha256_bytes(px),
            expected_size=len(px),
            label="moved",
        )
        info("[moved] moved shared repo re-registered; its content survived prune")


def phase_local_reclone_same_path(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A repo deleted and re-cloned at the same path re-claims its external
    store with NO markers. That store is the only copy of every committed
    file, so neither gc's zero-marker sweep nor the sweep after dropping the
    last dead marker may reclaim it while its content is still reachable."""
    with timings.measure("local-reclone-same-path"):
        store = work_root / "reclone-store"
        bare = work_root / "reclone-bare.git"
        a = work_root / "reclone-a"
        a.mkdir()
        env = client.make_env()
        env.pop("BALE_SERVER_URL", None)
        env.pop("BALE_TOKEN", None)
        git(["init", "--bare", "-b", "main", str(bare)], cwd=work_root, env=env)
        git(["init", "-b", "main", "."], cwd=a, env=env)
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=a,
            env=env,
        )
        run([str(client.git_bale_bin), "track", "*.bin"], cwd=a, env=env)
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"reclone")
        (a / "a.bin").write_bytes(payload)
        git(["add", ".gitattributes", "a.bin"], cwd=a, env=env)
        git(["commit", "-m", "a"], cwd=a, env=env)
        git(["push", str(bare), "main"], cwd=a, env=env)

        subprocess.run(["rm", "-rf", str(a)], check=True)
        git(["clone", "--no-checkout", str(bare), str(a)], cwd=work_root, env=env)
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=a,
            env=env,
        )
        if staged_markers(a):
            raise TestFailure("[reclone] precondition: a fresh clone has no markers")
        # post-checkout fires gc with zero markers.
        git(["checkout", "main"], cwd=a, env=env)
        run([str(client.git_bale_bin), "gc"], cwd=a, env=env)
        if not local_store_xorbs(store):
            raise TestFailure("[reclone] zero-marker gc swept the only copy")

        # Drop the last (dead) marker: the sweep that follows must also refuse.
        (a / "tmp.bin").write_bytes(
            deterministic_payload(LOCAL_PAYLOAD_BYTES // 4, seed=b"reclone-tmp")
        )
        git(["add", "tmp.bin"], cwd=a, env=env)
        h_tmp = pointer_hash_at(a, env, ":tmp.bin", label="reclone")
        git(["reset", "-q", "tmp.bin"], cwd=a, env=env)
        (a / "tmp.bin").unlink()
        # A racy-git re-clean of the fresh a.bin may have left a live marker,
        # which would keep gc off the whole-store sweep path under test.
        for h in staged_markers(a) - {h_tmp}:
            (a / ".git" / "bale" / "staging" / "file-index" / h).unlink()
        run([str(client.git_bale_bin), "gc"], cwd=a, env=env)
        if staged_markers(a):
            raise TestFailure("[reclone] gc kept the abandoned tmp.bin marker")

        (a / "a.bin").unlink()
        git(["checkout", "--", "a.bin"], cwd=a, env=env)
        verify_worktree(
            a,
            "a.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="reclone",
        )
        info("[reclone] re-cloned repo's store survived zero-marker and last-marker gc")


def phase_local_in_gitdir_store_claim(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A store inside a repo's git dir is claimed like any other: another repo
    pointed at it with `--store` is refused when the containing repo got there
    first, and — if the other repo claimed it first — the containing repo's gc
    must not sweep the other's content."""
    with timings.measure("local-in-gitdir-store-claim"):
        a, ea = init_repo_local(work_root=work_root, client=client, name="gitdir-a")
        pa = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"gitdir-a")
        (a / "a.bin").write_bytes(pa)
        git(["add", "a.bin"], cwd=a, env=ea)
        git(["commit", "-m", "a"], cwd=a, env=ea)
        a_store = per_repo_store(a)

        b = work_root / "gitdir-b"
        b.mkdir()
        eb = client.make_env()
        git(["init", "-b", "main", "."], cwd=b, env=eb)
        for extra in ([], ["--shared"]):
            init = run(
                [
                    str(client.git_bale_bin),
                    "init-local",
                    *extra,
                    "--store",
                    str(a_store),
                ],
                cwd=b,
                env=eb,
                expect_fail=True,
            )
            if init.returncode == 0:
                raise TestFailure(
                    f"[gitdir] init-local {extra} claimed another repo's in-gitdir store"
                )

        # Other order: C claims D's unused in-gitdir store first.
        d = work_root / "gitdir-d"
        d.mkdir()
        ed = client.make_env()
        git(["init", "-b", "main", "."], cwd=d, env=ed)
        d_store = per_repo_store(d)
        c, ec = work_root / "gitdir-c", client.make_env()
        c.mkdir()
        git(["init", "-b", "main", "."], cwd=c, env=ec)
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(d_store)],
            cwd=c,
            env=ec,
        )
        run([str(client.git_bale_bin), "track", "*.bin"], cwd=c, env=ec)
        pc = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"gitdir-c")
        (c / "c.bin").write_bytes(pc)
        git(["add", ".gitattributes", "c.bin"], cwd=c, env=ec)
        git(["commit", "-m", "c"], cwd=c, env=ec)
        xorbs = local_store_xorbs(d_store)

        init = run(
            [str(client.git_bale_bin), "init-local"], cwd=d, env=ed, expect_fail=True
        )
        if init.returncode == 0:
            raise TestFailure("[gitdir] D claimed its git-dir store already owned by C")
        for k, v in (
            ("filter.bale.process", "git-bale filter-process"),
            ("filter.bale.required", "true"),
            ("bale.local", "true"),
        ):
            git(["config", "--local", k, v], cwd=d, env=ed)
        gc = run([str(client.git_bale_bin), "gc"], cwd=d, env=ed, expect_fail=True)
        if gc.returncode == 0:
            raise TestFailure("[gitdir] gc in D did not refuse C's store")
        if local_store_xorbs(d_store) != xorbs:
            raise TestFailure("[gitdir] D's gc swept C's content from D's git dir")

        (c / "c.bin").unlink()
        git(["checkout", "--", "c.bin"], cwd=c, env=ec)
        verify_worktree(
            c,
            "c.bin",
            expected_sha=sha256_bytes(pc),
            expected_size=len(pc),
            label="gitdir-c",
        )
        (a / "a.bin").unlink()
        git(["checkout", "--", "a.bin"], cwd=a, env=ea)
        verify_worktree(
            a,
            "a.bin",
            expected_sha=sha256_bytes(pa),
            expected_size=len(pa),
            label="gitdir-a",
        )
        info("[gitdir] in-gitdir stores are claimed via .bale-owner in both orders")


def phase_local_pointer_passthrough(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A worktree holding raw pointer text (cloned before the filter was set
    up) must not be re-cleaned into a pointer-to-a-pointer by
    `git add --renormalize`; the pointer passes through and still smudges."""
    with timings.measure("local-pointer-passthrough"):
        shared = work_root / "passthrough-store"
        bare = work_root / "passthrough-bare.git"
        a, ea = init_repo_local(
            work_root=work_root,
            client=client,
            name="passthrough-a",
            shared_store=shared,
        )
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"passthrough")
        (a / "a.bin").write_bytes(payload)
        git(["add", "a.bin"], cwd=a, env=ea)
        git(["commit", "-m", "a"], cwd=a, env=ea)
        git(["init", "--bare", "-b", "main", str(bare)], cwd=work_root, env=ea)
        git(["push", str(bare), "main"], cwd=a, env=ea)
        committed = git(["rev-parse", "HEAD:a.bin"], cwd=a, env=ea).stdout.strip()

        b = work_root / "passthrough-b"
        eb = client.make_env()
        git(["clone", str(bare), str(b)], cwd=work_root, env=eb)
        if (b / "a.bin").stat().st_size >= len(payload):
            raise TestFailure(
                "[passthrough] precondition: clone should hold pointer text"
            )
        run(
            [
                str(client.git_bale_bin),
                "init-local",
                "--shared",
                "--store",
                str(shared),
            ],
            cwd=b,
            env=eb,
        )
        git(["add", "--renormalize", "."], cwd=b, env=eb)
        staged = git(["rev-parse", ":a.bin"], cwd=b, env=eb).stdout.strip()
        if staged != committed:
            raise TestFailure(
                "[passthrough] renormalize re-cleaned the pointer text into a new pointer"
            )
        (b / "a.bin").unlink()
        git(["checkout", "--", "a.bin"], cwd=b, env=eb)
        verify_worktree(
            b,
            "a.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="passthrough",
        )
        # JSON with a 64-hex "hash" is real content: clean it, don't pass it through.
        run([str(client.git_bale_bin), "track", "*.json"], cwd=b, env=eb)
        meta = (
            '{"hash": "' + sha256_bytes(b"release") + '", "algorithm": "sha256", '
            '"name": "release-1.2"}\n'
        ).encode()
        (b / "meta.json").write_bytes(meta)
        git(["add", ".gitattributes", "meta.json"], cwd=b, env=eb)
        git(["commit", "-m", "meta"], cwd=b, env=eb)
        (b / "meta.json").unlink()
        git(["checkout", "--", "meta.json"], cwd=b, env=eb)
        if (b / "meta.json").read_bytes() != meta:
            raise TestFailure(
                "[passthrough] pointer-shaped user JSON did not round-trip"
            )
        info("[passthrough] existing pointer passed through clean unchanged")


def phase_local_moved_repo(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """A moved repo keeps using its own (default, in-git-dir) store, and a
    missing external store is an error — never silently recreated empty at
    the old path."""
    with timings.measure("local-moved-repo"):
        a, env = init_repo_local(work_root=work_root, client=client, name="moved-old")
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"moved-a")
        (a / "a.bin").write_bytes(payload)
        git(["add", "a.bin"], cwd=a, env=env)
        git(["commit", "-m", "a"], cwd=a, env=env)
        moved = work_root / "moved-new"
        a.rename(moved)

        pb = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"moved-b")
        (moved / "b.bin").write_bytes(pb)
        git(["add", "b.bin"], cwd=moved, env=env)
        git(["commit", "-m", "b"], cwd=moved, env=env)
        if a.exists():
            raise TestFailure(f"[moved] a store was recreated at the old path {a}")
        for name, data in (("a.bin", payload), ("b.bin", pb)):
            (moved / name).unlink()
            git(["checkout", "--", name], cwd=moved, env=env)
            verify_worktree(
                moved,
                name,
                expected_sha=sha256_bytes(data),
                expected_size=len(data),
                label=f"moved-{name}",
            )

        store = work_root / "moved-ext-store"
        c = work_root / "moved-ext"
        c.mkdir()
        git(["init", "-b", "main", "."], cwd=c, env=env)
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=c,
            env=env,
        )
        run([str(client.git_bale_bin), "track", "*.bin"], cwd=c, env=env)
        git(["add", ".gitattributes"], cwd=c, env=env)
        git(["commit", "-m", "track"], cwd=c, env=env)
        store.rename(work_root / "moved-ext-store.away")
        (c / "c.bin").write_bytes(
            deterministic_payload(LOCAL_PAYLOAD_BYTES // 4, seed=b"moved-c")
        )
        add = git(["add", "c.bin"], cwd=c, env=env, expect_fail=True)
        if add.returncode == 0:
            raise TestFailure("[moved] clean accepted a missing external store")
        if store.exists():
            raise TestFailure("[moved] clean recreated the missing store empty")
        info("[moved] moved repo kept its store; a missing store is refused")


def phase_local_store_switch(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """After `init-local --store X` switches a repo's store, a re-add that
    hits the clean-cache must not emit a pointer whose bytes live only in the
    old store: the new commit has to be reconstructable from X."""
    with timings.measure("local-store-switch"):
        repo, env = init_repo_local(work_root=work_root, client=client, name="switch")
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"switch")
        (repo / "a.bin").write_bytes(payload)
        git(["add", "a.bin"], cwd=repo, env=env)
        git(["commit", "-m", "a"], cwd=repo, env=env)

        store = work_root / "switch-store"
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=repo,
            env=env,
        )
        git(["rm", "-q", "--cached", "a.bin"], cwd=repo, env=env)
        git(["commit", "-m", "drop"], cwd=repo, env=env)
        git(["add", "a.bin"], cwd=repo, env=env)
        git(["commit", "-m", "re-add"], cwd=repo, env=env)
        if not local_store_xorbs(store):
            raise TestFailure("[switch] re-add wrote nothing to the new store")
        (repo / "a.bin").unlink()
        git(["checkout", "--", "a.bin"], cwd=repo, env=env)
        verify_worktree(
            repo,
            "a.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="switch",
        )

        # Wiped and re-created at the same path: only the store id differs.
        subprocess.run(["rm", "-rf", str(store)], check=True)
        run(
            [str(client.git_bale_bin), "init-local", "--store", str(store)],
            cwd=repo,
            env=env,
        )
        git(["rm", "-q", "--cached", "a.bin"], cwd=repo, env=env)
        git(["commit", "-m", "drop again"], cwd=repo, env=env)
        git(["add", "a.bin"], cwd=repo, env=env)
        git(["commit", "-m", "re-add again"], cwd=repo, env=env)
        (repo / "a.bin").unlink()
        git(["checkout", "--", "a.bin"], cwd=repo, env=env)
        verify_worktree(
            repo,
            "a.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="switch-recreated",
        )
        info("[switch] re-add after a store switch is backed by the new store")


def phase_local_prune_force_moved(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """`prune --shared --force` that skipped a (moved) repo drops content only
    that repo referenced — but its worktree still has the bytes, so a re-add
    there must re-stage them rather than hit a stale clean-cache entry."""
    with timings.measure("local-prune-force-moved"):
        shared = work_root / "force-moved-store"
        a, ea = init_repo_local(
            work_root=work_root, client=client, name="force-a", shared_store=shared
        )
        b, eb = init_repo_local(
            work_root=work_root, client=client, name="force-b", shared_store=shared
        )
        pb = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"force-moved")
        (b / "b.bin").write_bytes(pb)
        git(["add", "b.bin"], cwd=b, env=eb)
        git(["commit", "-m", "b"], cwd=b, env=eb)

        moved = work_root / "force-b-moved"
        b.rename(moved)
        run([str(client.git_bale_bin), "prune", "--shared", "--force"], cwd=a, env=ea)

        os.utime(moved / "b.bin")
        git(["add", "b.bin"], cwd=moved, env=eb)
        (moved / "b.bin").unlink()
        git(["checkout", "--", "b.bin"], cwd=moved, env=eb)
        verify_worktree(
            moved,
            "b.bin",
            expected_sha=sha256_bytes(pb),
            expected_size=len(pb),
            label="force-moved",
        )
        info("[force-moved] re-add after a forced prune re-staged the worktree bytes")
