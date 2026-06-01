"""Fully-local (no-server) mode phases. These never touch `server`."""

from __future__ import annotations

import subprocess
import time
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


def phase_local_clean_gc_race(
    *, timings: Timings, client: ClientEnv, work_root: Path
) -> None:
    """Demonstrates the clean-vs-gc data race in local mode.

    Setup: add file1 and commit it (marker M1 + xorb X1 in store), then reset
    the commit so M1 becomes a dead marker.  While gc would sweep ALL objects
    (remaining == 0 after dropping M1), concurrently start a second `git add`
    with a test-knob delay so xorb X2 is written to the store but marker M2
    has not yet appeared.  gc fires in that window, drops M1, sees remaining==0,
    and sweeps X1 + X2.  file2 can no longer be reconstructed → data loss.

    This phase EXPECTS to FAIL (raise TestFailure) until gc respects the store
    lock (Task 15)."""
    with timings.measure("local-clean-gc-race"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-race"
        )
        store = per_repo_store(repo)

        # Step 1: add file1 and commit so M1 + X1 land in the store.
        p1 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-race-1")
        (repo / "file1.bin").write_bytes(p1)
        git(["add", "file1.bin"], cwd=repo, env=env)
        git(["commit", "-m", "file1"], cwd=repo, env=env)
        if not local_store_xorbs(store):
            raise TestFailure("[local-race] step1: no xorbs after committing file1")
        if not staged_markers(repo):
            raise TestFailure("[local-race] step1: no markers after committing file1")

        # Step 2: reset the commit so M1 becomes a dead marker (pointer gone
        # from every reachable commit and from the index).
        git(["reset", "HEAD~1", "--mixed"], cwd=repo, env=env)

        # Record baseline: how many xorbs are in the store before file2 is added.
        baseline_xorbs = len(local_store_xorbs(store))

        # Step 3: start a second `git add` in the background with a 3 s
        # marker-delay so xorb X2 lands in the store before M2 is written.
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

        # Step 4: poll until X2 (file2's NEW xorb) is in the store and M2 is
        # NOT yet written — the vulnerable window.  We need the xorb count to
        # EXCEED the pre-add baseline so we know X2 is present.  gc in this
        # window sees only M1 (dead), drops it, remaining==0, and sweeps ALL
        # objects including X2.
        deadline = time.monotonic() + 2.5
        window_hit = False
        while time.monotonic() < deadline:
            xorbs = local_store_xorbs(store)
            markers = staged_markers(repo)
            # Window: file2's NEW xorb is present (count > baseline) and M2 is
            # not yet written (markers still == {M1} only, i.e. len==1).
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

        # Fire gc.  Without the store lock: drops dead M1, remaining==0,
        # sweeps X1 + X2 (collateral data loss).
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)

        xorbs_after_gc = len(local_store_xorbs(store))
        info(f"[local-race] after gc: {xorbs_after_gc} xorb(s)")

        # Wait for the background git add to finish, then commit.
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

        # Assert X2 survived gc.  Without the store lock, gc swept X2 as
        # collateral damage when it dropped dead M1 and saw remaining==0.
        # This is the teeth of the test: it FAILS now (data loss) and passes
        # once Task 15 makes gc take the store lock before sweeping.
        if not local_store_xorbs(store):
            raise TestFailure(
                "[local-race] gc swept the store during the marker-delay window "
                f"(window_hit={window_hit}, xorbs before={xorbs_before_gc}, "
                f"after gc={xorbs_after_gc}, after add={xorbs_after_add}) — "
                "data loss: file2 cannot be reconstructed"
            )

        # Reconstruct file2 from the store (drop worktree + manifest cache).
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
    """Hammer concurrent store mutations under natural timing; assert zero data
    loss and no deadlock.

    Part A exercises per-repo store contention: each round backgrounds a
    `git add` and immediately fires `git-bale gc` — the lock ensures gc never
    sweeps an in-flight xorb, so every committed file must reconstruct after all
    rounds finish.

    Part B exercises shared-store contention: adds in two repos interleaved with
    `git-bale prune --shared` runs — prune holds the exclusive lock for its whole
    run, so a racing add serialises behind it and the shared store stays consistent.
    """
    with timings.measure("local-concurrent-stress"):
        git_bale_bin = str(client.git_bale_bin)

        # ── Part A: per-repo store, concurrent add + gc ───────────────────────
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="stress-perrepo"
        )

        # (filename, sha256, size) for post-run verification.
        committed: list[tuple[str, str, int]] = []

        for rnd in range(8):
            payload = deterministic_payload(
                LOCAL_PAYLOAD_BYTES, seed=f"stress-A-{rnd}".encode()
            )
            rel = f"f{rnd}.bin"
            (repo / rel).write_bytes(payload)

            # Background add — no artificial delay; races naturally with gc.
            proc = subprocess.Popen(
                ["git", "add", rel],
                cwd=str(repo),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # gc races the in-flight add; with the store lock it must serialise
            # and never sweep a live xorb being written by the add.
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

        # Verify all committed files reconstruct after the concurrent storm.
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

        # A final gc must not sweep any data that is still referenced.
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

        # ── Part B: shared store, concurrent adds + prune ────────────────────
        shared = work_root / "stress-shared"
        repo_a, env_a = init_repo_local(
            work_root=work_root, client=client, name="stress-sh-a", shared_store=shared
        )
        repo_b, env_b = init_repo_local(
            work_root=work_root, client=client, name="stress-sh-b", shared_store=shared
        )

        # (repo, rel, sha256, size) for verification.
        shared_committed: list[tuple[Path, dict, str, str, int]] = []

        # Interleave 4 files per repo; pair 0 races a background add with prune.
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
                    # Race: background add in repo_x while prune holds the lock.
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

        # Final prune — must not delete anything still referenced by either repo.
        run([git_bale_bin, "prune", "--shared"], cwd=repo_a, env=env_a)

        # Verify every committed file in both repos still reconstructs.
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
    """Demonstrates the cache-hit-clean vs gc data race in local mode.

    Setup: add f.bin and commit it so the clean-cache is populated for
    f.bin→H, plus marker H and objects H are in the store.  Then dereference
    H (reset the commit) so H is no longer reachable from the index or any
    commit, but the clean-cache entry, marker, and objects are still on disk.

    Re-add f.bin with BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS=3000 so the cache-
    hit path sleeps for 3 s before emitting the pointer.  Sleep 0.5 s after
    starting the add (the filter enters the delay in < 100 ms), then fire gc.
    Without the lock fix, gc acquires the lock, reads the stale index (f.bin
    not yet re-added), classifies H as dead, removes the marker, remaining==0,
    sweeps all objects — data loss: the committed pointer points to nowhere.
    With the fix the filter holds the lock from before the cache-load, so gc
    blocks on it until the add completes and git has updated the index."""
    with timings.measure("local-cache-hit-gc-race"):
        repo, env = init_repo_local(
            work_root=work_root, client=client, name="local-cachehit"
        )
        store = per_repo_store(repo)

        # Step 1: add f.bin and commit — populates clean-cache[f.bin→H], marker
        # H, objects H.  We need the clean-cache entry to exist so the re-add
        # takes the HIT path (not the miss path, which re-writes objects itself).
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"cachehit")
        base = git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
        (repo / "f.bin").write_bytes(payload)
        git(["add", "f.bin"], cwd=repo, env=env)
        git(["commit", "-m", "addf"], cwd=repo, env=env)

        if not local_store_xorbs(store):
            raise TestFailure("[cachehit] no xorbs after initial commit")
        if not staged_markers(repo):
            raise TestFailure("[cachehit] no markers after initial commit")

        # Step 2: dereference H while leaving the worktree intact.  git reset
        # --mixed rolls HEAD back to base and removes f.bin from the index but
        # keeps the worktree file, the marker, the xorbs, and the cache entry.
        git(["reset", "--mixed", base], cwd=repo, env=env)

        # Precondition check: cache entry must exist so the re-add is a HIT.
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

        # Step 3: start `git add f.bin` with the cache-HIT delay so the filter
        # sleeps for 3 s after verifying the cache hit and before emitting the
        # pointer.  The filter enters the delay in < 100 ms.
        add_env = {**env, "BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS": "3000"}
        proc = subprocess.Popen(
            ["git", "add", "f.bin"],
            cwd=str(repo),
            env=add_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Step 4: sleep 0.5 s so the filter is definitely inside the 3 s delay,
        # then fire gc.  Without the lock fix, gc acquires the lock (the filter
        # hasn't taken it yet), reads the stale index (no f.bin), marks H dead,
        # sweeps the objects.  After the delay, the filter emits the cached
        # pointer — but the objects are gone: data loss.
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

        # Step 5: wait for the background add to complete.
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

        # Step 6: integrity check — drop worktree + manifest cache and reconstruct
        # from the local store.  If gc swept the objects during the cache-hit delay
        # window, `git checkout -- f.bin` will fail here (smudge hard-errors when
        # the local store cannot reconstruct the file).
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

        # v1 committed (stays reachable); v2 staged then unstaged (a young,
        # unreferenced marker — exactly the shape an in-flight op transits).
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

        # gc with a long grace must KEEP the young v2 marker.
        long_grace = {**env, "BALE_GC_GRACE_SECS": "600"}
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=long_grace)
        if staged_markers(repo) != markers_before:
            raise TestFailure(
                "[grace] gc with a 600s grace reclaimed a marker younger than the "
                f"grace: before={markers_before} after={staged_markers(repo)}"
            )

        # gc with the grace disabled reclaims v2 (unreferenced) but keeps v1.
        no_grace = {**env, "BALE_GC_GRACE_SECS": "0"}
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=no_grace)
        after = staged_markers(repo)
        if len(after) >= len(markers_before):
            raise TestFailure(
                f"[grace] gc with grace=0 did not reclaim the orphan: "
                f"before={markers_before} after={after}"
            )

        # v1 is still committed → must reconstruct from the store.
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
