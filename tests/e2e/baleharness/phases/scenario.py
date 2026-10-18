"""Scenario phases (basic ops, offline, dedup, usage, clone, restart)."""

from __future__ import annotations

import os
import random
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from baleharness.client import ClientEnv, remote_url_ssh
from baleharness.config import (
    BIG_FILE_BYTES,
    BROWSER_DL_FILENAME,
    BROWSER_DL_JWT,
    CHURN_CLONE_AFTER_ROUNDS,
    CHURN_EDIT_BYTES,
    CHURN_EXTRA_BYTES,
    CHURN_FILE_A_BYTES,
    CHURN_FILE_B_BYTES,
    CHURN_ROUNDS,
    COLD_BIG_BYTES,
    COLD_SMALL_BYTES,
    E2E_HUB_TOKEN,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_REPO_3,
    E2E_REPO_CHURN,
    E2E_REPO_COLD_A,
    E2E_REPO_COLD_B,
    E2E_REPO_COLD_STAGED_A,
    E2E_REPO_COLD_STAGED_B,
    E2E_REPO_GC1,
    E2E_REPO_GC2,
    E2E_REPO_GC3,
    E2E_REPO_MERGE_A,
    E2E_REPO_MR_A,
    E2E_REPO_MR_B,
    E2E_REPO_MR_C,
    E2E_REPO_OFFLINE,
    E2E_REPO_SPILL,
    E2E_USER,
    GC_PAYLOAD_BYTES,
    HUGE_CHURN_ADD_PROB,
    HUGE_CHURN_BASE_FILES,
    HUGE_CHURN_CLONE_EVERY,
    HUGE_CHURN_DEL_PROB,
    HUGE_CHURN_EDIT_BYTES,
    HUGE_CHURN_EDIT_FILES,
    HUGE_CHURN_NEW_BYTES,
    HUGE_CHURN_PLAIN_ADD_PROB,
    HUGE_CHURN_ROUNDS_PER_MIN,
    HUGE_CHURN_WALK_STRIDE,
    JWT_TTL_YEARS,
    MERGE_FILE_BYTES,
    SIZE_TOLERANCE_BYTES,
    SMALL_FILE_BYTES,
    SPILL_FILE_BYTES,
    SPILL_INLINE_THRESHOLD,
)
from baleharness.gitutil import (
    cat_file_bytes,
    force_resmudge_and_verify,
    force_resmudge_cold,
    force_resmudge_lukewarm,
    get_bale_cache_dir,
    git,
    pointer_field,
    verify_pointer_at,
    verify_worktree,
)
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.mocks import TcpProxy, meta_db_query
from baleharness.payloads import deterministic_payload, modify_bytes, replace_region
from baleharness.proc import pick_free_port, run, sha256_bytes, sha256_file
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.storage import (
    clean_cache_entries,
    manifest_cache_entries,
    staging_files,
)
from baleharness.timing import Timings
from baleharness.usage import (
    fetch_repo_usage,
    fetch_usage,
    http_get_file,
    usage_status,
)


def phase_basic_user_ops(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Stage, unstage, re-stage, stash, pop, commit, push a small file, checking
    the pointer and worktree bytes at each step."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="alice",
    )
    payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"small")
    payload_sha = sha256_bytes(payload)
    blob_path = repo / "small.bin"
    blob_path.write_bytes(payload)
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:write",
    )

    with timings.measure("basic: stage small file"):
        git(["add", "small.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec=":small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-stage",
    )
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-stage",
    )

    staging_after_add = staging_files(repo)
    if not staging_after_add:
        raise TestFailure("staging dir empty after `git add`")
    info(
        f"  staging files: {len(staging_after_add)}, "
        f"size={fmt_bytes(sum(p.stat().st_size for p in staging_after_add))}"
    )
    clean_entries = clean_cache_entries(repo)
    if not clean_entries:
        raise TestFailure("clean-cache empty after `git add`")

    with timings.measure("basic: unstage"):
        git(["restore", "--staged", "small.bin"], cwd=repo, env=env)
    if git(["ls-files", "--stage", "small.bin"], cwd=repo, env=env).stdout.strip():
        raise TestFailure("small.bin still staged after `git restore --staged`")
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-unstage",
    )

    # `git restore --staged` fires post-checkout → gc, which sweeps the staging
    # and must also drop its clean-cache entry: else this re-add cache-hits to a
    # pointer whose never-pushed bytes are gone (the stage→unstage→stash
    # data-loss regression) and the stash/pop below can't reconstruct offline.
    with timings.measure("basic: re-stage (re-clean after gc-swept unstage)"):
        git(["add", "small.bin"], cwd=repo, env=env)
    if not staging_files(repo):
        raise TestFailure(
            "re-stage left staging empty — gc swept it and the re-add did not "
            "re-stage; the staged bytes are now unreconstructable offline"
        )
    verify_pointer_at(
        repo,
        env,
        spec=":small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-restage",
    )
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-restage",
    )

    with timings.measure("basic: stash"):
        git(["stash", "push", "-m", "e2e-stash"], cwd=repo, env=env)
    if blob_path.exists():
        raise TestFailure(
            "small.bin still in worktree after `git stash push` — stash didn't "
            "reset to HEAD"
        )
    stash_list = git(["stash", "list"], cwd=repo, env=env).stdout.decode()
    if "e2e-stash" not in stash_list:
        raise TestFailure(
            f"e2e-stash entry missing from `git stash list`:\n{stash_list}"
        )
    # The stash must hold the pointer, not smudge-expanded bytes.
    verify_pointer_at(
        repo,
        env,
        spec="stash@{0}:small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:in-stash",
    )

    with timings.measure("basic: stash pop"):
        git(["stash", "pop"], cwd=repo, env=env)
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-pop",
    )

    # `stash pop` without --index leaves the change unstaged.
    git(["add", "small.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec=":small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-pop-readd",
    )

    with timings.measure("basic: commit"):
        git(["commit", "-m", "add small.bin"], cwd=repo, env=env)
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-commit",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-commit",
    )

    # Nothing is on the server yet, so a re-smudge with caches wiped proves
    # reconstruction from staging.
    with timings.measure("basic: lukewarm resmudge (pre-push)"):
        force_resmudge_lukewarm(
            repo,
            env,
            "small.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="basic:lukewarm-pre-push",
        )

    # Clean is offline: nothing may reach the server before push.
    if server.disk_total_bytes() != 0:
        raise TestFailure(
            f"server disk non-zero before push: {fmt_bytes(server.disk_total_bytes())}"
        )

    with timings.measure("basic: push (drains staging)", bytes_moved=SMALL_FILE_BYTES):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    if staging_files(repo):
        raise TestFailure("staging not drained after push")
    if server.disk_total_bytes() <= 0:
        raise TestFailure("server disk still zero after push")
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-push",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="basic:after-push",
    )
    # Cold first: the lukewarm step wiped the caches and push doesn't refill
    # them, so only a cold smudge makes the following hot one genuinely hot.
    with timings.measure(
        "basic: cold resmudge after push", bytes_moved=SMALL_FILE_BYTES
    ):
        force_resmudge_cold(
            repo,
            env,
            "small.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="basic:cold-resmudge-after-push",
        )
    with timings.measure("basic: hot resmudge after push"):
        force_resmudge_and_verify(
            repo,
            env,
            "small.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="basic:hot-resmudge-after-push",
        )


def phase_multi_remote_push(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Push to `origin` (repo A), then to a second remote B on the same server:
    with staging already drained, B's push must still register the file under
    B's scope or a clone of B 404s on reconstruction. Part 2 covers a remote
    that already has the commits but not the bale objects."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_MR_A,
        name="multi-a",
    )
    payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"multi-remote")
    payload_sha = sha256_bytes(payload)
    (repo / "shared.bin").write_bytes(payload)
    git(["add", "shared.bin"], cwd=repo, env=env)
    git(["commit", "-m", "add shared.bin"], cwd=repo, env=env)

    with timings.measure("multi-remote: push to origin (repo A)"):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    # Drained staging forces the second push to re-source the bytes from a server.
    if staging_files(repo):
        raise TestFailure("multi-remote: staging not drained after origin push")
    if server.disk_total_bytes() == 0:
        raise TestFailure("multi-remote: server disk still zero after origin push")

    git(
        [
            "remote",
            "add",
            "mirror",
            remote_url_ssh(
                ssh_port=server.ssh_port, owner=E2E_OWNER, repo=E2E_REPO_MR_B
            ),
        ],
        cwd=repo,
        env=env,
    )
    with timings.measure("multi-remote: push to second remote (repo B)"):
        # Exercises the reachable-from-refs source path, not staged files.
        git(["push", "mirror", "main"], cwd=repo, env=env)

    clone_path, clone_env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_MR_B,
        name="multi-b-clone",
    )
    with timings.measure("multi-remote: cold clone+checkout of repo B"):
        git(["checkout", "main"], cwd=clone_path, env=clone_env)
    got = sha256_file(clone_path / "shared.bin")
    if got != payload_sha:
        raise TestFailure(
            f"multi-remote: repo B clone sha mismatch: got {got}, want {payload_sha}"
        )
    info("  repo B clone reconstructed shared.bin OK")

    # Part 2: C gets the git history but no bale objects (as from an old/argless
    # client), simulated by disabling the pre-push hook for one push. A NEW
    # branch push must still register the objects, not assume "commits there ⇒
    # objects there".
    git(
        [
            "remote",
            "add",
            "staleobj",
            remote_url_ssh(
                ssh_port=server.ssh_port, owner=E2E_OWNER, repo=E2E_REPO_MR_C
            ),
        ],
        cwd=repo,
        env=env,
    )
    hook = repo / ".git" / "hooks" / "pre-push"
    hook_bak = hook.with_name("pre-push.disabled")
    hook.rename(hook_bak)
    with timings.measure("multi-remote: seed repo C with commits only (no objects)"):
        git(["push", "staleobj", "main"], cwd=repo, env=env)
    hook_bak.rename(hook)

    # Delta 0 and refs/remotes/staleobj/main covers it, so push-pending must walk
    # the full reachable set, probe C (404), and re-source from origin.
    with timings.measure("multi-remote: push new branch to stale-object repo C"):
        git(["push", "staleobj", "main:revive"], cwd=repo, env=env)

    revive_clone, revive_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_MR_C,
        name="multi-c-clone",
    )
    with timings.measure("multi-remote: cold clone+checkout of repo C branch"):
        git(["checkout", "revive"], cwd=revive_clone, env=revive_env)
    got_c = sha256_file(revive_clone / "shared.bin")
    if got_c != payload_sha:
        raise TestFailure(
            f"multi-remote: repo C clone sha mismatch: got {got_c}, want {payload_sha}"
        )
    info("  repo C (stale-object remote) reconstructed shared.bin OK")


def _file_term_sum(server: ServerHandle, repo_id: str) -> tuple[str, int, int, int]:
    """(hash, size, Σ term unpacked_bytes, term count) for the one file under
    `repo_id`, summed over the GLOBAL (cross-repo) file_terms rows."""
    size_sub = "(SELECT total_bytes FROM files WHERE file_hash = ft.file_hash LIMIT 1)"
    tail = (
        "FROM file_terms ft "
        f"WHERE ft.file_hash IN (SELECT file_hash FROM files WHERE repo_id = '{repo_id}') "
        "GROUP BY ft.file_hash;"
    )
    res = meta_db_query(
        server,
        sqlite_sql=(
            f"SELECT lower(hex(ft.file_hash)), {size_sub}, "
            f"SUM(ft.unpacked_bytes), COUNT(*) {tail}"
        ),
        pg_sql=(
            f"SELECT encode(ft.file_hash, 'hex'), {size_sub}, "
            f"SUM(ft.unpacked_bytes), COUNT(*) {tail}"
        ),
    )
    if res.returncode != 0:
        raise TestFailure(
            f"term-merge: metadata query failed (rc={res.returncode}): "
            f"{res.stderr.decode('utf-8', 'replace')}"
        )
    lines = [ln for ln in res.stdout.decode().splitlines() if ln.strip()]
    if len(lines) != 1:
        raise TestFailure(
            f"term-merge: expected exactly one file under {repo_id}, got: {lines!r}"
        )
    h, size, term_sum, n = lines[0].split("|")
    return h, int(size), int(term_sum), int(n)


def phase_term_list_merge(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """The server's lookup_file guard must refuse a term list with Σterms > size.

    `file_terms` is global per file_hash, and the same content can be segmented
    into a different number of terms; merging two registrations leaves Σterms >
    file_size, which underflows xet's last-term trim and panics the client with a
    ~2^64-byte slice. Write-once registration prevents that state and re-pushes
    are byte-stable, so the client can't drive it: inject duplicate terms into
    meta.db directly (Σterms = 3×|F|) and assert a cold clone fails cleanly."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_MERGE_A,
        name="merge-a",
    )
    f_payload = deterministic_payload(MERGE_FILE_BYTES, seed=b"term-merge-F")
    f_sha = sha256_bytes(f_payload)
    (repo / "f.bin").write_bytes(f_payload)
    git(["add", "f.bin"], cwd=repo, env=env)
    git(["commit", "-m", "add f.bin"], cwd=repo, env=env)
    with timings.measure("term-merge: push F", bytes_moved=MERGE_FILE_BYTES):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    repo_id = f"{E2E_OWNER}/{E2E_REPO_MERGE_A}"
    _, size, term_sum, _ = _file_term_sum(server, repo_id)
    if term_sum != size:
        raise TestFailure(
            f"term-merge: a clean push already left Σterms({term_sum}) != size({size})"
        )

    clean_clone, clean_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_MERGE_A,
        name="merge-clone-clean",
    )
    git(["checkout", "main"], cwd=clean_clone, env=clean_env)
    if sha256_file(clean_clone / "f.bin") != f_sha:
        raise TestFailure("term-merge: baseline cold clone reconstructed F wrong")

    # Append term 0 twice: the over-sum (2×|F|) exceeds the last term (|F|), the
    # shape that underflows xet's trim.
    inject_sql = (
        "INSERT INTO file_terms (file_hash, term_index, xorb_hash, "
        "chunk_idx_start, chunk_idx_end, unpacked_bytes, verification) "
        "SELECT ft.file_hash, "
        "(SELECT MAX(term_index) + 1 FROM file_terms x WHERE x.file_hash = ft.file_hash), "
        "ft.xorb_hash, ft.chunk_idx_start, ft.chunk_idx_end, ft.unpacked_bytes, ft.verification "
        "FROM file_terms ft "
        f"WHERE ft.file_hash IN (SELECT file_hash FROM files WHERE repo_id = '{repo_id}') "
        "AND ft.term_index = 0;"
    )
    for _ in range(2):
        res = meta_db_query(server, sqlite_sql=inject_sql, pg_sql=inject_sql)
        if res.returncode != 0:
            raise TestFailure(
                f"term-merge: corrupt-term injection failed (rc={res.returncode}): "
                f"{res.stderr.decode('utf-8', 'replace')}"
            )
    _, size, term_sum, nterms = _file_term_sum(server, repo_id)
    if term_sum <= size:
        raise TestFailure(
            f"term-merge: injection didn't over-sum (Σ={term_sum}, size={size}, "
            f"terms={nterms}); test would be vacuous"
        )
    info(
        f"  injected corrupt term list: {nterms} terms summing to "
        f"{fmt_bytes(term_sum)} for a {fmt_bytes(size)} file"
    )

    bad_clone, bad_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_MERGE_A,
        name="merge-clone-corrupt",
    )
    # The guard answers 5xx, which xet retries with backoff for minutes.
    bad_env = dict(bad_env)
    bad_env["HF_XET_CLIENT_RETRY_MAX_ATTEMPTS"] = "1"
    bad_env["HF_XET_CLIENT_RETRY_BASE_DELAY"] = "100ms"
    bad_env["HF_XET_CLIENT_RETRY_MAX_DURATION"] = "2s"
    with timings.measure("term-merge: cold clone of corrupted file"):
        res = git(
            ["checkout", "main"],
            cwd=bad_clone,
            env=bad_env,
            capture=True,
            expect_fail=True,
        )
    out = (res.stdout + res.stderr).decode("utf-8", "replace")
    if "panicked" in out or "range end out of bounds" in out:
        raise TestFailure(
            "term-merge: server served the inconsistent (over-summing) term list "
            "and the client PANICKED reconstructing it — the lookup_file "
            f"consistency guard is missing. checkout output:\n{out}"
        )
    info("  corrupt term list rejected by the server guard; client did not panic")


def phase_cold_cache_repush(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """A cold-cache re-push of content the server already has must not re-store it.

    Bundling big.bin with a new small file repacks it into a fresh xorb hash, so
    only the server's global-dedup query can catch the duplicate. On-disk xorb
    growth is the ground truth (client upload counters aren't): ≈ small means
    deduped, ≈ big + small means double storage."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_COLD_A,
        name="cold-a",
    )
    big = deterministic_payload(COLD_BIG_BYTES, seed=b"cold-repush-big")
    big_sha = sha256_bytes(big)
    (repo / "big.bin").write_bytes(big)
    git(["add", "big.bin"], cwd=repo, env=env)
    git(["commit", "-m", "add big.bin"], cwd=repo, env=env)
    with timings.measure("cold-repush: push big to A", bytes_moved=COLD_BIG_BYTES):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    disk_before = server.disk_xorb_bytes()

    # "Fresh machine": only the server's global-dedup query can prevent a re-store.
    cache_dir = get_bale_cache_dir(repo, env)
    shutil.rmtree(cache_dir, ignore_errors=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(repo / ".git" / "bale" / "manifests", ignore_errors=True)
    shutil.rmtree(repo / ".git" / "bale" / "clean-cache", ignore_errors=True)

    # Forces a repack instead of re-emitting big.bin's original solo xorb verbatim.
    small = deterministic_payload(COLD_SMALL_BYTES, seed=b"cold-repush-small")
    small_sha = sha256_bytes(small)
    (repo / "small.bin").write_bytes(small)
    git(["add", "small.bin"], cwd=repo, env=env)
    git(["commit", "-m", "add small.bin"], cwd=repo, env=env)

    git(
        [
            "remote",
            "add",
            "mirror",
            remote_url_ssh(
                ssh_port=server.ssh_port, owner=E2E_OWNER, repo=E2E_REPO_COLD_B
            ),
        ],
        cwd=repo,
        env=env,
    )
    push_env = dict(env)
    push_env["RUST_LOG"] = "git_bale=debug"
    with timings.measure(
        "cold-repush: re-push big+small to B (cold cache)",
        bytes_moved=COLD_BIG_BYTES + COLD_SMALL_BYTES,
    ):
        res = git(["push", "mirror", "main"], cwd=repo, env=push_env, capture=True)
    disk_after = server.disk_xorb_bytes()
    growth = disk_after - disk_before

    out = (res.stdout + res.stderr).decode("utf-8", "replace")
    for line in out.splitlines():
        if "dedup breakdown" in line or line.strip().startswith("Uploading bales:"):
            info(f"  {line.strip()}")
    info(
        f"  server xorb storage grew {fmt_bytes(growth)} on the cold re-push "
        f"(big={fmt_bytes(COLD_BIG_BYTES)}, small={fmt_bytes(COLD_SMALL_BYTES)})"
    )
    # Re-sourcing big.bin repopulates the chunk cache (the dedup index), so only
    # the new small file should land.
    if growth >= COLD_BIG_BYTES * 3 // 4:
        raise TestFailure(
            f"cold-repush: server xorb storage grew {fmt_bytes(growth)} re-pushing a "
            f"{fmt_bytes(COLD_BIG_BYTES)} file already on the server — it was RE-STORED "
            "(double storage), not deduped"
        )
    info(
        f"  the unchanged {fmt_bytes(COLD_BIG_BYTES)} file was not re-stored "
        f"(server grew {fmt_bytes(growth)} ≈ the new small file only)"
    )

    clone_path, clone_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_COLD_B,
        name="cold-b-clone",
    )
    with timings.measure("cold-repush: cold clone+checkout B"):
        git(["checkout", "main"], cwd=clone_path, env=clone_env)
    if sha256_file(clone_path / "big.bin") != big_sha:
        raise TestFailure("cold-repush: repo B clone big.bin sha mismatch")
    if sha256_file(clone_path / "small.bin") != small_sha:
        raise TestFailure("cold-repush: repo B clone small.bin sha mismatch")
    info("  repo B reconstructed both files correctly")


def phase_cold_cache_repush_staged(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Staged-path cold-repush (the reported scenario): push, wipe every local
    dedup index, APPEND and commit WITHOUT pushing, then push to a fresh repo.
    The unchanged prefix must not be re-stored, and a cold clone must
    reconstruct the modified file."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_COLD_STAGED_A,
        name="cold-staged-a",
    )
    v1 = deterministic_payload(COLD_BIG_BYTES, seed=b"cold-staged-big")
    (repo / "big.bin").write_bytes(v1)
    git(["add", "big.bin"], cwd=repo, env=env)
    git(["commit", "-m", "add big.bin v1"], cwd=repo, env=env)
    with timings.measure("cold-staged: push v1 to A", bytes_moved=COLD_BIG_BYTES):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    disk_before = server.disk_xorb_bytes()

    cache_dir = get_bale_cache_dir(repo, env)
    shutil.rmtree(cache_dir, ignore_errors=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(repo / ".git" / "bale" / "manifests", ignore_errors=True)
    shutil.rmtree(repo / ".git" / "bale" / "clean-cache", ignore_errors=True)

    v2 = v1 + deterministic_payload(COLD_SMALL_BYTES, seed=b"cold-staged-tail")
    v2_sha = sha256_bytes(v2)
    (repo / "big.bin").write_bytes(v2)
    git(["add", "big.bin"], cwd=repo, env=env)
    git(["commit", "-m", "append a little to big.bin (not pushed)"], cwd=repo, env=env)

    git(
        [
            "remote",
            "add",
            "mirror",
            remote_url_ssh(
                ssh_port=server.ssh_port, owner=E2E_OWNER, repo=E2E_REPO_COLD_STAGED_B
            ),
        ],
        cwd=repo,
        env=env,
    )
    push_env = dict(env)
    push_env["RUST_LOG"] = "git_bale=debug"
    with timings.measure(
        "cold-staged: push modified (staged) to B (cold cache)",
        bytes_moved=COLD_BIG_BYTES + COLD_SMALL_BYTES,
    ):
        res = git(["push", "mirror", "main"], cwd=repo, env=push_env, capture=True)
    growth = server.disk_xorb_bytes() - disk_before

    out = (res.stdout + res.stderr).decode("utf-8", "replace")
    for line in out.splitlines():
        if "dedup breakdown" in line or line.strip().startswith("Uploading bales:"):
            info(f"  {line.strip()}")
    re_stored = growth - COLD_SMALL_BYTES  # growth beyond the genuinely-new tail
    info(
        f"  server xorb storage grew {fmt_bytes(growth)} (tail added "
        f"{fmt_bytes(COLD_SMALL_BYTES)}); ~{fmt_bytes(max(0, re_stored))} of the "
        f"unchanged {fmt_bytes(COLD_BIG_BYTES)} prefix was re-stored"
    )
    # v1 is reachable from the pushed history (from-refs) and the modified copy
    # dedups against it in-session, so only the new tail should land.
    if growth >= COLD_BIG_BYTES * 3 // 4:
        raise TestFailure(
            f"cold-staged: server xorb storage grew {fmt_bytes(growth)} re-pushing a "
            f"modified {fmt_bytes(COLD_BIG_BYTES)} file — its unchanged prefix was "
            "RE-STORED (double storage)"
        )
    info("  the unchanged prefix was not re-stored — only the new tail landed")

    clone_path, clone_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_COLD_STAGED_B,
        name="cold-staged-b-clone",
    )
    with timings.measure("cold-staged: cold clone+checkout B"):
        git(["checkout", "main"], cwd=clone_path, env=clone_env)
    if sha256_file(clone_path / "big.bin") != v2_sha:
        raise TestFailure("cold-staged: repo B clone big.bin (v2) sha mismatch")
    info("  repo B reconstructed the modified file correctly")


def phase_offline_no_network(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    jwt_secret_hex: str,
) -> None:
    """Only push/pull may touch the CAS server.

    With `bale.serverUrl` + `bale.token` both set the resolver skips the SSH
    handshake, so a counting TcpProxy in front of the server sees every contact
    attempt. Every local op (add, status/diff, commit, checkout, stash/pop,
    unstage, gc) must open 0 connections; push is the positive control. The token
    is self-minted with the server's JWT secret."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_OFFLINE,
        name="offline",
    )
    token = mint_bale_jwt(
        secret=bytes.fromhex(jwt_secret_hex),
        sub=E2E_USER,
        repo_type="model",
        repo_id=f"{E2E_OWNER}/{E2E_REPO_OFFLINE}",
        revision="main",
        scope="write",
        ttl_secs=JWT_TTL_YEARS * 365 * 24 * 3600,
    )
    proxy = TcpProxy(pick_free_port(), "127.0.0.1", server.cas_port)
    proxy.start()
    try:
        git(
            [
                "config",
                "--local",
                "bale.serverUrl",
                f"http://127.0.0.1:{proxy.listen_port}",
            ],
            cwd=repo,
            env=env,
        )
        git(["config", "--local", "bale.token", token], cwd=repo, env=env)

        payload = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"offline-net")
        payload_sha = sha256_bytes(payload)
        (repo / "data.bin").write_bytes(payload)

        def assert_offline(after: str) -> None:
            n = proxy.connections
            if n != 0:
                raise TestFailure(
                    f"[offline:{after}] git-bale opened {n} CAS connection(s) "
                    "during an operation that must be fully offline — only "
                    "push/pull may contact the server"
                )

        proxy.reset_counters()
        with timings.measure("offline: local ops make zero CAS connections"):
            git(["add", "data.bin"], cwd=repo, env=env)
            assert_offline("add")
            verify_pointer_at(
                repo,
                env,
                spec=":data.bin",
                expected_sha=payload_sha,
                expected_size=GC_PAYLOAD_BYTES,
                label="offline:add",
            )

            git(["status"], cwd=repo, env=env)
            git(["diff", "--cached"], cwd=repo, env=env)
            assert_offline("status+diff")

            git(["commit", "-m", "add data.bin"], cwd=repo, env=env)
            assert_offline("commit")

            # Committed but unpushed: smudge must reconstruct from staging.
            (repo / "data.bin").unlink()
            git(["checkout", "--", "data.bin"], cwd=repo, env=env)
            verify_worktree(
                repo,
                "data.bin",
                expected_sha=payload_sha,
                expected_size=GC_PAYLOAD_BYTES,
                label="offline:checkout",
            )
            assert_offline("checkout-smudge")

            payload2 = replace_region(
                payload, offset=4096, length=4096, seed=b"offline-v2"
            )
            payload2_sha = sha256_bytes(payload2)
            (repo / "data.bin").write_bytes(payload2)
            git(["add", "data.bin"], cwd=repo, env=env)
            assert_offline("re-add-v2")
            git(["stash", "push", "-m", "offline-stash"], cwd=repo, env=env)
            assert_offline("stash")
            git(["stash", "pop"], cwd=repo, env=env)
            verify_worktree(
                repo,
                "data.bin",
                expected_sha=payload2_sha,
                expected_size=GC_PAYLOAD_BYTES,
                label="offline:stash-pop",
            )
            assert_offline("stash-pop")

            # Unstage fires the post-checkout gc hook; then gc explicitly too.
            git(["add", "data.bin"], cwd=repo, env=env)
            git(["restore", "--staged", "data.bin"], cwd=repo, env=env)
            assert_offline("unstage")
            run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)
            assert_offline("gc")

        info(
            f"  all local ops complete with {proxy.connections} CAS "
            "connection(s) — fully offline"
        )

        # Positive control, else a dead proxy passes everything above vacuously.
        git(["add", "data.bin"], cwd=repo, env=env)
        git(["commit", "-m", "offline v2"], cwd=repo, env=env)
        proxy.reset_counters()
        with timings.measure(
            "offline: push (positive control — MUST hit CAS)",
            bytes_moved=GC_PAYLOAD_BYTES,
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if proxy.connections == 0:
            raise TestFailure(
                "push made zero CAS connections through the proxy — the "
                "no-network detector is dead, so the offline assertions above "
                "prove nothing"
            )
        info(
            f"  push opened {proxy.connections} CAS connection(s) — "
            "detector confirmed live"
        )
    finally:
        proxy.kill()


def phase_spilled_clean(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Clean's spill-to-tmpfile path (`handle_clean`'s NamedTempFile branch) and
    the file-backed `clean_cache::verify_chunks`, reached by capping
    `BALE_MAX_INLINE_CLEAN` at 1 MiB (the 4 GiB default never spills)."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_SPILL,
        name="spilled",
    )
    # git passes its env to the filter, so this applies to every clean below.
    env["BALE_MAX_INLINE_CLEAN"] = str(SPILL_INLINE_THRESHOLD)

    payload = deterministic_payload(SPILL_FILE_BYTES, seed=b"spilled-clean")
    payload_sha = sha256_bytes(payload)
    blob_path = repo / "spilled.bin"
    blob_path.write_bytes(payload)

    with timings.measure(
        "spilled: stage (spills to tmpfile)", bytes_moved=SPILL_FILE_BYTES
    ):
        git(["add", "spilled.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec=":spilled.bin",
        expected_sha=payload_sha,
        expected_size=SPILL_FILE_BYTES,
        label="spilled:after-stage",
    )
    staging_after_add = set(staging_files(repo))
    if not staging_after_add:
        raise TestFailure("spilled: staging dir empty after `git add`")
    if not clean_cache_entries(repo):
        raise TestFailure("spilled: clean-cache empty after `git add`")

    # Bump mtime so git re-runs clean, which must hit the clean-cache via the
    # file-backed verify_chunks and add no staging. Don't unstage instead: the
    # post-checkout gc would sweep staging and force a miss.
    os.utime(blob_path, None)
    with timings.measure("spilled: re-add (file-backed clean-cache hit)"):
        git(["add", "spilled.bin"], cwd=repo, env=env)
    if set(staging_files(repo)) != staging_after_add:
        raise TestFailure(
            "spilled: re-add changed staging files — clean-cache miss on the "
            "spilled verify path"
        )
    verify_pointer_at(
        repo,
        env,
        spec=":spilled.bin",
        expected_sha=payload_sha,
        expected_size=SPILL_FILE_BYTES,
        label="spilled:after-readd",
    )

    with timings.measure("spilled: commit"):
        git(["commit", "-m", "add spilled.bin"], cwd=repo, env=env)

    # Proves the tmpfile clean produced valid staging artifacts.
    with timings.measure("spilled: lukewarm resmudge (pre-push)"):
        force_resmudge_lukewarm(
            repo,
            env,
            "spilled.bin",
            expected_sha=payload_sha,
            expected_size=SPILL_FILE_BYTES,
            label="spilled:lukewarm-pre-push",
        )

    with timings.measure(
        "spilled: push (drains staging)", bytes_moved=SPILL_FILE_BYTES
    ):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    if staging_files(repo):
        raise TestFailure("spilled: staging not drained after push")

    with timings.measure(
        "spilled: cold resmudge after push", bytes_moved=SPILL_FILE_BYTES
    ):
        force_resmudge_cold(
            repo,
            env,
            "spilled.bin",
            expected_sha=payload_sha,
            expected_size=SPILL_FILE_BYTES,
            label="spilled:cold-resmudge-after-push",
        )
    with timings.measure("spilled: hot resmudge after push"):
        force_resmudge_and_verify(
            repo,
            env,
            "spilled.bin",
            expected_sha=payload_sha,
            expected_size=SPILL_FILE_BYTES,
            label="spilled:hot-resmudge-after-push",
        )


def phase_big_file_dedup(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    bale_admin_token: str,
) -> dict:
    """Push a 35 MiB file, an 8-byte edit, then a 1 MiB-region edit: per-push
    storage growth must track the change (chunk dedup) and `/v1/usage` must
    agree with disk. Returns the shas + commit oids the next phase needs.
    """
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="bigfile",
    )

    big_path = repo / "bigfile.bin"
    rev_state: dict = {"shas": [], "commits": [], "disk_after": [], "raw_after": []}

    payload_v1 = deterministic_payload(BIG_FILE_BYTES, seed=b"big-v1")
    big_path.write_bytes(payload_v1)
    sha_v1 = sha256_bytes(payload_v1)
    rev_state["shas"].append(sha_v1)
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:write",
    )
    with timings.measure("bigfile v1: stage", bytes_moved=BIG_FILE_BYTES):
        git(["add", "bigfile.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec=":bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-stage",
    )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-stage",
    )
    git(["commit", "-m", "bigfile v1"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-commit",
    )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-commit",
    )
    # Nothing on the server under this repo yet, so this can only use staging.
    with timings.measure(
        "bigfile v1: lukewarm resmudge (pre-push)", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_lukewarm(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v1,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v1:lukewarm-pre-push",
        )
    disk_before = server.disk_total_bytes()
    with timings.measure("bigfile v1: push", bytes_moved=BIG_FILE_BYTES):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    disk_after_v1 = server.disk_total_bytes()
    rev_state["disk_after"].append(disk_after_v1)
    rev_state["raw_after"].append(BIG_FILE_BYTES)
    growth_v1 = disk_after_v1 - disk_before
    if growth_v1 < BIG_FILE_BYTES * 0.5:
        # Even compressed, < 50% growth for new content means something was skipped.
        raise TestFailure(
            f"bigfile v1 push grew server by {fmt_bytes(growth_v1)} — "
            f"expected ≥ {fmt_bytes(BIG_FILE_BYTES // 2)}"
        )
    info(f"  bigfile v1: disk grew by {fmt_bytes(growth_v1)}")
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-push",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-push",
    )
    # Cold before hot: see phase_basic_user_ops.
    with timings.measure(
        "bigfile v1: cold resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v1,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v1:cold-resmudge-after-push",
        )
    with timings.measure(
        "bigfile v1: hot resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v1,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v1:hot-resmudge-after-push",
        )
    rev_state["commits"].append(
        git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
    )

    payload_v2 = modify_bytes(
        payload_v1,
        offset=BIG_FILE_BYTES // 2,
        replacement=b"\xde\xad\xbe\xef\x01\x02\x03\x04",
    )
    big_path.write_bytes(payload_v2)
    sha_v2 = sha256_bytes(payload_v2)
    rev_state["shas"].append(sha_v2)
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:write",
    )
    with timings.measure("bigfile v2: stage (8-byte poke)", bytes_moved=BIG_FILE_BYTES):
        git(["add", "bigfile.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec=":bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-stage",
    )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-stage",
    )
    git(["commit", "-m", "bigfile v2: 8-byte poke"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-commit",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD~1:bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:HEAD~1-still-v1",
    )
    disk_before_v2 = server.disk_total_bytes()
    with timings.measure("bigfile v2: push"):
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after_v2 = server.disk_total_bytes()
    rev_state["disk_after"].append(disk_after_v2)
    rev_state["raw_after"].append(BIG_FILE_BYTES * 2)
    growth_v2 = disk_after_v2 - disk_before_v2
    # An 8-byte edit touches a few ~64 KiB CDC chunks; 5 MiB is a generous
    # ceiling that still catches "no dedup".
    if growth_v2 > 5 * 1024 * 1024:
        raise TestFailure(
            f"bigfile v2 push grew server by {fmt_bytes(growth_v2)} for an "
            "8-byte edit — chunk-level dedup not working"
        )
    info(
        f"  bigfile v2 (8-byte edit) grew disk by {fmt_bytes(growth_v2)} — "
        f"dedup ratio ≈ {growth_v2 / BIG_FILE_BYTES:.4f}"
    )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-push",
    )
    # v1's cached chunks won't satisfy v2's smudge, so cold-then-hot again.
    with timings.measure(
        "bigfile v2: cold resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v2,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v2:cold-resmudge-after-push",
        )
    with timings.measure(
        "bigfile v2: hot resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v2,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v2:hot-resmudge-after-push",
        )
    rev_state["commits"].append(
        git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
    )

    payload_v3 = replace_region(
        payload_v2,
        offset=BIG_FILE_BYTES // 3,
        length=1 * 1024 * 1024,
        seed=b"big-v3-replacement",
    )
    big_path.write_bytes(payload_v3)
    sha_v3 = sha256_bytes(payload_v3)
    rev_state["shas"].append(sha_v3)
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v3,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:write",
    )
    with timings.measure(
        "bigfile v3: stage (1 MiB region)", bytes_moved=BIG_FILE_BYTES
    ):
        git(["add", "bigfile.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec=":bigfile.bin",
        expected_sha=sha_v3,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-stage",
    )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v3,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-stage",
    )
    git(["commit", "-m", "bigfile v3: 1 MiB region replaced"], cwd=repo, env=env)
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:bigfile.bin",
        expected_sha=sha_v3,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-commit",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD~1:bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:HEAD~1-still-v2",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD~2:bigfile.bin",
        expected_sha=sha_v1,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:HEAD~2-still-v1",
    )
    disk_before_v3 = server.disk_total_bytes()
    with timings.measure("bigfile v3: push"):
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after_v3 = server.disk_total_bytes()
    rev_state["disk_after"].append(disk_after_v3)
    rev_state["raw_after"].append(BIG_FILE_BYTES * 3)
    growth_v3 = disk_after_v3 - disk_before_v3
    # 1 MiB of new content plus a few touched neighbor chunks.
    if growth_v3 > 4 * 1024 * 1024:
        raise TestFailure(
            f"bigfile v3 push grew server by {fmt_bytes(growth_v3)} for a 1 MiB edit "
            "— expected ≤ 4 MiB"
        )
    if growth_v3 < 512 * 1024:
        raise TestFailure(
            f"bigfile v3 push grew server by only {fmt_bytes(growth_v3)} for a 1 MiB edit "
            "— expected ≥ 512 KiB (new bytes should not all dedup)"
        )
    info(
        f"  bigfile v3 (1 MiB edit) grew disk by {fmt_bytes(growth_v3)} — "
        f"dedup ratio ≈ {growth_v3 / BIG_FILE_BYTES:.4f}"
    )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=sha_v3,
        expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-push",
    )
    with timings.measure(
        "bigfile v3: cold resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v3,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v3:cold-resmudge-after-push",
        )
    with timings.measure(
        "bigfile v3: hot resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo,
            env,
            "bigfile.bin",
            expected_sha=sha_v3,
            expected_size=BIG_FILE_BYTES,
            label="bigfile-v3:hot-resmudge-after-push",
        )
    rev_state["commits"].append(
        git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
    )
    rev_state["repo_path"] = repo
    rev_state["env"] = env
    return rev_state


def phase_usage_api(
    *,
    timings: Timings,
    server: ServerHandle,
    bale_admin_token: str,
    admin_token_hex: str,
    jwt_secret_hex: str,
    rev_state: dict,
) -> None:
    """`/v1/usage/{owner}` and `/v1/usage/repo/{owner}/{repo}` against on-disk
    numbers (field contract: `bale-server-wire`), plus the `require_usage_access`
    arms the happy path misses: hex admin bearer accepted, other-owner JWT 403.
    """
    with timings.measure("usage api: fetch + verify"):
        owner_usage = fetch_usage(server, token=bale_admin_token, owner=E2E_OWNER)
        repo_usage = fetch_repo_usage(
            server, token=bale_admin_token, owner=E2E_OWNER, repo=E2E_REPO_2
        )
        info(f"  /v1/usage/{E2E_OWNER}: {owner_usage}")
        info(f"  /v1/usage/repo/{E2E_OWNER}/{E2E_REPO_2}: {repo_usage}")

        # Every revision counts separately.
        expected_raw_repo2 = 3 * BIG_FILE_BYTES
        if repo_usage["raw_bytes"] != expected_raw_repo2:
            raise TestFailure(
                f"repo usage raw_bytes={repo_usage['raw_bytes']} but expected "
                f"{expected_raw_repo2} (3 × {BIG_FILE_BYTES})"
            )

        # Every xorb on this server so far is E2E_OWNER's.
        disk_xorbs = server.disk_xorb_bytes()
        delta = abs(int(owner_usage["stored_bytes"]) - disk_xorbs)
        if delta > SIZE_TOLERANCE_BYTES:
            raise TestFailure(
                f"owner usage stored_bytes={owner_usage['stored_bytes']} disagrees "
                f"with on-disk xorbs ({disk_xorbs}) by {delta} bytes "
                f"(> tolerance {SIZE_TOLERANCE_BYTES})"
            )

        if repo_usage["stored_bytes"] > owner_usage["stored_bytes"]:
            raise TestFailure(
                f"repo stored_bytes={repo_usage['stored_bytes']} exceeds owner "
                f"stored_bytes={owner_usage['stored_bytes']} — accounting inverted"
            )
        if repo_usage["stored_bytes"] == 0:
            raise TestFailure(
                "repo stored_bytes is 0 but we pushed 35 MB three times — "
                "shard's CAS Info isn't reaching `xorbs`/`file_terms`"
            )

        # > 0: repo2's big xorbs share no chunks with any sibling repo's files.
        excl = int(repo_usage["exclusive_bytes"])
        if excl > int(repo_usage["stored_bytes"]):
            raise TestFailure(
                f"repo exclusive_bytes={excl} exceeds stored_bytes="
                f"{repo_usage['stored_bytes']} — exclusive set isn't a subset"
            )
        if excl == 0:
            raise TestFailure(
                "repo exclusive_bytes is 0 but repo2's 35 MB binary is shared "
                "with no sibling repo — exclusive accounting is wrong"
            )

        for label, blob in [("owner", owner_usage), ("repo", repo_usage)]:
            expected_savings = blob["raw_bytes"] - blob["stored_bytes"]
            if blob["dedup_savings_bytes"] != expected_savings:
                raise TestFailure(
                    f"{label} dedup_savings_bytes mismatch: got "
                    f"{blob['dedup_savings_bytes']}, expected raw - stored = "
                    f"{expected_savings}"
                )

    with timings.measure("usage api: admin-token + cross-owner authz"):
        # Everything above took the JWT branch; this hits the admin-accept arm.
        status = usage_status(server, token=admin_token_hex, owner=E2E_OWNER)
        if status != 200:
            raise TestFailure(
                f"hex admin token on /v1/usage/{E2E_OWNER} returned {status}, want 200"
            )
        intruder_jwt = mint_bale_jwt(
            secret=bytes.fromhex(jwt_secret_hex),
            sub="intruder",
            repo_type="model",
            repo_id="intruder/repo",
            revision="main",
            scope="read",
            ttl_secs=3600,
        )
        status = usage_status(server, token=intruder_jwt, owner=E2E_OWNER)
        if status != 403:
            raise TestFailure(
                f"JWT scoped to a different owner reading /v1/usage/{E2E_OWNER} "
                f"returned {status}, want 403 — cross-owner usage authz is broken"
            )


def phase_browser_file_download(
    *,
    timings: Timings,
    server: ServerHandle,
    rev_state: dict,
) -> None:
    """`GET /v1/files/{id}`, which the forge 302s into so bytes never transit it:

    1. Opaque hub token, no filename → 200, HEAD bytes, no `Content-Disposition`
       (no `FilenameSHA256` claim).
    2. Forge JWT + matching filename → 200 with `attachment; filename=…`.
    3. Forge JWT + tampered filename → 400.
    """
    repo, env = rev_state["repo_path"], rev_state["env"]
    # The pointer's `hash` is the file id.
    file_id = pointer_field(cat_file_bytes(repo, env, "HEAD:bigfile.bin"), "hash")
    expected_sha = rev_state["shas"][-1]  # HEAD == v3
    repo_id = f"{E2E_OWNER}/{E2E_REPO_2}"

    with timings.measure(
        "browser-download: opaque token, no filename", bytes_moved=BIG_FILE_BYTES
    ):
        status, body, headers = http_get_file(
            server, file_id=file_id, token=E2E_HUB_TOKEN, repo=repo_id
        )
        if status != 200:
            raise TestFailure(
                f"browser-download: expected 200, got {status}: {body[:200]!r}"
            )
        if len(body) != BIG_FILE_BYTES or sha256_bytes(body) != expected_sha:
            raise TestFailure(
                f"browser-download: reconstructed {len(body)} bytes / sha "
                f"{sha256_bytes(body)} != HEAD {BIG_FILE_BYTES} / {expected_sha}"
            )
        if "content-disposition" in headers:
            raise TestFailure(
                "browser-download: Content-Disposition set for a token with no "
                f"FilenameSHA256 claim ({headers['content-disposition']!r})"
            )

    with timings.measure(
        "browser-download: forge JWT + matching filename", bytes_moved=BIG_FILE_BYTES
    ):
        status, body, headers = http_get_file(
            server,
            file_id=file_id,
            token=BROWSER_DL_JWT,
            repo=repo_id,
            filename=BROWSER_DL_FILENAME,
        )
        if status != 200:
            raise TestFailure(
                f"browser-download(jwt): expected 200, got {status}: {body[:200]!r}"
            )
        if sha256_bytes(body) != expected_sha:
            raise TestFailure("browser-download(jwt): reconstructed bytes mismatch")
        cd = headers.get("content-disposition")
        expected_cd = f'attachment; filename="{BROWSER_DL_FILENAME}"'
        if cd != expected_cd:
            raise TestFailure(
                f"browser-download(jwt): Content-Disposition {cd!r} != {expected_cd!r}"
            )

    with timings.measure("browser-download: tampered filename rejected"):
        status, body, _ = http_get_file(
            server,
            file_id=file_id,
            token=BROWSER_DL_JWT,
            repo=repo_id,
            filename="evil.exe",
        )
        if status != 400:
            raise TestFailure(
                f"browser-download(tamper): expected 400 for a filename that "
                f"doesn't match the JWT claim, got {status}: {body[:200]!r}"
            )


def phase_dedup_duplicate_file(
    *,
    timings: Timings,
    server: ServerHandle,
    rev_state: dict,
) -> None:
    """A second file with bigfile.bin v3's bytes must add zero xorb bytes."""
    repo, env = rev_state["repo_path"], rev_state["env"]
    expected_sha = rev_state["shas"][-1]
    # A wrong worktree would make every assertion below measure the wrong thing.
    src = (repo / "bigfile.bin").read_bytes()
    if sha256_bytes(src) != expected_sha:
        raise TestFailure(
            "dedup: worktree bigfile.bin no longer matches v3 sha — "
            f"got {sha256_bytes(src)}, want {expected_sha}"
        )
    dup_path = repo / "bigfile_dup.bin"
    dup_path.write_bytes(src)
    verify_worktree(
        repo,
        "bigfile_dup.bin",
        expected_sha=expected_sha,
        expected_size=BIG_FILE_BYTES,
        label="dedup:write",
    )

    disk_before = server.disk_total_bytes()
    xorbs_before = server.disk_xorb_bytes()
    with timings.measure(
        "dedup: stage + commit + push duplicate", bytes_moved=BIG_FILE_BYTES
    ):
        git(["add", "bigfile_dup.bin"], cwd=repo, env=env)
        dup_staged = verify_pointer_at(
            repo,
            env,
            spec=":bigfile_dup.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:after-stage",
        )
        orig_committed = cat_file_bytes(repo, env, "HEAD:bigfile.bin")
        if pointer_field(dup_staged, "hash") != pointer_field(orig_committed, "hash"):
            raise TestFailure(
                "dedup: dup pointer 'hash' differs from v3 pointer 'hash' — "
                "clean filter is not chunking identical bytes identically"
            )
        git(["commit", "-m", "duplicate of bigfile v3"], cwd=repo, env=env)
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:bigfile_dup.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:after-commit",
        )
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:bigfile.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:HEAD-bigfile-still-v3",
        )
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after = server.disk_total_bytes()
    xorbs_after = server.disk_xorb_bytes()
    info(
        f"  dedup: total disk grew by {fmt_bytes(disk_after - disk_before)} "
        f"(xorbs: {fmt_bytes(xorbs_after - xorbs_before)})"
    )
    if xorbs_after - xorbs_before > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            f"dedup violation: xorb bytes grew by {fmt_bytes(xorbs_after - xorbs_before)} "
            "for a bit-identical second file"
        )
    verify_worktree(
        repo,
        "bigfile.bin",
        expected_sha=expected_sha,
        expected_size=BIG_FILE_BYTES,
        label="dedup:after-push-orig",
    )
    verify_worktree(
        repo,
        "bigfile_dup.bin",
        expected_sha=expected_sha,
        expected_size=BIG_FILE_BYTES,
        label="dedup:after-push-dup",
    )
    # The dup was registered without uploading a single xorb; it must still
    # reconstruct cold.
    with timings.measure("dedup: cold resmudge dup", bytes_moved=BIG_FILE_BYTES):
        force_resmudge_cold(
            repo,
            env,
            "bigfile_dup.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:cold-resmudge-dup",
        )
    with timings.measure("dedup: cold resmudge orig", bytes_moved=BIG_FILE_BYTES):
        force_resmudge_cold(
            repo,
            env,
            "bigfile.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:cold-resmudge-orig",
        )
    # orig's cold pass warmed manifests + chunks that also serve the identical dup.
    with timings.measure(
        "dedup: hot resmudge orig + dup", bytes_moved=2 * BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo,
            env,
            "bigfile.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:hot-resmudge-orig",
        )
        force_resmudge_and_verify(
            repo,
            env,
            "bigfile_dup.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:hot-resmudge-dup",
        )


def phase_push_idempotency(
    *,
    timings: Timings,
    server: ServerHandle,
    rev_state: dict,
) -> None:
    repo, env = rev_state["repo_path"], rev_state["env"]
    disk_before = server.disk_total_bytes()
    with timings.measure("idempotency: re-push"):
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after = server.disk_total_bytes()
    if abs(disk_after - disk_before) > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            f"re-push changed server disk by {fmt_bytes(disk_after - disk_before)} "
            "— push is not idempotent"
        )


def phase_clone_and_verify_history(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Cold-clone the bigfile repo and verify every historical revision's sha256."""
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="bobclone",
    )
    disk_before_clone = server.disk_total_bytes()
    with timings.measure("clone: cold smudge HEAD", bytes_moved=BIG_FILE_BYTES):
        git(["checkout", "main"], cwd=clone_path, env=env)
    disk_after_clone = server.disk_total_bytes()
    if disk_after_clone != disk_before_clone:
        raise TestFailure(
            f"server disk changed during clone: {disk_before_clone} → {disk_after_clone}"
        )

    # HEAD = v3, and so is bigfile_dup.bin.
    head_sha = sha256_file(clone_path / "bigfile.bin")
    expected_head_sha = rev_state["shas"][-1]
    if head_sha != expected_head_sha:
        raise TestFailure(
            f"clone HEAD sha mismatch: got {head_sha}, want {expected_head_sha}"
        )
    if (clone_path / "bigfile_dup.bin").exists():
        if sha256_file(clone_path / "bigfile_dup.bin") != expected_head_sha:
            raise TestFailure("dup file sha mismatch after clone")

    for idx, (commit, expected_sha) in enumerate(
        zip(rev_state["commits"], rev_state["shas"])
    ):
        with timings.measure(
            f"clone: checkout rev {idx + 1}/{len(rev_state['commits'])}"
        ):
            git(["checkout", commit, "--", "bigfile.bin"], cwd=clone_path, env=env)
        actual = sha256_file(clone_path / "bigfile.bin")
        if actual != expected_sha:
            raise TestFailure(
                f"rev {idx + 1} ({commit[:8]}) sha mismatch: got {actual}, "
                f"want {expected_sha}"
            )
        info(f"  rev {idx + 1} ({commit[:8]}) OK")


def phase_offline_and_restart(
    *,
    timings: Timings,
    server: ServerHandle,
    rt: Runtime,
    image_tag: str,
    data_root: Path,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    client: ClientEnv,
    ssh_public_key: str,
    work_root: Path,
    rev_state: dict,
    cas_port: int,
    ssh_port: int,
    admin_token_hex: str,
) -> ServerHandle:
    """Warm a clone's cache, stop the server and re-smudge (the hot path is
    offline), then restart on the same data dir and cold-clone again. Returns
    the new server handle.
    """
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="hotpath",
    )
    with timings.measure(
        "offline: warm cache via cold checkout", bytes_moved=BIG_FILE_BYTES
    ):
        git(["checkout", "main"], cwd=clone_path, env=env)
    # Check against the recorded sha, or the comparisons below only prove
    # "matches itself".
    expected_sha = rev_state["shas"][-1]
    cold_sha = sha256_file(clone_path / "bigfile.bin")
    if cold_sha != expected_sha:
        raise TestFailure(
            f"offline: cold checkout sha {cold_sha} != recorded v3 sha {expected_sha}"
        )
    if not manifest_cache_entries(clone_path):
        raise TestFailure("manifest cache empty after cold checkout")

    (clone_path / "bigfile.bin").unlink()
    info("  stopping server to force offline smudge")
    server.stop()
    with timings.measure("offline: smudge with server down"):
        git(["checkout", "--", "bigfile.bin"], cwd=clone_path, env=env)
    verify_worktree(
        clone_path,
        "bigfile.bin",
        expected_sha=expected_sha,
        expected_size=BIG_FILE_BYTES,
        label="offline:hot-smudge",
    )

    with timings.measure("restart: fresh container on persisted data dir"):
        new_server = start_container(
            rt,
            image_tag=image_tag,
            data_root=data_root,
            jwt_secret_hex=jwt_secret_hex,
            transfer_secret_hex=transfer_secret_hex,
            ssh_public_key=ssh_public_key,
            # Must host the gc + spilled-clean + churn repos too: those g3
            # phases run after this rebind, against the restarted server here.
            test_repos=[
                f"{E2E_OWNER}/{E2E_REPO}",
                f"{E2E_OWNER}/{E2E_REPO_2}",
                f"{E2E_OWNER}/{E2E_REPO_3}",
                f"{E2E_OWNER}/{E2E_REPO_SPILL}",
                f"{E2E_OWNER}/{E2E_REPO_CHURN}",
                f"{E2E_OWNER}/{E2E_REPO_GC1}",
                f"{E2E_OWNER}/{E2E_REPO_GC2}",
                f"{E2E_OWNER}/{E2E_REPO_GC3}",
            ],
            cas_port=cas_port,
            ssh_port=ssh_port,
            admin_token_hex=admin_token_hex,
            name_suffix=f"restart-{secrets.token_hex(3)}",
        )
    after_path, after_env, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=new_server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="afterrestart",
    )
    with timings.measure("restart: clone after restart", bytes_moved=BIG_FILE_BYTES):
        git(["checkout", "main"], cwd=after_path, env=after_env)
    verify_worktree(
        after_path,
        "bigfile.bin",
        expected_sha=expected_sha,
        expected_size=BIG_FILE_BYTES,
        label="restart:post-restart-clone",
    )
    # Present only when the dedup phase ran.
    if (after_path / "bigfile_dup.bin").exists():
        verify_worktree(
            after_path,
            "bigfile_dup.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="restart:post-restart-dup",
        )
    return new_server


@dataclass
class _ChurnParams:
    huge: bool
    minutes: int  # N from HUGE_CHURN=N (the ~wall-clock-minutes target); 0 if normal
    rounds: int
    clone_after: tuple
    walk_stride: int  # verify every Nth revision within a clone's walk
    # None = whole history; N = only the last N revisions (windows tile the history).
    walk_window: int | None
    base_files: tuple  # ((name, size), ...) created in round 0
    # Huge-mode-only knobs (ignored when huge is False).
    edit_files: tuple = (1, 1)  # (min, max) base files edited per round
    edit_bytes: tuple = (0, 0)  # (min, max) region replaced per edited file
    add_prob: float = 0.0
    plain_add_prob: float = 0.0  # of the adds, fraction that are plain text
    new_bytes: tuple = (0, 0)  # (min, max) size of a newly-added bale file
    del_prob: float = 0.0


def _churn_params(huge_minutes: int) -> _ChurnParams:
    """`huge_minutes` ≥ 1 (from `HUGE_CHURN=N`) selects the scaled stress run."""
    if huge_minutes >= 1:
        rounds = HUGE_CHURN_ROUNDS_PER_MIN * huge_minutes
        every = HUGE_CHURN_CLONE_EVERY
        clones = sorted(set(range(every - 1, rounds, every)) | {rounds - 1})
        return _ChurnParams(
            huge=True,
            minutes=huge_minutes,
            rounds=rounds,
            clone_after=tuple(clones),
            walk_stride=HUGE_CHURN_WALK_STRIDE,
            walk_window=every,
            base_files=HUGE_CHURN_BASE_FILES,
            edit_files=HUGE_CHURN_EDIT_FILES,
            edit_bytes=HUGE_CHURN_EDIT_BYTES,
            add_prob=HUGE_CHURN_ADD_PROB,
            plain_add_prob=HUGE_CHURN_PLAIN_ADD_PROB,
            new_bytes=HUGE_CHURN_NEW_BYTES,
            del_prob=HUGE_CHURN_DEL_PROB,
        )
    return _ChurnParams(
        huge=False,
        minutes=0,
        rounds=CHURN_ROUNDS,
        clone_after=CHURN_CLONE_AFTER_ROUNDS,
        walk_stride=1,
        walk_window=None,
        base_files=(("a.bin", CHURN_FILE_A_BYTES), ("b.bin", CHURN_FILE_B_BYTES)),
    )


def _churn_put_bale(repo: Path, files: dict, all_names: set, name: str, payload: bytes):
    (repo / name).write_bytes(payload)
    files[name] = (sha256_bytes(payload), len(payload))
    all_names.add(name)


def _churn_put_plain(repo: Path, files: dict, all_names: set, name: str, text: str):
    # write_bytes, not write_text: on Windows write_text translates \n -> \r\n,
    # but the expected sha/size below come from the untranslated text.encode().
    blob = text.encode()
    (repo / name).write_bytes(blob)
    files[name] = (sha256_bytes(blob), len(blob))
    all_names.add(name)


def _churn_delete(repo: Path, files: dict, name: str) -> None:
    (repo / name).unlink()
    del files[name]


def _churn_mutate_normal(
    r: int, repo: Path, files: dict, all_names: set, live: dict
) -> None:
    """Deterministic mutation plan: rotating region edit of a.bin every round,
    a static b.bin, a plain notes.txt, and add (r%3) / delete (r%4) of extras."""
    if r == 0:
        a = deterministic_payload(CHURN_FILE_A_BYTES, seed=b"churn-a")
        live["a.bin"] = a
        _churn_put_bale(repo, files, all_names, "a.bin", a)
        b = deterministic_payload(CHURN_FILE_B_BYTES, seed=b"churn-b")
        _churn_put_bale(repo, files, all_names, "b.bin", b)
        _churn_put_plain(repo, files, all_names, "notes.txt", f"churn round {r}\n")
        return
    offset = (r * CHURN_EDIT_BYTES) % (CHURN_FILE_A_BYTES - CHURN_EDIT_BYTES)
    a = replace_region(
        live["a.bin"],
        offset=offset,
        length=CHURN_EDIT_BYTES,
        seed=f"churn-a-r{r}".encode(),
    )
    live["a.bin"] = a
    _churn_put_bale(repo, files, all_names, "a.bin", a)
    _churn_put_plain(repo, files, all_names, "notes.txt", f"churn round {r}\n")
    if r % 3 == 0:
        _churn_put_bale(
            repo,
            files,
            all_names,
            f"extra{r}.bin",
            deterministic_payload(CHURN_EXTRA_BYTES, seed=f"churn-x{r}".encode()),
        )
    if r % 4 == 0:
        extras = sorted(n for n in files if n.startswith("extra"))
        if extras:
            _churn_delete(repo, files, extras[0])


def _churn_mutate_huge(
    r: int,
    params: _ChurnParams,
    rng: random.Random,
    repo: Path,
    files: dict,
    all_names: set,
    live: dict,
) -> None:
    """Every choice flows from `rng`, so the logged seed reproduces the run."""
    if r == 0:
        for name, size in params.base_files:
            payload = deterministic_payload(size, seed=f"churn-base-{name}".encode())
            live[name] = payload
            _churn_put_bale(repo, files, all_names, name, payload)
        _churn_put_plain(repo, files, all_names, "notes.txt", "churn round 0\n")
        return
    editable = sorted(live)
    lo, hi = params.edit_files
    for name in rng.sample(editable, rng.randint(lo, min(hi, len(editable)))):
        cur = live[name]
        size = len(cur)
        region = min(rng.randint(*params.edit_bytes), size)
        offset = rng.randint(0, size - region) if size > region else 0
        new = replace_region(
            cur, offset=offset, length=region, seed=f"churn-h-{name}-r{r}".encode()
        )
        live[name] = new
        _churn_put_bale(repo, files, all_names, name, new)
    _churn_put_plain(repo, files, all_names, "notes.txt", f"churn round {r}\n")
    if rng.random() < params.add_prob:
        if rng.random() < params.plain_add_prob:
            text = "".join(f"r{r} log line {i}\n" for i in range(rng.randint(50, 2000)))
            _churn_put_plain(repo, files, all_names, f"gen{r}.log", text)
        else:
            size = rng.randint(*params.new_bytes)
            _churn_put_bale(
                repo,
                files,
                all_names,
                f"gen{r}.bin",
                deterministic_payload(size, seed=f"churn-gen-{r}".encode()),
            )
    if rng.random() < params.del_prob:
        gens = sorted(n for n in files if n.startswith("gen"))
        if gens:
            _churn_delete(repo, files, rng.choice(gens))


def _churn_verify_snapshot(
    repo: Path,
    snapshot: dict,
    all_names: set,
    *,
    label: str,
) -> None:
    """Worktree must match `snapshot`; every other ever-seen file must be absent."""
    for name, (sha, size) in snapshot.items():
        verify_worktree(
            repo, name, expected_sha=sha, expected_size=size, label=f"{label}:{name}"
        )
    for name in all_names - set(snapshot):
        if (repo / name).exists():
            raise TestFailure(
                f"[{label}] {name} present in worktree but not in this "
                "revision's tree — a stale file leaked across checkouts"
            )


def _churn_clone_and_verify(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    history: list,
    all_names: set,
    round_idx: int,
    walk_stride: int = 1,
    walk_window: int | None = None,
) -> None:
    """Cold-clone after `round_idx` and verify each revision in the walk span
    byte-for-byte; `walk_window` limits it to the last N revisions."""
    head = history[round_idx]
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_CHURN,
        name=f"churnclone-r{round_idx}",
    )
    head_bytes = sum(size for _sha, size in head["snapshot"].values())
    with timings.measure(
        f"churn: clone after round {round_idx} (cold HEAD)", bytes_moved=head_bytes
    ):
        git(["checkout", "main"], cwd=clone_path, env=env)
    _churn_verify_snapshot(
        clone_path,
        head["snapshot"],
        all_names,
        label=f"churn:clone-r{round_idx}:HEAD",
    )
    # `git checkout <oid>` only re-smudges paths that differ, so each step
    # reconstructs just the delta.
    start = 0 if walk_window is None else max(0, round_idx - walk_window + 1)
    revs = sorted(set(range(start, round_idx + 1, walk_stride)) | {round_idx})
    note = ""
    if start > 0 or walk_stride > 1:
        note = f" (revs {start}..{round_idx}, {len(revs)} of {round_idx + 1})"
    with timings.measure(f"churn: clone-r{round_idx} walk {len(revs)} revisions"):
        for ri in revs:
            entry = history[ri]
            git(["checkout", entry["commit"]], cwd=clone_path, env=env)
            _churn_verify_snapshot(
                clone_path,
                entry["snapshot"],
                all_names,
                label=f"churn:clone-r{round_idx}:rev{ri}",
            )
        git(["checkout", "main"], cwd=clone_path, env=env)
    info(f"  churn: clone after round {round_idx} verified {len(revs)} revs{note}")


def phase_repeated_churn(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    huge_minutes: int = 0,
) -> None:
    """Many edit→commit→push rounds on ONE repo, guarding "data corrupted and
    server crashed after the Nth push": every round checks staged + committed
    pointers, `/healthz`, a non-shrinking disk total and the worktree, with
    cold-clone history walks at the clone rounds. `HUGE_CHURN=N ... --only
    churn` turns it into a randomized ~N-minute stress run (seed logged)."""
    params = _churn_params(huge_minutes)
    rng: random.Random | None = None
    if params.huge:
        seed = int(os.environ.get("HUGE_CHURN_SEED") or secrets.randbits(64))
        rng = random.Random(seed)
        base_total = sum(s for _n, s in params.base_files)
        info(
            f"churn: HUGE ×{params.minutes} (~{params.minutes} min target) — "
            f"{params.rounds} rounds, {len(params.base_files)} base files "
            f"({fmt_bytes(base_total)}), cold clone every {params.walk_window} "
            f"rounds, seed {seed} (set HUGE_CHURN_SEED to reproduce)"
        )

    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_CHURN,
        name="churn",
    )

    # {name: (sha256, size)}
    files: dict[str, tuple[str, int]] = {}
    all_names: set[str] = set()
    # Per round: {"commit": oid, "snapshot": files}
    history: list[dict] = []
    # Current bytes of each edited file (region edits chain).
    live: dict[str, bytes] = {}
    prev_disk = server.disk_total_bytes()

    for r in range(params.rounds):
        if params.huge:
            _churn_mutate_huge(r, params, rng, repo, files, all_names, live)
        else:
            _churn_mutate_normal(r, repo, files, all_names, live)

        with timings.measure(f"churn r{r}: stage"):
            git(["add", "-A"], cwd=repo, env=env)
        for name, (sha, size) in files.items():
            if name.endswith(".bin"):
                verify_pointer_at(
                    repo,
                    env,
                    spec=f":{name}",
                    expected_sha=sha,
                    expected_size=size,
                    label=f"churn-r{r}:staged:{name}",
                )

        git(["commit", "-m", f"churn round {r}"], cwd=repo, env=env)
        for name, (sha, size) in files.items():
            if name.endswith(".bin"):
                verify_pointer_at(
                    repo,
                    env,
                    spec=f"HEAD:{name}",
                    expected_sha=sha,
                    expected_size=size,
                    label=f"churn-r{r}:committed:{name}",
                )

        round_bytes = sum(size for _sha, size in files.values())
        with timings.measure(f"churn r{r}: push", bytes_moved=round_bytes):
            git(["push", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(f"churn r{r}: staging not drained after push")
        # A server crash removes the `--rm` container, so this probe fails.
        if not server.is_healthy():
            raise TestFailure(
                f"churn r{r}: server unhealthy after push — the push appears to "
                f"have crashed it\n--- container logs ---\n{server.logs()}"
            )
        disk = server.disk_total_bytes()
        if disk + SIZE_TOLERANCE_BYTES < prev_disk:
            raise TestFailure(
                f"churn r{r}: server disk shrank {fmt_bytes(prev_disk)} → "
                f"{fmt_bytes(disk)} across a push — CAS content went missing"
            )
        prev_disk = disk
        for name, (sha, size) in files.items():
            verify_worktree(
                repo,
                name,
                expected_sha=sha,
                expected_size=size,
                label=f"churn-r{r}:worktree-after-push:{name}",
            )

        history.append({"commit": _head_oid(repo, env), "snapshot": dict(files)})
        info(f"  churn round {r}: pushed {len(files)} files, disk {fmt_bytes(disk)}")

        if r in params.clone_after:
            _churn_clone_and_verify(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                history=history,
                all_names=all_names,
                round_idx=r,
                walk_stride=params.walk_stride,
                walk_window=params.walk_window,
            )


def _head_oid(repo: Path, env: dict) -> str:
    return git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
