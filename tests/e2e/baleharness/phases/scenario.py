"""Scenario phases (basic ops, offline, dedup, usage, clone, restart)."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import BIG_FILE_BYTES, BROWSER_DL_FILENAME, BROWSER_DL_JWT, E2E_HUB_TOKEN, E2E_OWNER, E2E_REPO, E2E_REPO_2, E2E_REPO_3, E2E_REPO_GC1, E2E_REPO_GC2, E2E_REPO_GC3, E2E_REPO_OFFLINE, E2E_REPO_SPILL, E2E_USER, GC_PAYLOAD_BYTES, JWT_TTL_YEARS, SIZE_TOLERANCE_BYTES, SMALL_FILE_BYTES, SPILL_FILE_BYTES, SPILL_INLINE_THRESHOLD
from baleharness.gitutil import cat_file_bytes, force_resmudge_and_verify, force_resmudge_cold, force_resmudge_lukewarm, git, pointer_field, verify_pointer_at, verify_worktree
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.mocks import TcpProxy
from baleharness.payloads import deterministic_payload, modify_bytes, replace_region
from baleharness.proc import pick_free_port, run, sha256_bytes, sha256_file
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.storage import clean_cache_entries, manifest_cache_entries, staging_files
from baleharness.timing import Timings
from baleharness.usage import fetch_repo_usage, fetch_usage, http_get_file


def phase_basic_user_ops(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Tracks a small file through the operations the user listed: stage,
    unstage, re-stage, stash, pop, commit. Verifies the index entry shape
    and worktree integrity at each step."""
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
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:write",
    )

    with timings.measure("basic: stage small file"):
        git(["add", "small.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec=":small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-stage",
    )
    verify_worktree(
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
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
    if (
        git(["ls-files", "--stage", "small.bin"], cwd=repo, env=env).stdout.strip()
    ):
        raise TestFailure("small.bin still staged after `git restore --staged`")
    # Unstage must not touch the worktree bytes.
    verify_worktree(
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-unstage",
    )

    # Re-stage. The `git restore --staged` above fires the post-checkout hook →
    # `git-bale gc`, which sweeps the now-unreferenced staging AND invalidates
    # its clean-cache entry — otherwise a cache-hit re-add would short-circuit to
    # a pointer whose bytes gc just deleted and which were never pushed (the
    # stage→unstage→stash data-loss regression). So the re-add must do a full
    # clean and re-populate staging; if it leaves staging empty, the stash/pop
    # below would have nothing to reconstruct from offline.
    with timings.measure("basic: re-stage (re-clean after gc-swept unstage)"):
        git(["add", "small.bin"], cwd=repo, env=env)
    if not staging_files(repo):
        raise TestFailure(
            "re-stage left staging empty — gc swept it and the re-add did not "
            "re-stage; the staged bytes are now unreconstructable offline"
        )
    verify_pointer_at(
        repo, env, spec=":small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-restage",
    )
    verify_worktree(
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
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
    # The stash itself encodes the file as a Bale pointer — verify the
    # stash's index tree has a matching pointer so we know the stash
    # captured the staged state intact, not the smudge-expanded bytes.
    verify_pointer_at(
        repo, env, spec="stash@{0}:small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:in-stash",
    )

    with timings.measure("basic: stash pop"):
        git(["stash", "pop"], cwd=repo, env=env)
    verify_worktree(
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-pop",
    )

    # `git stash pop` (without --index) leaves the change unstaged, so the
    # commit needs an explicit `git add` to pick the file back up.
    git(["add", "small.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec=":small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-pop-readd",
    )

    with timings.measure("basic: commit"):
        git(["commit", "-m", "add small.bin"], cwd=repo, env=env)
    verify_worktree(
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-commit",
    )
    verify_pointer_at(
        repo, env, spec="HEAD:small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-commit",
    )

    # Pre-push lukewarm: chunks are in .git/bale/staging/ but not on the
    # server yet — a successful re-smudge with the local caches wiped
    # proves the filter is reconstructing from staging, not the wire.
    with timings.measure("basic: lukewarm resmudge (pre-push)"):
        force_resmudge_lukewarm(
            repo, env, "small.bin",
            expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
            label="basic:lukewarm-pre-push",
        )

    # Pre-push: server must still be empty (defer-uploads contract).
    if server.disk_total_bytes() != 0:
        raise TestFailure(
            f"server disk non-zero before push: {fmt_bytes(server.disk_total_bytes())}"
        )

    with timings.measure(
        "basic: push (drains staging)", bytes_moved=SMALL_FILE_BYTES
    ):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
    if staging_files(repo):
        raise TestFailure("staging not drained after push")
    if server.disk_total_bytes() <= 0:
        raise TestFailure("server disk still zero after push")
    # Post-push: worktree + HEAD pointer must still match the original payload.
    verify_worktree(
        repo, "small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-push",
    )
    verify_pointer_at(
        repo, env, spec="HEAD:small.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="basic:after-push",
    )
    # Cold-then-hot ordering: the lukewarm step above wiped the local caches,
    # and `git push` doesn't repopulate them, so the only way to genuinely
    # measure the hot path post-push is to first run a cold smudge (which
    # repopulates the cache from the server) and only then the hot smudge.
    with timings.measure(
        "basic: cold resmudge after push", bytes_moved=SMALL_FILE_BYTES
    ):
        force_resmudge_cold(
            repo, env, "small.bin",
            expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
            label="basic:cold-resmudge-after-push",
        )
    with timings.measure("basic: hot resmudge after push"):
        force_resmudge_and_verify(
            repo, env, "small.bin",
            expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
            label="basic:hot-resmudge-after-push",
        )


def phase_offline_no_network(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    jwt_secret_hex: str,
) -> None:
    """Lock down the contract that *only* push/pull touch the CAS server.

    A counting TcpProxy sits between git-bale and the server. The resolver
    fast-path (`bale.serverUrl` + `bale.token` both set) routes every CAS
    round-trip through the proxy and skips the SSH forge handshake entirely,
    so `proxy.connections` is an exact count of server contact attempts.

    We assert it stays 0 across the full set of local operations — clean
    (`git add`), `git status`/`git diff`, `git commit`, smudge
    (`git checkout`), `git stash`/`pop`, unstage, and `git-bale gc` — then
    flip to a positive control: `git push` MUST make the count non-zero,
    proving the proxy is a working detector rather than a dead listener.

    The token is self-minted with the server's JWT secret (write scope,
    `repo_id = e2e/offline-net`), which the server's auth middleware accepts
    by signature alone — no SSH handshake needed to obtain it."""
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
            ["config", "--local", "bale.serverUrl",
             f"http://127.0.0.1:{proxy.listen_port}"],
            cwd=repo, env=env,
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
                repo, env, spec=":data.bin",
                expected_sha=payload_sha, expected_size=GC_PAYLOAD_BYTES,
                label="offline:add",
            )

            git(["status"], cwd=repo, env=env)
            git(["diff", "--cached"], cwd=repo, env=env)
            assert_offline("status+diff")

            git(["commit", "-m", "add data.bin"], cwd=repo, env=env)
            assert_offline("commit")

            # checkout = smudge. The file is committed but unpushed, so the
            # filter must reconstruct from `.git/bale/staging/` (lukewarm),
            # never the wire.
            (repo / "data.bin").unlink()
            git(["checkout", "--", "data.bin"], cwd=repo, env=env)
            verify_worktree(
                repo, "data.bin",
                expected_sha=payload_sha, expected_size=GC_PAYLOAD_BYTES,
                label="offline:checkout",
            )
            assert_offline("checkout-smudge")

            # A second revision driven through stash/pop and then abandoned.
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
                repo, "data.bin",
                expected_sha=payload2_sha, expected_size=GC_PAYLOAD_BYTES,
                label="offline:stash-pop",
            )
            assert_offline("stash-pop")

            # Stage v2, then unstage it (fires the post-checkout gc hook) and
            # run gc explicitly — all of which reconcile local staging only.
            git(["add", "data.bin"], cwd=repo, env=env)
            git(["restore", "--staged", "data.bin"], cwd=repo, env=env)
            assert_offline("unstage")
            run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)
            assert_offline("gc")

        info(
            f"  all local ops complete with {proxy.connections} CAS "
            "connection(s) — fully offline"
        )

        # ---- positive control: push MUST hit the server -------------------
        # Without this, a misconfigured proxy that never sees traffic would
        # make every assertion above pass vacuously. Re-stage + commit v2 so
        # push-pending has xorbs to upload, then push (its pre-push hook runs
        # `git-bale push-pending`) and assert the proxy saw the upload.
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
    """Drive the clean filter's spill-to-tmpfile path. The in-memory cap
    defaults to 4 GiB, so no realistic e2e file ever spills and `handle_clean`
    (the NamedTempFile branch) plus the file-backed `clean_cache::verify_chunks`
    go uncovered. Capping `BALE_MAX_INLINE_CLEAN` at 1 MiB and pushing a 5 MiB
    file forces the spill: the first `git add` stages via the tmpfile path; a
    touch + re-add reloads the clean-cache and verifies the spilled payload
    through the file-backed `verify_chunks`."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_SPILL,
        name="spilled",
    )
    # The filter reads this from the env git hands it, so the cap applies to
    # every clean below; the production default (4 GiB) would never spill.
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
        repo, env, spec=":spilled.bin",
        expected_sha=payload_sha, expected_size=SPILL_FILE_BYTES,
        label="spilled:after-stage",
    )
    staging_after_add = set(staging_files(repo))
    if not staging_after_add:
        raise TestFailure("spilled: staging dir empty after `git add`")
    if not clean_cache_entries(repo):
        raise TestFailure("spilled: clean-cache empty after `git add`")

    # Bump mtime (content unchanged) to invalidate git's stat cache, forcing the
    # next `git add` to re-run clean. That second clean reloads the clean-cache
    # and, because the payload still spills, verifies it through the file-backed
    # `verify_chunks` (not the in-memory variant). We deliberately do NOT unstage
    # here: `git restore --staged` would fire the post-checkout gc hook, which
    # sweeps + invalidates staging, turning this into a cache miss. A cache hit
    # must not produce new staging artifacts.
    os.utime(blob_path, None)
    with timings.measure("spilled: re-add (file-backed clean-cache hit)"):
        git(["add", "spilled.bin"], cwd=repo, env=env)
    if set(staging_files(repo)) != staging_after_add:
        raise TestFailure(
            "spilled: re-add changed staging files — clean-cache miss on the "
            "spilled verify path"
        )
    verify_pointer_at(
        repo, env, spec=":spilled.bin",
        expected_sha=payload_sha, expected_size=SPILL_FILE_BYTES,
        label="spilled:after-readd",
    )

    with timings.measure("spilled: commit"):
        git(["commit", "-m", "add spilled.bin"], cwd=repo, env=env)

    # Lukewarm: reconstruct the spilled file from staging before it's pushed —
    # proves the tmpfile clean produced valid staging artifacts.
    with timings.measure("spilled: lukewarm resmudge (pre-push)"):
        force_resmudge_lukewarm(
            repo, env, "spilled.bin",
            expected_sha=payload_sha, expected_size=SPILL_FILE_BYTES,
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
            repo, env, "spilled.bin",
            expected_sha=payload_sha, expected_size=SPILL_FILE_BYTES,
            label="spilled:cold-resmudge-after-push",
        )
    with timings.measure("spilled: hot resmudge after push"):
        force_resmudge_and_verify(
            repo, env, "spilled.bin",
            expected_sha=payload_sha, expected_size=SPILL_FILE_BYTES,
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
    """Push a 35 MB binary, then a slightly-modified version, then a larger
    1 MB-region edit. Asserts: storage growth per commit reflects the actual
    change (chunk-level dedup), and the server's `/v1/usage` API agrees with
    on-disk numbers.

    Returns a dict of payload shas + commit oids the next phase needs.
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

    # ---- revision 1 ------------------------------------------------------
    payload_v1 = deterministic_payload(BIG_FILE_BYTES, seed=b"big-v1")
    big_path.write_bytes(payload_v1)
    sha_v1 = sha256_bytes(payload_v1)
    rev_state["shas"].append(sha_v1)
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:write",
    )
    with timings.measure("bigfile v1: stage", bytes_moved=BIG_FILE_BYTES):
        git(["add", "bigfile.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec=":bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-stage",
    )
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-stage",
    )
    git(["commit", "-m", "bigfile v1"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec="HEAD:bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-commit",
    )
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-commit",
    )
    # Lukewarm reconstruction of 35 MB from staging only — the server has
    # nothing under this repo yet, so the cold path is guaranteed unreachable.
    with timings.measure(
        "bigfile v1: lukewarm resmudge (pre-push)", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_lukewarm(
            repo, env, "bigfile.bin",
            expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
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
        # Chunks compress some, but a totally-new 35 MB file should drive the
        # disk into the MB range. <50% growth means something didn't upload.
        raise TestFailure(
            f"bigfile v1 push grew server by {fmt_bytes(growth_v1)} — "
            f"expected ≥ {fmt_bytes(BIG_FILE_BYTES // 2)}"
        )
    info(f"  bigfile v1: disk grew by {fmt_bytes(growth_v1)}")
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-push",
    )
    verify_pointer_at(
        repo, env, spec="HEAD:bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v1:after-push",
    )
    # Cold first to warm the cache via server download, then hot, otherwise
    # the lukewarm step above would have left the cache empty and hot would
    # silently fall through. See basic phase for the full rationale.
    with timings.measure(
        "bigfile v1: cold resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo, env, "bigfile.bin",
            expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
            label="bigfile-v1:cold-resmudge-after-push",
        )
    with timings.measure(
        "bigfile v1: hot resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo, env, "bigfile.bin",
            expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
            label="bigfile-v1:hot-resmudge-after-push",
        )
    rev_state["commits"].append(
        git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
    )

    # ---- revision 2: 8-byte poke in the middle --------------------------
    payload_v2 = modify_bytes(
        payload_v1, offset=BIG_FILE_BYTES // 2, replacement=b"\xde\xad\xbe\xef\x01\x02\x03\x04"
    )
    big_path.write_bytes(payload_v2)
    sha_v2 = sha256_bytes(payload_v2)
    rev_state["shas"].append(sha_v2)
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:write",
    )
    with timings.measure("bigfile v2: stage (8-byte poke)", bytes_moved=BIG_FILE_BYTES):
        git(["add", "bigfile.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec=":bigfile.bin",
        expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-stage",
    )
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-stage",
    )
    git(["commit", "-m", "bigfile v2: 8-byte poke"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec="HEAD:bigfile.bin",
        expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-commit",
    )
    # v1's pointer must still be reachable through HEAD's history.
    verify_pointer_at(
        repo, env, spec="HEAD~1:bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:HEAD~1-still-v1",
    )
    disk_before_v2 = server.disk_total_bytes()
    with timings.measure("bigfile v2: push"):
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after_v2 = server.disk_total_bytes()
    rev_state["disk_after"].append(disk_after_v2)
    rev_state["raw_after"].append(BIG_FILE_BYTES * 2)
    growth_v2 = disk_after_v2 - disk_before_v2
    # An 8-byte edit should touch ≤ 3 chunks (the one containing the edit
    # plus shifted neighbors due to CDC boundaries). At ~64 KiB target chunks,
    # we expect well under 2 MiB of new content. 5 MiB is a generous ceiling
    # that still catches "no dedup happened" regressions.
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
        repo, "bigfile.bin",
        expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
        label="bigfile-v2:after-push",
    )
    # v2 has no preceding lukewarm — v1's cold left the cache populated with
    # v1's chunks, but those won't satisfy v2's smudge (different pointer,
    # likely different chunks after CDC shift). Cold-then-hot makes the
    # ordering invariant across all revisions.
    with timings.measure(
        "bigfile v2: cold resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo, env, "bigfile.bin",
            expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
            label="bigfile-v2:cold-resmudge-after-push",
        )
    with timings.measure(
        "bigfile v2: hot resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo, env, "bigfile.bin",
            expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
            label="bigfile-v2:hot-resmudge-after-push",
        )
    rev_state["commits"].append(
        git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
    )

    # ---- revision 3: 1 MiB region replacement ---------------------------
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
        repo, "bigfile.bin",
        expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:write",
    )
    with timings.measure("bigfile v3: stage (1 MiB region)", bytes_moved=BIG_FILE_BYTES):
        git(["add", "bigfile.bin"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec=":bigfile.bin",
        expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-stage",
    )
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-stage",
    )
    git(["commit", "-m", "bigfile v3: 1 MiB region replaced"], cwd=repo, env=env)
    verify_pointer_at(
        repo, env, spec="HEAD:bigfile.bin",
        expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-commit",
    )
    # The whole history must still resolve to the right pointers.
    verify_pointer_at(
        repo, env, spec="HEAD~1:bigfile.bin",
        expected_sha=sha_v2, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:HEAD~1-still-v2",
    )
    verify_pointer_at(
        repo, env, spec="HEAD~2:bigfile.bin",
        expected_sha=sha_v1, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:HEAD~2-still-v1",
    )
    disk_before_v3 = server.disk_total_bytes()
    with timings.measure("bigfile v3: push"):
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after_v3 = server.disk_total_bytes()
    rev_state["disk_after"].append(disk_after_v3)
    rev_state["raw_after"].append(BIG_FILE_BYTES * 3)
    growth_v3 = disk_after_v3 - disk_before_v3
    # 1 MiB of new content plus a few touched neighbors. ≤ 4 MiB.
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
        repo, "bigfile.bin",
        expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
        label="bigfile-v3:after-push",
    )
    with timings.measure(
        "bigfile v3: cold resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo, env, "bigfile.bin",
            expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
            label="bigfile-v3:cold-resmudge-after-push",
        )
    with timings.measure(
        "bigfile v3: hot resmudge after push", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo, env, "bigfile.bin",
            expected_sha=sha_v3, expected_size=BIG_FILE_BYTES,
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
    rev_state: dict,
) -> None:
    """Verifies `GET /v1/usage/{owner}` and `GET /v1/usage/repo/{owner}/{repo}`
    against the on-disk numbers.

    Contract from the wire types: `raw_bytes` = sum of file sizes registered
    for that scope (counting every revision separately), `stored_bytes` =
    actually-attributable on-disk cost, `dedup_savings_bytes = raw - stored`.
    Storage growth from this phase's pushes is the upper bound on
    `stored_bytes` for repo2.
    """
    with timings.measure("usage api: fetch + verify"):
        owner_usage = fetch_usage(server, token=bale_admin_token, owner=E2E_OWNER)
        repo_usage = fetch_repo_usage(
            server, token=bale_admin_token, owner=E2E_OWNER, repo=E2E_REPO_2
        )
        info(f"  /v1/usage/{E2E_OWNER}: {owner_usage}")
        info(f"  /v1/usage/repo/{E2E_OWNER}/{E2E_REPO_2}: {repo_usage}")

        # raw_bytes for repo2 must equal 3 * BIG_FILE_BYTES (three revisions
        # of the same logical 35 MB file).
        expected_raw_repo2 = 3 * BIG_FILE_BYTES
        if repo_usage["raw_bytes"] != expected_raw_repo2:
            raise TestFailure(
                f"repo usage raw_bytes={repo_usage['raw_bytes']} but expected "
                f"{expected_raw_repo2} (3 × {BIG_FILE_BYTES})"
            )

        # Owner stored_bytes vs xorbs-on-disk: every xorb in the data dir is
        # owned by E2E_OWNER (the basic phase + the bigfile phase both push
        # under the same owner, separate repos). So the owner-level number
        # has to match the on-disk xorb total within filesystem rounding.
        disk_xorbs = server.disk_xorb_bytes()
        delta = abs(int(owner_usage["stored_bytes"]) - disk_xorbs)
        if delta > SIZE_TOLERANCE_BYTES:
            raise TestFailure(
                f"owner usage stored_bytes={owner_usage['stored_bytes']} disagrees "
                f"with on-disk xorbs ({disk_xorbs}) by {delta} bytes "
                f"(> tolerance {SIZE_TOLERANCE_BYTES})"
            )

        # Per-repo stored_bytes must be a subset of (≤) the owner total —
        # repo2 doesn't own the small-file xorb the basic phase pushed under
        # repo1, so it can be strictly less.
        if repo_usage["stored_bytes"] > owner_usage["stored_bytes"]:
            raise TestFailure(
                f"repo stored_bytes={repo_usage['stored_bytes']} exceeds owner "
                f"stored_bytes={owner_usage['stored_bytes']} — accounting inverted"
            )
        # Repo's stored_bytes must be > 0 (we pushed 3 revisions of a 35 MB
        # binary into it) and dominate the owner total (the basic phase's
        # 8 KiB xorb is negligible relative to 35 MiB).
        if repo_usage["stored_bytes"] == 0:
            raise TestFailure(
                "repo stored_bytes is 0 but we pushed 35 MB three times — "
                "shard's CAS Info isn't reaching `xorbs`/`file_terms`"
            )

        # dedup_savings_bytes is derivable from raw - stored at both scopes.
        for label, blob in [("owner", owner_usage), ("repo", repo_usage)]:
            expected_savings = blob["raw_bytes"] - blob["stored_bytes"]
            if blob["dedup_savings_bytes"] != expected_savings:
                raise TestFailure(
                    f"{label} dedup_savings_bytes mismatch: got "
                    f"{blob['dedup_savings_bytes']}, expected raw - stored = "
                    f"{expected_savings}"
                )


def phase_browser_file_download(
    *,
    timings: Timings,
    server: ServerHandle,
    rev_state: dict,
) -> None:
    """Exercises the browser-facing `GET /v1/files/{id}` streaming download —
    the endpoint the forge 302s into so reconstructed bytes never round-trip
    through it. Three sub-cases:

    1. Opaque hub token, no filename → 200, bytes match HEAD, and *no*
       `Content-Disposition` (the token carries no `FilenameSHA256` claim).
    2. Forge JWT + matching filename → 200 with `Content-Disposition:
       attachment; filename="bigfile.bin"` (the claim binds the name).
    3. Forge JWT + tampered filename → 400 (the URL was rewritten).
    """
    repo, env = rev_state["repo_path"], rev_state["env"]
    # The staged/committed blob is the JSON pointer; its `hash` is the file id.
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
            server, file_id=file_id, token=BROWSER_DL_JWT, repo=repo_id,
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
            server, file_id=file_id, token=BROWSER_DL_JWT, repo=repo_id,
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
    """Adds a *second file* with the same content as bigfile.bin v3 in the
    same repo. The server should store zero new xorb bytes (full dedup) and
    only the shard for the new file's terms."""
    repo, env = rev_state["repo_path"], rev_state["env"]
    expected_sha = rev_state["shas"][-1]
    # Read the v3 content back from the worktree (filter is installed, so
    # the worktree has the original bytes). Cross-check the sha before
    # propagating it — if the worktree is wrong, the rest of this phase's
    # assertions would be measuring the wrong invariant.
    src = (repo / "bigfile.bin").read_bytes()
    if sha256_bytes(src) != expected_sha:
        raise TestFailure(
            "dedup: worktree bigfile.bin no longer matches v3 sha — "
            f"got {sha256_bytes(src)}, want {expected_sha}"
        )
    dup_path = repo / "bigfile_dup.bin"
    dup_path.write_bytes(src)
    verify_worktree(
        repo, "bigfile_dup.bin",
        expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
        label="dedup:write",
    )

    disk_before = server.disk_total_bytes()
    xorbs_before = server.disk_xorb_bytes()
    with timings.measure(
        "dedup: stage + commit + push duplicate", bytes_moved=BIG_FILE_BYTES
    ):
        git(["add", "bigfile_dup.bin"], cwd=repo, env=env)
        # Staged dup pointer must match v3's pointer exactly — same hash,
        # same size, same sha256 — otherwise the dedup signal is bogus.
        dup_staged = verify_pointer_at(
            repo, env, spec=":bigfile_dup.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
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
            repo, env, spec="HEAD:bigfile_dup.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
            label="dedup:after-commit",
        )
        verify_pointer_at(
            repo, env, spec="HEAD:bigfile.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
            label="dedup:HEAD-bigfile-still-v3",
        )
        git(["push", "origin", "main"], cwd=repo, env=env)
    disk_after = server.disk_total_bytes()
    xorbs_after = server.disk_xorb_bytes()
    info(
        f"  dedup: total disk grew by {fmt_bytes(disk_after - disk_before)} "
        f"(xorbs: {fmt_bytes(xorbs_after - xorbs_before)})"
    )
    # Xorbs must not grow at all — the chunks are bit-identical to v3's.
    if xorbs_after - xorbs_before > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            f"dedup violation: xorb bytes grew by {fmt_bytes(xorbs_after - xorbs_before)} "
            "for a bit-identical second file"
        )
    # Post-push worktree must still hold both files intact.
    verify_worktree(
        repo, "bigfile.bin",
        expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
        label="dedup:after-push-orig",
    )
    verify_worktree(
        repo, "bigfile_dup.bin",
        expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
        label="dedup:after-push-dup",
    )
    # The dup's pointer references xorbs the server owes from v3; cold-path
    # smudge must download them under the *dup* repo's scope check and end
    # up at the exact same bytes as the original.
    with timings.measure(
        "dedup: cold resmudge dup", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo, env, "bigfile_dup.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
            label="dedup:cold-resmudge-dup",
        )
    # And the original itself: the prior cold resmudge wiped the cache, so
    # this one starts from the same empty state and must also re-download.
    with timings.measure(
        "dedup: cold resmudge orig", bytes_moved=BIG_FILE_BYTES
    ):
        force_resmudge_cold(
            repo, env, "bigfile.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
            label="dedup:cold-resmudge-orig",
        )
    # Hot path now exercises the cache that the cold resmudges just warmed.
    # Because orig and dup share chunks (same pointer hash, bit-identical
    # bytes), the manifests + chunks left over from the orig cold pass also
    # satisfy a hot smudge of the dup.
    with timings.measure(
        "dedup: hot resmudge orig + dup", bytes_moved=2 * BIG_FILE_BYTES
    ):
        force_resmudge_and_verify(
            repo, env, "bigfile.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
            label="dedup:hot-resmudge-orig",
        )
        force_resmudge_and_verify(
            repo, env, "bigfile_dup.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
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
        # Nothing new to push; git should short-circuit, and even if pre-push
        # runs, push-pending finds nothing in staging.
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
    """Cold-clone the bigfile repo and check out each historical revision,
    verifying sha256 against the recorded value at each point."""
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="bobclone",
    )
    disk_before_clone = server.disk_total_bytes()
    with timings.measure(
        "clone: cold smudge HEAD", bytes_moved=BIG_FILE_BYTES
    ):
        git(["checkout", "main"], cwd=clone_path, env=env)
    # Server disk must not have grown — clone is read-only.
    disk_after_clone = server.disk_total_bytes()
    if disk_after_clone != disk_before_clone:
        raise TestFailure(
            f"server disk changed during clone: {disk_before_clone} → {disk_after_clone}"
        )

    # HEAD = revision 3. dedup_dup.bin should equal v3.
    head_sha = sha256_file(clone_path / "bigfile.bin")
    expected_head_sha = rev_state["shas"][-1]
    if head_sha != expected_head_sha:
        raise TestFailure(
            f"clone HEAD sha mismatch: got {head_sha}, want {expected_head_sha}"
        )
    if (clone_path / "bigfile_dup.bin").exists():
        if sha256_file(clone_path / "bigfile_dup.bin") != expected_head_sha:
            raise TestFailure("dup file sha mismatch after clone")

    # Walk back through revisions and verify each one's worktree state.
    for idx, (commit, expected_sha) in enumerate(
        zip(rev_state["commits"], rev_state["shas"])
    ):
        with timings.measure(f"clone: checkout rev {idx + 1}/{len(rev_state['commits'])}"):
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
    """Three checks rolled into one so the orchestration stays linear:

    1. Cold-clone to warm the cache (manifest + chunks).
    2. Stop the server; re-smudge from cache — must succeed without network
       (the hot path is by design offline).
    3. Start a fresh container against the *same* bind-mounted data dir;
       cold-clone again — proves data persists independently of the process.

    Returns the new server handle so the rest of the test can keep going.
    """
    # ---- warm a clone --------------------------------------------------
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
    # HEAD here is v3 (last revision pushed in phase_big_file_dedup, plus the
    # bigfile_dup.bin from phase_dedup_duplicate_file). Cross-check the cold
    # checkout against the known-good sha *before* using it as the reference
    # for the offline + restart comparisons — otherwise the rest of this
    # phase would be measuring "matches itself", not "matches the pushed
    # content".
    expected_sha = rev_state["shas"][-1]
    cold_sha = sha256_file(clone_path / "bigfile.bin")
    if cold_sha != expected_sha:
        raise TestFailure(
            f"offline: cold checkout sha {cold_sha} != recorded v3 sha "
            f"{expected_sha}"
        )
    if not manifest_cache_entries(clone_path):
        raise TestFailure("manifest cache empty after cold checkout")

    # ---- offline smudge ------------------------------------------------
    (clone_path / "bigfile.bin").unlink()
    info("  stopping server to force offline smudge")
    server.stop()
    with timings.measure("offline: smudge with server down"):
        git(["checkout", "--", "bigfile.bin"], cwd=clone_path, env=env)
    verify_worktree(
        clone_path, "bigfile.bin",
        expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
        label="offline:hot-smudge",
    )

    # ---- restart on same data dir -------------------------------------
    with timings.measure("restart: fresh container on persisted data dir"):
        new_server = start_container(
            rt,
            image_tag=image_tag,
            data_root=data_root,
            jwt_secret_hex=jwt_secret_hex,
            transfer_secret_hex=transfer_secret_hex,
            ssh_public_key=ssh_public_key,
            # Must host the gc + spilled-clean repos too: those g3 phases run
            # after this rebind, against the restarted server returned here.
            test_repos=[
                f"{E2E_OWNER}/{E2E_REPO}",
                f"{E2E_OWNER}/{E2E_REPO_2}",
                f"{E2E_OWNER}/{E2E_REPO_3}",
                f"{E2E_OWNER}/{E2E_REPO_SPILL}",
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
    with timings.measure(
        "restart: clone after restart", bytes_moved=BIG_FILE_BYTES
    ):
        git(["checkout", "main"], cwd=after_path, env=after_env)
    verify_worktree(
        after_path, "bigfile.bin",
        expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
        label="restart:post-restart-clone",
    )
    # The duplicate must also survive the restart — the prior phase pushed
    # bigfile_dup.bin to the same repo, and a clean post-restart checkout
    # should rehydrate it from the persisted xorbs/shards.
    if (after_path / "bigfile_dup.bin").exists():
        verify_worktree(
            after_path, "bigfile_dup.bin",
            expected_sha=expected_sha, expected_size=BIG_FILE_BYTES,
            label="restart:post-restart-dup",
        )
    return new_server


