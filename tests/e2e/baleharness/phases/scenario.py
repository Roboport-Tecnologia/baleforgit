"""Scenario phases (basic ops, offline, dedup, usage, clone, restart)."""

from __future__ import annotations

import os
import random
import secrets
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
    E2E_HUB_TOKEN,
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
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_REPO_3,
    E2E_REPO_CHURN,
    E2E_REPO_GC1,
    E2E_REPO_GC2,
    E2E_REPO_GC3,
    E2E_REPO_MR_A,
    E2E_REPO_MR_B,
    E2E_REPO_OFFLINE,
    E2E_REPO_SPILL,
    E2E_USER,
    GC_PAYLOAD_BYTES,
    JWT_TTL_YEARS,
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
    git,
    pointer_field,
    verify_pointer_at,
    verify_worktree,
)
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.mocks import TcpProxy
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
    # Unstage must not touch the worktree bytes.
    verify_worktree(
        repo,
        "small.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
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
    # The stash itself encodes the file as a Bale pointer — verify the
    # stash's index tree has a matching pointer so we know the stash
    # captured the staged state intact, not the smudge-expanded bytes.
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

    # `git stash pop` (without --index) leaves the change unstaged, so the
    # commit needs an explicit `git add` to pick the file back up.
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

    # Pre-push lukewarm: chunks are in .git/bale/staging/ but not on the
    # server yet — a successful re-smudge with the local caches wiped
    # proves the filter is reconstructing from staging, not the wire.
    with timings.measure("basic: lukewarm resmudge (pre-push)"):
        force_resmudge_lukewarm(
            repo,
            env,
            "small.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="basic:lukewarm-pre-push",
        )

    # Pre-push: server must still be empty (defer-uploads contract).
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
    # Post-push: worktree + HEAD pointer must still match the original payload.
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
    # Cold-then-hot ordering: the lukewarm step above wiped the local caches,
    # and `git push` doesn't repopulate them, so the only way to genuinely
    # measure the hot path post-push is to first run a cold smudge (which
    # repopulates the cache from the server) and only then the hot smudge.
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
    """Push a bale file to `origin` (repo A), then add a second remote (repo B
    on the same server) and push to it. The pre-push hook must register the
    file under B's repo scope — even though staging was drained by the first
    push — so a fresh clone of B can check it out. Before the multi-remote fix,
    B's push uploaded nothing and B's clone 404'd on reconstruction."""
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
    # Staging must drain after the origin push — that's precisely the state that
    # forces the second push to re-source the bytes from a server.
    if staging_files(repo):
        raise TestFailure("multi-remote: staging not drained after origin push")
    if server.disk_total_bytes() == 0:
        raise TestFailure("multi-remote: server disk still zero after origin push")

    # Add a second remote pointing at repo B on the SAME server and push to it.
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
        # The pre-push hook re-sources shared.bin from repo A and re-registers
        # it under repo B. Staging is empty here, so this exercises the
        # reachable-from-refs source path, not the staged-files path.
        git(["push", "mirror", "main"], cwd=repo, env=env)

    # The proof: a cold clone of repo B must reconstruct shared.bin. A 404 here
    # is the bug — B's server scope never learned about the file.
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

            # checkout = smudge. The file is committed but unpushed, so the
            # filter must reconstruct from `.git/bale/staging/` (lukewarm),
            # never the wire.
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
                repo,
                "data.bin",
                expected_sha=payload2_sha,
                expected_size=GC_PAYLOAD_BYTES,
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
        repo,
        env,
        spec=":spilled.bin",
        expected_sha=payload_sha,
        expected_size=SPILL_FILE_BYTES,
        label="spilled:after-readd",
    )

    with timings.measure("spilled: commit"):
        git(["commit", "-m", "add spilled.bin"], cwd=repo, env=env)

    # Lukewarm: reconstruct the spilled file from staging before it's pushed —
    # proves the tmpfile clean produced valid staging artifacts.
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
    # Lukewarm reconstruction of 35 MB from staging only — the server has
    # nothing under this repo yet, so the cold path is guaranteed unreachable.
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
        # Chunks compress some, but a totally-new 35 MB file should drive the
        # disk into the MB range. <50% growth means something didn't upload.
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
    # Cold first to warm the cache via server download, then hot, otherwise
    # the lukewarm step above would have left the cache empty and hot would
    # silently fall through. See basic phase for the full rationale.
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

    # ---- revision 2: 8-byte poke in the middle --------------------------
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
    # v1's pointer must still be reachable through HEAD's history.
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
        repo,
        "bigfile.bin",
        expected_sha=sha_v2,
        expected_size=BIG_FILE_BYTES,
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
    # The whole history must still resolve to the right pointers.
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
    rev_state: dict,
) -> None:
    """Verifies `GET /v1/usage/{owner}` and `GET /v1/usage/repo/{owner}/{repo}`
    against the on-disk numbers.

    Contract from the wire types: `raw_bytes` = sum of file sizes registered
    for that scope (counting every revision separately), `stored_bytes` =
    actually-attributable on-disk cost, `dedup_savings_bytes = raw - stored`.
    The repo response also carries `exclusive_bytes` = on-disk cost of xorbs no
    same-owner sibling repo references (`<= stored_bytes`). Storage growth from
    this phase's pushes is the upper bound on `stored_bytes` for repo2.
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

        # exclusive_bytes (xorbs no same-owner sibling references) is bounded
        # above by stored_bytes, and must be > 0 here: repo1 and repo2 share an
        # owner but repo2's three 35 MB revisions share no chunks with repo1's
        # 8 KiB file, so its big xorbs are exclusive to it.
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
        # Staged dup pointer must match v3's pointer exactly — same hash,
        # same size, same sha256 — otherwise the dedup signal is bogus.
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
    # Xorbs must not grow at all — the chunks are bit-identical to v3's.
    if xorbs_after - xorbs_before > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            f"dedup violation: xorb bytes grew by {fmt_bytes(xorbs_after - xorbs_before)} "
            "for a bit-identical second file"
        )
    # Post-push worktree must still hold both files intact.
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
    # The dup's pointer references xorbs the server owes from v3; cold-path
    # smudge must download them under the *dup* repo's scope check and end
    # up at the exact same bytes as the original.
    with timings.measure("dedup: cold resmudge dup", bytes_moved=BIG_FILE_BYTES):
        force_resmudge_cold(
            repo,
            env,
            "bigfile_dup.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
            label="dedup:cold-resmudge-dup",
        )
    # And the original itself: the prior cold resmudge wiped the cache, so
    # this one starts from the same empty state and must also re-download.
    with timings.measure("dedup: cold resmudge orig", bytes_moved=BIG_FILE_BYTES):
        force_resmudge_cold(
            repo,
            env,
            "bigfile.bin",
            expected_sha=expected_sha,
            expected_size=BIG_FILE_BYTES,
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
    with timings.measure("clone: cold smudge HEAD", bytes_moved=BIG_FILE_BYTES):
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
            f"offline: cold checkout sha {cold_sha} != recorded v3 sha {expected_sha}"
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
        clone_path,
        "bigfile.bin",
        expected_sha=expected_sha,
        expected_size=BIG_FILE_BYTES,
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
    # The duplicate must also survive the restart — the prior phase pushed
    # bigfile_dup.bin to the same repo, and a clean post-restart checkout
    # should rehydrate it from the persisted xorbs/shards.
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
    # None = walk the whole history; int = walk only the most recent N revisions
    # (a sliding window that tiles the history → linear total time).
    walk_window: "int | None"
    base_files: tuple  # ((name, size), ...) created in round 0
    # Huge-mode-only knobs (ignored when huge is False).
    edit_files: tuple = (1, 1)  # (min, max) base files edited per round
    edit_bytes: tuple = (0, 0)  # (min, max) region replaced per edited file
    add_prob: float = 0.0
    plain_add_prob: float = 0.0  # of the adds, fraction that are plain text
    new_bytes: tuple = (0, 0)  # (min, max) size of a newly-added bale file
    del_prob: float = 0.0


def _churn_params(huge_minutes: int) -> _ChurnParams:
    """`huge_minutes` is N from `HUGE_CHURN=N` (≈ minutes of wall-clock); N ≥ 1
    selects the scaled stress run, anything else the small default run. Rounds
    scale linearly with N and a cold clone is taken every CLONE_EVERY rounds,
    each walking the most recent CLONE_EVERY revisions — a window that tiles the
    full history, so coverage is complete but per-clone cost is constant."""
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
    """Randomized mutation plan (seeded `rng`): each round edits a random
    subset of the big base files at random offsets/lengths, rewrites a plain
    text file, and probabilistically adds (bale or plain) / deletes extra
    files. All choices flow from `rng`, so the logged seed reproduces the run.
    Payload *bytes* stay sha-verifiable — only the structure is random."""
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
    """Assert the checked-out worktree exactly matches `snapshot`
    ({name: (sha256, size)}): every file present with the right bytes, and
    every file that ever existed but isn't in this revision is absent."""
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
    walk_window: "int | None" = None,
) -> None:
    """Cold-clone the churn repo as it stands after `round_idx`, then walk a
    span of the revision history verifying each one reconstructs byte-for-byte.
    A fresh cache dir forces every smudge through the cold
    `/v1/reconstructions/` path against the reused server state.

    `walk_window` bounds the span to the most recent N revisions (huge mode);
    None walks the whole history (default mode). With clones placed every
    `walk_window` rounds the windows tile, so every revision is still
    cold-verified exactly once while each walk stays constant-cost."""
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
    # `git checkout <oid>` only re-smudges paths that differ from the current
    # tree, so each step reconstructs just the delta against the accumulating
    # server state.
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
    """Sustained churn against ONE reused repo: many rounds of
    edit→commit→push, with cold clones taken at several different points that
    each reconstruct the accumulated history byte-for-byte.

    This is the regression guard for the "data got corrupted and the server
    crashed after the Nth push" class of bug. Integrity is checked at every
    step: the staged pointer after each `git add`, the committed pointer after
    each commit, the server's `/healthz` after each push (a crash takes the
    container down under `--rm`, so the probe goes false), the monotonic
    server disk total, the post-push worktree, and a cold-clone history walk
    at the clone rounds.

    `huge_minutes >= 1` (opt-in via `HUGE_CHURN=N ... --only churn`) scales this
    into a randomized stress run of roughly N minutes: rounds scale linearly
    with N, several big base files are edited in random subsets, extra files
    are randomly added/deleted, and a cold clone every CLONE_EVERY rounds
    window-walks the history. The RNG seed is logged (override via
    `HUGE_CHURN_SEED`)."""
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

    # Logical worktree model, mutated round by round. {name: (sha256, size)}.
    files: dict[str, tuple[str, int]] = {}
    all_names: set[str] = set()
    # Per-round: {"commit": oid, "snapshot": {name: (sha, size)}}.
    history: list[dict] = []
    # Current bytes of every repeatedly-edited bale file (region edits chain).
    live: dict[str, bytes] = {}
    prev_disk = server.disk_total_bytes()

    for r in range(params.rounds):
        if params.huge:
            _churn_mutate_huge(r, params, rng, repo, files, all_names, live)
        else:
            _churn_mutate_normal(r, repo, files, all_names, live)

        with timings.measure(f"churn r{r}: stage"):
            git(["add", "-A"], cwd=repo, env=env)
        # Every bale file's staged pointer must match the bytes we just wrote.
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
        # The crash guard: a push that took the server down fails this probe.
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
        # Worktree must still hold the just-pushed bytes (push mustn't disturb it).
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
