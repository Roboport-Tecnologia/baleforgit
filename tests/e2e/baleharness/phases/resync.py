"""Disaster-recovery phase: server CAS wiped, client re-syncs via force-push."""

from __future__ import annotations

import secrets
from pathlib import Path

from baleharness.client import ClientEnv, remote_url_ssh
from baleharness.config import E2E_OWNER, E2E_REPO_RESYNC
from baleharness.gitutil import git, verify_pointer_at, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import pick_free_port, rmtree, run, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.storage import staging_files
from baleharness.timing import Timings

RESYNC_PAYLOAD_BYTES = 4 * 1024 * 1024


def phase_resync_after_cas_wipe(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Push, restart the server with a blank CAS (same bare repo), then delete
    `.git`, re-init, re-add (must re-stage) and force-push.

    That push must fail: the client's xet cache (outside `.git`) survives, so
    every chunk dedups, nothing is re-uploaded, and the blank server rejects the
    shard. The error must explain the cache mismatch (not a bare `400`), keep
    staging, and write nothing server-side. Following its advice
    (`BALE_XET_CACHE` → fresh dir) the re-push succeeds and a cold clone
    round-trips. Uses its own container so the wipe can't touch shared phases."""
    phase_root = work_root / "resync-wipe"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    # Sibling of `data` so start_container derives the same git-home: the old
    # `main` ref survives the wipe, making the later push a non-fast-forward.
    data_root_wiped = phase_root / "data2"
    data_root_wiped.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    # Same ports across the restart so the resolved URL doesn't change.
    cas_port = pick_free_port()
    ssh_port = pick_free_port()

    def _boot(data: Path, suffix: str) -> ServerHandle:
        return start_container(
            rt,
            image_tag=image_tag,
            data_root=data,
            jwt_secret_hex=jwt_secret,
            transfer_secret_hex=transfer_secret,
            ssh_public_key=ssh_public_key,
            test_repos=[f"{E2E_OWNER}/{E2E_REPO_RESYNC}"],
            cas_port=cas_port,
            ssh_port=ssh_port,
            admin_token_hex=admin_token_hex,
            name_suffix=suffix,
        )

    server = _boot(data_root, f"resync-{secrets.token_hex(3)}")
    wiped: ServerHandle | None = None
    payload = deterministic_payload(RESYNC_PAYLOAD_BYTES, seed=b"resync-wipe")
    payload_sha = sha256_bytes(payload)
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_RESYNC,
            name="resync-client",
        )
        (repo / "asset.bin").write_bytes(payload)
        with timings.measure(
            "resync: initial stage + commit + push", bytes_moved=RESYNC_PAYLOAD_BYTES
        ):
            git(["add", "asset.bin"], cwd=repo, env=env)
            git(["commit", "-m", "add binary asset"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure("resync: staging not drained after initial push")

        info("  restarting server with a blank CAS (fresh data dir)")
        server.stop()
        with timings.measure("resync: restart server with blank CAS"):
            wiped = _boot(data_root_wiped, f"resync-wiped-{secrets.token_hex(3)}")
        if wiped.disk_total_bytes() != 0:
            raise TestFailure(
                f"resync: restarted server CAS not blank "
                f"({wiped.disk_total_bytes()} bytes of xorbs/shards on disk)"
            )

        # asset.bin + .gitattributes stay in the worktree.
        info("  deleting .git and re-initializing the working repo")
        rmtree(repo / ".git")
        cache_dir = work_root / "cache-resync-client"  # outside .git, survived
        git(["init", "-b", "main", "."], cwd=repo, env=env)
        run([str(client.git_bale_bin), "install", "--local"], cwd=repo, env=env)
        git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=repo, env=env)
        git(
            [
                "remote",
                "add",
                "origin",
                remote_url_ssh(
                    ssh_port=wiped.ssh_port, owner=E2E_OWNER, repo=E2E_REPO_RESYNC
                ),
            ],
            cwd=repo,
            env=env,
        )
        with timings.measure(
            "resync: re-add after wipe", bytes_moved=RESYNC_PAYLOAD_BYTES
        ):
            git(["add", "-A"], cwd=repo, env=env)
        if not staging_files(repo):
            raise TestFailure(
                "resync: staging dir empty after re-add — the binary was not "
                "re-chunked into local staging"
            )
        verify_pointer_at(
            repo,
            env,
            spec=":asset.bin",
            expected_sha=payload_sha,
            expected_size=RESYNC_PAYLOAD_BYTES,
            label="resync:after-readd",
        )
        git(["commit", "-m", "re-add binary asset after wipe"], cwd=repo, env=env)

        with timings.measure("resync: force-push after wipe (expected reject)"):
            pushed = git(
                ["push", "-f", "-u", "origin", "main"],
                cwd=repo,
                env=env,
                expect_fail=True,
            )
        if pushed.returncode == 0:
            raise TestFailure(
                "resync: force-push unexpectedly succeeded — the wiped server "
                "cannot hold xorbs the dedup cache skipped re-uploading"
            )

        # xet alone surfaces a bare `400 Bad Request on /shards`.
        stderr = pushed.stderr.decode("utf-8", "replace")
        for needle in (
            "the server is missing content",
            "your local cache is incompatible",
            "Active cache directory:",
        ):
            if needle not in stderr:
                raise TestFailure(
                    f"resync: push was rejected but without the cache-mismatch "
                    f"explanation (missing {needle!r}). stderr:\n{stderr}"
                )

        # Staged bytes are still the only copy.
        if not staging_files(repo):
            raise TestFailure(
                "resync: staging drained despite a rejected push — push-pending "
                "cleared markers without a successful finalize"
            )
        if wiped.disk_total_bytes() != 0:
            raise TestFailure(
                f"resync: rejected push left {wiped.disk_total_bytes()} bytes of "
                "xorbs/shards on the server — partial write on a failed push"
            )

        fresh_cache = phase_root / "fresh-xet-cache"
        recover_env = dict(env)
        recover_env["BALE_XET_CACHE"] = str(fresh_cache)
        with timings.measure(
            "resync: force-push with fresh cache (recovers)",
            bytes_moved=RESYNC_PAYLOAD_BYTES,
        ):
            git(["push", "-f", "-u", "origin", "main"], cwd=repo, env=recover_env)
        if staging_files(repo):
            raise TestFailure(
                "resync: staging not drained after the recovering push — "
                "push-pending didn't finalize the re-upload"
            )
        if wiped.disk_total_bytes() == 0:
            raise TestFailure(
                "resync: recovering push reported success but the server holds "
                "no xorbs/shards — nothing was actually uploaded"
            )

        with timings.measure(
            "resync: cold clone after recovery", bytes_moved=RESYNC_PAYLOAD_BYTES
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=wiped,
                owner=E2E_OWNER,
                repo=E2E_REPO_RESYNC,
                name="resync-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "asset.bin",
            expected_sha=payload_sha,
            expected_size=RESYNC_PAYLOAD_BYTES,
            label="resync:after-recovery-clone",
        )
    finally:
        if wiped is not None:
            wiped.stop()
        else:
            server.stop()
