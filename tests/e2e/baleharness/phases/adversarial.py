"""Adversarial phases (wrong token, tampered xorb, quota exceeded)."""

from __future__ import annotations

import os
import secrets
import urllib.request
from pathlib import Path
from typing import Callable

from baleharness.client import ClientEnv
from baleharness.config import (
    BIG_FILE_BYTES,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    SIZE_TOLERANCE_BYTES,
    SMALL_FILE_BYTES,
)
from baleharness.gitutil import git, verify_pointer_at, verify_worktree
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import sha256_bytes, sha256_file
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings


def phase_adversarial_wrong_token(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """A repo whose bale.serverUrl/token are overridden to a deliberately
    wrong token: the push should fail before any data is corrupted."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="wrong-token",
    )
    # Pin a known-bad token so the resolver fast-paths to it (skipping SSH
    # forge auth). The server's verify_xet_token will reject it.
    git(
        ["config", "--local", "bale.serverUrl", server.public_host_url],
        cwd=repo,
        env=env,
    )
    git(
        ["config", "--local", "bale.token", "this-is-not-a-valid-jwt"],
        cwd=repo,
        env=env,
    )
    payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"wrongtoken")
    payload_sha = sha256_bytes(payload)
    (repo / "wrongtoken.bin").write_bytes(payload)
    with timings.measure("adversarial: stage with wrong token (offline)"):
        # Stage succeeds — clean is offline.
        git(["add", "wrongtoken.bin"], cwd=repo, env=env)
        verify_pointer_at(
            repo,
            env,
            spec=":wrongtoken.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="wrongtoken:after-stage",
        )
        git(["commit", "-m", "wrongtoken"], cwd=repo, env=env)
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:wrongtoken.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="wrongtoken:after-commit",
        )
    disk_before = server.disk_total_bytes()
    with timings.measure("adversarial: push fails (wrong token)"):
        completed = git(
            ["push", "-u", "origin", "main"],
            cwd=repo,
            env=env,
            expect_fail=True,
        )
        if completed.returncode == 0:
            raise TestFailure(
                "push with a bogus bale.token unexpectedly succeeded — "
                "verify_xet_token isn't blocking unauthorized uploads"
            )
    disk_after = server.disk_total_bytes()
    if abs(disk_after - disk_before) > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            "server disk changed during a push that should have been rejected: "
            f"{disk_before} → {disk_after}"
        )
    # A rejected push must not corrupt the client's worktree or its index/HEAD.
    verify_worktree(
        repo,
        "wrongtoken.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="wrongtoken:after-failed-push",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:wrongtoken.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="wrongtoken:after-failed-push",
    )


def _fs_writer(path: Path) -> Callable[[bytes], None]:
    return lambda data: path.write_bytes(data)


def _s3_writer(minio, key: str) -> Callable[[bytes], None]:
    return lambda data: minio.put_object(key, data)


def phase_adversarial_tampered_xorb(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Corrupt the stored xorbs (we own both the bind-mounted fs data dir and
    the MinIO bucket), then cold-clone in a fresh worktree. The smudge must
    NOT silently produce wrong bytes — it must either error or produce content
    whose sha256 the test detects as wrong."""
    # Backend-agnostic corrupt/restore. Corrupt EVERY stored xorb — flip a
    # window in the middle of each. Corrupting just one is fragile: HEAD's
    # reconstruction (rev v3 of bigfile) only reads a subset of any single
    # xorb's chunks (e.g. the chunk at the v1 xorb's middle is exactly the
    # region v3 replaced, so it's never read), and an xorb's trailing footer
    # isn't covered by any chunk byte-range either. Hitting all of them
    # guarantees at least one corrupted chunk lands on HEAD's read path. S3
    # mode pokes bucket objects; fs mode pokes files under data_root/xorbs.
    victims: list[tuple[str, bytes, Callable[[bytes], None]]] = []
    if server.s3_view is not None:
        minio = server.s3_view.minio
        for key, size in minio.list_objects(f"{server.s3_view.prefix}xorbs/"):
            if size <= 0:
                continue
            victims.append(
                (f"s3://{key}", minio.get_object(key), _s3_writer(minio, key))
            )
        if not victims:
            raise TestFailure("no xorb in bucket to tamper with")
    else:
        xorbs_dir = server.data_root / "xorbs"
        for cur, _dirs, names in os.walk(xorbs_dir):
            for name in names:
                p = Path(cur) / name
                if p.stat().st_size > 0:
                    victims.append(
                        (
                            str(p.relative_to(server.data_root)),
                            p.read_bytes(),
                            _fs_writer(p),
                        )
                    )
        if not victims:
            raise TestFailure("no xorb on disk to tamper with")

    def corrupt(data: bytes) -> bytes:
        window = min(4096, len(data))
        start = (len(data) - window) // 2
        out = bytearray(data)
        for i in range(start, start + window):
            out[i] ^= 0xFF
        return bytes(out)

    for label, original, write in victims:
        info(f"  corrupting {label} ({len(original)}B)")
        write(corrupt(original))

    try:
        clone_path, env, _cache = init_repo_for_clone(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_2,
            name="tampered",
        )
        bytes_match = False
        with timings.measure("adversarial: smudge a tampered xorb"):
            completed = git(
                ["checkout", "main"],
                cwd=clone_path,
                env=env,
                expect_fail=True,
            )
            if completed.returncode == 0 and (clone_path / "bigfile.bin").exists():
                got_sha = sha256_file(clone_path / "bigfile.bin")
                bytes_match = got_sha == rev_state["shas"][-1]
        if bytes_match:
            raise TestFailure(
                "tampered xorb still produced matching bytes — chunk-hash "
                "verification isn't catching corruption"
            )
    finally:
        # Restore so downstream phases aren't poisoned.
        for _label, original, write in victims:
            write(original)


def phase_adversarial_quota_exceeded(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Spin up a SEPARATE container with a tiny quota and confirm push fails
    cleanly instead of corrupting metadata. Uses a fresh data dir so it can't
    interfere with the main test's measurements."""
    quota_data = work_root / "quota-server-data"
    quota_data.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=quota_data,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        quota_bytes=1024,  # 1 KiB — anything more than a trivial blob trips it.
        admin_token_hex=admin_token_hex,
        name_suffix="quota",
    )
    try:
        # `server` here is the quota-specific container; init_repo_for_push
        # bakes its SSH port into the remote URL, so no extra ssh-config
        # plumbing is needed.
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="quota-client",
        )
        payload = deterministic_payload(BIG_FILE_BYTES, seed=b"quota-test")
        payload_sha = sha256_bytes(payload)
        (repo / "fatfile.bin").write_bytes(payload)
        disk_before = server.disk_total_bytes()
        with timings.measure("adversarial: push past quota (must fail)"):
            git(["add", "fatfile.bin"], cwd=repo, env=env)
            verify_pointer_at(
                repo,
                env,
                spec=":fatfile.bin",
                expected_sha=payload_sha,
                expected_size=BIG_FILE_BYTES,
                label="quota:after-stage",
            )
            git(["commit", "-m", "fatfile"], cwd=repo, env=env)
            verify_pointer_at(
                repo,
                env,
                spec="HEAD:fatfile.bin",
                expected_sha=payload_sha,
                expected_size=BIG_FILE_BYTES,
                label="quota:after-commit",
            )
            completed = git(
                ["push", "-u", "origin", "main"],
                cwd=repo,
                env=env,
                expect_fail=True,
            )
        if completed.returncode == 0:
            raise TestFailure("push past the 1 KiB quota unexpectedly succeeded")
        # Server should still be healthy after the rejected push.
        with urllib.request.urlopen(server.healthz_url, timeout=5) as resp:
            if resp.status != 200:
                raise TestFailure(
                    f"server unhealthy after rejected push: {resp.status}"
                )
        # The rejected push must leave server storage and client worktree
        # both intact — a partial upload that broke the quota check would
        # show up as a disk delta here.
        disk_after = server.disk_total_bytes()
        if disk_after - disk_before > SIZE_TOLERANCE_BYTES:
            raise TestFailure(
                "quota-rejected push grew server disk by "
                f"{fmt_bytes(disk_after - disk_before)} — quota enforcement "
                "is leaking xorbs through"
            )
        verify_worktree(
            repo,
            "fatfile.bin",
            expected_sha=payload_sha,
            expected_size=BIG_FILE_BYTES,
            label="quota:after-failed-push",
        )
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:fatfile.bin",
            expected_sha=payload_sha,
            expected_size=BIG_FILE_BYTES,
            label="quota:after-failed-push",
        )
    finally:
        server.stop()
