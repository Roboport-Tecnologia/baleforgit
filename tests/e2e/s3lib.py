"""The two S3 phases `run.py --coverage` runs on the instrumented image so
`bale-server-storage-s3` shows up in the coverage report (the full suite runs
on S3 via `run.py --backend s3`). Each scopes its writes under its own
`BALE_S3_PREFIX` so they share one bucket.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from baleharness.s3backend import (
    MinioGuard,
    Network,
    S3StorageView,
    s3_run_args,
    s3_server_env,
)

# Reuse run.py's plumbing so the fs and S3 phases can't drift apart.
from run import (
    BIG_FILE_BYTES,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_USER,
    JWT_TTL_YEARS,
    ClientEnv,
    Runtime,
    ServerHandle,
    TestFailure,
    Timings,
    deterministic_payload,
    fetch_repo_usage,
    fmt_bytes,
    git,
    info,
    init_repo_for_clone,
    init_repo_for_push,
    mint_bale_jwt,
    sha256_bytes,
    staging_files,
    start_container,
    verify_pointer_at,
    verify_worktree,
)


def _mint_admin_jwt(jwt_secret_hex: str, repo: str) -> str:
    return mint_bale_jwt(
        secret=bytes.fromhex(jwt_secret_hex),
        sub=E2E_USER,
        repo_type="model",
        repo_id=f"{E2E_OWNER}/{repo}",
        revision="main",
        scope="write",
        ttl_secs=JWT_TTL_YEARS * 365 * 24 * 3600,
    )


def _start_s3_server(
    *,
    rt: Runtime,
    image_tag: str,
    data_root: Path,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    ssh_public_key: str,
    test_repos: list[str],
    admin_token_hex: str,
    name_suffix: str,
    minio: MinioGuard,
    network: Network,
    prefix: str,
    endpoint_override: str | None = None,
    public_host_url_override: str | None = None,
    cas_port: int | None = None,
    ssh_port: int | None = None,
) -> ServerHandle:
    run_args = s3_run_args(network)
    return start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret_hex,
        transfer_secret_hex=transfer_secret_hex,
        ssh_public_key=ssh_public_key,
        test_repos=test_repos,
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=name_suffix,
        public_host_url_override=public_host_url_override,
        extra_env=s3_server_env(
            minio, prefix=prefix, endpoint_override=endpoint_override
        ),
        extra_run_args=run_args,
    )


def phase_s3_basic(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
    minio: MinioGuard,
    network: Network,
) -> None:
    """Push + cold clone against an S3-backed server: the bucket must receive
    the xorbs (no silent fs fallback) and the smudge must reconstruct through
    MinIO-presigned URLs."""
    phase_root = work_root / "s3-basic"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    prefix = "basic/"
    storage = S3StorageView(minio, prefix=prefix)

    server = _start_s3_server(
        rt=rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix="s3-basic",
        minio=minio,
        network=network,
        prefix=prefix,
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="s3-basic-client",
        )
        payload = deterministic_payload(64 * 1024, seed=b"s3-basic")
        payload_sha = sha256_bytes(payload)
        (repo / "smallish.bin").write_bytes(payload)

        with timings.measure("s3-basic: stage + commit", bytes_moved=len(payload)):
            git(["add", "smallish.bin"], cwd=repo, env=env)
            verify_pointer_at(
                repo,
                env,
                spec=":smallish.bin",
                expected_sha=payload_sha,
                expected_size=len(payload),
                label="s3-basic:after-stage",
            )
            git(["commit", "-m", "s3-basic"], cwd=repo, env=env)

        if storage.total_bytes() != 0:
            raise TestFailure(
                f"s3-basic: bucket prefix {prefix!r} non-empty before push: "
                f"{fmt_bytes(storage.total_bytes())}"
            )
        with timings.measure(
            "s3-basic: push (drains staging into S3)", bytes_moved=len(payload)
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure("s3-basic: staging not drained after push")
        if storage.total_bytes() <= 0:
            raise TestFailure(
                "s3-basic: bucket still empty after push — the server may "
                "have fallen back to the fs blob store"
            )
        info(f"  s3-basic: bucket grew to {fmt_bytes(storage.total_bytes())}")

        with timings.measure(
            "s3-basic: cold clone + checkout", bytes_moved=len(payload)
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="s3-basic-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "smallish.bin",
            expected_sha=payload_sha,
            expected_size=len(payload),
            label="s3-basic:after-clone",
        )
    finally:
        server.stop()


def phase_s3_dedup(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
    minio: MinioGuard,
    network: Network,
) -> None:
    """Push a 35 MiB file at three revisions (v1, 8-byte poke, 1 MiB region
    swap): the bucket grows only by each edit's delta, `raw_bytes` ≈ 3× the
    file, `stored_bytes` ≈ 1×.

    Distinct revisions are required: identical content at another path has
    the same file_hash, which the server registers once, so raw_bytes
    wouldn't grow and chunk-level dedup would go unexercised.
    """
    phase_root = work_root / "s3-dedup"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    prefix = "dedup/"
    storage = S3StorageView(minio, prefix=prefix)

    server = _start_s3_server(
        rt=rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO_2}"],
        admin_token_hex=admin_token_hex,
        name_suffix="s3-dedup",
        minio=minio,
        network=network,
        prefix=prefix,
    )
    admin_jwt = _mint_admin_jwt(jwt_secret, E2E_REPO_2)
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_2,
            name="s3-dedup-client",
        )

        payload_v1 = deterministic_payload(BIG_FILE_BYTES, seed=b"s3-dedup-v1")
        sha_v1 = sha256_bytes(payload_v1)
        (repo / "bigfile.bin").write_bytes(payload_v1)
        with timings.measure(
            "s3-dedup: v1 stage+commit+push", bytes_moved=BIG_FILE_BYTES
        ):
            git(["add", "bigfile.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-dedup v1"], cwd=repo, env=env)
            before_v1 = storage.total_bytes()
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        after_v1 = storage.total_bytes()
        grew_v1 = after_v1 - before_v1
        # Compression keeps a full upload below raw size.
        if grew_v1 < BIG_FILE_BYTES // 2:
            raise TestFailure(
                f"s3-dedup v1: bucket grew only {fmt_bytes(grew_v1)} — "
                f"expected ≥ {fmt_bytes(BIG_FILE_BYTES // 2)}"
            )
        info(f"  s3-dedup v1: bucket +{fmt_bytes(grew_v1)} (full payload)")

        v2_offset = BIG_FILE_BYTES // 2
        payload_v2 = (
            payload_v1[:v2_offset]
            + b"\xde\xad\xbe\xef\x01\x02\x03\x04"
            + payload_v1[v2_offset + 8 :]
        )
        sha_v2 = sha256_bytes(payload_v2)
        if sha_v2 == sha_v1:
            raise TestFailure("s3-dedup v2: sha256 unchanged after poke")
        (repo / "bigfile.bin").write_bytes(payload_v2)
        with timings.measure(
            "s3-dedup: v2 stage+commit+push (8-byte poke)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            git(["add", "bigfile.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-dedup v2: 8-byte poke"], cwd=repo, env=env)
            git(["push", "origin", "main"], cwd=repo, env=env)
        after_v2 = storage.total_bytes()
        grew_v2 = after_v2 - after_v1
        # CDC re-uploads a handful of ~64 KiB chunks plus a shard; 2 MiB is
        # slack for chunk-boundary variance.
        v2_max_growth = 2 * 1024 * 1024
        if grew_v2 > v2_max_growth:
            raise TestFailure(
                f"s3-dedup v2: bucket grew by {fmt_bytes(grew_v2)} for an "
                f"8-byte edit — expected ≤ {fmt_bytes(v2_max_growth)} "
                "(CDC chunk-level dedup not engaging)"
            )
        info(f"  s3-dedup v2: bucket +{fmt_bytes(grew_v2)} (8-byte edit)")

        v3_offset = BIG_FILE_BYTES // 4
        v3_len = 1024 * 1024
        v3_region = deterministic_payload(v3_len, seed=b"s3-dedup-v3-region")
        payload_v3 = (
            payload_v2[:v3_offset] + v3_region + payload_v2[v3_offset + v3_len :]
        )
        sha_v3 = sha256_bytes(payload_v3)
        if sha_v3 in (sha_v1, sha_v2):
            raise TestFailure("s3-dedup v3: sha256 collision with earlier rev")
        (repo / "bigfile.bin").write_bytes(payload_v3)
        with timings.measure(
            "s3-dedup: v3 stage+commit+push (1 MiB region)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            git(["add", "bigfile.bin"], cwd=repo, env=env)
            git(["commit", "-m", "s3-dedup v3: 1 MiB region"], cwd=repo, env=env)
            git(["push", "origin", "main"], cwd=repo, env=env)
        after_v3 = storage.total_bytes()
        grew_v3 = after_v3 - after_v2
        # ~1 MiB of new content plus boundary chunks.
        v3_max_growth = 3 * 1024 * 1024
        if grew_v3 > v3_max_growth:
            raise TestFailure(
                f"s3-dedup v3: bucket grew by {fmt_bytes(grew_v3)} for a "
                f"1 MiB edit — expected ≤ {fmt_bytes(v3_max_growth)}"
            )
        info(f"  s3-dedup v3: bucket +{fmt_bytes(grew_v3)} (1 MiB edit)")

        # raw_bytes sums the repo's distinct registered files (≈ 3× here);
        # stored_bytes is chunk-deduped on-disk xorb cost (≈ 1×).
        usage = fetch_repo_usage(
            server,
            token=admin_jwt,
            owner=E2E_OWNER,
            repo=E2E_REPO_2,
        )
        info(f"  s3-dedup: /v1/usage repo response = {usage}")
        raw = int(usage["raw_bytes"])
        stored = int(usage["stored_bytes"])
        savings = int(usage["dedup_savings_bytes"])

        # Loose floor: only "three revisions counted distinctly" matters.
        if raw < 2 * BIG_FILE_BYTES:
            raise TestFailure(
                f"s3-dedup: /v1/usage raw_bytes={raw} < expected ≥ "
                f"{2 * BIG_FILE_BYTES} — accounting isn't counting the "
                "three revisions distinctly"
            )
        if stored > BIG_FILE_BYTES * 3 // 2:
            raise TestFailure(
                f"s3-dedup: /v1/usage stored_bytes={stored} > expected "
                f"≤ {BIG_FILE_BYTES * 3 // 2} — chunk-level dedup isn't "
                "reaching the accounting layer"
            )
        if savings != raw - stored:
            raise TestFailure(
                f"s3-dedup: /v1/usage dedup_savings_bytes={savings} != "
                f"raw_bytes - stored_bytes = {raw - stored}"
            )
        if savings <= 0:
            raise TestFailure(
                f"s3-dedup: /v1/usage dedup_savings_bytes={savings} ≤ 0 — "
                "no savings recorded across three revisions"
            )
        info(
            f"  s3-dedup: raw={fmt_bytes(raw)}, stored={fmt_bytes(stored)}, "
            f"savings={fmt_bytes(savings)} "
            f"({100.0 * savings / raw:.1f}% of raw)"
        )

        # HEAD (v3) must reassemble from chunks shared with v1/v2.
        clone_path, clone_env, _ = init_repo_for_clone(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_2,
            name="s3-dedup-clone",
        )
        with timings.measure(
            "s3-dedup: cold clone HEAD (v3)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "bigfile.bin",
            expected_sha=sha_v3,
            expected_size=BIG_FILE_BYTES,
            label="s3-dedup:clone:v3",
        )
    finally:
        server.stop()
