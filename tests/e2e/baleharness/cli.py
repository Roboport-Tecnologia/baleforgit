"""Full end-to-end test for git-bale + baleforgit-server.

Drives the release `git-bale` binary against a single bundled podman
container that runs both `baleforgit-server` and `openssh-server`. The
test pushes and clones over SSH (the production-shaped transport for
both git operations and the Bale forge-auth handshake), exercises a wide
range of user operations on a 35 MB Bale-tracked binary, verifies file
integrity after every operation, verifies the `/v1/usage/...` API
numbers against the on-disk storage, walks adversarial cases (wrong
token, tampered xorb on disk, quota exceeded, missing auth), and prints
per-phase timing + throughput.

Not invoked by `cargo test` — run it directly:

    python3 tests/e2e/run.py

See `tests/e2e/README.md` for prereqs and flags."""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import secrets
import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Callable, Optional

from baleharness.client import ClientEnv, setup_client
from baleharness.config import (
    COVERAGE_IMAGE_TAG,
    DEFAULT_IMAGE_TAG,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_REPO_3,
    E2E_REPO_CHURN,
    E2E_REPO_GC1,
    E2E_REPO_GC2,
    E2E_REPO_COLD_A,
    E2E_REPO_COLD_B,
    E2E_REPO_COLD_STAGED_A,
    E2E_REPO_COLD_STAGED_B,
    E2E_REPO_COMPRESS,
    E2E_REPO_GC3,
    E2E_REPO_MERGE_A,
    E2E_REPO_MR_A,
    E2E_REPO_MR_B,
    E2E_REPO_MR_C,
    E2E_REPO_OFFLINE,
    E2E_REPO_SPILL,
    E2E_USER,
    JWT_TTL_YEARS,
    REPO_ROOT,
)
from baleharness.coverage import (
    CoverageConfig,
    generate_coverage_report,
    run_s3_coverage_phases,
    setup_coverage,
)
from baleharness.covstate import set_coverage
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, die, info, skip, warn
from baleharness.phases.adversarial import (
    phase_adversarial_quota_admin,
    phase_adversarial_quota_exceeded,
    phase_adversarial_shard_stage_quota,
    phase_adversarial_tampered_xorb,
    phase_adversarial_upload_guards,
    phase_adversarial_wrong_token,
)
from baleharness.phases.anon import phase_anonymous_public_clone
from baleharness.phases.compression import phase_compression_schemes
from baleharness.phases.coverage_phases import (
    phase_authz_http_coverage,
    phase_https_origin_coverage,
    phase_otlp_telemetry,
    phase_postgres_coverage,
)
from baleharness.phases.dedup_shard import phase_global_dedup_shard
from baleharness.phases.failure import (
    phase_failure_connection_drop_mid_upload,
    phase_failure_fs_concurrent_put,
    phase_failure_fs_write_fail,
    phase_failure_s3_conndrop,
    phase_failure_s3_presign_unreachable,
    phase_failure_server_kill_mid_upload,
    phase_failure_transient_db,
)
from baleharness.phases.gc import (
    phase_gc_abandon_checkout,
    phase_gc_keeps_unpushed,
    phase_gc_mixed,
)
from baleharness.phases.local import (
    phase_local_basic,
    phase_local_cache_hit_gc_race,
    phase_local_clean_gc_race,
    phase_local_concurrent_stress,
    phase_local_gc_abandon,
    phase_local_gc_grace,
    phase_local_prune_shared,
    phase_local_shared_dedup,
)
from baleharness.phases.mount import (
    phase_mount_diff,
    phase_mount_diff_mixed,
    phase_mount_edge_cases,
    phase_mount_rev,
)
from baleharness.phases.progress import phase_progress_demo
from baleharness.phases.push_pending import (
    phase_push_pending_corrupt_staging,
    phase_push_pending_noop,
)
from baleharness.phases.resync import phase_resync_after_cas_wipe
from baleharness.phases.scenario import (
    phase_basic_user_ops,
    phase_big_file_dedup,
    phase_browser_file_download,
    phase_clone_and_verify_history,
    phase_cold_cache_repush,
    phase_cold_cache_repush_staged,
    phase_dedup_duplicate_file,
    phase_multi_remote_push,
    phase_offline_and_restart,
    phase_offline_no_network,
    phase_push_idempotency,
    phase_repeated_churn,
    phase_spilled_clean,
    phase_term_list_merge,
    phase_usage_api,
)
from baleharness.phases.track import phase_track
from baleharness.proc import pick_free_port, tool_on_path
from baleharness.registry import PHASE_GROUPS_ORDER, order_within_group
from baleharness.runtime import build_image, detect_runtime, image_exists
from baleharness.pgbackend import (
    ActivePostgresBackend,
    PostgresGuard,
    set_active_postgres_backend,
)
from baleharness.s3backend import (
    ActiveS3Backend,
    MinioGuard,
    Network,
    set_active_s3_backend,
)
from baleharness.server import ServerHandle, start_container
from baleharness.state import STATE_FILE, load_state, save_state
from baleharness.timing import Timings


def resolve_git_bale(arg_path: Optional[str]) -> Path:
    candidates: list[Path] = []
    if arg_path:
        candidates.append(Path(arg_path))
    env_override = os.environ.get("GIT_BALE_BIN")
    if env_override:
        candidates.append(Path(env_override))
    exe = "git-bale.exe" if os.name == "nt" else "git-bale"
    candidates.append(REPO_ROOT / "target" / "release" / exe)
    for c in candidates:
        if c.is_file():
            info(f"using git-bale binary: {c}")
            return c.resolve()
    looked = "\n".join(f"  - {c}" for c in candidates)
    die(
        "could not locate a release `git-bale` binary. This test does NOT "
        "build via cargo — produce the binary first:\n"
        "    cargo build --release -p git-bale\n"
        f"then re-run, or pass --git-bale=PATH. Tried:\n{looked}"
    )
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-bale", default=None)
    parser.add_argument("--image-tag", default=DEFAULT_IMAGE_TAG)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--keep-tmpdir", action="store_true")
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help="Phase name(s) to skip (repeat the flag for multiple).",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="Run ONLY the named phase(s) (repeat the flag for multiple); "
        "every other phase is skipped. Composes with --skip (a phase named "
        "in both is skipped). Handy for iterating on one phase without "
        "listing every other phase after --skip.",
    )
    parser.add_argument(
        "--order",
        choices=["forward", "reverse", "random"],
        default="forward",
        help="Within-group phase order. Group order itself is always fixed.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for --order=random (so a failing matrix run reproduces).",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Use this path as the work directory instead of mkdtemp, and "
        "leave it intact on exit. Writes .e2e_state.json with secrets + "
        "rev_state so a follow-up --reuse-from run can continue.",
    )
    parser.add_argument(
        "--reuse-from",
        default=None,
        help="Reuse the data dir + git-home + secrets from a prior run "
        "(must have been launched with --state-dir). Only `read_only` "
        "phases are eligible to run in this mode.",
    )
    parser.add_argument(
        "--backend",
        choices=["fs", "s3"],
        default="fs",
        help="Blob store backend for every server in the run. 'fs' (default) "
        "uses the container's local data dir; 's3' brings up a MinIO sidecar "
        "on a per-run podman network and runs the WHOLE phase registry against "
        "it (each server scoped to its own bucket prefix). Mutually exclusive "
        "with --coverage and --reuse-from.",
    )
    parser.add_argument(
        "--meta",
        choices=["sqlite", "postgres"],
        default="sqlite",
        help="Metadata store for every server in the run. 'sqlite' (default) "
        "uses the container's local meta.db; 'postgres' brings up a Postgres "
        "sidecar on the per-run podman network and runs the WHOLE phase "
        "registry against it (each server scoped to its own database, the "
        "metadata analogue of the --backend s3 per-data_root bucket prefix). "
        "Composes with --backend. Mutually exclusive with --reuse-from (the "
        "sidecar is torn down at end of run).",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Build instrumented binaries (-C instrument-coverage) for both "
        "git-bale and the server, collect .profraw files into the "
        "coverage dir, and generate an HTML report at teardown. "
        "Builds use a separate target dir and image tag so the prod "
        "release/stripped path is left intact.",
    )
    parser.add_argument(
        "--coverage-dir",
        default=None,
        help="Where to put coverage profiles + the HTML report. Defaults "
        "to <repo>/target/coverage-e2e/. Implies --coverage.",
    )
    args = parser.parse_args()
    if args.coverage_dir and not args.coverage:
        args.coverage = True

    if args.reuse_from and args.state_dir:
        die("--reuse-from and --state-dir are mutually exclusive")

    if args.backend == "s3":
        # Coverage runs its own MinIO sidecar for the bespoke s3-* phases;
        # reuse-from would need bucket state we tear down at end of run.
        if args.coverage:
            die("--backend s3 and --coverage are mutually exclusive")
        if args.reuse_from:
            die(
                "--backend s3 can't --reuse-from: the MinIO bucket is torn "
                "down at end of run, so its xorbs aren't there to reuse."
            )

    if args.meta == "postgres":
        # Coverage's bespoke phases stand up their own containers without the
        # global backend; postgres metadata adds little there and complicates
        # the SIGKILL-skip logic. reuse-from would need the sidecar's database,
        # which is torn down at end of run.
        if args.coverage:
            die("--meta postgres and --coverage are mutually exclusive")
        if args.reuse_from:
            die(
                "--meta postgres can't --reuse-from: the Postgres sidecar is "
                "torn down at end of run, so its metadata isn't there to reuse."
            )

    info(f"platform: {platform.system()} {platform.release()} ({platform.machine()})")
    info(f"repo root: {REPO_ROOT}")
    info(f"phase order: {args.order}")
    if args.reuse_from:
        info(f"reusing state from: {args.reuse_from}")

    for tool in ("git", "ssh", "ssh-keygen"):
        if not tool_on_path(tool):
            skip(f"`{tool}` not on PATH (required for SSH transport)")

    rt = detect_runtime()

    # Coverage mode rebuilds both binaries with -C instrument-coverage, uses
    # a separate image tag, and arms cov so start_container bind-mounts
    # the profile dir into every server container. The prod (default) path
    # is unchanged.
    image_tag = args.image_tag
    cov: Optional[CoverageConfig] = None
    if args.coverage:
        if args.image_tag != DEFAULT_IMAGE_TAG:
            die(
                "--coverage manages its own image tag; --image-tag is ignored. "
                "Remove one of the two."
            )
        if args.git_bale:
            die("--coverage builds its own instrumented git-bale; remove --git-bale.")
        cov = setup_coverage(
            rt,
            coverage_dir_arg=args.coverage_dir,
            no_build=args.no_build,
        )
        set_coverage(cov)
        git_bale_bin = cov.git_bale_bin
        image_tag = COVERAGE_IMAGE_TAG
        # Host-side processes (git, git-bale spawned by git, the pre-push
        # hook) inherit os.environ unless a call site builds an explicit
        # env dict — and the ones that do (`ClientEnv.make_env`) start
        # from `os.environ.copy()`, so this propagates.
        os.environ["LLVM_PROFILE_FILE"] = cov.host_profile_template
        info(f"coverage: profile dir = {cov.profile_dir}")
        info(f"coverage: report will be at {cov.html_out / 'index.html'}")
        # The failure-* phases SIGKILL the server (or kill a sidecar
        # container) — the LLVM atexit hook can't flush profraws on
        # SIGKILL, and these paths are exercised by other phases anyway.
        # Skip them unless the user opted in via --no-skip-failure-phases
        # (not exposed; reorder the if to override).
        for name in ("failure-kill", "failure-conndrop", "failure-dbbusy"):
            if name not in args.skip:
                args.skip.append(name)
        info(
            "coverage: auto-skipping failure-kill / -conndrop / -dbbusy "
            "(server SIGKILL drops profraws)"
        )
    else:
        git_bale_bin = resolve_git_bale(args.git_bale)
        if not args.no_build:
            build_image(rt, image_tag)
        elif not image_exists(rt, image_tag):
            die(f"--no-build was passed but image {image_tag} doesn't exist")

    # Resolve the on-disk layout. With --reuse-from the data_root + git-home
    # already exist and must be left alone; with --state-dir we own the path
    # and create the per-run subdirs inside it; otherwise it's a private
    # mkdtemp.
    rng_seed = args.seed if args.seed is not None else secrets.randbits(64)
    rng = random.Random(rng_seed)
    if args.order == "random":
        info(f"random seed: {rng_seed}")

    reused: Optional[dict] = None
    delete_tmpdir_on_exit = True
    if args.reuse_from:
        tmpdir = Path(args.reuse_from).resolve()
        if not tmpdir.is_dir():
            die(f"--reuse-from path doesn't exist or isn't a directory: {tmpdir}")
        try:
            reused = load_state(tmpdir)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            die(f"--reuse-from: can't load {tmpdir / STATE_FILE}: {e}")
        # Fresh client work dir under the reused tempdir so each preserved
        # run gets clean client caches even though server state persists.
        work_root = tmpdir / f"work-{secrets.token_hex(3)}"
        work_root.mkdir()
        data_root = tmpdir / "server-data"
        if not data_root.is_dir():
            die(f"--reuse-from: server-data missing under {tmpdir}")
        delete_tmpdir_on_exit = False  # never delete state owned by caller
    elif args.state_dir:
        tmpdir = Path(args.state_dir).resolve()
        tmpdir.mkdir(parents=True, exist_ok=True)
        data_root = tmpdir / "server-data"
        data_root.mkdir(exist_ok=True)
        work_root = tmpdir / "work"
        work_root.mkdir(exist_ok=True)
        delete_tmpdir_on_exit = False
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix="baleforgit-e2e-"))
        data_root = tmpdir / "server-data"
        data_root.mkdir()
        work_root = tmpdir / "work"
        work_root.mkdir()
        delete_tmpdir_on_exit = not args.keep_tmpdir
    info(f"work dir: {tmpdir}")

    if reused is not None:
        jwt_secret_hex = reused["jwt_secret_hex"]
        transfer_secret_hex = reused["transfer_secret_hex"]
        admin_token_hex = reused["admin_token_hex"]
    else:
        jwt_secret_hex = secrets.token_bytes(32).hex()
        transfer_secret_hex = secrets.token_bytes(32).hex()
        admin_token_hex = secrets.token_bytes(32).hex()
    # JWT minted from the same secret the server uses, scoped to the test
    # owner — used by the test itself to call the usage admin endpoints.
    admin_jwt = mint_bale_jwt(
        secret=bytes.fromhex(jwt_secret_hex),
        sub=E2E_USER,
        repo_type="model",
        repo_id=f"{E2E_OWNER}/{E2E_REPO_2}",
        revision="main",
        scope="write",
        ttl_secs=JWT_TTL_YEARS * 365 * 24 * 3600,
    )

    timings = Timings()
    server: Optional[ServerHandle] = None
    client: Optional[ClientEnv] = None
    # S3 and Postgres sidecars share one per-run podman network.
    shared_network: Optional[Network] = None
    s3_minio: Optional[MinioGuard] = None
    pg_guard: Optional[PostgresGuard] = None
    exit_code = 0
    rev_state: dict = {}
    if reused is not None:
        # Seed rev_state from disk so read-only phases (clone, tampered-xorb)
        # know what to verify against.
        rev_state.update(reused.get("rev_state", {}))

    try:
        client = setup_client(work_root=work_root, git_bale_bin=git_bale_bin)
        ssh_public_key = client.ssh_pub.read_text().strip()
        # S3 mode: bring up the shared network + MinIO sidecar BEFORE any
        # container, then arm the process-global backend so every
        # start_container call (the shared one and each phase's) auto-wires
        # itself to MinIO under its own bucket prefix. tmpdir is the prefix
        # anchor — every server's data_root sits under it.
        if args.backend == "s3" or args.meta == "postgres":
            with timings.measure("setup: podman network"):
                shared_network = Network.create(rt)
        if args.backend == "s3":
            info("storage backend: S3 (MinIO sidecar)")
            with timings.measure("setup: minio sidecar"):
                s3_minio = MinioGuard.start(rt, shared_network)
            set_active_s3_backend(
                ActiveS3Backend(
                    minio=s3_minio, network=shared_network, prefix_anchor=tmpdir
                )
            )
        if args.meta == "postgres":
            info("metadata store: Postgres (sidecar)")
            with timings.measure("setup: postgres sidecar"):
                pg_guard = PostgresGuard.start(rt, shared_network)
            set_active_postgres_backend(
                ActivePostgresBackend(
                    guard=pg_guard, network=shared_network, prefix_anchor=tmpdir
                )
            )
        cas_port = pick_free_port()
        ssh_port = pick_free_port()
        with timings.measure("setup: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret_hex,
                transfer_secret_hex=transfer_secret_hex,
                ssh_public_key=ssh_public_key,
                test_repos=[
                    f"{E2E_OWNER}/{E2E_REPO}",
                    f"{E2E_OWNER}/{E2E_REPO_2}",
                    f"{E2E_OWNER}/{E2E_REPO_3}",
                    f"{E2E_OWNER}/{E2E_REPO_SPILL}",
                    f"{E2E_OWNER}/{E2E_REPO_OFFLINE}",
                    f"{E2E_OWNER}/{E2E_REPO_CHURN}",
                    f"{E2E_OWNER}/{E2E_REPO_GC1}",
                    f"{E2E_OWNER}/{E2E_REPO_GC2}",
                    f"{E2E_OWNER}/{E2E_REPO_GC3}",
                    f"{E2E_OWNER}/{E2E_REPO_MR_A}",
                    f"{E2E_OWNER}/{E2E_REPO_MR_B}",
                    f"{E2E_OWNER}/{E2E_REPO_MR_C}",
                    f"{E2E_OWNER}/{E2E_REPO_MERGE_A}",
                    f"{E2E_OWNER}/{E2E_REPO_COLD_A}",
                    f"{E2E_OWNER}/{E2E_REPO_COLD_B}",
                    f"{E2E_OWNER}/{E2E_REPO_COLD_STAGED_A}",
                    f"{E2E_OWNER}/{E2E_REPO_COLD_STAGED_B}",
                    f"{E2E_OWNER}/{E2E_REPO_COMPRESS}",
                ],
                cas_port=cas_port,
                ssh_port=ssh_port,
                admin_token_hex=admin_token_hex,
            )

        # ---- phase registry ------------------------------------------------
        # Each entry: (name, group, read_only, fn). fn is a thunk so we can
        # rebuild and reorder it without re-binding the captured variables.
        # rev_state and `server` are looked up at call time via the enclosing
        # scope, so the offline-restart rebind is visible to later phases.

        def _phase_basic() -> None:
            phase_basic_user_ops(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_multi_remote() -> None:
            phase_multi_remote_push(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_term_merge() -> None:
            phase_term_list_merge(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_cold_repush() -> None:
            phase_cold_cache_repush(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_cold_repush_staged() -> None:
            phase_cold_cache_repush_staged(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_wrong_token() -> None:
            phase_adversarial_wrong_token(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_offline_net() -> None:
            phase_offline_no_network(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                jwt_secret_hex=jwt_secret_hex,
            )

        def _phase_pp_noop() -> None:
            phase_push_pending_noop(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_pp_corrupt() -> None:
            phase_push_pending_corrupt_staging(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_track() -> None:
            phase_track(
                timings=timings,
                client=client,
                work_root=work_root,
            )

        def _phase_compression() -> None:
            phase_compression_schemes(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_spilled() -> None:
            phase_spilled_clean(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_bigfile() -> None:
            nonlocal rev_state
            rev_state = phase_big_file_dedup(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                bale_admin_token=admin_jwt,
            )

        def _phase_usage() -> None:
            phase_usage_api(
                timings=timings,
                server=server,
                bale_admin_token=admin_jwt,
                admin_token_hex=admin_token_hex,
                jwt_secret_hex=jwt_secret_hex,
                rev_state=rev_state,
            )

        def _phase_browser_download() -> None:
            phase_browser_file_download(
                timings=timings,
                server=server,
                rev_state=rev_state,
            )

        def _phase_dedup() -> None:
            phase_dedup_duplicate_file(
                timings=timings,
                server=server,
                rev_state=rev_state,
            )

        def _phase_idempotency() -> None:
            phase_push_idempotency(
                timings=timings,
                server=server,
                rev_state=rev_state,
            )

        def _phase_clone() -> None:
            phase_clone_and_verify_history(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                rev_state=rev_state,
            )

        def _phase_offline_restart() -> None:
            nonlocal server
            server = phase_offline_and_restart(
                timings=timings,
                server=server,
                rt=rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret_hex,
                transfer_secret_hex=transfer_secret_hex,
                client=client,
                ssh_public_key=ssh_public_key,
                work_root=work_root,
                rev_state=rev_state,
                cas_port=cas_port,
                ssh_port=ssh_port,
                admin_token_hex=admin_token_hex,
            )

        def _phase_tampered_xorb() -> None:
            phase_adversarial_tampered_xorb(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                rev_state=rev_state,
            )

        def _phase_mount_rev() -> None:
            phase_mount_rev(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                rev_state=rev_state,
            )

        def _phase_mount_diff() -> None:
            phase_mount_diff(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                rev_state=rev_state,
            )

        def _phase_mount_diff_mixed() -> None:
            phase_mount_diff_mixed(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_mount_edge() -> None:
            phase_mount_edge_cases(
                timings=timings,
                client=client,
                work_root=work_root,
            )

        def _phase_quota() -> None:
            phase_adversarial_quota_exceeded(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_quota_admin() -> None:
            phase_adversarial_quota_admin(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_shard_quota() -> None:
            phase_adversarial_shard_stage_quota(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_upload_guards() -> None:
            phase_adversarial_upload_guards(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_anon() -> None:
            phase_anonymous_public_clone(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_kill() -> None:
            phase_failure_server_kill_mid_upload(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_conndrop() -> None:
            phase_failure_connection_drop_mid_upload(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_dbbusy() -> None:
            phase_failure_transient_db(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_s3_conndrop() -> None:
            phase_failure_s3_conndrop(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_s3_presign_unreachable() -> None:
            phase_failure_s3_presign_unreachable(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_fs_writefail() -> None:
            phase_failure_fs_write_fail(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_fs_cput() -> None:
            phase_failure_fs_concurrent_put(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_progress_demo() -> None:
            phase_progress_demo(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
                # --only progress-demo → the env-driven interactive visual demo;
                # in a normal sweep → fixed, captured-and-asserted variants.
                from_only="progress-demo" in args.only,
            )

        def _phase_resync() -> None:
            phase_resync_after_cas_wipe(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_global_dedup_shard() -> None:
            phase_global_dedup_shard(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_gc_abandon() -> None:
            phase_gc_abandon_checkout(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_gc_keep() -> None:
            phase_gc_keeps_unpushed(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_gc_mixed() -> None:
            phase_gc_mixed(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
            )

        def _phase_churn() -> None:
            # HUGE mode is opt-in and only under `--only churn`, so a normal
            # full sweep never balloons into the stress variant. HUGE_CHURN=N
            # targets ~N minutes of wall-clock (N must be a positive int).
            huge_minutes = 0
            raw = os.environ.get("HUGE_CHURN")
            if "churn" in args.only and raw:
                try:
                    huge_minutes = max(0, int(raw))
                except ValueError:
                    die(f"HUGE_CHURN must be a non-negative integer, got {raw!r}")
            phase_repeated_churn(
                timings=timings,
                server=server,
                client=client,
                work_root=work_root,
                huge_minutes=huge_minutes,
            )

        def _phase_local_basic() -> None:
            phase_local_basic(timings=timings, client=client, work_root=work_root)

        def _phase_local_gc() -> None:
            phase_local_gc_abandon(timings=timings, client=client, work_root=work_root)

        def _phase_local_shared() -> None:
            phase_local_shared_dedup(
                timings=timings, client=client, work_root=work_root
            )

        def _phase_local_prune() -> None:
            phase_local_prune_shared(
                timings=timings, client=client, work_root=work_root
            )

        def _phase_local_race() -> None:
            phase_local_clean_gc_race(
                timings=timings, client=client, work_root=work_root
            )

        def _phase_local_stress() -> None:
            phase_local_concurrent_stress(
                timings=timings, client=client, work_root=work_root
            )

        def _phase_local_cachehit() -> None:
            phase_local_cache_hit_gc_race(
                timings=timings, client=client, work_root=work_root
            )

        def _phase_local_grace() -> None:
            phase_local_gc_grace(timings=timings, client=client, work_root=work_root)

        # name -> (group, read_only, fn)
        REGISTRY: dict[str, tuple[str, bool, Callable[[], None]]] = {
            "basic": ("g1", False, _phase_basic),
            # Two repos on one server: push to origin (A), then to a second
            # remote (B). Independent (own repos + commits), so g1.
            "multi-remote": ("g1", False, _phase_multi_remote),
            # file_terms consistency guard: push F, then inject duplicate terms
            # into its global term list via meta.db so Σterms > |F| (the corrupt
            # shape a per-term merge produced), and assert a cold clone is rejected
            # cleanly by the lookup_file guard instead of panicking the client.
            # Own repo + direct DB fault injection, so g1.
            "term-merge": ("g1", False, _phase_term_merge),
            # Measures whether a cold-cache re-push of content already on the
            # server double-stores it (reads server-side xorb disk growth) — the
            # ground-truth answer to "is it bandwidth or storage being wasted".
            # Own repos, so g1.
            "cold-repush": ("g1", False, _phase_cold_repush),
            # The staged variant: reproduces the reported "modify + commit (don't
            # push) + push to a new remote with a cold cache" path and measures how
            # much of the unchanged prefix gets re-stored. Own repos, so g1.
            "cold-repush-staged": ("g1", False, _phase_cold_repush_staged),
            "wrong-token": ("g1", False, _phase_wrong_token),
            # Routes git-bale's CAS traffic through a counting proxy and asserts
            # only push/pull cross it. Own repo + commits, so g1 (independent).
            "offline-no-network": ("g1", False, _phase_offline_net),
            # push-pending drain edge cases. Own ephemeral client repos against
            # the shared server, never push successfully, so g1 (independent).
            "push-pending-noop": ("g1", False, _phase_pp_noop),
            "push-pending-corrupt": ("g1", False, _phase_pp_corrupt),
            # `git-bale track` .gitattributes editing. Pure-local (no server),
            # own scratch dirs, so g1 (independent).
            "track": ("g1", False, _phase_track),
            # Pushes two compressible files (one stored LZ4, one BG4-LZ4) and
            # downloads them over HTTP, covering the server's xorb decompress
            # arms that the incompressible default payloads never reach. Own
            # repo + commits, so g1 (independent).
            "compression": ("g1", False, _phase_compression),
            "bigfile": ("g2-head", False, _phase_bigfile),
            "usage": ("g2-tail", True, _phase_usage),
            # Dereferences rev_state["repo_path"]/["env"] (the live bigfile
            # client repo) to read the pushed pointer's file id, so — like
            # idempotency — it can't run from a --reuse-from (hence not
            # read_only). Streams 35 MB back through the reconstruction path.
            "browser-download": ("g2-tail", False, _phase_browser_download),
            "dedup": ("g2-tail", False, _phase_dedup),
            # idempotency dereferences rev_state["repo_path"] (the bigfile
            # client repo from the same process), so it can't run from a
            # --reuse-from where rev_state was reconstructed from JSON.
            "idempotency": ("g2-tail", False, _phase_idempotency),
            "clone": ("g2-tail", True, _phase_clone),
            "offline-restart": ("g2-tail", True, _phase_offline_restart),
            "tampered-xorb": ("g2-tail", True, _phase_tampered_xorb),
            # Read-only FUSE mounts of pushed history. Skip cleanly when the
            # host has no libfuse / fuse-t installed.
            "mount-rev": ("g2-tail", True, _phase_mount_rev),
            "mount-diff": ("g2-tail", True, _phase_mount_diff),
            "quota": ("g3", False, _phase_quota),
            # PUT /v1/quotas/{owner} admin endpoint: 404 when disabled, 401 on
            # missing/non-hex/wrong bearer, 204 set+clear, each proven to take
            # effect on a push. Two own containers, g3.
            "quota-admin": ("g3", False, _phase_quota_admin),
            # Isolates upload_shard's delta-quota gate: owner A seeds content
            # unlimited, owner B (capped below it) pushes the same bytes → B's
            # xorbs dedup (no disk growth) so only the shard-stage check can
            # reject. Two owners, own container, g3.
            "shard-quota": ("g3", False, _phase_shard_quota),
            # Direct HTTP negative tests of the upload integrity gate, signed
            # transfer-URL guards, and write-scope enforcement. Own container, g3.
            "upload-guards": ("g3", False, _phase_upload_guards),
            # Public repo cloneable without credentials: the resolver probes the
            # forge anonymously first for op=download and only falls back to
            # `git credential fill` on 401. Own container + mock forge, so g3.
            "anon-public-clone": ("g3", False, _phase_anon),
            # Independent (own repo + commits), so g3 — not read-only because
            # it pushes new history that other phases shouldn't see.
            "mount-diff-mixed": ("g3", False, _phase_mount_diff_mixed),
            # Own repo + commits, forces the clean filter's spill path via a
            # capped BALE_MAX_INLINE_CLEAN. g3 for the same reason as above.
            "spilled-clean": ("g3", False, _phase_spilled),
            # mount/mount-diff arg+diff validation in mount/mod.rs (label
            # collision, empty diff, empty mount, sanitize_label). Own local
            # repo, no server, so g3 (independent).
            "mount-edge": ("g3", False, _phase_mount_edge),
            # Failure-recovery phases each own their own isolated container
            # + data dir, so they can crash/restart the server or block its
            # DB without disturbing earlier phases' state.
            "failure-kill": ("g3", False, _phase_failure_kill),
            "failure-conndrop": ("g3", False, _phase_failure_conndrop),
            "failure-dbbusy": ("g3", False, _phase_failure_dbbusy),
            # Server↔storage drop — only meaningful with a remote blob store,
            # so it self-skips under the fs backend and runs only on --backend s3.
            "failure-s3-conndrop": ("g3", False, _phase_failure_s3_conndrop),
            # Presign host the server can reach but the client can't: checkout
            # must fail fast via the cold-path watchdog, not hang on xet-core's
            # multi-hour retry backoff. S3-only (presigned URLs).
            "failure-s3-presign-unreachable": (
                "g3",
                False,
                _phase_failure_s3_presign_unreachable,
            ),
            # fs BlobStore write_atomic integrity: a forced write failure must
            # leave nothing (no half-write, no tmp leak), then a clean restart
            # recovers; and two concurrent same-content pushes must converge to
            # one stored copy. Both self-skip under --backend s3 (FsBlobStore
            # unused there). Own isolated containers → g3.
            "failure-fs-writefail": ("g3", False, _phase_failure_fs_writefail),
            "failure-fs-cput": ("g3", False, _phase_failure_fs_cput),
            # Disaster recovery: wipe the server CAS, then re-add + force-push
            # to repopulate it. Owns its own isolated container + data dir, so
            # the wipe doesn't touch earlier phases' shared-server state.
            "resync-wipe": ("g3", False, _phase_resync),
            # Server global-dedup shard footer: fetch one from /v1/chunks, plant
            # it in the client's xet shard-cache, and push again so the upload
            # session ingests it via read_all_truncated_hashes (the path that
            # underflowed on file_lookup_offset=0). Own container + repo, g3.
            "global-dedup-shard": ("g3", False, _phase_global_dedup_shard),
            # gc staging reconciliation. Each owns its own bare repo + commits,
            # so g3 — not read-only (they push new history).
            "gc-abandon-checkout": ("g3", False, _phase_gc_abandon),
            "gc-keeps-unpushed": ("g3", False, _phase_gc_keep),
            "gc-mixed": ("g3", False, _phase_gc_mixed),
            # Sustained churn: many edit→commit→push rounds against ONE reused
            # repo, with cold clones at several rounds that reconstruct the full
            # accumulated history. Integrity + server health checked every push.
            # Owns its own bare repo + commits, so g3 (not read-only).
            "churn": ("g3", False, _phase_churn),
            # Validates the upload progress indicator: a normal sweep pushes
            # fixed variants and asserts the captured summary; `--only
            # progress-demo` instead runs the env-driven interactive visual demo.
            "progress-demo": ("g3", False, _phase_progress_demo),
            # Fully-local (no-server) mode: init-local → add + commit a big file
            # → fresh checkout reconstructs from .git/bale/store. No server, so g3.
            "local-basic": ("g3", False, _phase_local_basic),
            "local-gc-abandon": ("g3", False, _phase_local_gc),
            "local-shared-dedup": ("g3", False, _phase_local_shared),
            "local-prune-shared": ("g3", False, _phase_local_prune),
            # Demonstrates the clean-vs-gc data race: gc fires in the window
            # between xorb written and marker written, sweeping the only copy.
            # Fails until gc respects the store lock (Task 15).
            "local-clean-gc-race": ("g3", False, _phase_local_race),
            # Natural-timing concurrent stress: per-repo add+gc races and shared
            # add+prune races under no artificial delay. Proves no deadlock and
            # no data loss under real contention.
            "local-concurrent-stress": ("g3", False, _phase_local_stress),
            # Cache-hit clean vs gc data race: a re-add that hits the clean-cache
            # must hold the store lock across the emit window, otherwise gc can
            # sweep the object copy between the cache-hit check and git's index
            # update. Fails without the lock-before-cache-load fix.
            "local-cache-hit-gc-race": ("g3", False, _phase_local_cachehit),
            "local-gc-grace": ("g3", False, _phase_local_grace),
        }

        # Build the within-group lists in declaration order, then apply
        # --order per group.
        by_group: dict[str, list[str]] = {g: [] for g in PHASE_GROUPS_ORDER}
        for name, (g, _ro, _fn) in REGISTRY.items():
            by_group[g].append(name)

        ordered: list[str] = []
        for g in PHASE_GROUPS_ORDER:
            # g2-head only ever has bigfile, but be defensive: never shuffle
            # the head group's contents — it exists precisely to pin order.
            if g == "g2-head":
                ordered.extend(by_group[g])
            else:
                ordered.extend(order_within_group(by_group[g], args.order, rng))

        in_reuse = reused is not None
        info(f"phase order resolved: {ordered}")

        # --only is an allowlist. Validate its names against the full phase
        # set (REGISTRY + the coverage-only phases) so a typo fails loudly
        # instead of silently running nothing.
        coverage_only_phases = {
            "s3-basic",
            "s3-dedup",
            "authz-http",
            "https-origin",
            "otlp",
            "postgres",
        }
        valid_phase_names = set(REGISTRY) | coverage_only_phases
        unknown_only = [n for n in args.only if n not in valid_phase_names]
        if unknown_only:
            die(
                f"--only: unknown phase name(s): {', '.join(unknown_only)}.\n"
                f"valid phases: {', '.join(sorted(valid_phase_names))}"
            )
        if args.only:
            info(f"--only active: running only {args.only}")

        def filtered_out(name: str) -> Optional[str]:
            """Reason `name` is excluded by --skip / --only, or None to run it."""
            if name in args.skip:
                return "per --skip"
            if args.only and name not in args.only:
                return "not in --only"
            return None

        for name in ordered:
            group, read_only, fn = REGISTRY[name]
            reason = filtered_out(name)
            if reason is not None:
                # Don't log the --only exclusion per phase — that's a line for
                # every other phase, which is exactly the noise --only avoids.
                if reason == "per --skip":
                    info(f"-- skipping phase {name!r} ({reason})")
                continue
            if in_reuse and not read_only:
                info(f"-- skipping phase {name!r} (not read-only in --reuse-from)")
                continue
            if group == "g2-tail" and not rev_state:
                info(f"-- skipping phase {name!r} (no rev_state yet)")
                continue
            fn()

        # Coverage mode also exercises the S3 backend and the HttpAuthz
        # path so the report includes bale-server-storage-s3 and
        # bale-server-authz-http. The fs server is stopped first so its
        # atexit flushes profraws (otherwise the still-running container
        # would only flush in the outer `finally`, well after the extra
        # phases have run). Each extra phase stands up its own
        # containers and tears them down itself.
        if cov is not None and not in_reuse:
            if server is not None:
                info("stopping fs server before extra coverage phases")
                server.stop()
                server = None
            run_s3_coverage_phases(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
                skip=set(args.skip),
                only=set(args.only),
            )
            extra_kwargs = dict(
                timings=timings,
                rt=rt,
                image_tag=image_tag,
                work_root=work_root,
                client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )
            for cov_name, cov_fn in (
                ("authz-http", phase_authz_http_coverage),
                ("https-origin", phase_https_origin_coverage),
                ("otlp", phase_otlp_telemetry),
                ("postgres", phase_postgres_coverage),
            ):
                reason = filtered_out(cov_name)
                if reason is not None:
                    info(f"-- skipping phase {cov_name!r} ({reason})")
                    continue
                cov_fn(**extra_kwargs)

        info("ALL CHECKS PASSED")
    except TestFailure as e:
        print(f"\n[e2e][FAIL]\n{e}\n", file=sys.stderr, flush=True)
        if server is not None:
            print("--- server logs ---", file=sys.stderr, flush=True)
            print(server.logs(), file=sys.stderr, flush=True)
        exit_code = 1
    except KeyboardInterrupt:
        warn("interrupted")
        exit_code = 130
    except Exception:
        traceback.print_exc()
        exit_code = 2
    finally:
        if server is not None:
            server.stop()
        if client is not None and client.ssh_agent is not None:
            client.ssh_agent.stop()
        # Note: per-phase containers (the offline-restart one and the quota
        # one) are stopped inside their own phases via try/finally. We
        # deliberately do NOT do a blanket `rm -f` on every container
        # matching CONTAINER_NAME_PREFIX — that would clobber concurrent
        # runs sharing the host (CI matrices, two devs on the same box).
        # S3 / Postgres teardown comes after every server (shared + per-phase)
        # is down, since a live container attached to the network blocks its
        # removal. The shared network is destroyed last, once both sidecars are
        # gone.
        set_active_s3_backend(None)
        set_active_postgres_backend(None)
        if s3_minio is not None:
            s3_minio.stop()
        if pg_guard is not None:
            pg_guard.stop()
        if shared_network is not None:
            shared_network.destroy()
        timings.print_report()
        if cov is not None:
            # Best-effort: don't let a broken llvm install mask phase results.
            try:
                generate_coverage_report(cov)
            except Exception as e:
                warn(f"coverage report generation raised: {e}")
        # Persist state for a follow-up --reuse-from run (only when we own
        # the path: explicit --state-dir, or --reuse-from itself updating
        # its source. In a plain --reuse-from run we don't write — the
        # caller's stash should stay frozen as the canonical reference.)
        if exit_code == 0 and args.state_dir and rev_state:
            save_state(
                tmpdir,
                jwt_secret_hex=jwt_secret_hex,
                transfer_secret_hex=transfer_secret_hex,
                admin_token_hex=admin_token_hex,
                rev_state=rev_state,
            )
            info(f"wrote {tmpdir / STATE_FILE}")
        if delete_tmpdir_on_exit:
            shutil.rmtree(tmpdir, ignore_errors=True)
        else:
            info(f"keeping work dir: {tmpdir}")
    return exit_code
