#!/usr/bin/env python3
"""End-to-end test for git-bale + baleforgit-server with the S3 blob store.

Drives the release `git-bale` binary against a `baleforgit-server` + sshd
container that uses a sidecar MinIO container as its `BlobStore`, in place
of the local filesystem store the default harness (run.py) uses.

Phases:
    s3-basic              push + cold-clone roundtrip (proves S3 is wired up)
    s3-dedup              CDC chunk-level dedup against MinIO object counts
    s3-failure-kill       server killed mid-upload while writing to MinIO
    s3-failure-conndrop   server↔MinIO connection dropped mid-PUT via TcpProxy

This is the focused S3 suite — it doesn't re-run the full fs phase set.
Run the broader user-flow / adversarial coverage via `python3 tests/e2e/run.py`.

Prereqs (same as run.py):
    - podman or docker on PATH, with the daemon/VM running
    - git, ssh, ssh-keygen on PATH
    - the release `target/release/git-bale` binary (or pass --git-bale)

First run pulls quay.io/minio/minio (~120 MB), cached thereafter.
"""

from __future__ import annotations

import argparse
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Callable, Optional

from run import (
    DEFAULT_IMAGE_TAG,
    REPO_ROOT,
    TestFailure,
    Timings,
    build_image,
    detect_runtime,
    die,
    image_exists,
    info,
    setup_client,
    skip,
    tool_on_path,
    warn,
)
from s3lib import (
    MinioGuard,
    Network,
    phase_s3_basic,
    phase_s3_dedup,
    phase_s3_failure_connection_drop_mid_upload,
    phase_s3_failure_server_kill_mid_upload,
)


PhaseFn = Callable[[], None]


def resolve_git_bale(explicit: Optional[str]) -> Path:
    """Same lookup order as run.py.resolve_git_bale, copied so this script
    doesn't depend on an internal name. The release binary lives at
    target/release/git-bale by default; --git-bale or $GIT_BALE_BIN
    overrides."""
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            die(f"--git-bale: {p} is not a file")
        return p
    env_path = (Path(__file__).resolve().parents[2] / "target" / "release" / "git-bale")
    if env_path.is_file():
        return env_path
    die(
        "could not find git-bale binary. Pass --git-bale PATH or run "
        "`cargo build --release -p git-bale` first."
    )
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-bale", default=None)
    parser.add_argument("--image-tag", default=DEFAULT_IMAGE_TAG)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--keep-tmpdir", action="store_true")
    parser.add_argument(
        "--skip", action="append", default=[],
        help="Phase name(s) to skip (repeat for multiple).",
    )
    args = parser.parse_args()

    info(f"platform: {platform.system()} {platform.release()} ({platform.machine()})")
    info(f"repo root: {REPO_ROOT}")
    info("storage backend: S3 (MinIO sidecar)")

    for tool in ("git", "ssh", "ssh-keygen"):
        if not tool_on_path(tool):
            skip(f"`{tool}` not on PATH (required for SSH transport)")

    git_bale_bin = resolve_git_bale(args.git_bale)
    rt = detect_runtime()

    if not args.no_build:
        build_image(rt, args.image_tag)
    elif not image_exists(rt, args.image_tag):
        die(f"--no-build was passed but image {args.image_tag} doesn't exist")

    tmpdir = Path(tempfile.mkdtemp(prefix="baleforgit-e2e-s3-"))
    work_root = tmpdir / "work"
    work_root.mkdir()
    info(f"work dir: {tmpdir}")

    timings = Timings()
    exit_code = 0
    client = None
    network: Optional[Network] = None
    minio: Optional[MinioGuard] = None
    try:
        client = setup_client(work_root=work_root, git_bale_bin=git_bale_bin)
        ssh_public_key = client.ssh_pub.read_text().strip()
        admin_token_hex = secrets.token_bytes(32).hex()

        # Bring up the per-run network and MinIO sidecar BEFORE any server
        # container — every phase reaches MinIO via the shared network.
        with timings.measure("setup: podman network"):
            network = Network.create(rt)
        with timings.measure("setup: minio sidecar"):
            minio = MinioGuard.start(rt, network)

        common_kwargs = dict(
            timings=timings, rt=rt, image_tag=args.image_tag,
            work_root=work_root, client=client,
            ssh_public_key=ssh_public_key,
            admin_token_hex=admin_token_hex,
            minio=minio, network=network,
        )

        # Phase registry. Plain list (not the g1/g2/g3 grouping run.py uses)
        # because every S3 phase is fully isolated — its own server
        # container, its own BALE_S3_PREFIX subtree of the bucket, its own
        # data_root for meta.db. No cross-phase dependencies.
        registry: dict[str, PhaseFn] = {
            "s3-basic":             lambda: phase_s3_basic(**common_kwargs),
            "s3-dedup":             lambda: phase_s3_dedup(**common_kwargs),
            "s3-failure-kill":      lambda: phase_s3_failure_server_kill_mid_upload(**common_kwargs),
            "s3-failure-conndrop":  lambda: phase_s3_failure_connection_drop_mid_upload(**common_kwargs),
        }
        ordered = list(registry.keys())
        info(f"phase order: {ordered}")

        for name in ordered:
            if name in args.skip:
                info(f"-- skipping phase {name!r} (per --skip)")
                continue
            registry[name]()

        info("ALL CHECKS PASSED")
    except TestFailure as e:
        print(f"\n[e2e-s3][FAIL]\n{e}\n", file=sys.stderr, flush=True)
        # MinIO logs go to its own container; the server logs go through
        # the phase's own try/finally. Surface MinIO logs here for the
        # case where MinIO itself is the problem (rare but possible).
        if minio is not None:
            print("--- minio logs ---", file=sys.stderr, flush=True)
            completed = subprocess.run(
                rt.cmd("logs", minio.container),
                capture_output=True, check=False,
            )
            print(
                completed.stdout.decode("utf-8", "replace")
                + completed.stderr.decode("utf-8", "replace"),
                file=sys.stderr, flush=True,
            )
        exit_code = 1
    except KeyboardInterrupt:
        warn("interrupted")
        exit_code = 130
    except Exception:
        traceback.print_exc()
        exit_code = 2
    finally:
        if minio is not None:
            minio.stop()
        if network is not None:
            network.destroy()
        if client is not None and client.ssh_agent is not None:
            client.ssh_agent.stop()
        timings.print_report()
        if not args.keep_tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        else:
            info(f"keeping work dir: {tmpdir}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
