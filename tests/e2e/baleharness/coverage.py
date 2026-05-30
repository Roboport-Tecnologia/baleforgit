"""Coverage mode (--coverage): instrumented builds + llvm-cov report."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from baleharness.config import COVERAGE_IMAGE_TAG, REPO_ROOT
from baleharness.logutil import TestFailure, die, info, warn
from baleharness.runtime import Runtime, build_image, image_exists

if TYPE_CHECKING:
    # Referenced only in the string annotations of run_s3_coverage_phases.
    from baleharness.client import ClientEnv
    from baleharness.timing import Timings


@dataclass
class CoverageConfig:
    profile_dir: Path  # host dir; bind-mounted as /coverage in containers
    git_bale_bin: Path  # instrumented host-side git-bale
    server_bin_host: Path  # copy of /usr/local/bin/baleforgit-server, podman-cp'd out
    html_out: Path  # llvm-cov show -output-dir target

    @property
    def container_profile_template(self) -> str:
        # %m is the binary hash; %p is the PID. Both required so the many
        # short-lived `git-bale filter-process` PIDs and the long-lived
        # server don't clobber each other.
        return "/coverage/server-%m-%p.profraw"

    @property
    def host_profile_template(self) -> str:
        return str(self.profile_dir / "host-%m-%p.profraw")


def _find_llvm_tool(name: str) -> Optional[Path]:
    # llvm-tools-preview ships its binaries under
    # `<sysroot>/lib/rustlib/<host-triple>/bin/`, not under any path
    # `rustup which` knows about. Resolve via rustc's --print queries.
    try:
        sysroot = subprocess.run(
            ["rustc", "--print", "sysroot"],
            capture_output=True,
            check=False,
            text=True,
        )
        host = subprocess.run(
            ["rustc", "--print", "host-tuple"],
            capture_output=True,
            check=False,
            text=True,
        )
        if sysroot.returncode == 0 and host.returncode == 0:
            candidate = (
                Path(sysroot.stdout.strip())
                / "lib"
                / "rustlib"
                / host.stdout.strip()
                / "bin"
                / name
            )
            if candidate.is_file():
                return candidate
    except FileNotFoundError:
        pass
    p = shutil.which(name)
    return Path(p) if p else None


def build_instrumented_git_bale() -> Path:
    """Build `git-bale` with `-C instrument-coverage` into a dedicated
    target dir so the prod release build isn't clobbered. Returns the
    binary path."""
    target_dir = REPO_ROOT / "target" / "coverage-e2e" / "cargo"
    info("building instrumented git-bale (RUSTFLAGS=-C instrument-coverage)")
    env = os.environ.copy()
    env["RUSTFLAGS"] = "-C instrument-coverage"
    # `--features coverage` enables an explicit __llvm_profile_write_file()
    # call right after fuse_main_real returns, because libfuse-t kills the
    # process by SIGPIPE on macOS unmount teardown before atexit can flush.
    r = subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "-p",
            "git-bale",
            "--features",
            "coverage",
            "--target-dir",
            str(target_dir),
        ],
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )
    if r.returncode != 0:
        raise TestFailure(
            f"instrumented git-bale build failed (exit {r.returncode}). "
            "Stderr was streamed above."
        )
    exe = "git-bale.exe" if os.name == "nt" else "git-bale"
    bin_path = target_dir / "release" / exe
    if not bin_path.is_file():
        raise TestFailure(f"expected instrumented binary at {bin_path}")
    return bin_path.resolve()


def extract_server_bin(rt: Runtime, image_tag: str, dest: Path) -> Path:
    """Copy /usr/local/bin/baleforgit-server out of the built image so
    llvm-cov can read its coverage sections at report time. Built id
    matches the binary the container ran, so .profraw files line up."""
    info(f"extracting server binary from {image_tag} for llvm-cov")
    created = subprocess.run(
        rt.cmd("create", image_tag),
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        raise TestFailure(f"`{rt.exe} create` failed: {created.stderr.strip()}")
    cid = created.stdout.strip()
    try:
        cp = subprocess.run(
            rt.cmd("cp", f"{cid}:/usr/local/bin/baleforgit-server", str(dest)),
            capture_output=True,
            check=False,
            text=True,
        )
        if cp.returncode != 0:
            raise TestFailure(f"`{rt.exe} cp` failed: {cp.stderr.strip()}")
    finally:
        subprocess.run(
            rt.cmd("rm", cid),
            capture_output=True,
            check=False,
        )
    return dest


def setup_coverage(
    rt: Runtime,
    *,
    coverage_dir_arg: Optional[str],
    no_build: bool = False,
) -> CoverageConfig:
    """Build instrumented binaries, build instrumented image, extract the
    server binary, and prepare the host profile dir. The prod image_tag
    is NOT touched — coverage uses its own tag. `no_build` skips both
    the instrumented git-bale build and the image build, but only if
    both artifacts already exist (otherwise we have nothing to run)."""
    if coverage_dir_arg:
        cov_root = Path(coverage_dir_arg).resolve()
    else:
        cov_root = REPO_ROOT / "target" / "coverage-e2e"
    cov_root.mkdir(parents=True, exist_ok=True)
    profile_dir = cov_root / "profiles"
    # Wipe stale .profraw from previous runs — otherwise the merged
    # profdata would conflate runs and llvm-cov would complain about
    # mismatched build ids.
    if profile_dir.exists():
        shutil.rmtree(profile_dir)
    profile_dir.mkdir(parents=True)
    # World-writable so the container's `bale` user (uid 10001, mapped
    # through rootless podman) can write profraws to the bind-mount.
    # Bind-mounted into every container so the in-container `bale` user can
    # write .profraw files. Windows ACLs differ and coverage mode isn't
    # supported there, so guard the POSIX chmod.
    if os.name != "nt":
        os.chmod(profile_dir, 0o777)
    html_out = cov_root / "html"
    if html_out.exists():
        shutil.rmtree(html_out)

    exe = "git-bale.exe" if os.name == "nt" else "git-bale"
    existing_git_bale = (
        REPO_ROOT / "target" / "coverage-e2e" / "cargo" / "release" / exe
    )
    server_bin_host_path = cov_root / "baleforgit-server"
    if no_build:
        if not existing_git_bale.is_file():
            die(
                "--no-build with --coverage: instrumented git-bale missing "
                f"at {existing_git_bale}"
            )
        if not image_exists(rt, COVERAGE_IMAGE_TAG):
            die("--no-build with --coverage: coverage image not built yet")
        git_bale_bin = existing_git_bale.resolve()
        if not server_bin_host_path.is_file():
            # Image is here, just need to re-extract the binary.
            extract_server_bin(rt, COVERAGE_IMAGE_TAG, server_bin_host_path)
        server_bin_host = server_bin_host_path
    else:
        git_bale_bin = build_instrumented_git_bale()
        build_image(rt, COVERAGE_IMAGE_TAG, coverage=True)
        server_bin_host = extract_server_bin(
            rt,
            COVERAGE_IMAGE_TAG,
            server_bin_host_path,
        )
    return CoverageConfig(
        profile_dir=profile_dir,
        git_bale_bin=git_bale_bin,
        server_bin_host=server_bin_host,
        html_out=html_out,
    )


def run_s3_coverage_phases(
    *,
    timings: "Timings",
    rt: "Runtime",
    image_tag: str,
    work_root: Path,
    client: "ClientEnv",
    ssh_public_key: str,
    admin_token_hex: str,
    skip: set,
    only: set = frozenset(),
) -> None:
    """Run s3-basic + s3-dedup with the same instrumented image so
    bale-server-storage-s3 shows up in the coverage report.

    Imported lazily because `s3lib` imports from `run` — putting the
    import at module top would deadlock the load order.

    s3-failure-kill / s3-failure-conndrop are NOT run in coverage mode
    for the same reason as the fs failure-* phases: SIGKILL prevents the
    LLVM atexit hook from flushing .profraw."""
    s3_phase_names = ("s3-basic", "s3-dedup")
    # Bail before the MinIO sidecar even starts if --skip/--only leave no
    # S3 phase to run — otherwise we'd pay for a network + container we
    # never use.
    if not [
        n for n in s3_phase_names if n not in skip and not (only and n not in only)
    ]:
        info("-- skipping S3 coverage setup (no S3 phases selected)")
        return
    from s3lib import (
        MinioGuard,
        Network,
        phase_s3_basic,
        phase_s3_dedup,
    )
    # All container-launching code shares one coverage-state global
    # (baleharness.covstate), so no cross-module mirroring is needed.

    network: Optional["Network"] = None
    minio: Optional["MinioGuard"] = None
    try:
        with timings.measure("s3-setup: podman network"):
            network = Network.create(rt)
        with timings.measure("s3-setup: minio sidecar"):
            minio = MinioGuard.start(rt, network)

        common = dict(
            timings=timings,
            rt=rt,
            image_tag=image_tag,
            work_root=work_root,
            client=client,
            ssh_public_key=ssh_public_key,
            admin_token_hex=admin_token_hex,
            minio=minio,
            network=network,
        )
        phases: list[tuple[str, Callable[[], None]]] = [
            ("s3-basic", lambda: phase_s3_basic(**common)),
            ("s3-dedup", lambda: phase_s3_dedup(**common)),
        ]
        for name, fn in phases:
            if name in skip:
                info(f"-- skipping phase {name!r} (per --skip)")
                continue
            if only and name not in only:
                info(f"-- skipping phase {name!r} (not in --only)")
                continue
            fn()
    finally:
        if minio is not None:
            minio.stop()
        if network is not None:
            network.destroy()


def generate_coverage_report(cov: CoverageConfig) -> None:
    """Merge profraws + render HTML. Best-effort: any failure here
    warns but does NOT flip the test exit code, since we want phase
    results to surface even if the llvm tooling is broken."""
    profraws = sorted(cov.profile_dir.glob("*.profraw"))
    if not profraws:
        warn(
            "coverage: no .profraw files found — instrumented build broken? "
            f"({cov.profile_dir})"
        )
        return
    info(f"coverage: merging {len(profraws)} profraw files")
    llvm_profdata = _find_llvm_tool("llvm-profdata")
    llvm_cov = _find_llvm_tool("llvm-cov")
    if llvm_profdata is None or llvm_cov is None:
        warn(
            "coverage: llvm-profdata / llvm-cov not found. Install with:\n"
            "    rustup component add llvm-tools-preview\n"
            f"  raw profraws kept under: {cov.profile_dir}"
        )
        return
    profdata = cov.profile_dir / "merged.profdata"
    merge = subprocess.run(
        [
            str(llvm_profdata),
            "merge",
            "-sparse",
            *[str(p) for p in profraws],
            "-o",
            str(profdata),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if merge.returncode != 0:
        warn(
            f"coverage: llvm-profdata merge failed (exit {merge.returncode}):\n"
            f"{merge.stderr}"
        )
        return
    cov.html_out.mkdir(parents=True, exist_ok=True)
    show = subprocess.run(
        [
            str(llvm_cov),
            "show",
            f"-instr-profile={profdata}",
            "-format=html",
            f"-output-dir={cov.html_out}",
            # /src/* paths come from the Dockerfile build stage's WORKDIR.
            # Remap to the host repo root so llvm-cov can find sources.
            f"-path-equivalence=/src,{REPO_ROOT}",
            "-ignore-filename-regex=(/\\.cargo/|/rustc/|/registry/|/\\.rustup/)",
            # First positional is the "main" binary; -object adds more.
            str(cov.git_bale_bin),
            "-object",
            str(cov.server_bin_host),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if show.returncode != 0:
        warn(f"coverage: llvm-cov show failed (exit {show.returncode}):\n{show.stderr}")
        return
    info(f"coverage report: {cov.html_out / 'index.html'}")
