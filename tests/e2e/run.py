#!/usr/bin/env python3
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

See `tests/e2e/README.md` for prereqs and flags.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import random
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE_TAG = "baleforgit-server-e2e:latest"
COVERAGE_IMAGE_TAG = "baleforgit-server-e2e-coverage:latest"
HEALTHZ_TIMEOUT_S = 60
SSH_READY_TIMEOUT_S = 60
CONTAINER_NAME_PREFIX = "baleforgit-e2e"
JWT_TTL_YEARS = 100
BIG_FILE_BYTES = 35 * 1024 * 1024  # 35 MB (~547 chunks at 64 KiB target).
SMALL_FILE_BYTES = 8 * 1024
GC_PAYLOAD_BYTES = 256 * 1024  # a handful of CDC chunks → real xorbs/shards staged
# The clean filter holds payloads in RAM up to a 4 GiB default, so no realistic
# e2e file ever spills to a tmpfile. The spilled-clean phase caps the threshold
# via BALE_MAX_INLINE_CLEAN and pushes a file above it to drive `handle_clean`'s
# tmpfile branch + the file-backed `clean_cache::verify_chunks` path.
SPILL_INLINE_THRESHOLD = 1024 * 1024  # 1 MiB
# Above the threshold, not a 1 MiB multiple (partial trailing chunk), and a
# 6-chunk index so verify's priority_order exercises its middle-sample shuffle.
SPILL_FILE_BYTES = 5 * 1024 * 1024 + 4096
# E2E_HUB_TOKEN is opaque inside the container; just needs to match what
# BALE_GRANTS expects.
E2E_HUB_TOKEN = "e2e-hub-token-not-a-secret"
E2E_OWNER = "e2e"
E2E_REPO = "repo"
E2E_REPO_2 = "repo2"
E2E_REPO_3 = "mixed-files"
E2E_REPO_SPILL = "spilled-clean"
# Dedicated repos for the gc staging-reconciliation phases. Each gc phase
# pushes its own `main`, so they can't share a bare repo with the push-side
# phases above (or each other) without a non-fast-forward collision.
E2E_REPO_GC1 = "gc-abandon"
E2E_REPO_GC2 = "gc-keep"
E2E_REPO_GC3 = "gc-mixed"
E2E_USER = "e2e"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_jwt_with_filename(filename: str) -> str:
    """A forge-style JWT carrying gitea's `FilenameSHA256` claim. bale-server
    base64url-decodes the payload to gate the download's `Content-Disposition`
    but never verifies the signature (the forge does), so a dummy sig is fine.
    No `:` in the base64url alphabet, so it slots into a BALE_GRANTS tuple."""
    header = _b64url_no_pad(b'{"alg":"HS256","typ":"JWT"}')
    claim = hashlib.sha256(filename.encode("utf-8")).hexdigest()
    payload = _b64url_no_pad(
        json.dumps({"FilenameSHA256": claim}, separators=(",", ":")).encode("utf-8")
    )
    return f"{header}.{payload}.{_b64url_no_pad(b'e2e-unverified-sig')}"


# The browser-download phase downloads bigfile.bin (pushed to repo2) through
# GET /v1/files/{id}, using this JWT to exercise the filename-binding branch.
BROWSER_DL_FILENAME = "bigfile.bin"
BROWSER_DL_JWT = forge_jwt_with_filename(BROWSER_DL_FILENAME)

# Tolerance for "no growth" assertions on disk: filesystems may round up to
# block boundaries even when nothing logically changed.
SIZE_TOLERANCE_BYTES = 4096


# =============================================================================
# Logging / errors
# =============================================================================


class TestFailure(Exception):
    pass


def info(msg: str) -> None:
    print(f"[e2e] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[e2e][warn] {msg}", file=sys.stderr, flush=True)


def die(msg: str, exit_code: int = 1) -> None:
    print(f"[e2e][fail] {msg}", file=sys.stderr, flush=True)
    sys.exit(exit_code)


def skip(msg: str) -> None:
    print(f"[e2e][skip] {msg}", file=sys.stderr, flush=True)
    sys.exit(77)


def fmt_bytes(n: int) -> str:
    n_f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n_f) < 1024.0:
            return f"{n_f:.1f} {unit}" if unit != "B" else f"{int(n_f)} {unit}"
        n_f /= 1024.0
    return f"{n_f:.1f} TiB"


# =============================================================================
# Subprocess helpers
# =============================================================================


def run(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    input_bytes: Optional[bytes] = None,
    check: bool = True,
    capture: bool = True,
    expect_fail: bool = False,
) -> subprocess.CompletedProcess:
    """Run a subprocess synchronously. Never uses a shell.

    If `expect_fail` is True, returns the completed process regardless of
    exit status (and `check` is ignored).
    """
    completed = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        input=input_bytes,
        capture_output=capture,
        check=False,
    )
    if expect_fail:
        return completed
    if check and completed.returncode != 0:
        raise TestFailure(
            f"command failed (exit {completed.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed


def tool_on_path(name: str) -> bool:
    return shutil.which(name) is not None


def pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def host_primary_ip() -> str:
    """The host's primary outbound IP — the address the kernel would use
    to send a packet to the public internet. The UDP `connect` is just a
    routing decision; no packet is sent.

    Used as a stable endpoint for host-bound services that have to be
    reachable from BOTH the host AND a podman container — the host
    loopbacks to it for free, and the container's default bridge routes
    to it via the host's interface. macOS rootless podman's
    `host-gateway` magic name is flaky, so we side-step it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 1))
        return s.getsockname()[0]
    finally:
        s.close()


def dir_size_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for cur, _dirs, files in os.walk(root):
        for f in files:
            p = Path(cur) / f
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# =============================================================================
# Timing report
# =============================================================================


@dataclass
class TimingEntry:
    name: str
    elapsed_s: float
    bytes_moved: int = 0  # populated only for throughput-relevant phases

    def throughput_mb_s(self) -> Optional[float]:
        if self.bytes_moved <= 0 or self.elapsed_s <= 0:
            return None
        return (self.bytes_moved / (1024 * 1024)) / self.elapsed_s


@dataclass
class Timings:
    entries: list[TimingEntry] = field(default_factory=list)

    @contextmanager
    def measure(self, name: str, *, bytes_moved: int = 0) -> Iterator[None]:
        info(f">>> phase: {name}")
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - t0
            self.entries.append(TimingEntry(name, elapsed, bytes_moved))
            tp = ""
            if bytes_moved > 0 and elapsed > 0:
                mbps = (bytes_moved / (1024 * 1024)) / elapsed
                tp = f"  [{mbps:.2f} MiB/s on {fmt_bytes(bytes_moved)}]"
            info(f"<<< {name}: {elapsed:.2f}s{tp}")

    def print_report(self) -> None:
        if not self.entries:
            return
        print("\n=== Timing summary ===", flush=True)
        name_w = max(len(e.name) for e in self.entries)
        total = 0.0
        for e in self.entries:
            total += e.elapsed_s
            tp = e.throughput_mb_s()
            tp_s = f"  {tp:6.2f} MiB/s ({fmt_bytes(e.bytes_moved)})" if tp else ""
            print(f"  {e.name.ljust(name_w)}  {e.elapsed_s:7.2f}s{tp_s}", flush=True)
        print(f"  {'TOTAL'.ljust(name_w)}  {total:7.2f}s", flush=True)


# =============================================================================
# JWT (HS256, hand-rolled — no pip deps)
# =============================================================================


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_bale_jwt(
    *,
    secret: bytes,
    sub: str,
    repo_type: str,
    repo_id: str,
    revision: str,
    scope: str,
    ttl_secs: int,
) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "repo_type": repo_type,
        "repo_id": repo_id,
        "revision": revision,
        "scope": scope,
        "exp": int(time.time()) + ttl_secs,
    }
    h_b = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b}.{p_b}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h_b}.{p_b}.{_b64url(sig)}"


# =============================================================================
# Container runtime wrappers
# =============================================================================


class Runtime:
    def __init__(self, exe: str) -> None:
        self.exe = exe

    def cmd(self, *args: str) -> list[str]:
        return [self.exe, *args]


def detect_runtime() -> Runtime:
    for name in ("podman", "docker"):
        if not tool_on_path(name):
            continue
        try:
            completed = subprocess.run(
                [name, "info"], capture_output=True, check=False, timeout=20
            )
        except (subprocess.SubprocessError, OSError) as e:
            warn(f"`{name} info` errored: {e}")
            continue
        if completed.returncode == 0:
            info(f"using container runtime: {name}")
            return Runtime(name)
        warn(
            f"`{name} info` exit {completed.returncode} — runtime present but "
            "daemon/VM not ready:\n"
            f"{completed.stderr.decode('utf-8', 'replace').strip()}"
        )
    skip(
        "no working container runtime found "
        "(needs `podman info` or `docker info` to succeed; "
        "on macOS, ensure `podman machine start` was run)."
    )
    raise AssertionError("unreachable")


def build_image(rt: Runtime, tag: str, *, coverage: bool = False) -> None:
    info(f"building image {tag} (this may take a few minutes on first run)")
    build_args: list[str] = []
    if coverage:
        # Flips the Dockerfile to compile with `-C instrument-coverage` and
        # skips `strip` so debug info survives for llvm-cov.
        build_args.extend(["--build-arg", "COVERAGE=1"])
    completed = subprocess.run(
        rt.cmd(
            "build",
            *build_args,
            "-t",
            tag,
            "-f",
            str(Path(__file__).parent / "Dockerfile"),
            str(REPO_ROOT),
        ),
        check=False,
    )
    if completed.returncode != 0:
        raise TestFailure(f"image build failed (exit {completed.returncode})")


# =============================================================================
# Coverage mode (--coverage)
# =============================================================================
#
# `--coverage` swaps the release/stripped builds for `-C instrument-coverage`
# builds and bind-mounts a host dir into every container so both the host-
# side `git-bale` and the in-container `baleforgit-server` write .profraw
# files to the same place. At teardown we merge them with llvm-profdata and
# render an HTML report via llvm-cov. The prod (default) path is unchanged.


@dataclass
class CoverageConfig:
    profile_dir: Path          # host dir; bind-mounted as /coverage in containers
    git_bale_bin: Path         # instrumented host-side git-bale
    server_bin_host: Path      # copy of /usr/local/bin/baleforgit-server, podman-cp'd out
    html_out: Path             # llvm-cov show -output-dir target

    @property
    def container_profile_template(self) -> str:
        # %m is the binary hash; %p is the PID. Both required so the many
        # short-lived `git-bale filter-process` PIDs and the long-lived
        # server don't clobber each other.
        return "/coverage/server-%m-%p.profraw"

    @property
    def host_profile_template(self) -> str:
        return str(self.profile_dir / "host-%m-%p.profraw")


# Module-level singleton so start_container() (called from many sites,
# including deep inside phase functions) doesn't need every call site
# rewritten to thread the config through. None in prod mode.
_COVERAGE: Optional[CoverageConfig] = None


def _find_llvm_tool(name: str) -> Optional[Path]:
    # llvm-tools-preview ships its binaries under
    # `<sysroot>/lib/rustlib/<host-triple>/bin/`, not under any path
    # `rustup which` knows about. Resolve via rustc's --print queries.
    try:
        sysroot = subprocess.run(
            ["rustc", "--print", "sysroot"],
            capture_output=True, check=False, text=True,
        )
        host = subprocess.run(
            ["rustc", "--print", "host-tuple"],
            capture_output=True, check=False, text=True,
        )
        if sysroot.returncode == 0 and host.returncode == 0:
            candidate = (
                Path(sysroot.stdout.strip())
                / "lib" / "rustlib" / host.stdout.strip() / "bin" / name
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
            "cargo", "build", "--release", "-p", "git-bale",
            "--features", "coverage",
            "--target-dir", str(target_dir),
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
        capture_output=True, check=False, text=True,
    )
    if created.returncode != 0:
        raise TestFailure(
            f"`{rt.exe} create` failed: {created.stderr.strip()}"
        )
    cid = created.stdout.strip()
    try:
        cp = subprocess.run(
            rt.cmd("cp", f"{cid}:/usr/local/bin/baleforgit-server", str(dest)),
            capture_output=True, check=False, text=True,
        )
        if cp.returncode != 0:
            raise TestFailure(
                f"`{rt.exe} cp` failed: {cp.stderr.strip()}"
            )
    finally:
        subprocess.run(
            rt.cmd("rm", cid), capture_output=True, check=False,
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
            die("--no-build with --coverage: instrumented git-bale missing "
                f"at {existing_git_bale}")
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
            rt, COVERAGE_IMAGE_TAG, server_bin_host_path,
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
) -> None:
    """Run s3-basic + s3-dedup with the same instrumented image so
    bale-server-storage-s3 shows up in the coverage report.

    Imported lazily because `s3lib` imports from `run` — putting the
    import at module top would deadlock the load order.

    s3-failure-kill / s3-failure-conndrop are NOT run in coverage mode
    for the same reason as the fs failure-* phases: SIGKILL prevents the
    LLVM atexit hook from flushing .profraw."""
    from s3lib import (
        MinioGuard,
        Network,
        phase_s3_basic,
        phase_s3_dedup,
    )
    # When run.py is invoked as a script Python loads it as `__main__`.
    # `s3lib` does `from run import ServerHandle, start_container, ...`,
    # which triggers a SECOND load of run.py as the module named `run`
    # — separate globals, `_COVERAGE = None` there. The ServerHandle /
    # start_container the s3 phases end up using are the `run`-module
    # copies, so we mirror our coverage state onto that module too.
    if (
        "run" in sys.modules
        and sys.modules["run"] is not sys.modules[__name__]
    ):
        sys.modules["run"]._COVERAGE = _COVERAGE

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
        [str(llvm_profdata), "merge", "-sparse",
         *[str(p) for p in profraws],
         "-o", str(profdata)],
        capture_output=True, check=False, text=True,
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
            str(llvm_cov), "show",
            f"-instr-profile={profdata}",
            "-format=html",
            f"-output-dir={cov.html_out}",
            # /src/* paths come from the Dockerfile build stage's WORKDIR.
            # Remap to the host repo root so llvm-cov can find sources.
            f"-path-equivalence=/src,{REPO_ROOT}",
            "-ignore-filename-regex=(/\\.cargo/|/rustc/|/registry/|/\\.rustup/)",
            # First positional is the "main" binary; -object adds more.
            str(cov.git_bale_bin),
            "-object", str(cov.server_bin_host),
        ],
        capture_output=True, check=False, text=True,
    )
    if show.returncode != 0:
        warn(
            f"coverage: llvm-cov show failed (exit {show.returncode}):\n"
            f"{show.stderr}"
        )
        return
    info(f"coverage report: {cov.html_out / 'index.html'}")


def image_exists(rt: Runtime, tag: str) -> bool:
    # podman has `image exists`; docker doesn't. Fall back to `image inspect`.
    if rt.exe == "podman":
        return (
            subprocess.run(
                rt.cmd("image", "exists", tag),
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )
    return (
        subprocess.run(
            rt.cmd("image", "inspect", tag),
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


# =============================================================================
# Server / sshd container lifecycle
# =============================================================================


@dataclass
class ServerHandle:
    rt: Runtime
    name: str
    cas_port: int
    ssh_port: int
    data_root: Path
    public_host_url: str

    @property
    def healthz_url(self) -> str:
        return f"{self.public_host_url}/healthz"

    def stop(self) -> None:
        # In coverage mode SIGKILL (`rm -f`) prevents the server's atexit
        # hook from flushing .profraw files. Send SIGTERM first so the
        # axum graceful-shutdown path runs, LLVM atexit writes profiles,
        # then `--rm` on `podman run` auto-removes the container. Prod
        # mode skips this for speed.
        if _COVERAGE is not None:
            subprocess.run(
                self.rt.cmd("stop", "-t", "10", self.name),
                capture_output=True, check=False,
            )
        subprocess.run(
            self.rt.cmd("rm", "-f", self.name), capture_output=True, check=False
        )

    def logs(self) -> str:
        completed = subprocess.run(
            self.rt.cmd("logs", self.name), capture_output=True, check=False
        )
        return (
            completed.stdout.decode("utf-8", "replace")
            + completed.stderr.decode("utf-8", "replace")
        )

    def disk_xorb_bytes(self) -> int:
        return dir_size_bytes(self.data_root / "xorbs")

    def disk_shard_bytes(self) -> int:
        return dir_size_bytes(self.data_root / "shards")

    def disk_total_bytes(self) -> int:
        return self.disk_xorb_bytes() + self.disk_shard_bytes()


def start_container(
    rt: Runtime,
    *,
    image_tag: str,
    data_root: Path,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    ssh_public_key: str,
    test_repos: list[str],
    cas_port: Optional[int] = None,
    ssh_port: Optional[int] = None,
    quota_bytes: Optional[int] = None,
    admin_token_hex: Optional[str] = None,
    name_suffix: Optional[str] = None,
    public_host_url_override: Optional[str] = None,
    extra_env: Optional[dict[str, str]] = None,
    extra_run_args: Optional[list[str]] = None,
) -> ServerHandle:
    cas_port = cas_port or pick_free_port()
    ssh_port = ssh_port or pick_free_port()
    # public_host_url is the URL the SSH forge-auth script hands back to the
    # client. The connection-drop phase points it at an in-process TCP proxy
    # instead of the container's port so it can sever connections mid-upload
    # while the server itself stays running.
    public_host_url = public_host_url_override or f"http://127.0.0.1:{cas_port}"
    name = f"{CONTAINER_NAME_PREFIX}-{name_suffix or secrets.token_hex(4)}"
    bale_grants = ",".join(
        f"{E2E_HUB_TOKEN}:{E2E_USER}:{r}:write" for r in test_repos
    )
    # The browser-download phase presents a forge-style JWT instead of the
    # opaque hub token, so register it as a read grant on repo2 wherever repo2
    # is hosted (static authz matches the bearer verbatim).
    repo2_id = f"{E2E_OWNER}/{E2E_REPO_2}"
    if repo2_id in test_repos:
        bale_grants += f",{BROWSER_DL_JWT}:{E2E_USER}:{repo2_id}:read"

    env_kvs = [
        f"BALE_LISTEN=0.0.0.0:8080",
        f"BALE_DATA_ROOT=/data",
        f"BALE_PUBLIC_URL={public_host_url}",
        f"BALE_PUBLIC_HOST_URL={public_host_url}",
        f"BALE_JWT_SECRET_HEX={jwt_secret_hex}",
        f"BALE_TRANSFER_SECRET_HEX={transfer_secret_hex}",
        f"BALE_GRANTS={bale_grants}",
        f"E2E_HUB_TOKEN={E2E_HUB_TOKEN}",
        f"SSH_AUTHORIZED_KEY={ssh_public_key}",
        f"TEST_REPOS={' '.join(test_repos)}",
        "RUST_LOG=info",
    ]
    if quota_bytes is not None:
        env_kvs.append(f"BALE_DEFAULT_QUOTA_BYTES={quota_bytes}")
    if admin_token_hex is not None:
        env_kvs.append(f"BALE_ADMIN_TOKEN_HEX={admin_token_hex}")
    # extra_env carries S3 wiring (BALE_S3_*) for run_s3.py. Existing call
    # sites in this file pass None and behave exactly as before.
    if extra_env:
        for k, v in extra_env.items():
            env_kvs.append(f"{k}={v}")

    # Bind-mount `<data_root>/git-home` too so the bare git repos under
    # /home/git survive a container restart. Without this, the restart
    # persistence phase brings up a fresh container with empty repos and the
    # post-restart clone has no refs to check out.
    git_home_root = data_root.parent / "git-home"
    git_home_root.mkdir(exist_ok=True)
    cmd: list[str] = [
        rt.exe,
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{cas_port}:8080",
        "-p",
        f"127.0.0.1:{ssh_port}:2222",
        "-v",
        f"{data_root}:/data",
        "-v",
        f"{git_home_root}:/home/git",
    ]
    # In --coverage mode every container shares the same host profile dir,
    # bind-mounted as /coverage. The in-container `bale` user writes
    # .profraw files there; entrypoint.sh propagates LLVM_PROFILE_FILE.
    if _COVERAGE is not None:
        cmd.extend(["-v", f"{_COVERAGE.profile_dir}:/coverage"])
        env_kvs.append(f"LLVM_PROFILE_FILE={_COVERAGE.container_profile_template}")
    for kv in env_kvs:
        cmd.extend(["-e", kv])
    # extra_run_args lets run_s3.py attach the container to a shared podman
    # network (for server→MinIO traffic) and inject host.containers.internal
    # via --add-host so a TcpProxy on the host is reachable from the server.
    if extra_run_args:
        cmd.extend(extra_run_args)
    cmd.append(image_tag)

    info(
        f"starting container {name} (cas=:{cas_port}, ssh=:{ssh_port}, "
        f"data={data_root})"
    )
    completed = subprocess.run(cmd, capture_output=True, check=False)
    if completed.returncode != 0:
        raise TestFailure(
            "container start failed:\n"
            f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
        )
    handle = ServerHandle(rt, name, cas_port, ssh_port, data_root, public_host_url)
    wait_for_healthz(handle)
    wait_for_ssh(handle)
    return handle


def wait_for_healthz(handle: ServerHandle) -> None:
    deadline = time.monotonic() + HEALTHZ_TIMEOUT_S
    last_err: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(handle.healthz_url, timeout=2) as resp:
                if resp.status == 200:
                    info("server healthz: ok")
                    return
                last_err = f"status {resp.status}"
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
            last_err = str(e)
        time.sleep(0.3)
    raise TestFailure(
        f"baleforgit-server did not become healthy within {HEALTHZ_TIMEOUT_S}s "
        f"(last error: {last_err})\n"
        f"--- container logs ---\n{handle.logs()}"
    )


def wait_for_ssh(handle: ServerHandle) -> None:
    deadline = time.monotonic() + SSH_READY_TIMEOUT_S
    last_err: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", handle.ssh_port), timeout=2) as s:
                banner = s.recv(64)
                if banner.startswith(b"SSH-"):
                    info(f"sshd banner: {banner.strip().decode('ascii', 'replace')}")
                    return
                last_err = f"non-SSH banner: {banner!r}"
        except (OSError, ConnectionError, TimeoutError) as e:
            last_err = str(e)
        time.sleep(0.3)
    raise TestFailure(
        f"sshd inside the container did not respond on :{handle.ssh_port} "
        f"within {SSH_READY_TIMEOUT_S}s (last error: {last_err})\n"
        f"--- container logs ---\n{handle.logs()}"
    )


# =============================================================================
# Git client setup (isolated HOME + ssh config)
# =============================================================================


class SshAgent:
    """Manages a per-test `ssh-agent` so subprocesses that invoke `ssh`
    without an `-i` flag (notably git-bale's forge-auth subprocess) can
    still authenticate. Without the agent, git-bale would rely on ssh's
    default identity-file lookup under `$HOME/.ssh/`, which is fragile
    across OS configurations (system-wide ssh_config can preempt it,
    `IdentitiesOnly` can disable it, etc.). The agent sidesteps all of
    that — any process that inherits `SSH_AUTH_SOCK` gets the key."""

    def __init__(self) -> None:
        self.sock: Optional[str] = None
        self.pid: Optional[int] = None

    def start(self, identity_file: Path) -> None:
        # `ssh-agent -s` prints sh-style assignments we parse.
        out = subprocess.check_output(["ssh-agent", "-s"]).decode("utf-8")
        for raw in out.splitlines():
            line = raw.strip()
            if line.startswith("SSH_AUTH_SOCK="):
                self.sock = line[len("SSH_AUTH_SOCK="):].split(";", 1)[0]
            elif line.startswith("SSH_AGENT_PID="):
                self.pid = int(line[len("SSH_AGENT_PID="):].split(";", 1)[0])
        if self.sock is None or self.pid is None:
            raise TestFailure(f"could not parse `ssh-agent -s` output:\n{out}")
        env = os.environ.copy()
        env["SSH_AUTH_SOCK"] = self.sock
        completed = subprocess.run(
            ["ssh-add", str(identity_file)],
            env=env,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"ssh-add failed (exit {completed.returncode}):\n"
                f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
            )

    def stop(self) -> None:
        if self.pid is None:
            return
        try:
            os.kill(self.pid, 15)  # SIGTERM
        except OSError:
            pass
        self.pid = None
        self.sock = None


@dataclass
class ClientEnv:
    home: Path
    ssh_key: Path
    ssh_pub: Path
    known_hosts: Path
    gitconfig: Path
    git_bale_bin: Path
    ssh_agent: Optional[SshAgent] = None

    def make_env(self) -> dict:
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        if os.name == "nt":
            env["USERPROFILE"] = str(self.home)
        env["GIT_CONFIG_GLOBAL"] = str(self.gitconfig)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        # The pre-push hook runs `git-bale push-pending` with no path; the
        # release binary's directory must be on PATH for the hook to find it.
        env["PATH"] = (
            str(self.git_bale_bin.parent) + os.pathsep + env.get("PATH", "")
        )
        env["GIT_AUTHOR_NAME"] = "Bale E2E"
        env["GIT_AUTHOR_EMAIL"] = "e2e@bale.invalid"
        env["GIT_COMMITTER_NAME"] = "Bale E2E"
        env["GIT_COMMITTER_EMAIL"] = "e2e@bale.invalid"
        # GIT_SSH_COMMAND wraps ssh so git uses our isolated identity and
        # ignores any user/system ssh config (`-F /dev/null`). The remote URL
        # is `ssh://git@127.0.0.1:PORT/...` — port lives in the URL, so we
        # don't need a per-server `Port` directive anywhere.
        env["GIT_SSH_COMMAND"] = (
            f"ssh -F /dev/null -i {self.ssh_key} -o IdentitiesOnly=yes "
            f"-o UserKnownHostsFile={self.known_hosts} "
            f"-o StrictHostKeyChecking=no -o BatchMode=yes"
        )
        # git-bale's forge-auth subprocess invokes bare `ssh` (no -i).
        # SSH_AUTH_SOCK hands it the same key via the agent without any
        # config dance.
        if self.ssh_agent is not None and self.ssh_agent.sock is not None:
            env["SSH_AUTH_SOCK"] = self.ssh_agent.sock
            # Defensive: a stale SSH_AGENT_PID inherited from the host
            # would confuse our agent's lifecycle.
            env.pop("SSH_AGENT_PID", None)
        return env


def setup_client(*, work_root: Path, git_bale_bin: Path) -> ClientEnv:
    home = work_root / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    # ssh refuses to offer identities from a .ssh dir with mode > 0700.
    os.chmod(ssh_dir, 0o700)
    gitconfig = work_root / "gitconfig"
    gitconfig.write_text("")
    ssh_key = ssh_dir / "id_ed25519"
    ssh_pub = ssh_dir / "id_ed25519.pub"
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.touch()
    run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(ssh_key),
            "-N",
            "",
            "-C",
            "baleforgit-e2e",
            "-q",
        ],
    )
    # ssh strict-modes refuses keys with mode > 0600.
    os.chmod(ssh_key, 0o600)
    os.chmod(ssh_pub, 0o644)
    # git's ssh is fully driven by GIT_SSH_COMMAND (`-F /dev/null` etc.).
    # git-bale's ssh gets its identity from SSH_AUTH_SOCK (ssh-agent),
    # so no ~/.ssh/config is needed at all — we leave the file unset.
    agent = SshAgent()
    agent.start(ssh_key)
    return ClientEnv(
        home=home,
        ssh_key=ssh_key,
        ssh_pub=ssh_pub,
        known_hosts=known_hosts,
        gitconfig=gitconfig,
        git_bale_bin=git_bale_bin,
        ssh_agent=agent,
    )


def remote_url_ssh(*, ssh_port: int, owner: str, repo: str) -> str:
    """ssh:// URL `ssh://git@127.0.0.1:PORT/<owner>/<repo>.git`. The form
    matters: scp-style URLs can't carry a port, which would force us to
    keep an ssh-config alias per running server in sync with the test's
    isolated `$HOME`. The ssh:// form keeps the port in the URL so both
    `git`'s SSH transport and `git-bale`'s direct ssh subprocess derive
    the right port from argv (`-p PORT`) without any config dance.

    The path is absolute on the server side — git-receive-pack will open
    `/<owner>/<repo>.git`. The container's entrypoint creates a symlink
    `/<owner>` -> `/home/git/<owner>` so that absolute path resolves to
    the actual bare repo. The resolver splits the path on the FIRST `/`
    to extract owner/repo, so this URL also yields owner=<owner>,
    repo=<repo> for the Bale forge-auth handshake."""
    return f"ssh://git@127.0.0.1:{ssh_port}/{owner}/{repo}.git"


# =============================================================================
# Git helpers
# =============================================================================


def git(args: list[str], *, cwd: Path, env: dict, capture: bool = True,
        expect_fail: bool = False) -> subprocess.CompletedProcess:
    return run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture=capture,
        expect_fail=expect_fail,
    )


def cat_file_bytes(repo: Path, env: dict, spec: str) -> bytes:
    return git(["cat-file", "-p", spec], cwd=repo, env=env).stdout


def is_bale_pointer(blob: bytes) -> bool:
    txt = blob.strip()
    if not (txt.startswith(b"{") and txt.endswith(b"}")):
        return False
    try:
        obj = json.loads(txt)
    except json.JSONDecodeError:
        return False
    return all(k in obj for k in ("hash", "file_size", "sha256"))


def pointer_field(blob: bytes, key: str) -> object:
    return json.loads(blob)[key]


def verify_worktree(
    repo: Path,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Assert the worktree file `rel` exists with the expected size + sha256."""
    p = repo / rel
    if not p.exists():
        raise TestFailure(f"[{label}] worktree file missing: {rel}")
    actual_size = p.stat().st_size
    if actual_size != expected_size:
        raise TestFailure(
            f"[{label}] {rel}: worktree size {actual_size} != expected "
            f"{expected_size}"
        )
    actual_sha = sha256_file(p)
    if actual_sha != expected_sha:
        raise TestFailure(
            f"[{label}] {rel}: worktree sha256 {actual_sha} != expected "
            f"{expected_sha}"
        )


def verify_pointer_at(
    repo: Path,
    env: dict,
    *,
    spec: str,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> bytes:
    """Assert the object at git `spec` (e.g. ':small.bin' or 'HEAD:big.bin') is
    a Bale pointer whose `sha256` and `file_size` match the expected payload.
    Returns the pointer bytes so callers can chain additional checks."""
    blob = cat_file_bytes(repo, env, spec)
    if not is_bale_pointer(blob):
        raise TestFailure(
            f"[{label}] expected Bale pointer at {spec}, got: {blob[:200]!r}"
        )
    got_size = int(pointer_field(blob, "file_size"))
    if got_size != expected_size:
        raise TestFailure(
            f"[{label}] {spec}: pointer file_size {got_size} != expected "
            f"{expected_size}"
        )
    got_sha = str(pointer_field(blob, "sha256"))
    if got_sha != expected_sha:
        raise TestFailure(
            f"[{label}] {spec}: pointer sha256 {got_sha} != expected "
            f"{expected_sha}"
        )
    return blob


def force_resmudge_and_verify(
    repo: Path,
    env: dict,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Hot-path resmudge: delete the worktree file, run `git checkout --`,
    and verify sha256 + size. Asserts the chunk cache AND manifest cache
    are populated as a precondition — otherwise the filter would silently
    fall through to lukewarm/cold and the test wouldn't actually be
    measuring the hot path."""
    manifests = repo / ".git" / "bale" / "manifests"
    cache_dir = get_bale_cache_dir(repo, env)
    if not _has_any_file(manifests):
        raise TestFailure(
            f"[{label}] hot-path precondition violated: manifest cache "
            f"{manifests} is empty — `git checkout --` would fall through "
            "to lukewarm/cold and this test would silently measure the "
            "wrong path"
        )
    if not _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] hot-path precondition violated: chunk cache "
            f"{cache_dir} is empty — `git checkout --` would fall through "
            "to lukewarm/cold and this test would silently measure the "
            "wrong path"
        )
    p = repo / rel
    if p.exists():
        p.unlink()
    git(["checkout", "--", rel], cwd=repo, env=env)
    verify_worktree(
        repo, rel,
        expected_sha=expected_sha, expected_size=expected_size,
        label=label,
    )


def get_bale_cache_dir(repo: Path, env: dict) -> Path:
    """The chunks cache directory the bale filter writes to (from
    `bale.cacheDir` in the per-repo git config). The test sets this
    explicitly in init_repo_for_push / init_repo_for_clone, so missing
    config here is a harness bug, not a product bug."""
    out = git(
        ["config", "--local", "--get", "bale.cacheDir"],
        cwd=repo, env=env,
    ).stdout.decode().strip()
    if not out:
        raise TestFailure(
            f"bale.cacheDir not set in {repo}/.git/config — harness bug"
        )
    return Path(out)


def _has_any_file(root: Path) -> bool:
    return root.exists() and any(p.is_file() for p in root.rglob("*"))


def force_resmudge_cold(
    repo: Path,
    env: dict,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Wipe the per-repo manifest cache, the chunk cache pointed to by
    `bale.cacheDir`, and the worktree file — then force `git checkout --`.
    With nothing on disk to hit the hot or lukewarm path, the bale filter
    has to traverse `/v1/reconstructions/` against the server.

    Verifies sha256 + size of the re-materialized file. Also asserts the
    chunk cache repopulated, which is what proves the round-trip actually
    went over the wire (an empty cache that stayed empty would mean the
    smudge silently produced bytes from somewhere this test can't see).
    """
    manifests = repo / ".git" / "bale" / "manifests"
    if manifests.exists():
        shutil.rmtree(manifests)
    cache_dir = get_bale_cache_dir(repo, env)
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] chunk cache {cache_dir} not actually empty after wipe"
        )
    (repo / rel).unlink()
    git(["checkout", "--", rel], cwd=repo, env=env)
    verify_worktree(
        repo, rel,
        expected_sha=expected_sha, expected_size=expected_size,
        label=label,
    )
    if not _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] cold smudge of {rel} did not repopulate {cache_dir} — "
            "smudge may not have hit /v1/reconstructions/"
        )


def force_resmudge_lukewarm(
    repo: Path,
    env: dict,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Wipe the hot-path caches BEFORE the file has been pushed, then force
    `git checkout --`. With no chunks on the server yet (`/v1/reconstructions/`
    would 404), the smudge filter can only succeed by reading from
    `.git/bale/staging/` — `try_smudge_from_staging` in filter_process.rs.

    Precondition: the file must be staged (xorbs/shards in staging/) but
    NOT pushed. Caller is responsible for ordering this between `git add`
    and `git push`.

    Verifies:
      - staging is populated before the test runs (otherwise lukewarm has
        nothing to read from and the assertion would be vacuous),
      - bytes after re-materialization match the expected payload,
      - staging is still populated after — lukewarm reads but mustn't drain.
    """
    if not staging_files(repo):
        raise TestFailure(
            f"[{label}] staging dir empty — lukewarm needs a staged file"
        )
    manifests = repo / ".git" / "bale" / "manifests"
    if manifests.exists():
        shutil.rmtree(manifests)
    cache_dir = get_bale_cache_dir(repo, env)
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] chunk cache {cache_dir} not empty after wipe"
        )
    (repo / rel).unlink()
    git(["checkout", "--", rel], cwd=repo, env=env)
    verify_worktree(
        repo, rel,
        expected_sha=expected_sha, expected_size=expected_size,
        label=label,
    )
    if not staging_files(repo):
        raise TestFailure(
            f"[{label}] staging dir empty after lukewarm smudge — the filter "
            "drained the lukewarm input it was supposed to leave alone"
        )


# =============================================================================
# Storage / cache footprint helpers
# =============================================================================


def staging_files(repo: Path) -> list[Path]:
    staging = repo / ".git" / "bale" / "staging"
    if not staging.exists():
        return []
    out: list[Path] = []
    for cur, _dirs, files in os.walk(staging):
        for f in files:
            is_xorb = f.startswith("default.") and _is_64_lower_hex(
                f[len("default."):]
            )
            is_shard = f.endswith(".mdb") and _is_64_lower_hex(f[: -len(".mdb")])
            if is_xorb or is_shard:
                out.append(Path(cur) / f)
    return out


def _is_64_lower_hex(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def clean_cache_entries(repo: Path) -> list[Path]:
    cache = repo / ".git" / "bale" / "clean-cache"
    if not cache.exists():
        return []
    return [p for p in cache.iterdir() if p.is_file() and _is_64_lower_hex(p.name)]


def manifest_cache_entries(repo: Path) -> list[Path]:
    m = repo / ".git" / "bale" / "manifests"
    if not m.exists():
        return []
    return [p for p in m.iterdir() if p.is_file()]


def staged_markers(repo: Path) -> set[str]:
    """The set of `<file_hex>` markers under `.git/bale/staging/file-index/`.
    Each marker name is the merkle file hash the clean filter recorded — the
    same value as a committed pointer's `hash` field, so we can correlate a
    marker with the file version that produced it. This is the precise signal
    `git-bale gc` operates on."""
    d = repo / ".git" / "bale" / "staging" / "file-index"
    if not d.exists():
        return set()
    return {p.name for p in d.iterdir() if p.is_file()}


def pointer_hash_at(repo: Path, env: dict, spec: str, *, label: str) -> str:
    """The bale pointer `hash` (merkle file id) for the blob at git `spec`
    (e.g. `HEAD:data.bin` for the committed version or `:data.bin` for the
    staged-in-index version)."""
    blob = cat_file_bytes(repo, env, spec)
    if not is_bale_pointer(blob):
        raise TestFailure(
            f"[{label}] expected a bale pointer at {spec}, got: {blob[:200]!r}"
        )
    return str(pointer_field(blob, "hash"))


# =============================================================================
# Usage API
# =============================================================================


def fetch_usage(handle: ServerHandle, *, token: str, owner: str) -> dict:
    req = urllib.request.Request(
        f"{handle.public_host_url}/v1/usage/{owner}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_repo_usage(
    handle: ServerHandle, *, token: str, owner: str, repo: str
) -> dict:
    req = urllib.request.Request(
        f"{handle.public_host_url}/v1/usage/repo/{owner}/{repo}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_file(
    handle: ServerHandle,
    *,
    file_id: str,
    token: str,
    repo: str,
    filename: Optional[str] = None,
) -> tuple[int, bytes, dict[str, str]]:
    """GET the browser-facing /v1/files/{id} download. The bearer rides in the
    query (`?token=`) because the forge 302s here without an Authorization
    header. Returns (status, body, headers) for both success and 4xx so the
    caller can assert on tamper-rejection too."""
    params = {"token": token, "repo": repo}
    if filename is not None:
        params["filename"] = filename
    url = (
        f"{handle.public_host_url}/v1/files/{file_id}"
        f"?{urllib.parse.urlencode(params)}"
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}


# =============================================================================
# Deterministic payloads (sha256-chain so failures reproduce exactly)
# =============================================================================


def deterministic_payload(size: int, *, seed: bytes = b"baleforgit-e2e") -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(seed + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:size])


def modify_bytes(buf: bytes, *, offset: int, replacement: bytes) -> bytes:
    arr = bytearray(buf)
    arr[offset : offset + len(replacement)] = replacement
    return bytes(arr)


def replace_region(buf: bytes, *, offset: int, length: int, seed: bytes) -> bytes:
    region = deterministic_payload(length, seed=seed)
    arr = bytearray(buf)
    arr[offset : offset + length] = region
    return bytes(arr)


# =============================================================================
# Repo bootstrap (the user-side bits)
# =============================================================================


def init_repo_for_push(
    *,
    work_root: Path,
    client: ClientEnv,
    server: ServerHandle,
    owner: str,
    repo: str,
    name: str = "alice",
) -> tuple[Path, dict]:
    """Init a working repo, install the bale filter, set the SSH remote
    pointing at `server`, and seed `.gitattributes`. Returns (repo_path,
    env). The remote URL carries the server's SSH port, so multiple
    servers can coexist without any ssh-config gymnastics."""
    env = client.make_env()
    work = work_root / name
    work.mkdir()
    git(["init", "-b", "main", "."], cwd=work, env=env)
    # `install --local` writes filter.bale.process + required=true AND the
    # pre-push hook that runs `git-bale push-pending`.
    run([str(client.git_bale_bin), "install", "--local"], cwd=work, env=env)
    cache_dir = work_root / f"cache-{name}"
    cache_dir.mkdir(exist_ok=True)
    git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=work, env=env)
    git(
        [
            "remote",
            "add",
            "origin",
            remote_url_ssh(ssh_port=server.ssh_port, owner=owner, repo=repo),
        ],
        cwd=work,
        env=env,
    )
    (work / ".gitattributes").write_text("*.bin filter=bale -text\n")
    git(["add", ".gitattributes"], cwd=work, env=env)
    git(["commit", "-m", "enable bale filter"], cwd=work, env=env)
    return work, env


def init_repo_for_clone(
    *,
    work_root: Path,
    client: ClientEnv,
    server: ServerHandle,
    owner: str,
    repo: str,
    name: str,
) -> tuple[Path, dict, Path]:
    """Clone over SSH with --no-checkout, install the filter, configure a
    fresh cache dir, then checkout. Returns (repo_path, env, cache_dir).
    The fresh cache means smudge will run through the cold network path,
    which is what most clone-side checks need."""
    env = client.make_env()
    target = work_root / name
    cache_dir = work_root / f"cache-{name}"
    cache_dir.mkdir(exist_ok=True)
    url = remote_url_ssh(ssh_port=server.ssh_port, owner=owner, repo=repo)
    git(["clone", "--no-checkout", url, str(target)], cwd=work_root, env=env)
    run([str(client.git_bale_bin), "install", "--local"], cwd=target, env=env)
    git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=target, env=env)
    return target, env, cache_dir


# =============================================================================
# Failure-injection helpers (server-kill / connection-drop / db-busy)
# =============================================================================


class TcpProxy:
    """Pure-stdlib forwarding proxy used by the failure-recovery phases.
    Listens on 127.0.0.1:`listen_port` and shovels bytes to `upstream` in
    both directions. `kill()` slams every socket shut to simulate an abrupt
    connection drop (no FIN); `start()` may be called again afterwards to
    bring the proxy back up on the same listen port for the retry leg.

    `throttle_bytes_per_sec` rate-limits the *client → server* direction
    (the direction that carries xorb/shard upload bodies). Returning bytes
    are passed through at full speed. The throttle exists so the upload
    takes long enough for the harness to reliably interrupt it mid-flight
    on localhost, where an unthrottled 35 MiB push completes in well under
    a second and the race window vanishes.

    NOT a general-purpose proxy — only safe for use in this test harness.
    """

    def __init__(
        self,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        *,
        throttle_bytes_per_sec: Optional[int] = None,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self.listen_port = listen_port
        self.upstream = (upstream_host, upstream_port)
        self.throttle_bytes_per_sec = throttle_bytes_per_sec
        # bind_host is "127.0.0.1" for the existing client↔server drop phase,
        # and "0.0.0.0" for the S3-conndrop phase so the server container can
        # reach the proxy via host.containers.internal.
        self.bind_host = bind_host
        self._lock = threading.Lock()
        self._listen_sock: Optional[socket.socket] = None
        self._active: list[socket.socket] = []
        self._accept_thread: Optional[threading.Thread] = None
        self._stopped = True
        self._bytes_forwarded = 0

    @property
    def bytes_forwarded(self) -> int:
        with self._lock:
            return self._bytes_forwarded

    def start(self) -> None:
        with self._lock:
            if not self._stopped:
                return
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((self.bind_host, self.listen_port))
            ls.listen(16)
            self._listen_sock = ls
            self._stopped = False
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._accept_thread = t

    def _accept_loop(self) -> None:
        while True:
            with self._lock:
                ls = self._listen_sock
                stopped = self._stopped
            if stopped or ls is None:
                return
            try:
                client_sock, _ = ls.accept()
            except OSError:
                return
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                upstream_sock.connect(self.upstream)
            except OSError:
                client_sock.close()
                continue
            with self._lock:
                self._active.extend((client_sock, upstream_sock))
            # Only throttle the client → server direction; responses get
            # passed through at full speed.
            threading.Thread(
                target=self._pump,
                args=(client_sock, upstream_sock),
                kwargs={"throttle": self.throttle_bytes_per_sec},
                daemon=True,
            ).start()
            threading.Thread(
                target=self._pump,
                args=(upstream_sock, client_sock),
                daemon=True,
            ).start()

    def _pump(
        self,
        a: socket.socket,
        b: socket.socket,
        *,
        throttle: Optional[int] = None,
    ) -> None:
        chunk_size = 16 * 1024 if throttle is not None else 64 * 1024
        try:
            while True:
                data = a.recv(chunk_size)
                if not data:
                    break
                b.sendall(data)
                with self._lock:
                    self._bytes_forwarded += len(data)
                if throttle is not None and throttle > 0:
                    time.sleep(len(data) / float(throttle))
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass

    def kill(self) -> None:
        """Slam all sockets. Active client/upstream sockets are closed without
        a FIN, simulating an abrupt drop from the client's perspective."""
        with self._lock:
            self._stopped = True
            ls, self._listen_sock = self._listen_sock, None
            active, self._active = self._active, []
        if ls is not None:
            try:
                ls.close()
            except OSError:
                pass
        for s in active:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None


class MockAuthzServer:
    """Stand-in for the upstream `/check_access` endpoint a real forge
    would expose. Used by the `authz-http` coverage phase to drive
    `bale-server-authz-http::HttpAuthz`.

    Wire contract (see `crates/bale-server-authz-http/src/lib.rs`):
        POST /check_access  { "hub_bearer": ..., "repo": {...}, "scope": ... }
        200 OK { "user_id": "alice" }   — known token + sufficient scope
        401 Unauthorized                — unknown hub_bearer
        403 Forbidden                   — known token, insufficient access
        any other (e.g. 500)            — upstream failure (HttpAuthz maps to Internal)

    Binds 0.0.0.0:port so the server container can reach it via the
    host's primary IP (the standard cross-bridge route).

    The decision function receives (hub_bearer, repo_id, scope_str) and
    returns (http_status:int, body_dict:dict). Each phase configures its
    own decision logic.
    """

    def __init__(
        self,
        decide: Callable[[str, str, str], tuple[int, dict]],
        *,
        port: Optional[int] = None,
    ) -> None:
        self.decide = decide
        self.port = port or pick_free_port()
        self.calls: list[tuple[str, str, str, int]] = []  # (bearer, repo_id, scope, status)
        self._server: Optional["http.server.ThreadingHTTPServer"] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        # The container reaches us via the host's primary IP — the
        # bridge routes to it for free. 127.0.0.1 wouldn't work because
        # that's the container's own loopback inside its netns.
        return f"http://{host_primary_ip()}:{self.port}"

    def start(self) -> None:
        import http.server

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: N802
                # http.server's default writes one stderr line per request,
                # which would drown our own info() output. Drop them.
                pass

            def do_POST(self):  # noqa: N802
                if self.path != "/check_access":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8"))
                    bearer = body.get("hub_bearer", "")
                    repo_id = body.get("repo", {}).get("repo_id", "")
                    scope = body.get("scope", "")
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                status, payload = outer.decide(bearer, repo_id, scope)
                with outer._lock:
                    outer.calls.append((bearer, repo_id, scope, status))
                body_bytes = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)

        self._server = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="MockAuthzServer"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


class MockForgeServer:
    """Stand-in for a git forge's `/<owner>/<repo>.git/info/bale/authenticate`
    endpoint — the HTTPS half of the forge protocol the git-bale resolver uses
    when `origin` is an `http(s)://` URL (instead of the SSH
    `git-bale-authenticate` command). A real forge verifies the user's password
    locally and returns the baleforgit-server href plus a short-lived Bearer;
    we return a fixed href + hub token (`docs/BALE_FORGE_PROTOCOL.md`).

    Wire shape the resolver expects (resolver.rs `authenticate_http`):
        POST /<owner>/<repo>.git/info/bale/authenticate?op=upload|download
        Authorization: Basic <base64(user:pass)>
        200 { "href": "<bale-server-url>", "header": {"Authorization": "Bearer <tok>"} }

    We do NOT serve git smart-HTTP: the two operations that drive the HTTP
    resolver branch — `git-bale push-pending` and a cold smudge — only read
    `origin`'s URL and POST to this endpoint; they never transfer git refs.
    That keeps the mock to one endpoint instead of wrapping `git http-backend`.
    The client runs on the host, so it reaches us on 127.0.0.1.
    """

    def __init__(
        self, *, bale_href: str, hub_token: str, port: Optional[int] = None
    ) -> None:
        self.bale_href = bale_href.rstrip("/")
        self.hub_token = hub_token
        self.port = port or pick_free_port()
        self.calls: list[tuple[str, bool]] = []  # (op, had_basic_auth)
        self._server: Optional["http.server.ThreadingHTTPServer"] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        import http.server

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: N802
                pass

            def do_POST(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if not parsed.path.endswith("/info/bale/authenticate"):
                    self.send_response(404)
                    self.end_headers()
                    return
                op = urllib.parse.parse_qs(parsed.query).get("op", [""])[0]
                had_basic = self.headers.get("Authorization", "").startswith("Basic ")
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with outer._lock:
                    outer.calls.append((op, had_basic))
                body = json.dumps(
                    {
                        "href": outer.bale_href,
                        "header": {"Authorization": f"Bearer {outer.hub_token}"},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="MockForgeServer"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def wait_for_server_progress(
    server: ServerHandle, *, min_bytes: int, timeout_s: float = 15.0
) -> int:
    """Poll the server's xorbs directory until at least `min_bytes` have
    landed. Returns the disk total seen. The wait window must be short
    enough that the in-flight push hasn't completed yet — we want to
    catch it mid-upload, not after."""
    deadline = time.monotonic() + timeout_s
    last = 0
    while time.monotonic() < deadline:
        last = server.disk_xorb_bytes()
        if last >= min_bytes:
            return last
        time.sleep(0.05)
    raise TestFailure(
        f"server xorb bytes did not reach {min_bytes} within {timeout_s}s "
        f"(stalled at {last})"
    )


@contextmanager
def hold_db_writer_lock(server: ServerHandle, hold_seconds: float) -> Iterator[None]:
    """Open the server's SQLite meta.db from a sidecar `sqlite3` shell INSIDE
    the container, take an IMMEDIATE write lock for `hold_seconds`, and
    yield. Used by the transient-db-failure phase to force the server's
    SQLite writes to hit SQLITE_BUSY transiently — sqlx's default 5s
    busy_timeout should turn the contention into a brief wait, not an
    error, so a concurrent client push sees no failure.

    The lock-holder runs inside the container (not on the host) because
    rootless podman bind mounts go through a VM on macOS, where host-side
    fcntl locks don't propagate to the in-VM SQLite.

    The sqlite3 CLI buffers its stdout when not on a TTY, so an
    interactive driver from outside can't reliably detect "lock held" via
    SELECT output. Instead, drive sqlite3 with a heredoc that touches a
    marker file after BEGIN IMMEDIATE returns — we poll for the marker
    to confirm the lock was acquired before yielding."""
    marker = "/tmp/bale-e2e-dblock-held"
    # Wipe any leftover marker from an earlier run inside the same container.
    subprocess.run(
        server.rt.cmd("exec", server.name, "rm", "-f", marker),
        capture_output=True, check=False,
    )
    script = (
        "sqlite3 /data/meta.db <<'EOF'\n"
        "BEGIN IMMEDIATE;\n"
        f".system touch {marker}\n"
        f".system sleep {hold_seconds}\n"
        "COMMIT;\n"
        "EOF\n"
    )
    completed = subprocess.run(
        server.rt.cmd("exec", "-d", server.name, "bash", "-c", script),
        capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise TestFailure(
            f"detached sqlite3 lock-holder failed to start (exit "
            f"{completed.returncode}): "
            f"{completed.stderr.decode('utf-8', 'replace')}"
        )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        check = subprocess.run(
            server.rt.cmd("exec", server.name, "test", "-f", marker),
            capture_output=True, check=False,
        )
        if check.returncode == 0:
            break
        time.sleep(0.05)
    else:
        raise TestFailure(
            f"sidecar sqlite3 never created {marker} within 10s — "
            "BEGIN IMMEDIATE may have failed silently"
        )
    try:
        yield
    finally:
        # The detached sqlite3 will COMMIT and exit on its own once
        # `sleep hold_seconds` elapses; nothing to clean up here.
        pass


# =============================================================================
# Scenario phases
# =============================================================================


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

    # Re-stage — pointer cache should short-circuit the clean filter.
    staging_before = set(staging_files(repo))
    with timings.measure("basic: re-stage (pointer cache hit)"):
        git(["add", "small.bin"], cwd=repo, env=env)
    staging_after = set(staging_files(repo))
    if staging_before != staging_after:
        raise TestFailure(
            "re-stage produced different staging files — pointer cache miss"
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
    file forces the spill: the first `git add` stages via the tmpfile path; an
    unstage + re-add reloads the clean-cache and verifies the spilled payload
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

    # Unstage + re-add. The second clean reloads the clean-cache and, because
    # the payload still spills, verifies it through the file-backed
    # `verify_chunks` (not the in-memory variant). A cache hit must not produce
    # new staging artifacts.
    git(["restore", "--staged", "spilled.bin"], cwd=repo, env=env)
    with timings.measure("spilled: re-stage (file-backed clean-cache hit)"):
        git(["add", "spilled.bin"], cwd=repo, env=env)
    if set(staging_files(repo)) != staging_after_add:
        raise TestFailure(
            "spilled: re-stage changed staging files — clean-cache miss on the "
            "spilled verify path"
        )
    verify_pointer_at(
        repo, env, spec=":spilled.bin",
        expected_sha=payload_sha, expected_size=SPILL_FILE_BYTES,
        label="spilled:after-restage",
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


# =============================================================================
# Mount helpers (read-only FUSE mounts via `git-bale mount` / `mount-diff`)
# =============================================================================


class MountUnavailable(Exception):
    """libfuse / fuse-t not installed on this host. The mount phase signals
    this to its caller so the whole phase skips instead of failing.

    `stderr` carries the binary's full stderr so the skip handler can log
    everything — under --coverage a mount-up timeout previously surfaced as
    a single-line "skipped" without any clue what the binary was doing."""

    def __init__(self, reason: str, *, stderr: str = "") -> None:
        super().__init__(reason)
        self.stderr = stderr


_LIBFUSE_HINT = "needs libfuse at runtime"


def _unmount_path(mount_point: Path) -> None:
    """Best-effort unmount. fusermount3 / fusermount on Linux (rootless-safe),
    plain `umount` everywhere else. Silent if not currently mounted."""
    for cmd in (
        ["fusermount3", "-u", str(mount_point)],
        ["fusermount", "-u", str(mount_point)],
        ["umount", str(mount_point)],
    ):
        if not shutil.which(cmd[0]):
            continue
        r = subprocess.run(cmd, capture_output=True, check=False)
        if r.returncode == 0:
            return


def _is_mounted(mount_point: Path, parent: Path) -> bool:
    """A FUSE mount makes `mount_point`'s st_dev differ from its parent's.
    Works on Linux + macOS (fuse-t) without parsing /proc/mounts."""
    try:
        return mount_point.stat().st_dev != parent.stat().st_dev
    except OSError:
        return False


def _wait_mounted(
    mount_point: Path, parent: Path, proc: subprocess.Popen, timeout_s: float
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return  # caller will inspect the dead process
        if _is_mounted(mount_point, parent):
            return
        time.sleep(0.05)


@contextmanager
def _mount_session(
    *,
    client: ClientEnv,
    repo: Path,
    env: dict,
    mount_root: Path,
    argv_tail: list[str],
    label: str,
) -> Iterator[Path]:
    """Spawn `git-bale <argv_tail>` (mount or mount-diff), wait for the FUSE
    mount to come up, yield the mount point. Cleans up the mount and the
    process on exit even if the body raises.

    Raises MountUnavailable when libfuse/fuse-t is missing on the host so
    the caller can skip the phase rather than failing it."""
    mount_point = mount_root / f"mnt-{secrets.token_hex(3)}"
    mount_point.mkdir()
    cmd = [str(client.git_bale_bin), *argv_tail, "--mount", str(mount_point)]
    proc = subprocess.Popen(
        cmd,
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    mounted = False
    try:
        # llvm-cov instrumentation slows the binary by ~5x on macOS; the
        # prod 30s timeout would expire before fuse_main_real even returned
        # from mount(), causing the whole subsystem to skip silently.
        wait_timeout = 120.0 if _COVERAGE is not None else 30.0
        _wait_mounted(mount_point, mount_root, proc, timeout_s=wait_timeout)
        mounted = _is_mounted(mount_point, mount_root)
        if not mounted:
            try:
                stdout, stderr = proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=2.0)
            err_txt = stderr.decode("utf-8", "replace") if stderr else ""
            out_txt = stdout.decode("utf-8", "replace") if stdout else ""
            if _LIBFUSE_HINT in err_txt:
                raise MountUnavailable(
                    err_txt.strip().splitlines()[0], stderr=err_txt.strip()
                )
            raise TestFailure(
                f"[{label}] mount never came up after {wait_timeout:.0f}s "
                f"(exit={proc.returncode}):\nstderr:\n{err_txt}\n"
                f"stdout:\n{out_txt}"
            )
        yield mount_point
    finally:
        # Unmount first so libfuse returns from fuse_main_real and the
        # foreground process exits on its own; killing while still mounted
        # can leave a stale entry on macOS (fuse-t) for tens of seconds.
        if mounted:
            _unmount_path(mount_point)
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        try:
            proc.communicate(timeout=1.0)
        except (subprocess.TimeoutExpired, ValueError):
            pass
        # Under --coverage, .profraw files are only written on clean exit.
        # fuse-t kills the mount process by SIGPIPE during teardown, so the
        # binary installs a SIGPIPE handler that flushes the profile and
        # _exit(0)s (see mount/backend/libfuse.rs). A non-zero/sig exit here
        # means that handler regressed and this session's coverage is lost.
        if _COVERAGE is not None and proc.returncode not in (0, None):
            info(
                f"-- [{label}] WARNING: mount proc exit={proc.returncode} "
                f"(expected 0 under --coverage) — profile data for this "
                f"session was likely dropped"
            )
        try:
            mount_point.rmdir()
        except OSError:
            pass


def mount_rev_session(
    *,
    client: ClientEnv,
    repo: Path,
    env: dict,
    mount_root: Path,
    rev: str,
    paths: Optional[list[str]] = None,
    label: str = "mount-rev",
):
    argv = ["mount", rev]
    if paths:
        argv.append("--")
        argv.extend(paths)
    return _mount_session(
        client=client, repo=repo, env=env, mount_root=mount_root,
        argv_tail=argv, label=label,
    )


def mount_diff_session(
    *,
    client: ClientEnv,
    repo: Path,
    env: dict,
    mount_root: Path,
    rev_a: str,
    rev_b: str,
    label_a: str,
    label_b: str,
    paths: Optional[list[str]] = None,
    label: str = "mount-diff",
):
    argv = [
        "mount-diff", rev_a, rev_b,
        "--label-a", label_a, "--label-b", label_b,
    ]
    if paths:
        argv.append("--")
        argv.extend(paths)
    return _mount_session(
        client=client, repo=repo, env=env, mount_root=mount_root,
        argv_tail=argv, label=label,
    )


# =============================================================================
# Mount phases
# =============================================================================


def phase_mount_rev(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Cold-clone the bigfile repo, mount HEAD as a read-only FUSE FS, and
    verify both the non-bale `.gitattributes` (served from gix's ODB) and
    the bale-tracked `bigfile.bin` (reconstructed via the same Reader the
    smudge filter uses) come through correctly.

    The mount path exercises Reader's cold-then-warm transition end-to-end
    over real SSH-forge auth + network reconstruction — coverage no Rust
    unit test reaches because libfuse is mocked out there."""
    if not rev_state.get("shas"):
        raise TestFailure("mount-rev: rev_state missing — bigfile phase didn't run")
    expected_sha = rev_state["shas"][-1]
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root, client=client, server=server,
        owner=E2E_OWNER, repo=E2E_REPO_2, name="mount-rev-clone",
    )
    mount_root = work_root / "mount-rev-points"
    mount_root.mkdir(exist_ok=True)
    try:
        with timings.measure(
            "mount-rev: mount HEAD + read bigfile via FUSE",
            bytes_moved=BIG_FILE_BYTES,
        ):
            with mount_rev_session(
                client=client, repo=clone_path, env=env,
                mount_root=mount_root, rev="HEAD",
                label="mount-rev",
            ) as mp:
                # Plain (non-bale) blob: byte-for-byte against what git itself
                # would hand back — the only correct answer for a small text
                # file served from gix's ODB through the FUSE plain_cache path.
                mounted_attrs = (mp / ".gitattributes").read_bytes()
                source_attrs = git(
                    ["show", "HEAD:.gitattributes"], cwd=clone_path, env=env,
                ).stdout
                if mounted_attrs != source_attrs:
                    raise TestFailure(
                        f"mount-rev: .gitattributes mismatch\n"
                        f"  mounted: {mounted_attrs!r}\n"
                        f"  source:  {source_attrs!r}"
                    )
                # stat must report the *decompressed* size, not the pointer
                # JSON length — Reader.size_of reads only the pointer.
                size = (mp / "bigfile.bin").stat().st_size
                if size != BIG_FILE_BYTES:
                    raise TestFailure(
                        f"mount-rev: bigfile.bin stat size {size} != "
                        f"{BIG_FILE_BYTES} (size_of returning pointer JSON "
                        "length instead of file_size?)"
                    )
                got_sha = sha256_file(mp / "bigfile.bin")
                if got_sha != expected_sha:
                    raise TestFailure(
                        f"mount-rev: bigfile.bin sha {got_sha} != HEAD sha "
                        f"{expected_sha} — Reader reconstructed wrong bytes"
                    )
                # If lazy dir population is broken, individual lookups still
                # work but readdir returns an empty list.
                names = sorted(p.name for p in mp.iterdir())
                for required in (".gitattributes", "bigfile.bin"):
                    if required not in names:
                        raise TestFailure(
                            f"mount-rev: readdir missing {required!r}; got {names}"
                        )
        # Hot path: re-mount on the same clone hits the manifest + chunk
        # caches the first mount populated.
        with timings.measure(
            "mount-rev: re-mount HEAD (hot caches)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            with mount_rev_session(
                client=client, repo=clone_path, env=env,
                mount_root=mount_root, rev="HEAD",
                label="mount-rev-hot",
            ) as mp:
                got_sha = sha256_file(mp / "bigfile.bin")
                if got_sha != expected_sha:
                    raise TestFailure(
                        f"mount-rev (hot): bigfile.bin sha {got_sha} != "
                        f"{expected_sha} — cache returned stale bytes"
                    )
    except MountUnavailable as e:
        info(f"-- mount-rev: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-rev: binary stderr:\n{e.stderr}")


def phase_mount_diff(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Cold-clone the bigfile repo, mount `git diff v1 v3`, and verify both
    sides reconstruct correctly with their respective shas. Both sides are
    bale-tracked pointers, so each one drives a full Reader cold-path
    reconstruction through libfuse."""
    if len(rev_state.get("commits", [])) < 3:
        raise TestFailure(
            "mount-diff: rev_state needs v1+v3 commits — bigfile phase did "
            "not produce them"
        )
    v1_commit = rev_state["commits"][0]
    v3_commit = rev_state["commits"][2]
    v1_sha = rev_state["shas"][0]
    v3_sha = rev_state["shas"][2]
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root, client=client, server=server,
        owner=E2E_OWNER, repo=E2E_REPO_2, name="mount-diff-clone",
    )
    mount_root = work_root / "mount-diff-points"
    mount_root.mkdir(exist_ok=True)
    try:
        with timings.measure(
            "mount-diff: v1 vs v3 + read both sides via FUSE",
            bytes_moved=2 * BIG_FILE_BYTES,
        ):
            with mount_diff_session(
                client=client, repo=clone_path, env=env,
                mount_root=mount_root,
                rev_a=v1_commit, rev_b=v3_commit,
                label_a="v1", label_b="v3",
                label="mount-diff",
            ) as mp:
                names = sorted(p.name for p in mp.iterdir())
                for required in ("bigfile__v1.bin", "bigfile__v3.bin"):
                    if required not in names:
                        raise TestFailure(
                            f"mount-diff: labeled entry {required!r} missing "
                            f"from readdir; got {names}"
                        )
                got_v1 = sha256_file(mp / "bigfile__v1.bin")
                if got_v1 != v1_sha:
                    raise TestFailure(
                        f"mount-diff: bigfile__v1.bin sha {got_v1} != v1 sha "
                        f"{v1_sha} — reconstructed wrong bytes for side A"
                    )
                got_v3 = sha256_file(mp / "bigfile__v3.bin")
                if got_v3 != v3_sha:
                    raise TestFailure(
                        f"mount-diff: bigfile__v3.bin sha {got_v3} != v3 sha "
                        f"{v3_sha} — reconstructed wrong bytes for side B"
                    )
                for name in ("bigfile__v1.bin", "bigfile__v3.bin"):
                    sz = (mp / name).stat().st_size
                    if sz != BIG_FILE_BYTES:
                        raise TestFailure(
                            f"mount-diff: {name} stat size {sz} != "
                            f"{BIG_FILE_BYTES}"
                        )
        # Pathspec must yield an empty diff and exit with "no files differ"
        # rather than silently mounting an empty FS.
        empty_mp = mount_root / f"empty-{secrets.token_hex(3)}"
        empty_mp.mkdir()
        try:
            with timings.measure("mount-diff: pathspec rejects empty result"):
                completed = subprocess.run(
                    [
                        str(client.git_bale_bin), "mount-diff",
                        v1_commit, v3_commit,
                        "--label-a", "v1", "--label-b", "v3",
                        "--mount", str(empty_mp),
                        "--", "no-such-path",
                    ],
                    cwd=str(clone_path), env=env,
                    capture_output=True, check=False, timeout=30.0,
                )
            if completed.returncode == 0:
                raise TestFailure(
                    "mount-diff: pathspec filtering an empty result did not "
                    "error (would have mounted an empty FS instead)"
                )
            err = completed.stderr.decode("utf-8", "replace")
            if _LIBFUSE_HINT in err:
                info(f"-- mount-diff pathspec: skipping ({err.splitlines()[0]})")
            elif "no files differ" not in err:
                raise TestFailure(
                    f"mount-diff: pathspec-empty exit was non-zero but "
                    f"stderr lacked 'no files differ':\n{err}"
                )
        finally:
            try:
                empty_mp.rmdir()
            except OSError:
                pass
    except MountUnavailable as e:
        info(f"-- mount-diff: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-diff: binary stderr:\n{e.stderr}")


def phase_mount_diff_mixed(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Sets up a fresh repo with TWO files that both change across two
    commits — a plain text file (`notes.txt`, served from gix's ODB) and a
    bale-tracked binary (`data.bin`, reconstructed through the Reader cold
    path). Mounts the diff and asserts:

      - both labelled sides of *each* file match `git show <rev>:<path>`
        byte-for-byte (catches any silent path-routing or chunking bug
        that would surface as off-by-one bytes or wrong-side wiring),
      - `diff -q` on each pair reports a difference and exits 1, proving
        the labelled sides aren't accidentally serving the same content.

    The mount-diff happy-path test (`mount-diff`) only exercises a single
    bale-tracked binary; this one is what catches regressions where plain
    git blobs and bale pointers go through divergent code paths in the
    Reader and one of them silently breaks."""
    repo, env = init_repo_for_push(
        work_root=work_root, client=client, server=server,
        owner=E2E_OWNER, repo=E2E_REPO_3, name="mount-diff-mixed",
    )
    plain_v1 = b"alpha\nbravo\ncharlie\ndelta\n"
    plain_v2 = b"alpha\nbravo CHANGED\ncharlie\ndelta\necho added\n"
    # 256 KiB so CDC produces a handful of chunks; small enough to keep
    # the test fast.
    bale_v1 = deterministic_payload(256 * 1024, seed=b"mixed-bale-v1")
    bale_v2 = modify_bytes(bale_v1, offset=10_000, replacement=b"\xff" * 32)

    (repo / "notes.txt").write_bytes(plain_v1)
    (repo / "data.bin").write_bytes(bale_v1)
    git(["add", "notes.txt", "data.bin"], cwd=repo, env=env)
    git(["commit", "-m", "v1: notes + data"], cwd=repo, env=env)
    commit_v1 = git(
        ["rev-parse", "HEAD"], cwd=repo, env=env,
    ).stdout.decode().strip()

    (repo / "notes.txt").write_bytes(plain_v2)
    (repo / "data.bin").write_bytes(bale_v2)
    git(["add", "notes.txt", "data.bin"], cwd=repo, env=env)
    git(["commit", "-m", "v2: edit both"], cwd=repo, env=env)
    commit_v2 = git(
        ["rev-parse", "HEAD"], cwd=repo, env=env,
    ).stdout.decode().strip()

    git(["push", "-u", "origin", "main"], cwd=repo, env=env)

    # Cold-clone so mount goes through the same network reconstruction path
    # a fresh user would hit (no chunk cache, no manifests).
    clone_path, clone_env, _cache = init_repo_for_clone(
        work_root=work_root, client=client, server=server,
        owner=E2E_OWNER, repo=E2E_REPO_3, name="mount-diff-mixed-clone",
    )
    mount_root = work_root / "mount-diff-mixed-points"
    mount_root.mkdir(exist_ok=True)

    # `kind` distinguishes the comparison path: plain files round-trip
    # through gix's ODB so `git show` returns the literal bytes; bale files
    # store a pointer JSON in the ODB and the mount serves the reconstructed
    # content, so the right cross-check is the bytes we committed + a
    # pointer-shape assertion on what `git show` returns.
    files = [
        ("notes", ".txt", "plain", plain_v1, plain_v2),
        ("data", ".bin", "bale", bale_v1, bale_v2),
    ]

    try:
        with timings.measure(
            "mount-diff-mixed: mount + byte-for-byte verify",
            bytes_moved=2 * (len(plain_v1) + len(plain_v2) + len(bale_v1) + len(bale_v2)),
        ):
            with mount_diff_session(
                client=client, repo=clone_path, env=clone_env,
                mount_root=mount_root,
                rev_a=commit_v1, rev_b=commit_v2,
                label_a="v1", label_b="v2",
                label="mount-diff-mixed",
            ) as mp:
                names = sorted(p.name for p in mp.iterdir())
                expected = {
                    f"{stem}__{lbl}{ext}"
                    for stem, ext, _, _, _ in files
                    for lbl in ("v1", "v2")
                }
                if not expected.issubset(set(names)):
                    raise TestFailure(
                        f"mount-diff-mixed: readdir missing some of {expected}; "
                        f"got {names}"
                    )
                for stem, ext, kind, bytes_v1, bytes_v2 in files:
                    for label, expected_bytes, src_rev in (
                        ("v1", bytes_v1, commit_v1),
                        ("v2", bytes_v2, commit_v2),
                    ):
                        mounted = (mp / f"{stem}__{label}{ext}").read_bytes()
                        if mounted != expected_bytes:
                            raise TestFailure(
                                f"mount-diff-mixed: {stem}__{label}{ext} bytes "
                                f"don't match what we committed "
                                f"(got {len(mounted)} B, want {len(expected_bytes)} B; "
                                f"first 64 B mounted={mounted[:64]!r}, "
                                f"expected={expected_bytes[:64]!r})"
                            )
                        odb_blob = git(
                            ["show", f"{src_rev}:{stem}{ext}"],
                            cwd=clone_path, env=clone_env,
                        ).stdout
                        if kind == "plain":
                            # Plain blobs: the ODB stores the literal bytes,
                            # so `git show` and the mount must agree.
                            if odb_blob != mounted:
                                raise TestFailure(
                                    f"mount-diff-mixed: plain {stem}__{label}{ext} "
                                    f"mount bytes disagree with `git show "
                                    f"{src_rev[:8]}:{stem}{ext}` ({len(mounted)} "
                                    f"vs {len(odb_blob)} B)"
                                )
                        else:
                            # Bale: ODB holds a pointer JSON, mount serves the
                            # reconstructed bytes. Verify the pointer's sha256
                            # matches the content the mount reconstructed —
                            # that's the link between the two views.
                            if not is_bale_pointer(odb_blob):
                                raise TestFailure(
                                    f"mount-diff-mixed: bale {stem}{ext}@{src_rev[:8]} "
                                    f"ODB blob isn't a pointer: {odb_blob[:200]!r}"
                                )
                            pointer_sha = str(pointer_field(odb_blob, "sha256"))
                            if pointer_sha != sha256_bytes(mounted):
                                raise TestFailure(
                                    f"mount-diff-mixed: bale {stem}__{label}{ext} "
                                    f"pointer sha256 {pointer_sha} != "
                                    f"sha256(mounted bytes) {sha256_bytes(mounted)}"
                                )

                # `diff -q` exits 1 when files differ. Confirms the two
                # labelled sides really are distinct content (a wiring bug
                # that served the same blob on both sides would slip past
                # the read checks above for v1 only).
                for stem, ext, _kind, _, _ in files:
                    a = mp / f"{stem}__v1{ext}"
                    b = mp / f"{stem}__v2{ext}"
                    r = subprocess.run(
                        ["diff", "-q", str(a), str(b)],
                        capture_output=True, check=False,
                    )
                    if r.returncode != 1:
                        raise TestFailure(
                            f"mount-diff-mixed: diff -q {a.name} {b.name} "
                            f"returned {r.returncode}, expected 1 "
                            f"(stdout={r.stdout!r})"
                        )
    except MountUnavailable as e:
        info(f"-- mount-diff-mixed: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-diff-mixed: binary stderr:\n{e.stderr}")


# =============================================================================
# Adversarial phases
# =============================================================================


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
            repo, env, spec=":wrongtoken.bin",
            expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
            label="wrongtoken:after-stage",
        )
        git(["commit", "-m", "wrongtoken"], cwd=repo, env=env)
        verify_pointer_at(
            repo, env, spec="HEAD:wrongtoken.bin",
            expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
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
        repo, "wrongtoken.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="wrongtoken:after-failed-push",
    )
    verify_pointer_at(
        repo, env, spec="HEAD:wrongtoken.bin",
        expected_sha=payload_sha, expected_size=SMALL_FILE_BYTES,
        label="wrongtoken:after-failed-push",
    )


def phase_adversarial_tampered_xorb(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Corrupt one xorb on disk (we own the bind-mounted data dir), then
    cold-clone in a fresh worktree. The smudge must NOT silently produce
    wrong bytes — it must either error or produce content whose sha256 the
    test detects as wrong."""
    xorbs_dir = server.data_root / "xorbs"
    victim: Optional[Path] = None
    for cur, _dirs, files in os.walk(xorbs_dir):
        for f in files:
            victim = Path(cur) / f
            break
        if victim is not None:
            break
    if victim is None:
        raise TestFailure("no xorb on disk to tamper with")
    info(f"  flipping the last byte of {victim.relative_to(server.data_root)}")
    original = victim.read_bytes()
    if len(original) == 0:
        raise TestFailure("victim xorb is empty")
    tampered = bytearray(original)
    tampered[-1] ^= 0xFF
    victim.write_bytes(bytes(tampered))

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
        victim.write_bytes(original)


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
                repo, env, spec=":fatfile.bin",
                expected_sha=payload_sha, expected_size=BIG_FILE_BYTES,
                label="quota:after-stage",
            )
            git(["commit", "-m", "fatfile"], cwd=repo, env=env)
            verify_pointer_at(
                repo, env, spec="HEAD:fatfile.bin",
                expected_sha=payload_sha, expected_size=BIG_FILE_BYTES,
                label="quota:after-commit",
            )
            completed = git(
                ["push", "-u", "origin", "main"],
                cwd=repo,
                env=env,
                expect_fail=True,
            )
        if completed.returncode == 0:
            raise TestFailure(
                "push past the 1 KiB quota unexpectedly succeeded"
            )
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
            repo, "fatfile.bin",
            expected_sha=payload_sha, expected_size=BIG_FILE_BYTES,
            label="quota:after-failed-push",
        )
        verify_pointer_at(
            repo, env, spec="HEAD:fatfile.bin",
            expected_sha=payload_sha, expected_size=BIG_FILE_BYTES,
            label="quota:after-failed-push",
        )
    finally:
        server.stop()


# =============================================================================
# Failure-recovery phases (server crash, connection drop, transient DB failure)
# =============================================================================


def _start_push_background(
    repo: Path, env: dict
) -> subprocess.Popen:
    """Spawn `git push -u origin main` in the background so the harness can
    interrupt it while it's still streaming bytes. Stdout/stderr are captured
    so the failure mode can be inspected after the kill."""
    return subprocess.Popen(
        ["git", "push", "-u", "origin", "main"],
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def fail_fast_xet_env(env: dict) -> dict:
    """Trim xet-client's retry budget so a deliberately-broken upstream
    surfaces as a push error in ~1s instead of the default ~30–360s
    (5 attempts × exponential backoff from 3s base). Production clients
    want the generous default; the failure-recovery phases want to drive
    the failure deterministically and move on."""
    env = dict(env)
    env["HF_XET_CLIENT_RETRY_MAX_ATTEMPTS"] = "1"
    env["HF_XET_CLIENT_RETRY_BASE_DELAY"] = "100ms"
    env["HF_XET_CLIENT_RETRY_MAX_DURATION"] = "2s"
    return env


def _wait_push(proc: subprocess.Popen, timeout_s: float) -> int:
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)
        raise TestFailure(
            f"git push subprocess did not exit within {timeout_s}s; killed"
        )
    return proc.returncode


AUTHZ_HTTP_REPOS = ["authz-http/allow", "authz-http/denied", "authz-http/error"]


def _authz_http_decide(bearer: str, repo_id: str, scope: str) -> tuple[int, dict]:
    """Decision function the MockAuthzServer uses in the authz-http phase.
    Drives every branch of `HttpAuthz::check_repo_access`:
      - 200 success  -> exercise the happy path + JWT mint
      - 403 denied   -> exercise the Forbidden branch
      - 500 internal -> exercise the catch-all upstream-error branch
      - 401 unauth   -> tested via direct curl with an unknown bearer
    """
    if bearer != E2E_HUB_TOKEN:
        return 401, {"error": "unknown bearer"}
    if repo_id == "authz-http/allow":
        return 200, {"user_id": "alice"}
    if repo_id == "authz-http/denied":
        return 403, {"error": "no write grant"}
    if repo_id == "authz-http/error":
        return 500, {"error": "upstream broken"}
    return 403, {"error": f"unknown repo {repo_id!r}"}


HTTP_ORIGIN_REPO = f"{E2E_OWNER}/http-origin"


def phase_https_origin_coverage(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drive the git-bale resolver's HTTP(S)-origin auth branch. When `origin`
    is an `http://` URL the resolver gets Basic creds from `git credential
    fill`, POSTs the forge's `/info/bale/authenticate`, then exchanges the
    forge bearer for a bale token — versus the SSH `git-bale-authenticate`
    command every other phase uses. Covers resolver.rs `Http | Https` arm,
    `authenticate_http`, and `git_credential_fill`.

    `git-bale push-pending` (op=upload) and a cold smudge (op=download) both
    read `origin` and take the HTTP branch, exercising both scope arms. Neither
    transfers git refs, so a single mock endpoint suffices — no git smart-HTTP
    server needed.
    """
    owner, name = HTTP_ORIGIN_REPO.split("/", 1)
    phase_root = work_root / "https-origin"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server: Optional[ServerHandle] = None
    forge: Optional[MockForgeServer] = None
    try:
        with timings.measure("https-origin: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[HTTP_ORIGIN_REPO],
                admin_token_hex=admin_token_hex,
                name_suffix="https-origin",
            )
        forge = MockForgeServer(
            bale_href=server.public_host_url, hub_token=E2E_HUB_TOKEN
        )
        forge.start()
        info(f"https-origin: mock forge at {forge.base_url}")

        env = client.make_env()
        # The credential helper always supplies creds, but belt-and-suspenders
        # against a hang if it ever doesn't.
        env["GIT_TERMINAL_PROMPT"] = "0"
        work = work_root / "https-origin-client"
        work.mkdir()
        git(["init", "-b", "main", "."], cwd=work, env=env)
        run([str(client.git_bale_bin), "install", "--local"], cwd=work, env=env)
        cache_dir = work_root / "cache-https-origin"
        cache_dir.mkdir(exist_ok=True)
        git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=work, env=env)
        # git_credential_fill reads credential.helper from local config; this
        # canned helper hands back fixed Basic creds (the mock forge accepts
        # any) so the resolver never blocks on an interactive prompt.
        git(
            [
                "config", "--local", "credential.helper",
                "!f() { echo username=e2e; echo password=pw; }; f",
            ],
            cwd=work, env=env,
        )
        origin = f"{forge.base_url}/{owner}/{name}.git"
        git(["remote", "add", "origin", origin], cwd=work, env=env)
        (work / ".gitattributes").write_text("*.bin filter=bale -text\n")
        git(["add", ".gitattributes"], cwd=work, env=env)
        git(["commit", "-m", "enable bale filter"], cwd=work, env=env)

        payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"http-origin")
        sha = sha256_bytes(payload)
        (work / "f.bin").write_bytes(payload)
        git(["add", "f.bin"], cwd=work, env=env)  # clean → staging (offline)
        git(["commit", "-m", "add f.bin"], cwd=work, env=env)

        # Upload: push-pending resolves origin over HTTP (op=upload) and POSTs
        # xorbs/shards to the bale href the forge returned, draining staging.
        with timings.measure("https-origin: push-pending (HTTP resolve + upload)"):
            run([str(client.git_bale_bin), "push-pending"], cwd=work, env=env)

        # Download: with staging drained + caches wiped, the smudge must
        # resolve origin over HTTP (op=download) and reconstruct over the wire.
        with timings.measure("https-origin: cold smudge (HTTP resolve + reconstruct)"):
            force_resmudge_cold(
                work, env, "f.bin",
                expected_sha=sha, expected_size=SMALL_FILE_BYTES,
                label="https-origin",
            )

        ops = {op for op, _ in forge.calls}
        if "upload" not in ops or "download" not in ops:
            raise TestFailure(
                f"https-origin: forge ops {sorted(ops)} missing upload/download "
                "— the HTTP resolver branch didn't drive both scopes"
            )
        if not forge.calls or not all(had_basic for _, had_basic in forge.calls):
            raise TestFailure(
                "https-origin: a forge authenticate call arrived without Basic "
                "auth — git_credential_fill path not exercised"
            )
        info(
            f"https-origin: forge recorded {len(forge.calls)} authenticate "
            f"calls, ops={sorted(ops)}"
        )
    finally:
        if forge is not None:
            forge.stop()
        if server is not None:
            server.stop()


def phase_authz_http_coverage(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drive `bale-server-authz-http::HttpAuthz` via a Python mock of the
    upstream /check_access endpoint. The server container is brought up
    with `BALE_AUTHZ_HTTP_URL` set, which makes the bin choose the HTTP
    branch in main.rs (winning over `BALE_GRANTS`). One container, three
    push attempts against three repos so the mock can vary the response.
    Plus one direct probe with a bogus bearer to hit the 401 branch."""
    phase_root = work_root / "authz-http"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()

    mock = MockAuthzServer(_authz_http_decide)
    mock.start()
    info(f"authz-http: mock listening at {mock.url}")
    server: Optional[ServerHandle] = None
    try:
        with timings.measure("authz-http: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=AUTHZ_HTTP_REPOS,
                admin_token_hex=admin_token_hex,
                name_suffix="authz-http",
                extra_env={"BALE_AUTHZ_HTTP_URL": mock.url},
            )

        def _push_small(repo_name: str, *, expect_fail: bool, label: str) -> None:
            owner, name = repo_name.split("/", 1)
            repo, env = init_repo_for_push(
                work_root=work_root, client=client, server=server,
                owner=owner, repo=name, name=f"authz-http-{name}",
            )
            payload = deterministic_payload(SMALL_FILE_BYTES, seed=label.encode())
            (repo / "f.bin").write_bytes(payload)
            git(["add", "f.bin"], cwd=repo, env=env)
            git(["commit", "-m", label], cwd=repo, env=env)
            with timings.measure(f"authz-http: push {label}"):
                completed = git(
                    ["push", "-u", "origin", "main"],
                    cwd=repo, env=env, expect_fail=True,
                )
            if expect_fail and completed.returncode == 0:
                raise TestFailure(
                    f"authz-http: push to {repo_name} unexpectedly succeeded "
                    f"({label})"
                )
            if not expect_fail and completed.returncode != 0:
                raise TestFailure(
                    f"authz-http: push to {repo_name} failed (exit "
                    f"{completed.returncode}):\nstdout={completed.stdout!r}\n"
                    f"stderr={completed.stderr!r}"
                )

        _push_small("authz-http/allow", expect_fail=False, label="allow")
        _push_small("authz-http/denied", expect_fail=True, label="denied")
        _push_small("authz-http/error", expect_fail=True, label="error")

        # 401 branch — direct token-mint probe with an unknown hub bearer.
        # Going via the git client would require overriding the baked-in
        # `git-bale-authenticate` script in the image, which isn't worth
        # the complexity for a single status-code branch.
        with timings.measure("authz-http: 401 probe (unknown bearer)"):
            req = urllib.request.Request(
                f"{server.public_host_url}/api/models/authz-http/allow/"
                f"bale-write-token/main",
                headers={"Authorization": "Bearer not-the-right-bearer"},
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    raise TestFailure(
                        f"authz-http: 401 probe unexpectedly got "
                        f"{resp.status}"
                    )
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    raise TestFailure(
                        f"authz-http: 401 probe got HTTP {e.code}, "
                        f"expected 401"
                    )

        statuses = [s for *_, s in mock.calls]
        info(f"authz-http: mock recorded {len(mock.calls)} calls, statuses={statuses}")
        for expected in (200, 401, 403, 500):
            if expected not in statuses:
                raise TestFailure(
                    f"authz-http: mock never returned {expected} — "
                    f"branch coverage incomplete (saw {statuses})"
                )
    finally:
        if server is not None:
            server.stop()
        mock.stop()


def phase_failure_server_kill_mid_upload(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Crash the server mid-upload, bring it back, and verify the user can
    re-run `git push` and recover. A throttled TCP proxy in front of the
    CAS port gives us a multi-second upload window on localhost (without
    it, a 4 MiB push to 127.0.0.1 finishes in tens of milliseconds and
    racing the kill is hopeless). When the proxy has seen the first byte
    of the request body we SIGKILL the container — guaranteeing the
    upload is mid-stream, the server-side put_xorb hasn't run, and
    push-pending must error out without draining staging."""
    phase_root = work_root / "failure-kill"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    cas_port = pick_free_port()
    ssh_port = pick_free_port()
    proxy_port = pick_free_port()
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=cas_port,
        # ~1 MiB/s. 4 MiB payload → ~4s upload, plenty of room to kill
        # mid-stream without making the suite uncomfortably slow.
        throttle_bytes_per_sec=1024 * 1024,
    )
    proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=f"kill-mid-upload-{secrets.token_hex(3)}",
        public_host_url_override=proxy_url,
    )
    new_server: Optional[ServerHandle] = None
    payload_size = 4 * 1024 * 1024
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="kill-mid-upload-client",
        )
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(payload_size, seed=b"kill-mid-upload")
        payload_sha = sha256_bytes(payload)
        (repo / "killtest.bin").write_bytes(payload)
        with timings.measure("failure-kill: stage + commit", bytes_moved=payload_size):
            git(["add", "killtest.bin"], cwd=repo, env=env)
            git(["commit", "-m", "kill mid-upload"], cwd=repo, env=env)
        verify_pointer_at(
            repo, env, spec="HEAD:killtest.bin",
            expected_sha=payload_sha, expected_size=payload_size,
            label="failure-kill:after-commit",
        )

        # Start the push, wait for the proxy to start seeing upload bytes,
        # then SIGKILL the server (`podman rm -f` defaults to SIGKILL).
        # The threshold is tiny — once bytes are flowing, the throttle
        # gives us ample headroom before the request body fully lands.
        with timings.measure("failure-kill: push then crash"):
            proc = _start_push_background(repo, env)
            try:
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.02)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"proxy never saw ≥64 KiB within 15s "
                        f"(seen {proxy.bytes_forwarded})"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise
            info("  killing server mid-upload")
            server.stop()
            # Also slam the proxy: with the upstream dead, xet-data's
            # built-in retry loop would otherwise keep reconnecting
            # through the still-listening proxy until its retry budget
            # ran out — a 30–60s hang that masks the real failure.
            # Killing the proxy makes the next connect refuse instantly,
            # so the client surfaces a transport error promptly.
            proxy.kill()
            rc = _wait_push(proc, timeout_s=30.0)
            if rc == 0:
                raise TestFailure(
                    "push subprocess unexpectedly succeeded despite mid-upload "
                    "server kill"
                )

        if not staging_files(repo):
            raise TestFailure(
                "failure-kill: staging dir empty after crashed push — "
                "push-pending drained staging before the upload finalized"
            )
        verify_worktree(
            repo, "killtest.bin",
            expected_sha=payload_sha, expected_size=payload_size,
            label="failure-kill:after-crashed-push",
        )
        verify_pointer_at(
            repo, env, spec="HEAD:killtest.bin",
            expected_sha=payload_sha, expected_size=payload_size,
            label="failure-kill:after-crashed-push",
        )

        # Restart the proxy BEFORE the container: start_container waits
        # for /healthz at the public_host_url, which we've overridden to
        # the proxy URL — so the proxy has to be listening (and able to
        # forward to the new container's cas_port) before that check can
        # succeed.
        proxy.start()
        with timings.measure("failure-kill: restart server"):
            new_server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
                cas_port=cas_port,
                ssh_port=ssh_port,
                admin_token_hex=admin_token_hex,
                name_suffix=f"kill-mid-upload-restart-{secrets.token_hex(3)}",
                public_host_url_override=proxy_url,
            )

        # Retry. Content-addressed: any xorbs that landed before the crash
        # will be re-POSTed with `was_inserted=false` (or the server's
        # crash truncated the on-disk write, in which case the body is
        # missing and the re-upload writes the full bytes). Either way,
        # the final state has the full content available.
        with timings.measure(
            "failure-kill: retry push after restart", bytes_moved=payload_size
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "failure-kill: staging dir not drained after successful retry"
            )

        # Cold-clone in a fresh worktree to confirm the file genuinely
        # reconstructs from server-side state — not a hot-cache illusion
        # in the original push client.
        with timings.measure(
            "failure-kill: cold clone after recovery", bytes_moved=payload_size
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=new_server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="kill-mid-upload-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "killtest.bin",
            expected_sha=payload_sha, expected_size=payload_size,
            label="failure-kill:after-recovery-clone",
        )
    finally:
        proxy.kill()
        if new_server is not None:
            new_server.stop()
        else:
            server.stop()


def phase_failure_connection_drop_mid_upload(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drop the client→server TCP connection mid-upload while the server
    itself stays running. Uses a small in-process TCP proxy as the
    advertised CAS URL: kill()ing the proxy slams every socket without a
    FIN, mimicking a sudden network drop. The proxy is then restarted and
    the retry must succeed, with no server-side intervention needed."""
    phase_root = work_root / "failure-conndrop"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    cas_port = pick_free_port()
    ssh_port = pick_free_port()
    proxy_port = pick_free_port()
    proxy = TcpProxy(
        listen_port=proxy_port,
        upstream_host="127.0.0.1",
        upstream_port=cas_port,
        throttle_bytes_per_sec=1024 * 1024,
    )
    proxy.start()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    payload_size = 4 * 1024 * 1024
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        cas_port=cas_port,
        ssh_port=ssh_port,
        admin_token_hex=admin_token_hex,
        name_suffix=f"conndrop-{secrets.token_hex(3)}",
        # BALE_PUBLIC_HOST_URL is what the SSH forge-auth script returns
        # to the client. Pointing it at the proxy means every CAS request
        # the client makes flows through us — so we can sever them.
        public_host_url_override=proxy_url,
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="conndrop-client",
        )
        env = fail_fast_xet_env(env)
        payload = deterministic_payload(payload_size, seed=b"conndrop")
        payload_sha = sha256_bytes(payload)
        (repo / "conndrop.bin").write_bytes(payload)
        with timings.measure("failure-conndrop: stage + commit", bytes_moved=payload_size):
            git(["add", "conndrop.bin"], cwd=repo, env=env)
            git(["commit", "-m", "conndrop mid-upload"], cwd=repo, env=env)

        with timings.measure("failure-conndrop: push then drop"):
            proc = _start_push_background(repo, env)
            try:
                # Wait for the proxy to actually forward something — proves
                # the in-flight upload is mid-stream, not still in the
                # client's CDC pre-processing.
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    if proxy.bytes_forwarded >= 64 * 1024:
                        break
                    time.sleep(0.05)
                if proxy.bytes_forwarded < 64 * 1024:
                    raise TestFailure(
                        f"proxy never forwarded ≥64 KiB within 15s "
                        f"(seen {proxy.bytes_forwarded})"
                    )
            except TestFailure:
                proc.kill()
                proc.wait(timeout=2.0)
                raise
            info("  dropping all connections via proxy.kill()")
            proxy.kill()
            rc = _wait_push(proc, timeout_s=30.0)
            if rc == 0:
                raise TestFailure(
                    "push subprocess unexpectedly succeeded despite mid-upload "
                    "connection drop"
                )
        if not staging_files(repo):
            raise TestFailure(
                "failure-conndrop: staging dir empty after dropped push"
            )
        # Confirm the server itself is still healthy — the whole point of
        # this phase versus the kill phase is the server stays up. Bypass
        # the (just-killed) proxy by hitting the container's mapped cas
        # port directly; server.healthz_url goes through the proxy URL.
        direct_healthz = f"http://127.0.0.1:{server.cas_port}/healthz"
        with urllib.request.urlopen(direct_healthz, timeout=5) as resp:
            if resp.status != 200:
                raise TestFailure(
                    f"server unhealthy after connection drop: {resp.status}"
                )

        # Bring the proxy back and retry. No container restart, no JWT
        # refresh — the previously-resolved token is still valid (JWTs
        # carry a 1-hour TTL by default) and the retry should reuse it.
        proxy.start()
        with timings.measure(
            "failure-conndrop: retry push after proxy restart",
            bytes_moved=payload_size,
        ):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "failure-conndrop: staging dir not drained after successful retry"
            )
        with timings.measure(
            "failure-conndrop: cold clone after recovery", bytes_moved=payload_size
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="conndrop-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "conndrop.bin",
            expected_sha=payload_sha, expected_size=payload_size,
            label="failure-conndrop:after-recovery-clone",
        )
    finally:
        proxy.kill()
        server.stop()


def phase_failure_transient_db(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Force SQLITE_BUSY transiently while a push is in flight. The user-side
    push should succeed: sqlx's busy_timeout (5s default) gives the server
    enough headroom to wait out the contention without surfacing an error.

    Uses a small file so the upload completes quickly once the lock is
    released — and asserts the wallclock is ≥ the lock-hold duration, which
    is what proves the server actually waited for the busy DB instead of
    racing past it on a separate connection."""
    phase_root = work_root / "failure-dbbusy"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix=f"dbbusy-{secrets.token_hex(3)}",
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="dbbusy-client",
        )
        # Use a medium-sized payload (1 MiB): big enough to take real DB
        # writes (xorb_frames row, files row, file_terms rows), small enough
        # that the upload itself finishes fast and the wallclock is
        # dominated by the lock-hold window.
        payload_size = 1 * 1024 * 1024
        payload = deterministic_payload(payload_size, seed=b"dbbusy")
        payload_sha = sha256_bytes(payload)
        (repo / "dbbusy.bin").write_bytes(payload)
        with timings.measure("failure-dbbusy: stage + commit", bytes_moved=payload_size):
            git(["add", "dbbusy.bin"], cwd=repo, env=env)
            git(["commit", "-m", "dbbusy"], cwd=repo, env=env)

        hold_seconds = 2.0
        t0 = time.perf_counter()
        with timings.measure("failure-dbbusy: push while DB writer-locked"):
            with hold_db_writer_lock(server, hold_seconds=hold_seconds):
                # Lock is held NOW. Run push synchronously inside the
                # context so the server's DB writes hit SQLITE_BUSY and
                # rely on sqlx's busy_timeout to wait out the lock.
                git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        push_elapsed = time.perf_counter() - t0

        # The whole-push wallclock must be ≥ the lock-hold window — if it
        # finished faster, the server somehow didn't actually contend with
        # the sidecar lock and the test was vacuous. We don't bound the
        # upper end: SQLite serializes writers and the post-release work
        # can take real time.
        if push_elapsed < hold_seconds * 0.8:
            raise TestFailure(
                f"failure-dbbusy: push finished in {push_elapsed:.2f}s but "
                f"lock was held for {hold_seconds:.2f}s — the server's "
                "writes didn't actually wait on the writer lock"
            )
        info(f"  push wallclock {push_elapsed:.2f}s (lock held {hold_seconds:.1f}s)")
        if staging_files(repo):
            raise TestFailure(
                "failure-dbbusy: staging not drained — push reported success "
                "but push-pending didn't finalize"
            )
        # Verify the file actually round-tripped: cold-clone in a fresh
        # worktree and check the bytes against the original.
        with timings.measure(
            "failure-dbbusy: cold clone", bytes_moved=payload_size
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="dbbusy-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path, "dbbusy.bin",
            expected_sha=payload_sha, expected_size=payload_size,
            label="failure-dbbusy:after-clone",
        )
    finally:
        server.stop()


# =============================================================================
# Top-level orchestration
# =============================================================================


# =============================================================================
# gc phases (staging-area reconciliation)
# =============================================================================
#
# `git add` stages a bale file's xorbs/shards offline under
# `.git/bale/staging/`; only a successful `git push` (pre-push hook running
# `git-bale push-pending`) drains them. Abandoning a staged change (`git
# reset` + `git checkout`) used to leak those bytes forever. `git-bale gc`
# reconciles staging against git reachability; the post-checkout/-commit/-merge
# hooks installed by `install --local` run it. Each phase owns its own bare
# repo so they're independent of the push-side phases and of each other.


def phase_gc_abandon_checkout(
    *, timings: Timings, server: ServerHandle, client: ClientEnv, work_root: Path
) -> None:
    """The user-reported bug: stage a change, then abandon it entirely. The
    post-checkout hook's gc must sweep the orphaned staging.

    The baseline v1 is pushed first, so push-pending has already wiped its
    staging and v1 lives on the server. After abandoning v2 there is nothing
    left in git that references any staged bytes → gc does a full wipe."""
    with timings.measure("gc-abandon-checkout"):
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_GC1, name="gc-abandon",
        )
        rel = "big.bin"
        v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-abandon-v1")
        v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-abandon-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "add big v1"], cwd=repo, env=env)
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        if staging_files(repo):
            raise TestFailure(
                "[gc-abandon] precondition: push should have drained staging, "
                f"but xorbs/shards remain: {[str(p) for p in staging_files(repo)]}"
            )

        # Stage a change...
        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        if not staging_files(repo):
            raise TestFailure("[gc-abandon] git add should have staged v2 xorbs")
        if not staged_markers(repo):
            raise TestFailure("[gc-abandon] git add should have written a marker")

        # ...then abandon it: unstage, then discard the worktree edit. The
        # `git checkout` fires the post-checkout hook → `git-bale gc`.
        git(["reset"], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)

        leftover = staging_files(repo)
        if leftover:
            raise TestFailure(
                "[gc-abandon] staging not reclaimed after the change was "
                f"discarded; orphaned objects remain: {[str(p) for p in leftover]}"
            )
        if staged_markers(repo):
            raise TestFailure(
                f"[gc-abandon] stale markers survived the discard: {staged_markers(repo)}"
            )
        # Worktree is back to v1.
        verify_worktree(
            repo, rel, expected_sha=sha256_bytes(v1),
            expected_size=len(v1), label="gc-abandon",
        )
        info("[gc-abandon] orphaned staging swept; v1 worktree intact")


def phase_gc_keeps_unpushed(
    *, timings: Timings, server: ServerHandle, client: ClientEnv, work_root: Path
) -> None:
    """DATA-LOSS GUARD. Two stacked commits, neither pushed: C1 adds v1, C2
    changes it to v2. The branch tip references only v2, but a future `git
    push` uploads BOTH commits, so v1's staged bytes are still needed. A
    naive cleanup keyed on the worktree/tip would drop v1 and silently
    corrupt history; gc must keep it.

    Proof is end-to-end: after gc, push both commits, cold-clone, and check
    out every revision — if v1 had been dropped the server would lack it and
    the C1 checkout would fail or mismatch."""
    with timings.measure("gc-keeps-unpushed"):
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_GC2, name="gc-keep",
        )
        rel = "data.bin"
        v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-keep-v1")
        v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-keep-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "data v1"], cwd=repo, env=env)
        c1 = git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
        h1 = pointer_hash_at(repo, env, f"HEAD:{rel}", label="gc-keep")

        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "data v2"], cwd=repo, env=env)
        c2 = git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
        h2 = pointer_hash_at(repo, env, f"HEAD:{rel}", label="gc-keep")

        before = staged_markers(repo)
        if not {h1, h2} <= before:
            raise TestFailure(
                "[gc-keep] precondition: both unpushed versions should be "
                f"staged; want {{{h1[:8]}.., {h2[:8]}..}} have {before}"
            )

        # Manual gc — the tip only references v2, but v1 lives in unpushed C1.
        run([str(client.git_bale_bin), "gc"], cwd=repo, env=env)

        after = staged_markers(repo)
        if not {h1, h2} <= after:
            raise TestFailure(
                "[gc-keep] DATA LOSS: gc dropped a marker for committed-but-"
                f"unpushed content. before={before} after={after}"
            )

        # Push both commits, cold-clone, verify EVERY revision reconstructs.
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        clone, cenv, _cache = init_repo_for_clone(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_GC2, name="gc-keep-clone",
        )
        git(["checkout", c1], cwd=clone, env=cenv)
        verify_worktree(
            clone, rel, expected_sha=sha256_bytes(v1),
            expected_size=len(v1), label="gc-keep@C1",
        )
        git(["checkout", c2], cwd=clone, env=cenv)
        verify_worktree(
            clone, rel, expected_sha=sha256_bytes(v2),
            expected_size=len(v2), label="gc-keep@C2",
        )
        info("[gc-keep] unpushed v1 survived gc; all revisions reconstruct")


def phase_gc_mixed(
    *, timings: Timings, server: ServerHandle, client: ClientEnv, work_root: Path
) -> None:
    """The mixed case: one committed-but-unpushed version (must survive) plus
    one staged-then-abandoned version (must be forgotten). gc keeps the live
    marker and drops only the dangling one; v1 stays pushable + reconstructable."""
    with timings.measure("gc-mixed"):
        repo, env = init_repo_for_push(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_GC3, name="gc-mixed",
        )
        rel = "m.bin"
        v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-mixed-v1")
        v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"gc-mixed-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "m v1"], cwd=repo, env=env)  # committed, NOT pushed
        h1 = pointer_hash_at(repo, env, f"HEAD:{rel}", label="gc-mixed")

        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)  # staged, never committed
        h2 = pointer_hash_at(repo, env, f":{rel}", label="gc-mixed")
        if h1 == h2:
            raise TestFailure("[gc-mixed] v1 and v2 unexpectedly hash-collided")

        git(["reset"], cwd=repo, env=env)               # unstage v2 (now dangling)
        git(["checkout", "--", rel], cwd=repo, env=env)  # restore v1; fires gc hook

        markers = staged_markers(repo)
        if h1 not in markers:
            raise TestFailure(
                "[gc-mixed] DATA LOSS: gc dropped the committed-but-unpushed "
                f"v1 marker {h1[:8]}..; markers={markers}"
            )
        if h2 in markers:
            raise TestFailure(
                "[gc-mixed] gc kept the abandoned (never-committed) v2 marker "
                f"{h2[:8]}..; markers={markers}"
            )

        # v1 still uploads and reconstructs after a cold clone.
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        clone, cenv, _cache = init_repo_for_clone(
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO_GC3, name="gc-mixed-clone",
        )
        git(["checkout", "main"], cwd=clone, env=cenv)
        verify_worktree(
            clone, rel, expected_sha=sha256_bytes(v1),
            expected_size=len(v1), label="gc-mixed",
        )
        info("[gc-mixed] live v1 kept, dangling v2 dropped, v1 reconstructs")


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


# =============================================================================
# Phase registry + ordering
# =============================================================================

# A phase has:
#   name:      CLI-visible identifier (matches --skip filters)
#   group:     "g1" (independent push-side), "g2-head" (always first in g2),
#              "g2-tail" (depends on bigfile's rev_state), "g3" (isolated)
#   read_only: True for phases that don't mutate server state from the client
#              side; these are the only ones a --reuse-from run is allowed to
#              execute. False = phase pushes new commits or boots a fresh
#              container with empty data.
#
# Group ORDER is fixed: g1 → g2-head → g2-tail → g3. Within each group the
# order is determined by --order. g2-head only ever holds bigfile (so it's a
# noop group for reordering), but it lets us guarantee bigfile runs before
# anything that consumes rev_state without making the ordering function
# inspect dependencies.

PHASE_GROUPS_ORDER = ["g1", "g2-head", "g2-tail", "g3"]


def order_within_group(phases: list[str], order: str, rng: random.Random) -> list[str]:
    if order == "forward":
        return list(phases)
    if order == "reverse":
        return list(reversed(phases))
    if order == "random":
        out = list(phases)
        rng.shuffle(out)
        return out
    raise ValueError(f"unknown order: {order!r}")


# =============================================================================
# Multi-run state stash (for --state-dir / --reuse-from)
# =============================================================================


STATE_FILE = ".e2e_state.json"


def save_state(
    state_dir: Path,
    *,
    jwt_secret_hex: str,
    transfer_secret_hex: str,
    admin_token_hex: str,
    rev_state: dict,
) -> None:
    """Persist the bits a follow-up --reuse-from run needs: server-side
    secrets so JWT/transfer signatures stay valid against the same data
    dir, and rev_state's shas/commits so read-only phases know what to
    expect from the already-pushed history."""
    payload = {
        "jwt_secret_hex": jwt_secret_hex,
        "transfer_secret_hex": transfer_secret_hex,
        "admin_token_hex": admin_token_hex,
        # rev_state contains Paths and a dict env; strip to the JSON-friendly
        # subset the read-only phases actually consume.
        "rev_state": {
            "shas": list(rev_state.get("shas", [])),
            "commits": list(rev_state.get("commits", [])),
            "disk_after": list(rev_state.get("disk_after", [])),
            "raw_after": list(rev_state.get("raw_after", [])),
        },
    }
    (state_dir / STATE_FILE).write_text(json.dumps(payload, indent=2))


def load_state(state_dir: Path) -> dict:
    return json.loads((state_dir / STATE_FILE).read_text())


# =============================================================================
# main()
# =============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-bale", default=None)
    parser.add_argument("--image-tag", default=DEFAULT_IMAGE_TAG)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--keep-tmpdir", action="store_true")
    parser.add_argument(
        "--skip", action="append", default=[],
        help="Phase name(s) to skip (repeat the flag for multiple).",
    )
    parser.add_argument(
        "--order", choices=["forward", "reverse", "random"], default="forward",
        help="Within-group phase order. Group order itself is always fixed.",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Seed for --order=random (so a failing matrix run reproduces).",
    )
    parser.add_argument(
        "--state-dir", default=None,
        help="Use this path as the work directory instead of mkdtemp, and "
             "leave it intact on exit. Writes .e2e_state.json with secrets + "
             "rev_state so a follow-up --reuse-from run can continue.",
    )
    parser.add_argument(
        "--reuse-from", default=None,
        help="Reuse the data dir + git-home + secrets from a prior run "
             "(must have been launched with --state-dir). Only `read_only` "
             "phases are eligible to run in this mode.",
    )
    parser.add_argument(
        "--coverage", action="store_true",
        help="Build instrumented binaries (-C instrument-coverage) for both "
             "git-bale and the server, collect .profraw files into the "
             "coverage dir, and generate an HTML report at teardown. "
             "Builds use a separate target dir and image tag so the prod "
             "release/stripped path is left intact.",
    )
    parser.add_argument(
        "--coverage-dir", default=None,
        help="Where to put coverage profiles + the HTML report. Defaults "
             "to <repo>/target/coverage-e2e/. Implies --coverage.",
    )
    args = parser.parse_args()
    if args.coverage_dir and not args.coverage:
        args.coverage = True

    if args.reuse_from and args.state_dir:
        die("--reuse-from and --state-dir are mutually exclusive")

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
    # a separate image tag, and arms _COVERAGE so start_container bind-mounts
    # the profile dir into every server container. The prod (default) path
    # is unchanged.
    image_tag = args.image_tag
    global _COVERAGE
    if args.coverage:
        if args.image_tag != DEFAULT_IMAGE_TAG:
            die("--coverage manages its own image tag; --image-tag is ignored. "
                "Remove one of the two.")
        if args.git_bale:
            die("--coverage builds its own instrumented git-bale; "
                "remove --git-bale.")
        _COVERAGE = setup_coverage(
            rt,
            coverage_dir_arg=args.coverage_dir,
            no_build=args.no_build,
        )
        git_bale_bin = _COVERAGE.git_bale_bin
        image_tag = COVERAGE_IMAGE_TAG
        # Host-side processes (git, git-bale spawned by git, the pre-push
        # hook) inherit os.environ unless a call site builds an explicit
        # env dict — and the ones that do (`ClientEnv.make_env`) start
        # from `os.environ.copy()`, so this propagates.
        os.environ["LLVM_PROFILE_FILE"] = _COVERAGE.host_profile_template
        info(f"coverage: profile dir = {_COVERAGE.profile_dir}")
        info(f"coverage: report will be at {_COVERAGE.html_out / 'index.html'}")
        # The failure-* phases SIGKILL the server (or kill a sidecar
        # container) — the LLVM atexit hook can't flush profraws on
        # SIGKILL, and these paths are exercised by other phases anyway.
        # Skip them unless the user opted in via --no-skip-failure-phases
        # (not exposed; reorder the if to override).
        for name in ("failure-kill", "failure-conndrop", "failure-dbbusy"):
            if name not in args.skip:
                args.skip.append(name)
        info("coverage: auto-skipping failure-kill / -conndrop / -dbbusy "
             "(server SIGKILL drops profraws)")
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
    exit_code = 0
    rev_state: dict = {}
    if reused is not None:
        # Seed rev_state from disk so read-only phases (clone, tampered-xorb)
        # know what to verify against.
        rev_state.update(reused.get("rev_state", {}))

    try:
        client = setup_client(work_root=work_root, git_bale_bin=git_bale_bin)
        ssh_public_key = client.ssh_pub.read_text().strip()
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
                    f"{E2E_OWNER}/{E2E_REPO_GC1}",
                    f"{E2E_OWNER}/{E2E_REPO_GC2}",
                    f"{E2E_OWNER}/{E2E_REPO_GC3}",
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
                timings=timings, server=server, client=client, work_root=work_root,
            )

        def _phase_wrong_token() -> None:
            phase_adversarial_wrong_token(
                timings=timings, server=server, client=client, work_root=work_root,
            )

        def _phase_spilled() -> None:
            phase_spilled_clean(
                timings=timings, server=server, client=client, work_root=work_root,
            )

        def _phase_bigfile() -> None:
            nonlocal rev_state
            rev_state = phase_big_file_dedup(
                timings=timings, server=server, client=client,
                work_root=work_root, bale_admin_token=admin_jwt,
            )

        def _phase_usage() -> None:
            phase_usage_api(
                timings=timings, server=server,
                bale_admin_token=admin_jwt, rev_state=rev_state,
            )

        def _phase_browser_download() -> None:
            phase_browser_file_download(
                timings=timings, server=server, rev_state=rev_state,
            )

        def _phase_dedup() -> None:
            phase_dedup_duplicate_file(
                timings=timings, server=server, rev_state=rev_state,
            )

        def _phase_idempotency() -> None:
            phase_push_idempotency(
                timings=timings, server=server, rev_state=rev_state,
            )

        def _phase_clone() -> None:
            phase_clone_and_verify_history(
                timings=timings, server=server, client=client,
                work_root=work_root, rev_state=rev_state,
            )

        def _phase_offline_restart() -> None:
            nonlocal server
            server = phase_offline_and_restart(
                timings=timings, server=server, rt=rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret_hex,
                transfer_secret_hex=transfer_secret_hex,
                client=client, ssh_public_key=ssh_public_key,
                work_root=work_root, rev_state=rev_state,
                cas_port=cas_port, ssh_port=ssh_port,
                admin_token_hex=admin_token_hex,
            )

        def _phase_tampered_xorb() -> None:
            phase_adversarial_tampered_xorb(
                timings=timings, server=server, client=client,
                work_root=work_root, rev_state=rev_state,
            )

        def _phase_mount_rev() -> None:
            phase_mount_rev(
                timings=timings, server=server, client=client,
                work_root=work_root, rev_state=rev_state,
            )

        def _phase_mount_diff() -> None:
            phase_mount_diff(
                timings=timings, server=server, client=client,
                work_root=work_root, rev_state=rev_state,
            )

        def _phase_mount_diff_mixed() -> None:
            phase_mount_diff_mixed(
                timings=timings, server=server, client=client,
                work_root=work_root,
            )

        def _phase_quota() -> None:
            phase_adversarial_quota_exceeded(
                timings=timings, rt=rt, image_tag=image_tag,
                work_root=work_root, client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_kill() -> None:
            phase_failure_server_kill_mid_upload(
                timings=timings, rt=rt, image_tag=image_tag,
                work_root=work_root, client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_conndrop() -> None:
            phase_failure_connection_drop_mid_upload(
                timings=timings, rt=rt, image_tag=image_tag,
                work_root=work_root, client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_failure_dbbusy() -> None:
            phase_failure_transient_db(
                timings=timings, rt=rt, image_tag=image_tag,
                work_root=work_root, client=client,
                ssh_public_key=ssh_public_key,
                admin_token_hex=admin_token_hex,
            )

        def _phase_gc_abandon() -> None:
            phase_gc_abandon_checkout(
                timings=timings, server=server, client=client, work_root=work_root,
            )

        def _phase_gc_keep() -> None:
            phase_gc_keeps_unpushed(
                timings=timings, server=server, client=client, work_root=work_root,
            )

        def _phase_gc_mixed() -> None:
            phase_gc_mixed(
                timings=timings, server=server, client=client, work_root=work_root,
            )

        # name -> (group, read_only, fn)
        REGISTRY: dict[str, tuple[str, bool, Callable[[], None]]] = {
            "basic":           ("g1",      False, _phase_basic),
            "wrong-token":     ("g1",      False, _phase_wrong_token),
            "bigfile":         ("g2-head", False, _phase_bigfile),
            "usage":           ("g2-tail", True,  _phase_usage),
            # Dereferences rev_state["repo_path"]/["env"] (the live bigfile
            # client repo) to read the pushed pointer's file id, so — like
            # idempotency — it can't run from a --reuse-from (hence not
            # read_only). Streams 35 MB back through the reconstruction path.
            "browser-download": ("g2-tail", False, _phase_browser_download),
            "dedup":           ("g2-tail", False, _phase_dedup),
            # idempotency dereferences rev_state["repo_path"] (the bigfile
            # client repo from the same process), so it can't run from a
            # --reuse-from where rev_state was reconstructed from JSON.
            "idempotency":     ("g2-tail", False, _phase_idempotency),
            "clone":           ("g2-tail", True,  _phase_clone),
            "offline-restart": ("g2-tail", True,  _phase_offline_restart),
            "tampered-xorb":   ("g2-tail", True,  _phase_tampered_xorb),
            # Read-only FUSE mounts of pushed history. Skip cleanly when the
            # host has no libfuse / fuse-t installed.
            "mount-rev":       ("g2-tail", True,  _phase_mount_rev),
            "mount-diff":      ("g2-tail", True,  _phase_mount_diff),
            "quota":           ("g3",      False, _phase_quota),
            # Independent (own repo + commits), so g3 — not read-only because
            # it pushes new history that other phases shouldn't see.
            "mount-diff-mixed": ("g3",     False, _phase_mount_diff_mixed),
            # Own repo + commits, forces the clean filter's spill path via a
            # capped BALE_MAX_INLINE_CLEAN. g3 for the same reason as above.
            "spilled-clean":   ("g3",      False, _phase_spilled),
            # Failure-recovery phases each own their own isolated container
            # + data dir, so they can crash/restart the server or block its
            # DB without disturbing earlier phases' state.
            "failure-kill":      ("g3", False, _phase_failure_kill),
            "failure-conndrop":  ("g3", False, _phase_failure_conndrop),
            "failure-dbbusy":    ("g3", False, _phase_failure_dbbusy),
            # gc staging reconciliation. Each owns its own bare repo + commits,
            # so g3 — not read-only (they push new history).
            "gc-abandon-checkout": ("g3", False, _phase_gc_abandon),
            "gc-keeps-unpushed":   ("g3", False, _phase_gc_keep),
            "gc-mixed":            ("g3", False, _phase_gc_mixed),
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

        for name in ordered:
            group, read_only, fn = REGISTRY[name]
            if name in args.skip:
                info(f"-- skipping phase {name!r} (per --skip)")
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
        if _COVERAGE is not None and not in_reuse:
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
            )
            if "authz-http" not in args.skip:
                phase_authz_http_coverage(
                    timings=timings,
                    rt=rt,
                    image_tag=image_tag,
                    work_root=work_root,
                    client=client,
                    ssh_public_key=ssh_public_key,
                    admin_token_hex=admin_token_hex,
                )
            else:
                info("-- skipping phase 'authz-http' (per --skip)")

            if "https-origin" not in args.skip:
                phase_https_origin_coverage(
                    timings=timings,
                    rt=rt,
                    image_tag=image_tag,
                    work_root=work_root,
                    client=client,
                    ssh_public_key=ssh_public_key,
                    admin_token_hex=admin_token_hex,
                )
            else:
                info("-- skipping phase 'https-origin' (per --skip)")

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
        timings.print_report()
        if _COVERAGE is not None:
            # Best-effort: don't let a broken llvm install mask phase results.
            try:
                generate_coverage_report(_COVERAGE)
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


if __name__ == "__main__":
    sys.exit(main())
