"""Read-only FUSE mount helpers shared by the mount phases."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from baleharness.client import ClientEnv
from baleharness.covstate import get_coverage
from baleharness.logutil import TestFailure, info


class MountUnavailable(Exception):
    """libfuse / fuse-t not installed on this host. The mount phase signals
    this to its caller so the whole phase skips instead of failing.

    `stderr` carries the binary's full stderr so the skip handler can log
    everything — under --coverage a mount-up timeout previously surfaced as
    a single-line "skipped" without any clue what the binary was doing."""

    def __init__(self, reason: str, *, stderr: str = "") -> None:
        super().__init__(reason)
        self.stderr = stderr


# git-bale's mount backends print one of these when their FS driver can't be
# loaded — libfuse/fuse-t on POSIX, WinFsp on Windows. Either means "skip".
_LIBFUSE_HINT = "needs libfuse at runtime"
_WINFSP_HINT = "needs WinFsp at runtime"


def driver_missing(err: str) -> bool:
    return _LIBFUSE_HINT in err or _WINFSP_HINT in err


def ensure_fs_driver() -> None:
    """On Windows, install WinFsp if absent (downloading the MSI) so the mount
    backend can run, raising MountUnavailable to skip if it can't be
    provisioned. No-op on POSIX — the git-bale binary's own libfuse probe
    drives the skip there."""
    if os.name != "nt":
        return
    from baleharness import winfsp as _winfsp

    try:
        _winfsp.ensure_winfsp()
    except _winfsp.WinfspUnavailable as e:
        raise MountUnavailable(f"WinFsp unavailable: {e}") from e


def _unmount_path(mount_point: Path) -> None:
    """Best-effort unmount. fusermount3 / fusermount on Linux (rootless-safe),
    plain `umount` everywhere else. Silent if not currently mounted."""
    if os.name == "nt":
        # WinFsp auto-unmounts when the hosting git-bale process exits, which
        # the session's finally block triggers; there's no fusermount step.
        return
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
    """Has the FS come up at `mount_point`? On POSIX a FUSE mount makes its
    st_dev differ from the parent's. On Windows the mount point is a directory
    WinFsp *creates* (we ensure it didn't pre-exist), so its appearance as a
    directory is the readiness signal."""
    if os.name == "nt":
        try:
            return mount_point.is_dir()
        except OSError:
            return False
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

    Raises MountUnavailable when the FS driver (libfuse/fuse-t, or WinFsp on
    Windows) is missing on the host so the caller can skip the phase."""
    ensure_fs_driver()
    mount_point = mount_root / f"mnt-{secrets.token_hex(3)}"
    if os.name == "nt":
        # WinFsp creates the mount directory itself and refuses a pre-existing
        # one, so ensure the parent exists and the target does not.
        mount_root.mkdir(parents=True, exist_ok=True)
        if mount_point.exists():
            shutil.rmtree(mount_point, ignore_errors=True)
    else:
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
        wait_timeout = 120.0 if get_coverage() is not None else 30.0
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
            if driver_missing(err_txt):
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
        if get_coverage() is not None and proc.returncode not in (0, None):
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
        client=client,
        repo=repo,
        env=env,
        mount_root=mount_root,
        argv_tail=argv,
        label=label,
    )


def mount_diff_session(
    *,
    client: ClientEnv,
    repo: Path,
    env: dict,
    mount_root: Path,
    rev_a: str,
    rev_b: str,
    label_a: Optional[str] = None,
    label_b: Optional[str] = None,
    paths: Optional[list[str]] = None,
    label: str = "mount-diff",
):
    # Omitting --label-a/--label-b lets the binary derive labels from the revs
    # via sanitize_label (mount/mod.rs); pass them to pin explicit labels.
    argv = ["mount-diff", rev_a, rev_b]
    if label_a is not None:
        argv += ["--label-a", label_a]
    if label_b is not None:
        argv += ["--label-b", label_b]
    if paths:
        argv.append("--")
        argv.extend(paths)
    return _mount_session(
        client=client,
        repo=repo,
        env=env,
        mount_root=mount_root,
        argv_tail=argv,
        label=label,
    )
