"""Read-only FUSE mount helpers shared by the mount phases."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.covstate import get_coverage
from baleharness.logutil import TestFailure, info


class MountUnavailable(Exception):
    """FS driver missing on this host: the mount phase skips instead of failing.

    `stderr` carries the binary's full stderr so the skip is diagnosable."""

    def __init__(self, reason: str, *, stderr: str = "") -> None:
        super().__init__(reason)
        self.stderr = stderr


# Printed by git-bale's mount backends when their FS driver can't be loaded.
_LIBFUSE_HINT = "needs libfuse at runtime"
_WINFSP_HINT = "needs WinFsp at runtime"


def driver_missing(err: str) -> bool:
    return _LIBFUSE_HINT in err or _WINFSP_HINT in err


def ensure_fs_driver() -> None:
    """Provision WinFsp on Windows (MountUnavailable if impossible). No-op on
    POSIX, where the binary's own libfuse probe drives the skip."""
    if os.name != "nt":
        return
    from baleharness import winfsp as _winfsp

    try:
        _winfsp.ensure_winfsp()
    except _winfsp.WinfspUnavailable as e:
        raise MountUnavailable(f"WinFsp unavailable: {e}") from e


def _unmount_path(mount_point: Path) -> None:
    """Best-effort; fusermount first because it's rootless-safe on Linux."""
    if os.name == "nt":
        # WinFsp unmounts when the hosting git-bale process exits.
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
    """POSIX: st_dev differs from the parent's. Windows: WinFsp creates the
    (deliberately absent) mount directory, so its appearance is the signal."""
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
            return
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
    """Run `git-bale <argv_tail> --mount <dir>` and yield the mount point once up.

    Raises MountUnavailable when the host lacks the FS driver."""
    ensure_fs_driver()
    mount_point = mount_root / f"mnt-{secrets.token_hex(3)}"
    if os.name == "nt":
        # WinFsp creates the mount directory itself and refuses a pre-existing one.
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
        # llvm-cov slows the binary ~5x on macOS; 30s would expire before
        # fuse_main_real finished mounting.
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
        # Unmount first so the process exits on its own; killing it while
        # mounted can leave a stale fuse-t entry on macOS for tens of seconds.
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
        # .profraw is only written on clean exit; fuse-t SIGPIPEs the process at
        # teardown, so libfuse.rs installs a handler that flushes and _exit(0)s.
        # A non-zero exit here means that handler regressed.
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
    paths: list[str] | None = None,
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
    label_a: str | None = None,
    label_b: str | None = None,
    paths: list[str] | None = None,
    label: str = "mount-diff",
):
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
