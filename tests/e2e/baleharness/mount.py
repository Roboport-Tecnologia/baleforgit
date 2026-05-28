"""Read-only FUSE mount helpers shared by the mount phases."""
from __future__ import annotations

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

