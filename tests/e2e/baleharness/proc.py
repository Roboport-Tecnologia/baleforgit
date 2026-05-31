"""Subprocess + small filesystem/socket/hash helpers."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import stat
import subprocess
from pathlib import Path
from typing import Optional, Union

from baleharness.logutil import TestFailure


def rmtree(path: Union[str, Path]) -> None:
    """`shutil.rmtree` that also works on Windows git trees. Git writes loose
    objects read-only, and Windows refuses `os.unlink` on a read-only file
    (WinError 5), so clear the read-only bit across the tree first. No-op on
    a missing path."""
    if not os.path.exists(path):
        return
    for root, dirs, files in os.walk(path):
        # Only files get the bare write bit. A directory chmod'd to write-only
        # loses its POSIX read/execute bits, and shutil.rmtree's safe-fd path
        # then can't os.open it to recurse (EACCES) — so dirs keep owner rwx.
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), stat.S_IRWXU)
            except OSError:
                pass
        for name in files:
            try:
                os.chmod(os.path.join(root, name), stat.S_IWRITE)
            except OSError:
                pass
    shutil.rmtree(path)


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
