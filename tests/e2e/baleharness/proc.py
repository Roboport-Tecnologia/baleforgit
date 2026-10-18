from __future__ import annotations

import hashlib
import os
import shutil
import socket
import stat
import subprocess
from pathlib import Path

from baleharness.logutil import TestFailure


def rmtree(path: str | Path) -> None:
    """Git writes loose objects read-only and Windows refuses to unlink those
    (WinError 5), so clear the read-only bit first. No-op on a missing path."""
    if not os.path.exists(path):
        return
    for root, dirs, files in os.walk(path):
        # Dirs need owner rwx: a write-only dir can't be os.open'd by
        # shutil.rmtree's safe-fd path (EACCES).
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
    cwd: Path | None = None,
    env: dict | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
    capture: bool = True,
    expect_fail: bool = False,
) -> subprocess.CompletedProcess:
    """`expect_fail` returns regardless of exit status (overrides `check`)."""
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
    """Primary outbound IP (the UDP `connect` only routes; nothing is sent).
    Reachable from both the host and a podman container, unlike macOS rootless
    podman's flaky `host-gateway`."""
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
