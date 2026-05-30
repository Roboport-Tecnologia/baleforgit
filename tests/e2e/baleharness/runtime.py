"""Container runtime detection + image build helpers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from baleharness.config import E2E_DIR, REPO_ROOT
from baleharness.logutil import TestFailure, info, skip, warn
from baleharness.proc import tool_on_path


class Runtime:
    def __init__(self, exe: str) -> None:
        self.exe = exe

    def cmd(self, *args: str) -> list[str]:
        return [self.exe, *args]


def host_mount_path(p: Path) -> str:
    """Host side of a `-v host:container` bind mount. On Windows, podman/docker
    want forward-slash paths — a backslash `WindowsPath` would make the `-v`
    parser split on the wrong colon (the drive-letter `C:` vs the `:` separator).
    The drive letter is preserved (`C:/Users/...`), which both runtimes accept."""
    return p.as_posix() if os.name == "nt" else str(p)


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
            str(E2E_DIR / "Dockerfile"),
            str(REPO_ROOT),
        ),
        check=False,
    )
    if completed.returncode != 0:
        raise TestFailure(f"image build failed (exit {completed.returncode})")


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
