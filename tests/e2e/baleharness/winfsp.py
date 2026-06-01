"""Windows-only: make sure WinFsp is installed so git-bale's WinFsp mount
backend can run. WinFsp ships the FUSE-compat `winfsp-x64.dll` plus a kernel
driver; if the DLL isn't loadable we download the official MSI and install it
(`msiexec /qn`, which needs admin). Imported lazily by `mount.py` — never on
non-Windows hosts."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from baleharness.logutil import info, warn


class WinfspUnavailable(Exception):
    """WinFsp isn't installed and couldn't be provisioned (no admin, no
    network, etc.). The mount phase turns this into a skip, not a failure."""


_RELEASES_API = "https://api.github.com/repos/winfsp/winfsp/releases/latest"
# Last-resort direct MSI if the releases API is unreachable. Best-effort: the
# API lookup above is the canonical source and yields the current URL.
_FALLBACK_MSI = (
    "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi"
)


def _dll_name() -> str:
    arch = os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64").upper()
    return {
        "AMD64": "winfsp-x64.dll",
        "ARM64": "winfsp-a64.dll",
        "X86": "winfsp-x86.dll",
    }.get(arch, "winfsp-x64.dll")


def _dll_loads() -> bool:
    """True if the WinFsp user-mode FUSE DLL can be loaded — by bare name (it's
    on PATH or in the app dir) or from the default `%ProgramFiles*%\\WinFsp\\bin`
    install location. The kernel driver is exercised only when a mount runs."""
    name = _dll_name()
    candidates = [name]
    for var in ("ProgramFiles(x86)", "ProgramW6432", "ProgramFiles"):
        base = os.environ.get(var)
        if base:
            candidates.append(str(Path(base) / "WinFsp" / "bin" / name))
    for cand in candidates:
        try:
            ctypes.WinDLL(cand)  # type: ignore[attr-defined]  # Windows-only
            return True
        except OSError:
            continue
    return False


def winfsp_present() -> bool:
    return os.name == "nt" and _dll_loads()


def _latest_msi_url() -> str:
    try:
        req = urllib.request.Request(_RELEASES_API, headers={"User-Agent": "bale-e2e"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for asset in data.get("assets", []):
            url = asset.get("browser_download_url", "")
            if url.endswith(".msi"):
                return url
        warn("WinFsp latest release has no .msi asset; using pinned URL")
    except Exception as e:  # network / JSON — fall back to the pinned URL
        warn(f"WinFsp release lookup failed ({e}); using pinned MSI URL")
    return _FALLBACK_MSI


def ensure_winfsp() -> None:
    """Ensure WinFsp is installed, downloading + installing the MSI if needed.
    Raises WinfspUnavailable if it can't be provisioned (so the caller skips)."""
    if os.name != "nt":
        raise WinfspUnavailable("WinFsp is only available on Windows")
    if _dll_loads():
        return

    url = _latest_msi_url()
    msi = Path(tempfile.gettempdir()) / "winfsp-bale-e2e.msi"
    info(f"WinFsp not found; downloading installer: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bale-e2e"})
        with urllib.request.urlopen(req, timeout=300) as resp, msi.open("wb") as f:
            shutil.copyfileobj(resp, f)
    except Exception as e:
        raise WinfspUnavailable(f"downloading WinFsp MSI failed: {e}") from e

    # The kernel-driver install needs admin; /norestart avoids a reboot prompt.
    info("installing WinFsp (msiexec /qn) — needs administrator privileges")
    completed = subprocess.run(
        ["msiexec", "/i", str(msi), "/qn", "/norestart"],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise WinfspUnavailable(
            f"msiexec install failed (exit {completed.returncode}); "
            "installing WinFsp needs administrator privileges"
        )
    if not _dll_loads():
        raise WinfspUnavailable("WinFsp installed but its DLL still isn't loadable")
    info("WinFsp installed")
