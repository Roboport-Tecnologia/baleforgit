"""Logging + the TestFailure exception + byte formatting."""

from __future__ import annotations

import sys

# On Windows the default stdio codec is the locale ANSI codepage (cp1252),
# which can't encode the glyphs the harness prints (≈, →, —) — print() then
# raises UnicodeEncodeError and aborts the suite mid-phase. Force UTF-8 with a
# replacement fallback so output can never crash the run, on any host.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure is not None:
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


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
