"""Logging + the TestFailure exception + byte formatting."""

from __future__ import annotations

import sys


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
