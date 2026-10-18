"""Deterministic sha256-chained payload generation."""

from __future__ import annotations

import array
import hashlib
import sys


def deterministic_payload(size: int, *, seed: bytes = b"baleforgit-e2e") -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(seed + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:size])


def lz4_friendly_payload(size: int, *, seed: bytes = b"lz4") -> bytes:
    """Compressible bytes that xet's auto policy stores as plain LZ4 (scheme 1).

    Each 64 KiB window repeats a 4 KiB sha256 block: LZ4 compresses it hard, but
    all four byte-lanes share one popcount distribution, so the BG4 predictor
    stays below threshold. Distinct per-window blocks keep windows from deduping."""
    window = 64 * 1024
    block_len = 4096
    out = bytearray()
    w = 0
    while len(out) < size:
        block = deterministic_payload(block_len, seed=seed + b"-" + str(w).encode())
        reps = -(-window // block_len)
        out += (block * reps)[:window]
        w += 1
    return bytes(out[:size])


def bg4_friendly_payload(size: int, *, start: int = 0) -> bytes:
    """Compressible bytes that xet's auto policy stores as BG4-LZ4 (scheme 2).

    A little-endian u32 ramp: lane 0 cycles while lanes 2-3 stay near zero, a
    per-lane popcount skew that pushes the BG4 predictor over threshold, and the
    near-constant high lanes collapse after grouping, so BG4-LZ4 wins and sticks."""
    n = size // 4
    arr = array.array("I", range(start, start + n))
    if arr.itemsize != 4:  # 'I' is 4 bytes on every platform we run on
        raise ValueError(f"expected 4-byte u32 array, got itemsize {arr.itemsize}")
    if sys.byteorder != "little":
        arr.byteswap()
    out = bytearray(arr.tobytes())
    if len(out) < size:
        out += bytes(size - len(out))
    return bytes(out)


def modify_bytes(buf: bytes, *, offset: int, replacement: bytes) -> bytes:
    arr = bytearray(buf)
    arr[offset : offset + len(replacement)] = replacement
    return bytes(arr)


def replace_region(buf: bytes, *, offset: int, length: int, seed: bytes) -> bytes:
    region = deterministic_payload(length, seed=seed)
    arr = bytearray(buf)
    arr[offset : offset + length] = region
    return bytes(arr)
