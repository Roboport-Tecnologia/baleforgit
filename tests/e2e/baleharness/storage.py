from __future__ import annotations

import os
from pathlib import Path


def staging_files(repo: Path) -> list[Path]:
    staging = repo / ".git" / "bale" / "staging"
    if not staging.exists():
        return []
    out: list[Path] = []
    for cur, _dirs, files in os.walk(staging):
        for f in files:
            is_xorb = f.startswith("default.") and _is_64_lower_hex(
                f[len("default.") :]
            )
            is_shard = f.endswith(".mdb") and _is_64_lower_hex(f[: -len(".mdb")])
            if is_xorb or is_shard:
                out.append(Path(cur) / f)
    return out


def _is_64_lower_hex(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def clean_cache_entries(repo: Path) -> list[Path]:
    cache = repo / ".git" / "bale" / "clean-cache"
    if not cache.exists():
        return []
    return [p for p in cache.iterdir() if p.is_file() and _is_64_lower_hex(p.name)]


def manifest_cache_entries(repo: Path) -> list[Path]:
    m = repo / ".git" / "bale" / "manifests"
    if not m.exists():
        return []
    return [p for p in m.iterdir() if p.is_file()]


def local_store_objects(store_dir: Path) -> list[Path]:
    """Excludes `shard-cache/`: xet rewrites its lookup files on every clean, so
    it grows even when a second repo adds identical bytes."""
    if not store_dir.exists():
        return []
    out: list[Path] = []
    for cur, _dirs, files in os.walk(store_dir):
        if "shard-cache" in Path(cur).parts:
            continue
        for f in files:
            is_xorb = f.startswith("default.") and _is_64_lower_hex(
                f[len("default.") :]
            )
            is_shard = f.endswith(".mdb") and _is_64_lower_hex(f[: -len(".mdb")])
            if is_xorb or is_shard:
                out.append(Path(cur) / f)
    return out


def local_store_xorbs(store_dir: Path) -> list[Path]:
    """Content-level dedup is asserted on xorbs alone: identical bytes from a
    second repo add no xorbs, though the shard layer may add shards."""
    return [p for p in local_store_objects(store_dir) if p.name.startswith("default.")]


def per_repo_store(repo: Path) -> Path:
    return repo / ".git" / "bale" / "store"


def staged_markers(repo: Path) -> set[str]:
    """Marker names equal the pointer's `hash` field — the exact set gc reclaims by."""
    d = repo / ".git" / "bale" / "staging" / "file-index"
    if not d.exists():
        return set()
    return {p.name for p in d.iterdir() if p.is_file()}
