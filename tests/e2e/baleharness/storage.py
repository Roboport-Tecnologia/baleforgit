"""Storage / cache footprint helpers (staging, clean-cache, manifests)."""

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
    """Content xorbs/shards under an arbitrary local store dir (per-repo or
    shared). Excludes `shard-cache/` — that subdirectory holds client-side
    lookup-optimization files written by xet on every clean, not deduplicated
    content objects, so it grows even when a second repo adds identical bytes."""
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
    """Only the xorb objects under a store dir. Used to assert content-level
    dedup: a second repo adding identical bytes must produce no new xorbs,
    even though the shard layer may add compact/index shards."""
    return [p for p in local_store_objects(store_dir) if p.name.startswith("default.")]


def per_repo_store(repo: Path) -> Path:
    return repo / ".git" / "bale" / "store"


def staged_markers(repo: Path) -> set[str]:
    """The set of `<file_hex>` markers under `.git/bale/staging/file-index/`.
    Each marker name is the merkle file hash the clean filter recorded — the
    same value as a committed pointer's `hash` field, so we can correlate a
    marker with the file version that produced it. This is the precise signal
    `git-bale gc` operates on."""
    d = repo / ".git" / "bale" / "staging" / "file-index"
    if not d.exists():
        return set()
    return {p.name for p in d.iterdir() if p.is_file()}
