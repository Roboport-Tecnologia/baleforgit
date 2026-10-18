"""git invocation + bale pointer / worktree / resmudge verification."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from baleharness.logutil import TestFailure
from baleharness.proc import rmtree, run, sha256_file
from baleharness.storage import staging_files


def git(
    args: list[str],
    *,
    cwd: Path,
    env: dict,
    capture: bool = True,
    expect_fail: bool = False,
) -> subprocess.CompletedProcess:
    return run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture=capture,
        expect_fail=expect_fail,
    )


def cat_file_bytes(repo: Path, env: dict, spec: str) -> bytes:
    return git(["cat-file", "-p", spec], cwd=repo, env=env).stdout


def is_bale_pointer(blob: bytes) -> bool:
    txt = blob.strip()
    if not (txt.startswith(b"{") and txt.endswith(b"}")):
        return False
    try:
        obj = json.loads(txt)
    except json.JSONDecodeError:
        return False
    return all(k in obj for k in ("hash", "file_size", "sha256"))


def pointer_field(blob: bytes, key: str) -> object:
    return json.loads(blob)[key]


def verify_worktree(
    repo: Path,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    p = repo / rel
    if not p.exists():
        raise TestFailure(f"[{label}] worktree file missing: {rel}")
    actual_size = p.stat().st_size
    if actual_size != expected_size:
        raise TestFailure(
            f"[{label}] {rel}: worktree size {actual_size} != expected {expected_size}"
        )
    actual_sha = sha256_file(p)
    if actual_sha != expected_sha:
        raise TestFailure(
            f"[{label}] {rel}: worktree sha256 {actual_sha} != expected {expected_sha}"
        )


def verify_pointer_at(
    repo: Path,
    env: dict,
    *,
    spec: str,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> bytes:
    """Assert `spec` (e.g. 'HEAD:big.bin') is a matching pointer; returns it."""
    blob = cat_file_bytes(repo, env, spec)
    if not is_bale_pointer(blob):
        raise TestFailure(
            f"[{label}] expected Bale pointer at {spec}, got: {blob[:200]!r}"
        )
    got_size = int(pointer_field(blob, "file_size"))
    if got_size != expected_size:
        raise TestFailure(
            f"[{label}] {spec}: pointer file_size {got_size} != expected "
            f"{expected_size}"
        )
    got_sha = str(pointer_field(blob, "sha256"))
    if got_sha != expected_sha:
        raise TestFailure(
            f"[{label}] {spec}: pointer sha256 {got_sha} != expected {expected_sha}"
        )
    return blob


def force_resmudge_and_verify(
    repo: Path,
    env: dict,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Hot-path resmudge. Requires both chunk and manifest caches populated, or
    the filter would silently fall through to lukewarm/cold."""
    manifests = repo / ".git" / "bale" / "manifests"
    cache_dir = get_bale_cache_dir(repo, env)
    if not _has_any_file(manifests):
        raise TestFailure(
            f"[{label}] hot-path precondition violated: manifest cache "
            f"{manifests} is empty — `git checkout --` would fall through "
            "to lukewarm/cold and this test would silently measure the "
            "wrong path"
        )
    if not _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] hot-path precondition violated: chunk cache "
            f"{cache_dir} is empty — `git checkout --` would fall through "
            "to lukewarm/cold and this test would silently measure the "
            "wrong path"
        )
    p = repo / rel
    if p.exists():
        p.unlink()
    git(["checkout", "--", rel], cwd=repo, env=env)
    verify_worktree(
        repo,
        rel,
        expected_sha=expected_sha,
        expected_size=expected_size,
        label=label,
    )


def get_bale_cache_dir(repo: Path, env: dict) -> Path:
    """`bale.cacheDir`; init_repo_for_push/clone set it, so unset = harness bug."""
    out = (
        git(
            ["config", "--local", "--get", "bale.cacheDir"],
            cwd=repo,
            env=env,
        )
        .stdout.decode()
        .strip()
    )
    if not out:
        raise TestFailure(f"bale.cacheDir not set in {repo}/.git/config — harness bug")
    return Path(out)


def _has_any_file(root: Path) -> bool:
    return root.exists() and any(p.is_file() for p in root.rglob("*"))


def force_resmudge_cold(
    repo: Path,
    env: dict,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Wipe manifest + chunk caches so smudge must go through `/v1/reconstructions/`.
    The chunk cache repopulating is what proves the round-trip went over the wire.
    """
    manifests = repo / ".git" / "bale" / "manifests"
    if manifests.exists():
        rmtree(manifests)
    cache_dir = get_bale_cache_dir(repo, env)
    if cache_dir.exists():
        rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] chunk cache {cache_dir} not actually empty after wipe"
        )
    (repo / rel).unlink()
    git(["checkout", "--", rel], cwd=repo, env=env)
    verify_worktree(
        repo,
        rel,
        expected_sha=expected_sha,
        expected_size=expected_size,
        label=label,
    )
    if not _has_any_file(cache_dir):
        raise TestFailure(
            f"[{label}] cold smudge of {rel} did not repopulate {cache_dir} — "
            "smudge may not have hit /v1/reconstructions/"
        )


def force_resmudge_lukewarm(
    repo: Path,
    env: dict,
    rel: str,
    *,
    expected_sha: str,
    expected_size: int,
    label: str,
) -> None:
    """Smudge from `.git/bale/staging/` (`try_smudge_from_staging`) with caches wiped.

    Call between `git add` and `git push`: with nothing on the server yet, only
    staging can satisfy the smudge. Staging must survive it (read, not drained).
    """
    if not staging_files(repo):
        raise TestFailure(f"[{label}] staging dir empty — lukewarm needs a staged file")
    manifests = repo / ".git" / "bale" / "manifests"
    if manifests.exists():
        rmtree(manifests)
    cache_dir = get_bale_cache_dir(repo, env)
    if cache_dir.exists():
        rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if _has_any_file(cache_dir):
        raise TestFailure(f"[{label}] chunk cache {cache_dir} not empty after wipe")
    (repo / rel).unlink()
    git(["checkout", "--", rel], cwd=repo, env=env)
    verify_worktree(
        repo,
        rel,
        expected_sha=expected_sha,
        expected_size=expected_size,
        label=label,
    )
    if not staging_files(repo):
        raise TestFailure(
            f"[{label}] staging dir empty after lukewarm smudge — the filter "
            "drained the lukewarm input it was supposed to leave alone"
        )


def pointer_hash_at(repo: Path, env: dict, spec: str, *, label: str) -> str:
    """Pointer `hash` (merkle file id) at `spec`, e.g. `HEAD:x.bin` or `:x.bin`."""
    blob = cat_file_bytes(repo, env, spec)
    if not is_bale_pointer(blob):
        raise TestFailure(
            f"[{label}] expected a bale pointer at {spec}, got: {blob[:200]!r}"
        )
    return str(pointer_field(blob, "hash"))
