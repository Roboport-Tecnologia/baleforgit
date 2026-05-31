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
    """Assert the worktree file `rel` exists with the expected size + sha256."""
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
    """Assert the object at git `spec` (e.g. ':small.bin' or 'HEAD:big.bin') is
    a Bale pointer whose `sha256` and `file_size` match the expected payload.
    Returns the pointer bytes so callers can chain additional checks."""
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
    """Hot-path resmudge: delete the worktree file, run `git checkout --`,
    and verify sha256 + size. Asserts the chunk cache AND manifest cache
    are populated as a precondition — otherwise the filter would silently
    fall through to lukewarm/cold and the test wouldn't actually be
    measuring the hot path."""
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
    """The chunks cache directory the bale filter writes to (from
    `bale.cacheDir` in the per-repo git config). The test sets this
    explicitly in init_repo_for_push / init_repo_for_clone, so missing
    config here is a harness bug, not a product bug."""
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
    """Wipe the per-repo manifest cache, the chunk cache pointed to by
    `bale.cacheDir`, and the worktree file — then force `git checkout --`.
    With nothing on disk to hit the hot or lukewarm path, the bale filter
    has to traverse `/v1/reconstructions/` against the server.

    Verifies sha256 + size of the re-materialized file. Also asserts the
    chunk cache repopulated, which is what proves the round-trip actually
    went over the wire (an empty cache that stayed empty would mean the
    smudge silently produced bytes from somewhere this test can't see).
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
    """Wipe the hot-path caches BEFORE the file has been pushed, then force
    `git checkout --`. With no chunks on the server yet (`/v1/reconstructions/`
    would 404), the smudge filter can only succeed by reading from
    `.git/bale/staging/` — `try_smudge_from_staging` in filter_process.rs.

    Precondition: the file must be staged (xorbs/shards in staging/) but
    NOT pushed. Caller is responsible for ordering this between `git add`
    and `git push`.

    Verifies:
      - staging is populated before the test runs (otherwise lukewarm has
        nothing to read from and the assertion would be vacuous),
      - bytes after re-materialization match the expected payload,
      - staging is still populated after — lukewarm reads but mustn't drain.
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
    """The bale pointer `hash` (merkle file id) for the blob at git `spec`
    (e.g. `HEAD:data.bin` for the committed version or `:data.bin` for the
    staged-in-index version)."""
    blob = cat_file_bytes(repo, env, spec)
    if not is_bale_pointer(blob):
        raise TestFailure(
            f"[{label}] expected a bale pointer at {spec}, got: {blob[:200]!r}"
        )
    return str(pointer_field(blob, "hash"))
