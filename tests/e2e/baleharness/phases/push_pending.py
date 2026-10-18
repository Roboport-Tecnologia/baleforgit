"""push-pending drain edge cases (empty staging; failed re-translate)."""

from __future__ import annotations

from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_GC1,
    E2E_REPO_GC3,
    GC_PAYLOAD_BYTES,
    SIZE_TOLERANCE_BYTES,
)
from baleharness.gitutil import git, pointer_hash_at, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import run, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.server import ServerHandle
from baleharness.storage import staged_markers, staging_files
from baleharness.timing import Timings


def phase_push_pending_noop(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """`git-bale push-pending` with nothing staged is a clean no-op.

    The pre-push hook runs push-pending on *every* push, including pushes
    that touched no bale-tracked file — those leave `.git/bale/staging/`
    absent. push-pending must short-circuit and exit 0, never error
    (which would block the push). This drives the `!staging.exists()`
    early return before any auth resolution or server contact."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="pp-noop",
    )
    staging = repo / ".git" / "bale" / "staging"
    if staging.exists():
        raise TestFailure(
            f"pp-noop: precondition violated — {staging} exists before any "
            "bale-tracked file was added"
        )
    with timings.measure("push-pending-noop: drain with no staging dir"):
        # check=True: a non-zero exit here is a real product bug (the hook
        # would block every push), so let `run` raise with the output.
        run([str(client.git_bale_bin), "push-pending"], cwd=repo, env=env)
    if staging.exists():
        raise TestFailure(
            "pp-noop: push-pending created a staging dir while draining nothing"
        )


def phase_push_pending_corrupt_staging(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """A failed re-translate must abort WITHOUT draining staging.

    push-pending reconstructs each staged file from `.git/bale/staging/`
    through a local download session, then re-cleans it through the online
    upload session. If the local reconstruct fails — staging corruption, or
    a `file-index/` marker outliving the xorb it points at — push-pending
    must error and leave the marker + remaining objects in place. The
    load-bearing property: it must never clear the marker (report the file
    as drained) when it couldn't actually upload it, or the staged bytes
    are silently lost.

    We simulate the corruption by deleting the staged xorb data after
    `git add` while keeping the marker, then assert push-pending fails at
    the local-reconstruct step, the marker survives, and nothing reached
    the server."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="pp-corrupt",
    )
    payload = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"pp-corrupt")
    (repo / "corrupt.bin").write_bytes(payload)
    # Clean is offline, so this stages xorbs/shards + a file-index marker
    # without any server contact.
    git(["add", "corrupt.bin"], cwd=repo, env=env)
    # push-pending only uploads content the pushed refs (here: HEAD) reach.
    git(["commit", "-m", "corrupt"], cwd=repo, env=env)
    file_hex = pointer_hash_at(repo, env, ":corrupt.bin", label="pp-corrupt:staged")
    if file_hex not in staged_markers(repo):
        raise TestFailure(
            f"pp-corrupt: expected a staging marker for {file_hex} after add, "
            f"got {sorted(staged_markers(repo))}"
        )
    # Delete the xorb data (the bytes), keeping shards + marker: the marker
    # still advertises the file and the shard still resolves it to chunks,
    # but the chunks' backing xorb is gone — exactly the "marker outlives
    # its xorb" corruption. The local download session reads only from
    # staging (never bale.cacheDir or the server), so this is unrecoverable.
    xorbs = [p for p in staging_files(repo) if p.name.startswith("default.")]
    if not xorbs:
        raise TestFailure(
            f"pp-corrupt: `git add` of a {GC_PAYLOAD_BYTES}-byte file produced "
            "no staged xorb to delete — payload may be below the inline threshold"
        )
    info(f"  deleting {len(xorbs)} staged xorb(s), keeping shards + marker")
    for x in xorbs:
        x.unlink()

    disk_before = server.disk_total_bytes()
    with timings.measure("push-pending-corrupt: drain with missing xorb"):
        completed = run(
            [str(client.git_bale_bin), "push-pending"],
            cwd=repo,
            env=env,
            expect_fail=True,
        )
    stderr = completed.stderr.decode("utf-8", "replace")
    if completed.returncode == 0:
        raise TestFailure(
            "pp-corrupt: push-pending succeeded despite the staged xorb being "
            "deleted — it must fail the local reconstruct, not silently report "
            f"success.\nstderr:\n{stderr}"
        )
    if "local reconstruct" not in stderr:
        raise TestFailure(
            "pp-corrupt: push-pending failed, but not at the expected "
            f"local-reconstruct step.\nstderr:\n{stderr}"
        )
    if file_hex not in staged_markers(repo):
        raise TestFailure(
            f"pp-corrupt: marker {file_hex} was cleared after a FAILED "
            "push-pending — staging was drained for a file that never uploaded, "
            "so the staged bytes are now lost"
        )
    disk_after = server.disk_total_bytes()
    if disk_after - disk_before > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            f"pp-corrupt: server disk grew by {disk_after - disk_before} bytes "
            "during a push-pending that failed before any upload"
        )


def phase_push_pending_only_pushed(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """push-pending uploads only content the push references. An uncommitted
    edit that `git status` re-cleaned (so it has a staged marker) must stay on
    the machine: not uploaded, not drained."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        # Its own bare repo's spare branch: usage accounting of E2E_REPO stays exact.
        repo=E2E_REPO_GC1,
        name="pp-only-pushed",
    )
    v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"pp-only-v1")
    v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"pp-only-v2")
    (repo / "p.bin").write_bytes(v1)
    git(["add", "p.bin"], cwd=repo, env=env)
    git(["commit", "-m", "p v1"], cwd=repo, env=env)
    h1 = pointer_hash_at(repo, env, "HEAD:p.bin", label="pp-only")

    # Uncommitted edit, cleaned by `git status` (git re-runs the filter on a
    # stat-dirty file) — plus an explicit add/reset to be sure a marker exists.
    (repo / "p.bin").write_bytes(v2)
    git(["status"], cwd=repo, env=env)
    git(["add", "p.bin"], cwd=repo, env=env)
    h2 = pointer_hash_at(repo, env, ":p.bin", label="pp-only")
    git(["reset", "-q"], cwd=repo, env=env)
    if h2 not in staged_markers(repo):
        raise TestFailure(
            f"pp-only: expected a marker for the uncommitted edit {h2[:8]}.."
        )

    disk_before = server.disk_total_bytes()
    with timings.measure("push-pending-only-pushed: push with an uncommitted edit"):
        git(["push", "origin", "main:pp-only-pushed"], cwd=repo, env=env)
    markers = staged_markers(repo)
    if h1 in markers:
        raise TestFailure(f"pp-only: pushed v1 {h1[:8]}.. was not drained")
    if h2 not in markers:
        raise TestFailure(
            f"pp-only: the uncommitted edit's marker {h2[:8]}.. was drained by a push "
            "that doesn't reference it"
        )
    grew = server.disk_total_bytes() - disk_before
    # v1 and v2 are independent random payloads: uploading v2 would add ~its size.
    if grew > GC_PAYLOAD_BYTES + GC_PAYLOAD_BYTES // 2:
        raise TestFailure(
            f"pp-only: server grew by {grew} bytes for a push of one "
            f"{GC_PAYLOAD_BYTES}-byte file — the uncommitted edit was uploaded too"
        )
    info("[pp-only] uncommitted edit stayed local; only pushed content uploaded")

    # `git push <url>` hands the hook the URL as the remote name; with leftover
    # markers push-pending must not treat it as a `refs/remotes/<name>/` prefix.
    url = git(["remote", "get-url", "origin"], cwd=repo, env=env).stdout.decode()
    (repo / "q.bin").write_bytes(
        deterministic_payload(GC_PAYLOAD_BYTES // 4, seed=b"pp-only-url")
    )
    # v2 stays staged (index-live, so gc keeps its marker) but uncommitted.
    git(["add", "p.bin", "q.bin"], cwd=repo, env=env)
    git(["commit", "-m", "q", "--", "q.bin"], cwd=repo, env=env)
    if h2 not in staged_markers(repo):
        raise TestFailure("pp-only: precondition — staged v2 marker missing")
    h3 = pointer_hash_at(repo, env, "HEAD:q.bin", label="pp-only-url")
    with timings.measure("push-pending-only-pushed: push to a bare URL"):
        git(["push", url.strip(), "main:pp-only-url"], cwd=repo, env=env)
    markers = staged_markers(repo)
    if h3 in markers:
        raise TestFailure(f"pp-only: URL push did not drain {h3[:8]}..")
    if h2 not in markers:
        raise TestFailure("pp-only: URL push drained the staged-but-unpushed marker")
    info("[pp-only] push to a bare URL with leftover markers succeeded")


def phase_push_pending_noverify_heal(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """A commit pushed with `--no-verify` leaves the remote advertising a
    pointer whose bytes exist only in local staging. The next normal push must
    upload it (the target already references it) even though it isn't in that
    push's ref delta, so a clone of the earlier commit then works."""
    branch = "pp-noverify"
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        # A spare branch of the gc-mixed repo: no other phase reads it.
        repo=E2E_REPO_GC3,
        name="pp-noverify",
    )
    v1 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"pp-noverify-a")
    v2 = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"pp-noverify-b")
    (repo / "a.bin").write_bytes(v1)
    git(["add", "a.bin"], cwd=repo, env=env)
    git(["commit", "-m", "a"], cwd=repo, env=env)
    c1 = git(["rev-parse", "HEAD"], cwd=repo, env=env).stdout.decode().strip()
    h1 = pointer_hash_at(repo, env, "HEAD:a.bin", label="pp-noverify")
    git(["push", "--no-verify", "origin", f"main:{branch}"], cwd=repo, env=env)
    if h1 not in staged_markers(repo):
        raise TestFailure("pp-noverify: --no-verify push should leave a.bin staged")

    early, eenv, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_GC3,
        name="pp-noverify-early",
    )
    pre = git(["checkout", c1], cwd=early, env=eenv, expect_fail=True)
    if pre.returncode == 0:
        raise TestFailure(
            "pp-noverify: precondition — a.bin reconstructed before it was ever uploaded"
        )

    (repo / "b.bin").write_bytes(v2)
    git(["add", "b.bin"], cwd=repo, env=env)
    git(["commit", "-m", "b"], cwd=repo, env=env)
    with timings.measure("push-pending-noverify-heal: normal push after --no-verify"):
        git(["push", "origin", f"main:{branch}"], cwd=repo, env=env)
    if h1 in staged_markers(repo):
        raise TestFailure(
            "pp-noverify: the earlier --no-verify content was not uploaded/drained "
            "by the next normal push"
        )

    clone, cenv, _ = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_GC3,
        name="pp-noverify-clone",
    )
    git(["checkout", c1], cwd=clone, env=cenv)
    verify_worktree(
        clone,
        "a.bin",
        expected_sha=sha256_bytes(v1),
        expected_size=len(v1),
        label="pp-noverify@c1",
    )
    info(
        "[pp-noverify] --no-verify content uploaded by the next push; old commit clones"
    )
