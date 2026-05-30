"""Mount phases (mount-rev, mount-diff, mount-diff-mixed)."""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import BIG_FILE_BYTES, E2E_OWNER, E2E_REPO_2, E2E_REPO_3
from baleharness.gitutil import git, is_bale_pointer, pointer_field
from baleharness.logutil import TestFailure, info
from baleharness.mount import (
    MountUnavailable,
    driver_missing,
    ensure_fs_driver,
    mount_diff_session,
    mount_rev_session,
)
from baleharness.payloads import deterministic_payload, modify_bytes
from baleharness.proc import sha256_bytes, sha256_file
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.server import ServerHandle
from baleharness.timing import Timings


def phase_mount_rev(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Cold-clone the bigfile repo, mount HEAD as a read-only FUSE FS, and
    verify both the non-bale `.gitattributes` (served from gix's ODB) and
    the bale-tracked `bigfile.bin` (reconstructed via the same Reader the
    smudge filter uses) come through correctly.

    The mount path exercises Reader's cold-then-warm transition end-to-end
    over real SSH-forge auth + network reconstruction — coverage no Rust
    unit test reaches because libfuse is mocked out there."""
    if not rev_state.get("shas"):
        raise TestFailure("mount-rev: rev_state missing — bigfile phase didn't run")
    expected_sha = rev_state["shas"][-1]
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="mount-rev-clone",
    )
    mount_root = work_root / "mount-rev-points"
    mount_root.mkdir(exist_ok=True)
    try:
        with timings.measure(
            "mount-rev: mount HEAD + read bigfile via FUSE",
            bytes_moved=BIG_FILE_BYTES,
        ):
            with mount_rev_session(
                client=client,
                repo=clone_path,
                env=env,
                mount_root=mount_root,
                rev="HEAD",
                label="mount-rev",
            ) as mp:
                # Plain (non-bale) blob: byte-for-byte against what git itself
                # would hand back — the only correct answer for a small text
                # file served from gix's ODB through the FUSE plain_cache path.
                mounted_attrs = (mp / ".gitattributes").read_bytes()
                source_attrs = git(
                    ["show", "HEAD:.gitattributes"],
                    cwd=clone_path,
                    env=env,
                ).stdout
                if mounted_attrs != source_attrs:
                    raise TestFailure(
                        f"mount-rev: .gitattributes mismatch\n"
                        f"  mounted: {mounted_attrs!r}\n"
                        f"  source:  {source_attrs!r}"
                    )
                # stat must report the *decompressed* size, not the pointer
                # JSON length — Reader.size_of reads only the pointer.
                size = (mp / "bigfile.bin").stat().st_size
                if size != BIG_FILE_BYTES:
                    raise TestFailure(
                        f"mount-rev: bigfile.bin stat size {size} != "
                        f"{BIG_FILE_BYTES} (size_of returning pointer JSON "
                        "length instead of file_size?)"
                    )
                got_sha = sha256_file(mp / "bigfile.bin")
                if got_sha != expected_sha:
                    raise TestFailure(
                        f"mount-rev: bigfile.bin sha {got_sha} != HEAD sha "
                        f"{expected_sha} — Reader reconstructed wrong bytes"
                    )
                # If lazy dir population is broken, individual lookups still
                # work but readdir returns an empty list.
                names = sorted(p.name for p in mp.iterdir())
                for required in (".gitattributes", "bigfile.bin"):
                    if required not in names:
                        raise TestFailure(
                            f"mount-rev: readdir missing {required!r}; got {names}"
                        )
        # Hot path: re-mount on the same clone hits the manifest + chunk
        # caches the first mount populated.
        with timings.measure(
            "mount-rev: re-mount HEAD (hot caches)",
            bytes_moved=BIG_FILE_BYTES,
        ):
            with mount_rev_session(
                client=client,
                repo=clone_path,
                env=env,
                mount_root=mount_root,
                rev="HEAD",
                label="mount-rev-hot",
            ) as mp:
                got_sha = sha256_file(mp / "bigfile.bin")
                if got_sha != expected_sha:
                    raise TestFailure(
                        f"mount-rev (hot): bigfile.bin sha {got_sha} != "
                        f"{expected_sha} — cache returned stale bytes"
                    )
    except MountUnavailable as e:
        info(f"-- mount-rev: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-rev: binary stderr:\n{e.stderr}")


def phase_mount_diff(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Cold-clone the bigfile repo, mount `git diff v1 v3`, and verify both
    sides reconstruct correctly with their respective shas. Both sides are
    bale-tracked pointers, so each one drives a full Reader cold-path
    reconstruction through libfuse."""
    if len(rev_state.get("commits", [])) < 3:
        raise TestFailure(
            "mount-diff: rev_state needs v1+v3 commits — bigfile phase did "
            "not produce them"
        )
    v1_commit = rev_state["commits"][0]
    v3_commit = rev_state["commits"][2]
    v1_sha = rev_state["shas"][0]
    v3_sha = rev_state["shas"][2]
    clone_path, env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_2,
        name="mount-diff-clone",
    )
    mount_root = work_root / "mount-diff-points"
    mount_root.mkdir(exist_ok=True)
    try:
        with timings.measure(
            "mount-diff: v1 vs v3 + read both sides via FUSE",
            bytes_moved=2 * BIG_FILE_BYTES,
        ):
            with mount_diff_session(
                client=client,
                repo=clone_path,
                env=env,
                mount_root=mount_root,
                rev_a=v1_commit,
                rev_b=v3_commit,
                label_a="v1",
                label_b="v3",
                label="mount-diff",
            ) as mp:
                names = sorted(p.name for p in mp.iterdir())
                for required in ("bigfile__v1.bin", "bigfile__v3.bin"):
                    if required not in names:
                        raise TestFailure(
                            f"mount-diff: labeled entry {required!r} missing "
                            f"from readdir; got {names}"
                        )
                got_v1 = sha256_file(mp / "bigfile__v1.bin")
                if got_v1 != v1_sha:
                    raise TestFailure(
                        f"mount-diff: bigfile__v1.bin sha {got_v1} != v1 sha "
                        f"{v1_sha} — reconstructed wrong bytes for side A"
                    )
                got_v3 = sha256_file(mp / "bigfile__v3.bin")
                if got_v3 != v3_sha:
                    raise TestFailure(
                        f"mount-diff: bigfile__v3.bin sha {got_v3} != v3 sha "
                        f"{v3_sha} — reconstructed wrong bytes for side B"
                    )
                for name in ("bigfile__v1.bin", "bigfile__v3.bin"):
                    sz = (mp / name).stat().st_size
                    if sz != BIG_FILE_BYTES:
                        raise TestFailure(
                            f"mount-diff: {name} stat size {sz} != {BIG_FILE_BYTES}"
                        )
        # Pathspec must yield an empty diff and exit with "no files differ"
        # rather than silently mounting an empty FS.
        empty_mp = mount_root / f"empty-{secrets.token_hex(3)}"
        empty_mp.mkdir()
        try:
            with timings.measure("mount-diff: pathspec rejects empty result"):
                completed = subprocess.run(
                    [
                        str(client.git_bale_bin),
                        "mount-diff",
                        v1_commit,
                        v3_commit,
                        "--label-a",
                        "v1",
                        "--label-b",
                        "v3",
                        "--mount",
                        str(empty_mp),
                        "--",
                        "no-such-path",
                    ],
                    cwd=str(clone_path),
                    env=env,
                    capture_output=True,
                    check=False,
                    timeout=30.0,
                )
            if completed.returncode == 0:
                raise TestFailure(
                    "mount-diff: pathspec filtering an empty result did not "
                    "error (would have mounted an empty FS instead)"
                )
            err = completed.stderr.decode("utf-8", "replace")
            if driver_missing(err):
                info(f"-- mount-diff pathspec: skipping ({err.splitlines()[0]})")
            elif "no files differ" not in err:
                raise TestFailure(
                    f"mount-diff: pathspec-empty exit was non-zero but "
                    f"stderr lacked 'no files differ':\n{err}"
                )
        finally:
            try:
                empty_mp.rmdir()
            except OSError:
                pass
    except MountUnavailable as e:
        info(f"-- mount-diff: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-diff: binary stderr:\n{e.stderr}")


def phase_mount_diff_mixed(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Sets up a fresh repo with TWO files that both change across two
    commits — a plain text file (`notes.txt`, served from gix's ODB) and a
    bale-tracked binary (`data.bin`, reconstructed through the Reader cold
    path). Mounts the diff and asserts:

      - both labelled sides of *each* file match `git show <rev>:<path>`
        byte-for-byte (catches any silent path-routing or chunking bug
        that would surface as off-by-one bytes or wrong-side wiring),
      - `diff -q` on each pair reports a difference and exits 1, proving
        the labelled sides aren't accidentally serving the same content.

    The mount-diff happy-path test (`mount-diff`) only exercises a single
    bale-tracked binary; this one is what catches regressions where plain
    git blobs and bale pointers go through divergent code paths in the
    Reader and one of them silently breaks."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_3,
        name="mount-diff-mixed",
    )
    plain_v1 = b"alpha\nbravo\ncharlie\ndelta\n"
    plain_v2 = b"alpha\nbravo CHANGED\ncharlie\ndelta\necho added\n"
    # 256 KiB so CDC produces a handful of chunks; small enough to keep
    # the test fast.
    bale_v1 = deterministic_payload(256 * 1024, seed=b"mixed-bale-v1")
    bale_v2 = modify_bytes(bale_v1, offset=10_000, replacement=b"\xff" * 32)

    (repo / "notes.txt").write_bytes(plain_v1)
    (repo / "data.bin").write_bytes(bale_v1)
    git(["add", "notes.txt", "data.bin"], cwd=repo, env=env)
    git(["commit", "-m", "v1: notes + data"], cwd=repo, env=env)
    commit_v1 = (
        git(
            ["rev-parse", "HEAD"],
            cwd=repo,
            env=env,
        )
        .stdout.decode()
        .strip()
    )

    (repo / "notes.txt").write_bytes(plain_v2)
    (repo / "data.bin").write_bytes(bale_v2)
    git(["add", "notes.txt", "data.bin"], cwd=repo, env=env)
    git(["commit", "-m", "v2: edit both"], cwd=repo, env=env)
    commit_v2 = (
        git(
            ["rev-parse", "HEAD"],
            cwd=repo,
            env=env,
        )
        .stdout.decode()
        .strip()
    )

    git(["push", "-u", "origin", "main"], cwd=repo, env=env)

    # Cold-clone so mount goes through the same network reconstruction path
    # a fresh user would hit (no chunk cache, no manifests).
    clone_path, clone_env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_3,
        name="mount-diff-mixed-clone",
    )
    mount_root = work_root / "mount-diff-mixed-points"
    mount_root.mkdir(exist_ok=True)

    # `kind` distinguishes the comparison path: plain files round-trip
    # through gix's ODB so `git show` returns the literal bytes; bale files
    # store a pointer JSON in the ODB and the mount serves the reconstructed
    # content, so the right cross-check is the bytes we committed + a
    # pointer-shape assertion on what `git show` returns.
    files = [
        ("notes", ".txt", "plain", plain_v1, plain_v2),
        ("data", ".bin", "bale", bale_v1, bale_v2),
    ]

    try:
        with timings.measure(
            "mount-diff-mixed: mount + byte-for-byte verify",
            bytes_moved=2
            * (len(plain_v1) + len(plain_v2) + len(bale_v1) + len(bale_v2)),
        ):
            with mount_diff_session(
                client=client,
                repo=clone_path,
                env=clone_env,
                mount_root=mount_root,
                rev_a=commit_v1,
                rev_b=commit_v2,
                label_a="v1",
                label_b="v2",
                label="mount-diff-mixed",
            ) as mp:
                names = sorted(p.name for p in mp.iterdir())
                expected = {
                    f"{stem}__{lbl}{ext}"
                    for stem, ext, _, _, _ in files
                    for lbl in ("v1", "v2")
                }
                if not expected.issubset(set(names)):
                    raise TestFailure(
                        f"mount-diff-mixed: readdir missing some of {expected}; "
                        f"got {names}"
                    )
                for stem, ext, kind, bytes_v1, bytes_v2 in files:
                    for label, expected_bytes, src_rev in (
                        ("v1", bytes_v1, commit_v1),
                        ("v2", bytes_v2, commit_v2),
                    ):
                        mounted = (mp / f"{stem}__{label}{ext}").read_bytes()
                        if mounted != expected_bytes:
                            raise TestFailure(
                                f"mount-diff-mixed: {stem}__{label}{ext} bytes "
                                f"don't match what we committed "
                                f"(got {len(mounted)} B, want {len(expected_bytes)} B; "
                                f"first 64 B mounted={mounted[:64]!r}, "
                                f"expected={expected_bytes[:64]!r})"
                            )
                        odb_blob = git(
                            ["show", f"{src_rev}:{stem}{ext}"],
                            cwd=clone_path,
                            env=clone_env,
                        ).stdout
                        if kind == "plain":
                            # Plain blobs: the ODB stores the literal bytes,
                            # so `git show` and the mount must agree.
                            if odb_blob != mounted:
                                raise TestFailure(
                                    f"mount-diff-mixed: plain {stem}__{label}{ext} "
                                    f"mount bytes disagree with `git show "
                                    f"{src_rev[:8]}:{stem}{ext}` ({len(mounted)} "
                                    f"vs {len(odb_blob)} B)"
                                )
                        else:
                            # Bale: ODB holds a pointer JSON, mount serves the
                            # reconstructed bytes. Verify the pointer's sha256
                            # matches the content the mount reconstructed —
                            # that's the link between the two views.
                            if not is_bale_pointer(odb_blob):
                                raise TestFailure(
                                    f"mount-diff-mixed: bale {stem}{ext}@{src_rev[:8]} "
                                    f"ODB blob isn't a pointer: {odb_blob[:200]!r}"
                                )
                            pointer_sha = str(pointer_field(odb_blob, "sha256"))
                            if pointer_sha != sha256_bytes(mounted):
                                raise TestFailure(
                                    f"mount-diff-mixed: bale {stem}__{label}{ext} "
                                    f"pointer sha256 {pointer_sha} != "
                                    f"sha256(mounted bytes) {sha256_bytes(mounted)}"
                                )

                # `diff -q` exits 1 when files differ. Confirms the two
                # labelled sides really are distinct content (a wiring bug
                # that served the same blob on both sides would slip past
                # the read checks above for v1 only).
                for stem, ext, _kind, _, _ in files:
                    a = mp / f"{stem}__v1{ext}"
                    b = mp / f"{stem}__v2{ext}"
                    r = subprocess.run(
                        ["diff", "-q", str(a), str(b)],
                        capture_output=True,
                        check=False,
                    )
                    if r.returncode != 1:
                        raise TestFailure(
                            f"mount-diff-mixed: diff -q {a.name} {b.name} "
                            f"returned {r.returncode}, expected 1 "
                            f"(stdout={r.stdout!r})"
                        )
    except MountUnavailable as e:
        info(f"-- mount-diff-mixed: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-diff-mixed: binary stderr:\n{e.stderr}")


def phase_mount_edge_cases(
    *,
    timings: Timings,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """`mount` / `mount-diff` argument + diff validation in `mount/mod.rs`,
    the paths the happy-path mount phases never reach. All git-level (no
    bale/server), so it builds its own throwaway repo with plain text files:

      - mount-diff with identical labels is rejected (`both resolve`);
      - mount-diff of two identical-tree commits errors `no files differ`
        with no pathspec (the paths-empty arm of the empty-diff guard);
      - mount of a revision filtered to nothing errors `no files in`;
      - mount of an empty-tree commit errors `no files in` (paths-empty arm);
      - mount-diff with NO --label-a/--label-b derives labels via
        sanitize_label — `HEAD~2`/`HEAD~1` sanitize to `HEAD_2`/`HEAD_1`
        (the `~` exercises the non-alnum replacement), and those labels must
        show up in the mounted filenames.

    Skips cleanly (like the other mount phases) when libfuse/fuse-t is absent."""
    env = client.make_env()
    bale = str(client.git_bale_bin)

    # Three commits: c1, c2 (differs from c1), c3 (--allow-empty, same tree as
    # c2). So HEAD=c3, HEAD~1=c2, HEAD~2=c1: HEAD~2..HEAD~1 has a real diff,
    # HEAD~1..HEAD is empty.
    repo = work_root / "mount-edge"
    repo.mkdir()
    git(["init", "-b", "main", "."], cwd=repo, env=env)
    (repo / "notes.txt").write_text("alpha\nbravo\n")
    git(["add", "notes.txt"], cwd=repo, env=env)
    git(["commit", "-m", "c1"], cwd=repo, env=env)
    (repo / "notes.txt").write_text("alpha\nbravo CHANGED\ncharlie\n")
    git(["add", "notes.txt"], cwd=repo, env=env)
    git(["commit", "-m", "c2"], cwd=repo, env=env)
    git(["commit", "--allow-empty", "-m", "c3 (same tree as c2)"], cwd=repo, env=env)

    # Separate repo whose only commit has an empty tree (no files at all).
    empty_repo = work_root / "mount-edge-empty"
    empty_repo.mkdir()
    git(["init", "-b", "main", "."], cwd=empty_repo, env=env)
    git(["commit", "--allow-empty", "-m", "empty root"], cwd=empty_repo, env=env)

    mount_root = work_root / "mount-edge-points"
    mount_root.mkdir()
    throwaway = mount_root / "unused"
    throwaway.mkdir()

    def expect_fail(cwd: Path, argv_tail: list[str], needle: str, what: str) -> None:
        """Run a mount/mount-diff expected to exit before mounting; assert it
        failed with `needle` in stderr. A libfuse-missing exit short-circuits
        the whole phase to a skip (the binary can't reach the validation)."""
        # --mount must precede any `--` pathspec separator, else clap folds it
        # into the (last = true) `paths` and reports it as missing.
        if "--" in argv_tail:
            i = argv_tail.index("--")
            argv = [*argv_tail[:i], "--mount", str(throwaway), *argv_tail[i:]]
        else:
            argv = [*argv_tail, "--mount", str(throwaway)]
        completed = subprocess.run(
            [bale, *argv],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            check=False,
            timeout=120.0,
        )
        err = completed.stderr.decode("utf-8", "replace")
        if driver_missing(err):
            raise MountUnavailable(
                err.strip().splitlines()[0] if err.strip() else "FS driver missing",
                stderr=err.strip(),
            )
        if completed.returncode == 0:
            raise TestFailure(f"mount-edge: {what} unexpectedly succeeded")
        if needle not in err:
            raise TestFailure(
                f"mount-edge: {what} failed but stderr lacked {needle!r}:\n{err}"
            )

    try:
        # On Windows the first check below runs git-bale directly (no session),
        # so provision WinFsp up front; on POSIX this is a no-op.
        ensure_fs_driver()
        with timings.measure("mount-edge: arg/diff validation + sanitize labels"):
            # Identical labels collide (reached only after a non-empty diff).
            expect_fail(
                repo,
                [
                    "mount-diff",
                    "HEAD~2",
                    "HEAD~1",
                    "--label-a",
                    "dup",
                    "--label-b",
                    "dup",
                ],
                "both resolve",
                "identical labels",
            )
            # Two identical-tree commits, no pathspec: paths-empty empty-diff arm.
            expect_fail(
                repo,
                ["mount-diff", "HEAD~1", "HEAD"],
                "no files differ",
                "empty diff (no pathspec)",
            )
            # Single-rev mount filtered to nothing: paths-nonempty empty arm.
            expect_fail(
                repo,
                ["mount", "HEAD", "--", "no-such-path"],
                "no files in",
                "mount with empty pathspec result",
            )
            # Single-rev mount of an empty tree, no pathspec: paths-empty arm.
            expect_fail(
                empty_repo,
                ["mount", "HEAD"],
                "no files in",
                "mount of an empty-tree commit",
            )

            # Auto-derived labels: HEAD~2 -> "HEAD_2", HEAD~1 -> "HEAD_1".
            with mount_diff_session(
                client=client,
                repo=repo,
                env=env,
                mount_root=mount_root,
                rev_a="HEAD~2",
                rev_b="HEAD~1",
                label="mount-edge-autolabel",
            ) as mp:
                names = sorted(p.name for p in mp.iterdir())
                for required in ("notes__HEAD_2.txt", "notes__HEAD_1.txt"):
                    if required not in names:
                        raise TestFailure(
                            f"mount-edge: auto-label {required!r} missing from "
                            f"readdir (sanitize_label not applied?); got {names}"
                        )
                mounted = (mp / "notes__HEAD_2.txt").read_bytes()
                source = git(["show", "HEAD~2:notes.txt"], cwd=repo, env=env).stdout
                if mounted != source:
                    raise TestFailure(
                        "mount-edge: notes__HEAD_2.txt bytes "
                        f"{mounted!r} != git show HEAD~2:notes.txt {source!r}"
                    )
    except MountUnavailable as e:
        info(f"-- mount-edge: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-edge: binary stderr:\n{e.stderr}")
    finally:
        try:
            throwaway.rmdir()
        except OSError:
            pass
