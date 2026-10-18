"""Mount phases (mount-rev, mount-diff, mount-diff-mixed, mount-edge, mount-local)."""

from __future__ import annotations

import secrets
import shutil
import subprocess
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    BIG_FILE_BYTES,
    E2E_OWNER,
    E2E_REPO_2,
    E2E_REPO_3,
    LOCAL_PAYLOAD_BYTES,
)
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
from baleharness.repo import init_repo_for_clone, init_repo_for_push, init_repo_local
from baleharness.server import ServerHandle
from baleharness.storage import local_store_xorbs, per_repo_store
from baleharness.timing import Timings


def phase_mount_rev(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Cold-clone the bigfile repo, mount HEAD, and check a plain blob (from
    the ODB) and a bale file (Reader reconstruction) cold, then warm."""
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
        with (
            timings.measure(
                "mount-rev: mount HEAD + read bigfile via FUSE",
                bytes_moved=BIG_FILE_BYTES,
            ),
            mount_rev_session(
                client=client,
                repo=clone_path,
                env=env,
                mount_root=mount_root,
                rev="HEAD",
                label="mount-rev",
            ) as mp,
        ):
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
            # stat must report the file size, not the pointer JSON length
            # (`Reader::size_of` reads only the pointer).
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
            # Broken lazy dir population still serves lookups but empties readdir.
            names = sorted(p.name for p in mp.iterdir())
            for required in (".gitattributes", "bigfile.bin"):
                if required not in names:
                    raise TestFailure(
                        f"mount-rev: readdir missing {required!r}; got {names}"
                    )
        # Re-mount hits the manifest + chunk caches the first mount populated.
        with (
            timings.measure(
                "mount-rev: re-mount HEAD (hot caches)",
                bytes_moved=BIG_FILE_BYTES,
            ),
            mount_rev_session(
                client=client,
                repo=clone_path,
                env=env,
                mount_root=mount_root,
                rev="HEAD",
                label="mount-rev-hot",
            ) as mp,
        ):
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
    """Cold-clone the bigfile repo, mount v1 vs v3, and verify each side's
    cold reconstruction; a pathspec matching nothing must error."""
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
        with (
            timings.measure(
                "mount-diff: v1 vs v3 + read both sides via FUSE",
                bytes_moved=2 * BIG_FILE_BYTES,
            ),
            mount_diff_session(
                client=client,
                repo=clone_path,
                env=env,
                mount_root=mount_root,
                rev_a=v1_commit,
                rev_b=v3_commit,
                label_a="v1",
                label_b="v3",
                label="mount-diff",
            ) as mp,
        ):
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
        # An empty filtered diff must error, not mount an empty FS.
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
    """A plain file and a bale file both change across two commits; every
    labelled side must match the committed bytes and each pair must differ
    (`diff -q` exits 1). Catches one of the Reader's two divergent paths
    (ODB blob vs pointer) breaking — `mount-diff` covers only bale files."""
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
    # 256 KiB: a handful of CDC chunks, still fast.
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

    # For bale files `git show` returns the pointer, so cross-check its sha256.
    files = [
        ("notes", ".txt", "plain", plain_v1, plain_v2),
        ("data", ".bin", "bale", bale_v1, bale_v2),
    ]

    try:
        with (
            timings.measure(
                "mount-diff-mixed: mount + byte-for-byte verify",
                bytes_moved=2
                * (len(plain_v1) + len(plain_v2) + len(bale_v1) + len(bale_v2)),
            ),
            mount_diff_session(
                client=client,
                repo=clone_path,
                env=clone_env,
                mount_root=mount_root,
                rev_a=commit_v1,
                rev_b=commit_v2,
                label_a="v1",
                label_b="v2",
                label="mount-diff-mixed",
            ) as mp,
        ):
            names = sorted(p.name for p in mp.iterdir())
            expected = {
                f"{stem}__{lbl}{ext}"
                for stem, ext, _, _, _ in files
                for lbl in ("v1", "v2")
            }
            if not expected.issubset(set(names)):
                raise TestFailure(
                    f"mount-diff-mixed: readdir missing some of {expected}; got {names}"
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
                        if odb_blob != mounted:
                            raise TestFailure(
                                f"mount-diff-mixed: plain {stem}__{label}{ext} "
                                f"mount bytes disagree with `git show "
                                f"{src_rev[:8]}:{stem}{ext}` ({len(mounted)} "
                                f"vs {len(odb_blob)} B)"
                            )
                    else:
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

            # Catches both sides wired to the same blob.
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
    """`mount`/`mount-diff` validation in `mount/mod.rs`, on a plain-git repo
    (no server): identical labels, empty diff, pathspec filtering to nothing,
    empty-tree commit, and auto-derived `sanitize_label` labels (`HEAD~2` →
    `HEAD_2`). Skips when libfuse/fuse-t is absent."""
    env = client.make_env()
    bale = str(client.git_bale_bin)

    # HEAD~2..HEAD~1 has a real diff; HEAD~1..HEAD (c3 is --allow-empty) is empty.
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

    empty_repo = work_root / "mount-edge-empty"
    empty_repo.mkdir()
    git(["init", "-b", "main", "."], cwd=empty_repo, env=env)
    git(["commit", "--allow-empty", "-m", "empty root"], cwd=empty_repo, env=env)

    mount_root = work_root / "mount-edge-points"
    mount_root.mkdir()
    throwaway = mount_root / "unused"
    throwaway.mkdir()

    def expect_fail(cwd: Path, argv_tail: list[str], needle: str, what: str) -> None:
        """A missing FS driver skips the whole phase: validation is never reached."""
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
            # Reached only after a non-empty diff.
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
            expect_fail(
                repo,
                ["mount-diff", "HEAD~1", "HEAD"],
                "no files differ",
                "empty diff (no pathspec)",
            )
            expect_fail(
                repo,
                ["mount", "HEAD", "--", "no-such-path"],
                "no files in",
                "mount with empty pathspec result",
            )
            expect_fail(
                empty_repo,
                ["mount", "HEAD"],
                "no files in",
                "mount of an empty-tree commit",
            )

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


def phase_mount_local(
    *,
    timings: Timings,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """Fully-local `mount` reconstructs from the local store with no server (a
    miss used to fall through to the network and fail auth), and a corrupted
    store fails the read rather than serving wrong bytes."""
    repo, env = init_repo_local(work_root=work_root, client=client, name="mount-local")
    rel = "local.bin"
    payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"mount-local")
    (repo / rel).write_bytes(payload)
    git(["add", rel], cwd=repo, env=env)
    git(["commit", "-m", "local"], cwd=repo, env=env)
    # Fresh chunk cache + no manifests, so the hot path can't serve it.
    git(
        ["config", "bale.cacheDir", str(work_root / "mount-local-cache")],
        cwd=repo,
        env=env,
    )
    shutil.rmtree(repo / ".git" / "bale" / "manifests", ignore_errors=True)

    mount_root = work_root / "mount-local-points"
    mount_root.mkdir()
    try:
        with (
            timings.measure(
                "mount-local: read bale file from local store",
                bytes_moved=len(payload),
            ),
            mount_rev_session(
                client=client,
                repo=repo,
                env=env,
                mount_root=mount_root,
                rev="HEAD",
                label="mount-local",
            ) as mp,
        ):
            got = sha256_file(mp / rel)
            if got != sha256_bytes(payload):
                raise TestFailure(
                    f"mount-local: {rel} sha {got} != committed sha — "
                    "local-store reconstruction served wrong bytes"
                )

        for x in local_store_xorbs(per_repo_store(repo)):
            data = bytearray(x.read_bytes())
            mid = len(data) // 2
            for i in range(mid, min(mid + 4096, len(data))):
                data[i] ^= 0xFF
            x.chmod(0o644)  # xet stores objects read-only
            x.write_bytes(bytes(data))
        with mount_rev_session(
            client=client,
            repo=repo,
            env=env,
            mount_root=mount_root,
            rev="HEAD",
            label="mount-local-tampered",
        ) as mp:
            try:
                got = sha256_file(mp / rel)
            except OSError as e:
                info(f"-- mount-local: corrupted store refused ({e})")
            else:
                raise TestFailure(
                    f"mount-local: read through a corrupted store succeeded (sha {got})"
                )
    except MountUnavailable as e:
        info(f"-- mount-local: skipping ({e})")
        if e.stderr and e.stderr != str(e):
            info(f"-- mount-local: binary stderr:\n{e.stderr}")
