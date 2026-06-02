"""Xorb compression coverage phase.

The default sha256-chained payloads are high-entropy, so xet's auto policy
reverts every chunk to scheme 0 (uncompressed) — leaving the server's LZ4 and
BG4-LZ4 decompress arms (`verify_xorb_body` on upload, `decompress_xorb_chunks_into`
on the browser file-download path) cold in coverage. This phase pushes two
deliberately compressible files: one xet stores as plain LZ4 (scheme 1), one as
BG4-LZ4 (scheme 2). It asserts both schemes actually landed on disk (so the test
isn't vacuous if the heuristic shifts), then downloads both files over HTTP so
the server-side decompress path runs each arm, and cold-clones to prove the
smudge/reconstruction path round-trips compressed content intact.
"""

from __future__ import annotations

import os
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    COMPRESS_FILE_BYTES,
    E2E_HUB_TOKEN,
    E2E_OWNER,
    E2E_REPO_COMPRESS,
)
from baleharness.gitutil import cat_file_bytes, git, pointer_field
from baleharness.logutil import TestFailure, info
from baleharness.payloads import bg4_friendly_payload, lz4_friendly_payload
from baleharness.proc import sha256_bytes, sha256_file
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.server import ServerHandle
from baleharness.timing import Timings
from baleharness.usage import http_get_file


def _frame_schemes(body: bytes) -> list[int]:
    """The compression scheme byte of each chunk frame in a stored xorb body,
    mirroring the server's `parse_xorb_frames`: 8-byte little-endian header,
    `compressed_length` is a u24 at offset 1, `compression_scheme` at offset 4,
    and a non-zero version byte marks the footer (stop)."""
    schemes: list[int] = []
    pos = 0
    n = len(body)
    while pos + 8 <= n:
        if body[pos] != 0:  # footer / unknown trailer
            break
        compressed_length = body[pos + 1] | (body[pos + 2] << 8) | (body[pos + 3] << 16)
        frame_len = 8 + compressed_length
        if pos + frame_len > n:
            break
        schemes.append(body[pos + 4])
        pos += frame_len
    return schemes


def _stored_xorb_schemes(server: ServerHandle) -> set[int]:
    """The union of compression schemes across every xorb the server holds
    (fs `data_root/xorbs` or the MinIO bucket prefix under S3)."""
    seen: set[int] = set()
    if server.s3_view is not None:
        view = server.s3_view
        for key, _sz in view.minio.list_objects(f"{view.prefix}xorbs/"):
            seen.update(_frame_schemes(view.minio.get_object(key)))
    else:
        xorbs_dir = server.data_root / "xorbs"
        for cur, _dirs, names in os.walk(xorbs_dir):
            for fn in names:
                seen.update(_frame_schemes((Path(cur) / fn).read_bytes()))
    return seen


def phase_compression_schemes(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_COMPRESS,
        name="compression",
    )

    # *.bin is tracked through the bale filter (see init_repo_for_push).
    lz4_payload = lz4_friendly_payload(COMPRESS_FILE_BYTES)
    bg4_payload = bg4_friendly_payload(COMPRESS_FILE_BYTES)
    files = {
        "lz4.bin": (lz4_payload, sha256_bytes(lz4_payload)),
        "bg4.bin": (bg4_payload, sha256_bytes(bg4_payload)),
    }
    for name, (payload, _sha) in files.items():
        (repo / name).write_bytes(payload)
    git(["add", "lz4.bin", "bg4.bin"], cwd=repo, env=env)
    git(["commit", "-m", "add compressible files"], cwd=repo, env=env)

    with timings.measure(
        "compression: push (verify decompresses LZ4 + BG4 frames)",
        bytes_moved=2 * COMPRESS_FILE_BYTES,
    ):
        git(["push", "-u", "origin", "main"], cwd=repo, env=env)

    # Self-validation: the payloads must actually have been stored compressed,
    # otherwise the upload/download below would only re-cover the scheme-0 path.
    # Scheme 1 = LZ4, scheme 2 = BG4-LZ4 (presence, not absence — other phases
    # store scheme-0 frames and that's fine).
    schemes = _stored_xorb_schemes(server)
    missing = {1, 2} - schemes
    if missing:
        raise TestFailure(
            f"compression: expected LZ4 (1) and BG4-LZ4 (2) frames on disk, "
            f"missing {sorted(missing)} (saw {sorted(schemes)}) — the payloads "
            "didn't compress, so the server's decompress arms stay uncovered"
        )
    info(f"  stored xorb compression schemes: {sorted(schemes)} (LZ4 + BG4 present)")

    # Browser file-download path → `fetch_and_decompress_term` →
    # `decompress_xorb_chunks_into`, run once per scheme.
    repo_id = f"{E2E_OWNER}/{E2E_REPO_COMPRESS}"
    for name, (_payload, sha) in files.items():
        file_id = pointer_field(cat_file_bytes(repo, env, f"HEAD:{name}"), "hash")
        with timings.measure(
            f"compression: HTTP download {name} (server decompress)",
            bytes_moved=COMPRESS_FILE_BYTES,
        ):
            status, body, _headers = http_get_file(
                server, file_id=file_id, token=E2E_HUB_TOKEN, repo=repo_id
            )
        if status != 200:
            raise TestFailure(
                f"compression: download {name} expected 200, got {status}: {body[:200]!r}"
            )
        if sha256_bytes(body) != sha:
            raise TestFailure(
                f"compression: downloaded {name} bytes mismatch — decompression "
                "corrupted the file"
            )

    # Cold clone proves the native smudge/reconstruction path also round-trips
    # compressed content intact.
    clone_path, clone_env, _cache = init_repo_for_clone(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO_COMPRESS,
        name="compression-clone",
    )
    with timings.measure("compression: cold clone+checkout"):
        git(["checkout", "main"], cwd=clone_path, env=clone_env)
    for name, (_payload, sha) in files.items():
        if sha256_file(clone_path / name) != sha:
            raise TestFailure(f"compression: clone {name} sha mismatch after checkout")
    info("  cold clone reconstructed both compressed files correctly")
