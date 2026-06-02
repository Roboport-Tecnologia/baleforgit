"""Regression: the server's global-dedup shard footer must not underflow the
client's `read_all_truncated_hashes` when ingested into the upload session."""

from __future__ import annotations

import secrets
import struct
import urllib.error
import urllib.request
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import (
    E2E_OWNER,
    E2E_REPO_DEDUP_SHARD,
    E2E_USER,
    GC_PAYLOAD_BYTES,
    JWT_TTL_YEARS,
)
from baleharness.gitutil import git
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, info
from baleharness.mocks import meta_db_query
from baleharness.payloads import deterministic_payload
from baleharness.proc import sha256_bytes
from baleharness.repo import init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings

# MDBShardFileFooter on the wire: 9 leading u64s, a 32-byte HMAC key, two u64
# timestamps, 72 bytes of reserved/_buffer fields, then footer_offset (u64).
SHARD_FOOTER_SIZE = 200
SHARD_FOOTER_VERSION = 1


def phase_global_dedup_shard(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """A global-dedup shard the server hands back must ingest without crashing.

    `GET /v1/chunks/{prefix}/{hash}` returns a minimal shard with no lookup
    tables. Its footer must still set each lookup-table *offset* to the section
    end (== footer_offset), never 0: xet's `read_all_truncated_hashes` — run on
    every shard the upload session's `ShardFileManager` ingests, in BOTH debug
    and release builds — takes `file_lookup_offset` as the END of the xorb-info
    byte range, so a 0 makes `file_lookup_offset - xorb_info_offset` underflow
    (debug panic; release a multi-exabyte `Vec::with_capacity` → OOM). The
    pre-push hook dies and `git push` fails.

    Reproducing the crash through a real push would need a chunk whose hash is
    global-dedup eligible (`hash % 1024 == 0`, ~1 in 1024) and the release
    binary can't lower that modulus (the `HF_XET_*` override is debug-only). So
    we drive it deterministically:

      1. Seed the server, fetch the dedup shard for a known chunk straight from
         the endpoint, and assert its footer is well-formed.
      2. Plant that exact shard into the client's xet shard-cache under a valid
         `<64hex>.mdb` name and push again. The upload session scans + ingests
         it through `read_all_truncated_hashes` — the precise crash path — so
         the push must succeed.

    Owns its own isolated container so the bare repo + grants don't have to be
    threaded through the shared server (and its offline-restart rebind)."""
    phase_root = work_root / "dedup-shard"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()

    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO_DEDUP_SHARD}"],
        admin_token_hex=admin_token_hex,
        name_suffix=f"dedupshard-{secrets.token_hex(3)}",
    )
    try:
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_DEDUP_SHARD,
            name="dedup-shard-client",
        )
        # Pin the xet cache: this is the dir the upload session caches global-
        # dedup shards in, the dir we plant into, and the dir the second push's
        # FileUploadSession::new scans. git-bale maps BALE_XET_CACHE onto xet's
        # HF_XET_CACHE; the filter + pre-push hook inherit it from `env`.
        xet_cache = phase_root / "xet-cache"
        env["BALE_XET_CACHE"] = str(xet_cache)

        # First push seeds the server with chunks AND mkdir's
        # <xet_cache>/<server-key>/shard-cache/ (SessionShardInterface::new).
        payload = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"dedup-shard")
        (repo / "seed.bin").write_bytes(payload)
        git(["add", "seed.bin"], cwd=repo, env=env)
        git(["commit", "-m", "seed bale content"], cwd=repo, env=env)
        with timings.measure("global-dedup-shard: seed push"):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)

        shard = _fetch_dedup_shard(server, jwt_secret)
        _assert_footer_wellformed(shard)

        # Plant the server's dedup shard into the upload session's cache dir
        # under a valid <64hex>.mdb name (scan_impl loads it by filename; the
        # content-hash check is the debug-only verify, so any 64-hex name is
        # ingested) and push again. The second push's FileUploadSession::new
        # scans + ingests it via read_all_truncated_hashes — the crash path.
        shard_cache = _find_shard_cache_dir(xet_cache)
        planted = shard_cache / f"{sha256_bytes(shard)}.mdb"
        planted.write_bytes(shard)
        info(f"  planted dedup shard at {planted}")

        edited = deterministic_payload(GC_PAYLOAD_BYTES, seed=b"dedup-shard-v2")
        (repo / "seed.bin").write_bytes(edited)
        git(["add", "seed.bin"], cwd=repo, env=env)
        git(["commit", "-m", "edit triggers a fresh upload session"], cwd=repo, env=env)
        with timings.measure("global-dedup-shard: push with planted dedup shard"):
            # Plain git(): a non-zero exit means push-pending's upload session
            # crashed ingesting the planted shard (the bug). Let it raise.
            git(["push", "origin", "main"], cwd=repo, env=env)
    finally:
        server.stop()


def _fetch_dedup_shard(server: ServerHandle, jwt_secret_hex: str) -> bytes:
    """GET /v1/chunks/default/{hash} for a chunk the server just stored."""
    raw_chunk_hash = _server_chunk_hash(server)
    token = mint_bale_jwt(
        secret=bytes.fromhex(jwt_secret_hex),
        sub=E2E_USER,
        repo_type="model",
        repo_id=f"{E2E_OWNER}/{E2E_REPO_DEDUP_SHARD}",
        revision="main",
        scope="read",
        ttl_secs=JWT_TTL_YEARS * 365 * 24 * 3600,
    )
    url = f"{server.public_host_url}/v1/chunks/default/{_encode_hash(raw_chunk_hash)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise TestFailure(
            f"global-dedup-shard: GET {url} returned {e.code} (expected 200 for "
            f"a chunk the server just stored).\nbody: {body}"
        ) from e


def _server_chunk_hash(server: ServerHandle) -> bytes:
    """Read one raw chunk hash from the server's metadata store, querying INSIDE
    a container: rootless podman bind mounts go through a VM on macOS, so a
    host-side read of the WAL-mode meta.db is unreliable (same reason
    hold_db_writer_lock execs sqlite3 in the container)."""
    out = meta_db_query(
        server,
        sqlite_sql="SELECT hex(chunk_hash) FROM chunks LIMIT 1;",
        pg_sql="SELECT encode(chunk_hash, 'hex') FROM chunks LIMIT 1;",
    )
    text = out.stdout.decode("utf-8", "replace").strip()
    if out.returncode != 0 or not text:
        raise TestFailure(
            "global-dedup-shard: could not read a chunk hash from the server's "
            f"meta.db (rc={out.returncode}) — the seed push may not have "
            f"registered any chunks.\nstderr: {out.stderr.decode('utf-8', 'replace')}"
        )
    return bytes.fromhex(text)


def _encode_hash(raw: bytes) -> str:
    """Mirror bale-server-wire encode_hash: hex each 8-byte group in reverse
    byte order (xet's swapped-u64-group hex). decode_hash undoes this to recover
    the raw bytes stored in the chunks table, so the lookup matches."""
    if len(raw) != 32:
        raise TestFailure(f"expected a 32-byte chunk hash, got {len(raw)} bytes")
    return "".join(raw[g * 8 : g * 8 + 8][::-1].hex() for g in range(4))


def _find_shard_cache_dir(xet_cache: Path) -> Path:
    matches = sorted(xet_cache.glob("*/shard-cache"))
    if len(matches) != 1:
        # The seed push's upload session mkdir's exactly one
        # <server-key>/shard-cache. A different count means the xet cache layout
        # changed and the plant-and-reingest guard is no longer wired — fail
        # loudly rather than silently skip it.
        raise TestFailure(
            f"global-dedup-shard: expected one <server-key>/shard-cache under "
            f"{xet_cache} after the seed push, found {matches}"
        )
    return matches[0]


def _assert_footer_wellformed(shard: bytes) -> None:
    if len(shard) < SHARD_FOOTER_SIZE:
        raise TestFailure(
            f"global-dedup-shard: server returned {len(shard)} bytes, smaller "
            f"than a {SHARD_FOOTER_SIZE}-byte shard footer"
        )
    footer = shard[-SHARD_FOOTER_SIZE:]
    (
        version,
        _file_info_offset,
        xorb_info_offset,
        file_lookup_offset,
        _file_lookup_num,
        xorb_lookup_offset,
        _xorb_lookup_num,
        chunk_lookup_offset,
        chunk_lookup_num,
    ) = struct.unpack_from("<9Q", footer, 0)
    footer_offset = struct.unpack_from("<Q", footer, SHARD_FOOTER_SIZE - 8)[0]

    if version != SHARD_FOOTER_VERSION:
        raise TestFailure(
            f"global-dedup-shard: footer version {version}, expected "
            f"{SHARD_FOOTER_VERSION}"
        )
    # A dedup response carries no lookup tables; this is the branch in
    # read_all_truncated_hashes that underflowed.
    if chunk_lookup_num != 0:
        raise TestFailure(
            f"global-dedup-shard: expected a lookup-table-less dedup shard "
            f"(chunk_lookup_num_entry == 0), got {chunk_lookup_num}"
        )
    # The bug: file_lookup_offset == 0 < xorb_info_offset, so the xorb-info byte
    # range (xorb_info_offset, file_lookup_offset) inverts and the client does
    # (file_lookup_offset - xorb_info_offset) → underflow. With no lookup
    # tables, every lookup offset must equal footer_offset (the section end).
    if not (xorb_info_offset <= file_lookup_offset == footer_offset != 0):
        raise TestFailure(
            "global-dedup-shard: malformed dedup shard footer — "
            f"xorb_info_offset={xorb_info_offset}, "
            f"file_lookup_offset={file_lookup_offset}, "
            f"footer_offset={footer_offset}. With no lookup tables, "
            "file_lookup_offset must equal footer_offset (not 0), or xet's "
            "read_all_truncated_hashes underflows (file_lookup_offset - "
            "xorb_info_offset) and the ingesting push crashes."
        )
    if xorb_lookup_offset != footer_offset or chunk_lookup_offset != footer_offset:
        raise TestFailure(
            "global-dedup-shard: xorb/chunk lookup offsets must also point at "
            f"the section end ({footer_offset}); got xorb_lookup_offset="
            f"{xorb_lookup_offset}, chunk_lookup_offset={chunk_lookup_offset}"
        )
