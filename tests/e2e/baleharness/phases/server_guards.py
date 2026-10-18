"""Server-side integrity guards against a hostile (or buggy) writer: shard
registration must prove possession of the content it names, client-supplied
CAS chunk lists must never reach the global dedup index, xorb decompression
must be bounded, and the recorded frame layout must always describe the exact
xorb bytes the blob store kept."""

from __future__ import annotations

import json
import os
import re
import secrets
import struct
import subprocess
import threading
import time
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import E2E_HUB_TOKEN, E2E_OWNER, E2E_USER
from baleharness.gitutil import git, pointer_hash_at, verify_worktree
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, info
from baleharness.mocks import MockAuthzServer
from baleharness.payloads import deterministic_payload
from baleharness.phases.adversarial import _http
from baleharness.proc import pick_free_port, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.s3backend import get_active_s3_backend
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings

SG_VICTIM_REPO = "shard-guards-victim"
SG_RACE_REPO = "shard-guards-race"
SG_HEAL_REPO = "xorb-layout-heal"
SG_DEDUP_A = "global-dedup-a"
SG_DEDUP_B = "global-dedup-b"
SG_OVERSIZE_REPO = "oversize-xorb"
OVERSIZE_FILE_BYTES = 66 * 1024 * 1024
SG_LARGE_REPO = "large-file"
LARGE_FILE_BYTES = 600 * 1024 * 1024
SG_OVERLAP_REPO = "fetch-overlap"
SG_REPEAT_REPO = "dedup-repeated-chunk"
SG_QUOTA_REPO = "quota-atomic"
SG_ATTACKER = "mallory/shard-guards"
RACE_FILES = 12
RACE_FILE_BYTES = 192 * 1024

_SHARD_TAG = bytes(
    [72, 70, 82, 101, 112, 111, 77, 101, 116, 97, 68, 97, 116, 97, 0, 85, 105]
    + [103, 69, 106, 123, 129, 87, 131, 165, 189, 217, 92, 205, 209, 74, 169]
)
_FLAG_WITH_VERIFICATION = 1 << 31


def _wire_to_raw(hex_: str) -> bytes:
    # Inverse of bale-server-wire's encode_hash: each 8-byte group is
    # byte-reversed relative to its 16-char hex run.
    out = bytearray(32)
    for g in range(4):
        out[g * 8 : g * 8 + 8] = bytes.fromhex(hex_[g * 16 : g * 16 + 16])[::-1]
    return bytes(out)


def _raw_to_wire(raw: bytes) -> str:
    return "".join(raw[g * 8 : g * 8 + 8][::-1].hex() for g in range(4))


def _shard(files: list[dict], cas_blocks: list[dict] = ()) -> bytes:
    """Minimal MDB shard (no footer), mirroring bale-server-shard's serializer.
    files: {hash, terms: [(xorb_raw, unpacked, start, end)], verifications|None}
    cas_blocks: {xorb, chunks: [(chunk_raw, byte_start, unpacked)]}"""
    out = bytearray(_SHARD_TAG + struct.pack("<QQ", 2, 0))
    for f in files:
        ver = f.get("verifications")
        flags = _FLAG_WITH_VERIFICATION if ver is not None else 0
        out += f["hash"] + struct.pack("<II", flags, len(f["terms"])) + bytes(8)
        for xorb, unpacked, start, end in f["terms"]:
            out += xorb + struct.pack("<IIII", 0, unpacked, start, end)
        for v in ver or []:
            out += v + bytes(16)
    out += b"\xff" * 32 + bytes(16)
    for cb in cas_blocks:
        total = sum(c[2] for c in cb["chunks"])
        out += cb["xorb"] + struct.pack("<IIII", 0, len(cb["chunks"]), total, total)
        for chunk, byte_start, unpacked in cb["chunks"]:
            out += chunk + struct.pack("<II", byte_start, unpacked) + bytes(8)
    out += b"\xff" * 32 + bytes(16)
    return bytes(out)


def _xxh32(data: bytes, seed: int = 0) -> int:
    p1, p2, p3, p4, p5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    m = 0xFFFFFFFF

    def rotl(x: int, r: int) -> int:
        return ((x << r) | (x >> (32 - r))) & m

    n = len(data)
    i = 0
    if n >= 16:
        v = [(seed + p1 + p2) & m, (seed + p2) & m, seed & m, (seed - p1) & m]
        while i + 16 <= n:
            for k in range(4):
                (w,) = struct.unpack_from("<I", data, i + 4 * k)
                v[k] = (rotl((v[k] + w * p2) & m, 13) * p1) & m
            i += 16
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & m
    else:
        h = (seed + p5) & m
    h = (h + n) & m
    while i + 4 <= n:
        (w,) = struct.unpack_from("<I", data, i)
        h = (rotl((h + w * p3) & m, 17) * p4) & m
        i += 4
    while i < n:
        h = (rotl((h + data[i] * p5) & m, 11) * p1) & m
        i += 1
    h ^= h >> 15
    h = (h * p2) & m
    h ^= h >> 13
    h = (h * p3) & m
    h ^= h >> 16
    return h


def _lz4_frame(blocks: list[tuple[bytes, bool]]) -> bytes:
    """LZ4 frame (independent blocks, 4 MiB max, no checksums). Each block is
    (bytes, stored_uncompressed)."""
    desc = bytes([0x60, 0x70])
    out = bytearray(struct.pack("<I", 0x184D2204) + desc)
    out.append((_xxh32(desc) >> 8) & 0xFF)
    for data, raw in blocks:
        out += struct.pack("<I", len(data) | (0x80000000 if raw else 0)) + data
    out += struct.pack("<I", 0)
    return bytes(out)


def _xorb_frames(body: bytes) -> list[tuple[int, int, bytes]]:
    """(scheme, uncompressed_len, payload) per frame, stopping at the footer."""
    frames, pos = [], 0
    while pos + 8 <= len(body) and body[pos] == 0:
        clen = int.from_bytes(body[pos + 1 : pos + 4], "little")
        ulen = int.from_bytes(body[pos + 5 : pos + 8], "little")
        frames.append((body[pos + 4], ulen, body[pos + 8 : pos + 8 + clen]))
        pos += 8 + clen
    return frames


def _strip_footer(body: bytes) -> bytes:
    return b"".join(_frame(*f) for f in _xorb_frames(body))


def _frame(scheme: int, ulen: int, payload: bytes) -> bytes:
    return (
        bytes([0])
        + len(payload).to_bytes(3, "little")
        + bytes([scheme])
        + ulen.to_bytes(3, "little")
        + payload
    )


def _reencode_lz4(body: bytes) -> bytes:
    """Same chunks (so the same xorb hash), different on-disk bytes: every
    uncompressed frame is re-wrapped as an LZ4 frame of stored blocks, which
    shifts every subsequent frame offset."""
    out = bytearray()
    for scheme, ulen, payload in _xorb_frames(body):
        if scheme == 0:
            out += _frame(1, ulen, _lz4_frame([(payload, True)]))
        else:
            out += _frame(scheme, ulen, payload)
    if bytes(out) == body[: len(out)]:
        raise TestFailure("re-encoding changed nothing — no uncompressed frames")
    return bytes(out)


def _bomb_xorb(blocks: int) -> bytes:
    """One xorb frame declaring a 100-byte chunk whose LZ4 payload inflates to
    `blocks` x 4 MiB: an unbounded decoder allocates GiBs before it can compare
    lengths."""
    block_out = 4 * 1024 * 1024
    match_len = block_out - 1 - 5
    ext = match_len - 4 - 15
    seq = bytes([0x1F]) + b"A" + struct.pack("<H", 1)
    seq += b"\xff" * (ext // 255) + bytes([ext % 255])
    seq += bytes([0x50]) + b"BBBBB"
    return _frame(1, 100, _lz4_frame([(seq, False)] * blocks))


def _race_posts(url: str, bearer: str, bodies: list[bytes]) -> list[int]:
    """POST each body to `url` concurrently (released together by a barrier)."""
    return [
        status for status, _ in _race_posts_full([url] * len(bodies), bearer, bodies)
    ]


def _race_posts_full(
    urls: list[str], bearer: str, bodies: list[bytes]
) -> list[tuple[int, bytes]]:
    """POST bodies[i] to urls[i] concurrently; (status, body) per request."""
    results: list[tuple[int, bytes]] = [(0, b"")] * len(bodies)
    gate = threading.Barrier(len(bodies))

    def post(idx: int) -> None:
        gate.wait()
        results[idx] = _http("POST", urls[idx], bearer=bearer, body=bodies[idx])

    threads = [threading.Thread(target=post, args=(k,)) for k in range(len(bodies))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _expect_status(label: str, got: tuple[int, bytes], want: int) -> str:
    status, body = got
    text = body.decode(errors="replace")
    if status != want:
        raise TestFailure(f"{label}: got {status}, want {want}: {text[:300]}")
    return text


def phase_shard_guards(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """A writer to repo B must not be able to (1) re-register a file it
    doesn't hold into its own repo and read it, (2) bind an unregistered file
    hash to arbitrary bytes, (3) inject chunk→xorb mappings into the global
    dedup index, (4) OOM the server with an LZ4 bomb; and (5) concurrent
    uploads of one xorb in two valid encodings must leave a layout that
    matches the stored body. Own container, g3."""
    phase_root = work_root / "shard-guards"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_VICTIM_REPO}", f"{E2E_OWNER}/{SG_RACE_REPO}"],
        name_suffix="shard-guards",
    )
    try:
        base = server.public_host_url

        def jwt(repo_id: str) -> str:
            return mint_bale_jwt(
                secret=bytes.fromhex(jwt_secret),
                sub=E2E_USER,
                repo_type="model",
                repo_id=repo_id,
                revision="main",
                scope="write",
                ttl_secs=3600,
            )

        victim_jwt = jwt(f"{E2E_OWNER}/{SG_VICTIM_REPO}")
        attacker_jwt = jwt(SG_ATTACKER)

        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_VICTIM_REPO,
            name="victim",
        )
        payload = deterministic_payload(RACE_FILE_BYTES, seed=b"shard-guards-victim")
        (repo / "secret.bin").write_bytes(payload)
        with timings.measure("shard-guards: victim push"):
            git(["add", "secret.bin"], cwd=repo, env=env)
            git(["commit", "-m", "secret"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        file_hex = pointer_hash_at(repo, env, "HEAD:secret.bin", label="shard-guards")
        recon = json.loads(
            _expect_status(
                "victim reconstruction",
                _http(
                    "GET", f"{base}/v1/reconstructions/{file_hex}", bearer=victim_jwt
                ),
                200,
            )
        )
        terms = [
            (
                _wire_to_raw(t["hash"]),
                t["unpacked_length"],
                t["range"]["start"],
                t["range"]["end"],
            )
            for t in recon["terms"]
        ]
        recon_url = f"{base}/v1/reconstructions/{file_hex}"

        with timings.measure("shard-guards: replayed terms, no proof (400)"):
            # The attacker replays the exact terms a reconstruction reveals, so
            # the file hash re-aggregates correctly; only the verification range
            # hashes (which need plaintext chunk hashes) can stop it.
            for label, ver in [
                ("no verification entries", None),
                ("forged verification", [secrets.token_bytes(32) for _ in terms]),
            ]:
                shard = _shard(
                    [
                        {
                            "hash": _wire_to_raw(file_hex),
                            "terms": terms,
                            "verifications": ver,
                        }
                    ]
                )
                _expect_status(
                    f"replayed terms with {label}",
                    _http("POST", f"{base}/shards", bearer=attacker_jwt, body=shard),
                    400,
                )
                _expect_status(
                    f"attacker reconstruction after {label}",
                    _http("GET", recon_url, bearer=attacker_jwt),
                    404,
                )

        with timings.measure("shard-guards: unregistered hash poisoning (400)"):
            bogus_hash = secrets.token_bytes(32)
            shard = _shard(
                [
                    {
                        "hash": bogus_hash,
                        "terms": terms,
                        "verifications": [secrets.token_bytes(32) for _ in terms],
                    }
                ]
            )
            _expect_status(
                "binding an unregistered hash to someone else's xorb",
                _http("POST", f"{base}/shards", bearer=attacker_jwt, body=shard),
                400,
            )

        with timings.measure("shard-guards: CAS-block dedup poisoning ignored"):
            fake_chunk = secrets.token_bytes(32)
            xorb_raw = terms[0][0]
            shard = _shard(
                [], [{"xorb": xorb_raw, "chunks": [(fake_chunk, 0, terms[0][1])]}]
            )
            _http("POST", f"{base}/shards", bearer=attacker_jwt, body=shard)
            _expect_status(
                "dedup lookup of a chunk only a client CAS block claimed",
                _http(
                    "GET",
                    f"{base}/v1/chunks/default/{_raw_to_wire(fake_chunk)}",
                    bearer=attacker_jwt,
                ),
                404,
            )

        with timings.measure("shard-guards: LZ4 decompression bomb (400)"):
            bomb = _bomb_xorb(900)
            started = time.monotonic()
            _expect_status(
                "LZ4 bomb xorb",
                _http(
                    "POST",
                    f"{base}/v1/xorbs/default/{'33' * 32}",
                    bearer=attacker_jwt,
                    body=bomb,
                    timeout=120,
                ),
                400,
            )
            elapsed = time.monotonic() - started
            if elapsed > 20:
                raise TestFailure(
                    f"LZ4 bomb took {elapsed:.1f}s to reject — unbounded decode"
                )
            _expect_status("healthz after bomb", _http("GET", f"{base}/healthz"), 200)

        with timings.measure("shard-guards: concurrent two-encoding xorb uploads"):
            race_repo, race_env = init_repo_for_push(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_RACE_REPO,
                name="race",
            )
            race_jwt = jwt(f"{E2E_OWNER}/{SG_RACE_REPO}")
            payloads = {}
            for i in range(RACE_FILES):
                name = f"r{i}.bin"
                payloads[name] = deterministic_payload(
                    RACE_FILE_BYTES, seed=f"shard-guards-race-{i}".encode()
                )
                (race_repo / name).write_bytes(payloads[name])
                git(["add", name], cwd=race_repo, env=race_env)
            git(["commit", "-m", "race"], cwd=race_repo, env=race_env)
            xorb_dir = (
                race_repo / ".git" / "bale" / "staging" / "xet" / "xorbs" / "xorbs"
            )
            staged = sorted(
                p for p in xorb_dir.iterdir() if p.name.startswith("default.")
            )
            if len(staged) < RACE_FILES:
                raise TestFailure(
                    f"expected ≥{RACE_FILES} staged xorbs under {xorb_dir}, found {len(staged)}"
                )
            failures: list[str] = []
            for p in staged:
                xorb_hex = p.name.split(".", 1)[1]
                # Local staging keeps xet's footer; uploads carry frames only.
                original = _strip_footer(p.read_bytes())
                bodies = [original, _reencode_lz4(original)]
                results = _race_posts(
                    f"{base}/v1/xorbs/default/{xorb_hex}", race_jwt, bodies
                )
                if results != [200, 200]:
                    failures.append(f"{xorb_hex}: {results}")
            if failures:
                raise TestFailure(f"concurrent xorb uploads failed: {failures}")
            git(["push", "-u", "origin", "main"], cwd=race_repo, env=race_env)
            clone, clone_env, _cache = init_repo_for_clone(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_RACE_REPO,
                name="race-clone",
            )
            git(["checkout", "main"], cwd=clone, env=clone_env)
            for name, data in payloads.items():
                verify_worktree(
                    clone,
                    name,
                    expected_sha=sha256_bytes(data),
                    expected_size=len(data),
                    label=f"shard-guards race clone {name}",
                )
            info(f"  shard-guards: {len(staged)} two-encoding races, clone intact")
    finally:
        server.stop()


def phase_xorb_layout_heal(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """A xorb upload whose layout committed but whose blob write failed must
    not pin that layout: a later upload of the same hash in a *different*
    (equally valid) compression stores its own bytes, so the recorded frame
    offsets must follow them, or every file using the xorb fails to
    reconstruct. Driven with BALE_TEST_FS_WRITE_FAIL, so fs-backend only.
    Own container, g3."""
    if get_active_s3_backend() is not None:
        info("-- xorb-layout-heal: fs write-fail hook is S3-skipped")
        return
    phase_root = work_root / "xorb-layout-heal"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    repo_id = f"{E2E_OWNER}/{SG_HEAL_REPO}"
    ports = {"cas_port": pick_free_port(), "ssh_port": pick_free_port()}

    def start(extra_env: dict[str, str] | None) -> ServerHandle:
        return start_container(
            rt,
            image_tag=image_tag,
            data_root=data_root,
            jwt_secret_hex=jwt_secret,
            transfer_secret_hex=transfer_secret,
            ssh_public_key=ssh_public_key,
            test_repos=[repo_id],
            name_suffix=f"layout-heal-{secrets.token_hex(3)}",
            extra_env=extra_env,
            **ports,
        )

    server = start({"BALE_TEST_FS_WRITE_FAIL": "1"})
    try:
        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_HEAL_REPO,
            name="heal",
        )
        payload = deterministic_payload(RACE_FILE_BYTES, seed=b"xorb-layout-heal")
        (repo / "h.bin").write_bytes(payload)
        git(["add", "h.bin"], cwd=repo, env=env)
        git(["commit", "-m", "heal"], cwd=repo, env=env)
        xorb_dir = repo / ".git" / "bale" / "staging" / "xet" / "xorbs" / "xorbs"
        staged = [p for p in xorb_dir.iterdir() if p.name.startswith("default.")]
        if len(staged) != 1:
            raise TestFailure(f"expected one staged xorb, found {len(staged)}")
        xorb_hex = staged[0].name.split(".", 1)[1]
        original = staged[0].read_bytes()
        # A second file starting at chunk 1 dedups to a mid-xorb term, whose
        # byte range only resolves correctly if the layout matches the blob (a
        # whole-xorb range from offset 0 parses frame-by-frame either way).
        tail = payload[_xorb_frames(original)[0][1] :]
        token = mint_bale_jwt(
            secret=bytes.fromhex(jwt_secret),
            sub=E2E_USER,
            repo_type="model",
            repo_id=repo_id,
            revision="main",
            scope="write",
            ttl_secs=3600,
        )
        with timings.measure("xorb-layout-heal: alt-encoding upload fails mid-write"):
            status, _ = _http(
                "POST",
                f"{server.public_host_url}/v1/xorbs/default/{xorb_hex}",
                bearer=token,
                body=_reencode_lz4(original),
            )
            if status != 500:
                raise TestFailure(f"write-fail upload returned {status}, want 500")
        server.stop()
        server = start(None)
        with timings.measure("xorb-layout-heal: push + clone original encoding"):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
            (repo / "tail.bin").write_bytes(tail)
            git(["add", "tail.bin"], cwd=repo, env=env)
            git(["commit", "-m", "tail"], cwd=repo, env=env)
            git(["push"], cwd=repo, env=env)
            clone, clone_env, _cache = init_repo_for_clone(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_HEAL_REPO,
                name="heal-clone",
            )
            # Ground truth on the server: the mid-xorb term's signed byte range
            # must start exactly at the stored blob's frame boundary.
            tail_hex = pointer_hash_at(repo, env, "HEAD:tail.bin", label="layout-heal")
            recon = json.loads(
                _expect_status(
                    "tail reconstruction",
                    _http(
                        "GET",
                        f"{server.public_host_url}/v1/reconstructions/{tail_hex}",
                        bearer=token,
                    ),
                    200,
                )
            )
            raw = _wire_to_raw(xorb_hex).hex()
            stored = (data_root / "xorbs" / raw[:2] / raw[2:4] / raw).read_bytes()
            starts, pos = [], 0
            for _scheme, _ulen, frame_payload in _xorb_frames(stored):
                starts.append(pos)
                pos += 8 + len(frame_payload)
            for info_ in recon["fetch_info"][xorb_hex]:
                want = starts[info_["range"]["start"]]
                got = info_["url_range"]["start"]
                if got != want:
                    raise TestFailure(
                        f"layout/blob mismatch: term range starts at byte {got}, "
                        f"stored frame starts at {want}"
                    )
            # tail.bin first, cold: checking out h.bin would fetch the whole
            # xorb and serve tail.bin's chunks from the chunk cache instead.
            # .gitattributes before it, or git writes the raw pointer unfiltered.
            git(["checkout", "main", "--", ".gitattributes"], cwd=clone, env=clone_env)
            git(["checkout", "main", "--", "tail.bin"], cwd=clone, env=clone_env)
            git(["checkout", "main", "--", "."], cwd=clone, env=clone_env)
            for name, data in [("tail.bin", tail), ("h.bin", payload)]:
                verify_worktree(
                    clone,
                    name,
                    expected_sha=sha256_bytes(data),
                    expected_size=len(data),
                    label=f"xorb-layout-heal clone {name}",
                )
    finally:
        server.stop()


def _count_xorb_posts(logs: str) -> int:
    plain = re.sub(r"\x1b\[[0-9;]*m", "", logs)
    return sum(
        1
        for line in plain.splitlines()
        if "on_response" in line and "method=POST" in line and "/v1/xorbs/" in line
    )


def phase_global_dedup_hit(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """A second user (fresh HOME and caches, so no local shard-cache dedup)
    pushing content another repo already stored must dedup against the server:
    the global-dedup response's wrapped chunk hashes have to match what xet
    computes (keyed BLAKE3), and the resulting shard — terms into the other
    repo's xorb — must pass the server's proof-of-possession check. Expect zero
    xorb uploads for the second push and a byte-exact clone. Own container, g3."""
    phase_root = work_root / "global-dedup-hit"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=secrets.token_bytes(32).hex(),
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_DEDUP_A}", f"{E2E_OWNER}/{SG_DEDUP_B}"],
        name_suffix="global-dedup-hit",
    )
    try:
        payload = deterministic_payload(4 * 1024 * 1024, seed=b"global-dedup-hit")
        repo_a, env_a = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_DEDUP_A,
            name="dedup-a",
        )
        (repo_a / "f.bin").write_bytes(payload)
        with timings.measure("global-dedup-hit: user A pushes"):
            git(["add", "f.bin"], cwd=repo_a, env=env_a)
            git(["commit", "-m", "a"], cwd=repo_a, env=env_a)
            git(["push", "-u", "origin", "main"], cwd=repo_a, env=env_a)

        repo_b, env_b = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_DEDUP_B,
            name="dedup-b",
        )
        home_b = phase_root / "home-b"
        home_b.mkdir()
        env_b = dict(env_b, HOME=str(home_b))
        (repo_b / "f.bin").write_bytes(payload)
        posts_before = _count_xorb_posts(server.logs())
        with timings.measure("global-dedup-hit: user B pushes same content"):
            git(["add", "f.bin"], cwd=repo_b, env=env_b)
            git(["commit", "-m", "b"], cwd=repo_b, env=env_b)
            git(["push", "-u", "origin", "main"], cwd=repo_b, env=env_b)
        uploaded = _count_xorb_posts(server.logs()) - posts_before
        if uploaded != 0:
            raise TestFailure(
                f"user B uploaded {uploaded} xorb(s) for content the server already "
                "holds — global dedup never matched"
            )
        clone, clone_env, _cache = init_repo_for_clone(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_DEDUP_B,
            name="dedup-b-clone",
        )
        git(["checkout", "main"], cwd=clone, env=clone_env)
        verify_worktree(
            clone,
            "f.bin",
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="global-dedup-hit clone",
        )
    finally:
        server.stop()


def phase_oversize_xorb(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """xet cuts xorbs at 64 MiB of *unpacked* data and stores incompressible
    chunks raw plus an 8-byte header each, so a legit serialized xorb can be
    slightly over 64 MiB. Search seeds (offline `git add`, inspect staging)
    for one that produces such a xorb, then push and cold-clone it. Own
    container, g3."""
    phase_root = work_root / "oversize-xorb"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=secrets.token_bytes(32).hex(),
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_OVERSIZE_REPO}"],
        name_suffix="oversize-xorb",
    )
    try:
        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_OVERSIZE_REPO,
            name="oversize",
        )
        xorb_dir = repo / ".git" / "bale" / "staging" / "xet" / "xorbs" / "xorbs"
        payload = None
        with timings.measure("oversize-xorb: search for a >64 MiB serialized xorb"):
            for seed in range(60):
                candidate = deterministic_payload(
                    OVERSIZE_FILE_BYTES, seed=f"oversize-{seed}".encode()
                )
                (repo / "big.bin").write_bytes(candidate)
                git(["add", "big.bin"], cwd=repo, env=env)
                sizes = [p.stat().st_size for p in xorb_dir.glob("default.*")]
                if any(sz > 64 * 1024 * 1024 for sz in sizes):
                    payload = candidate
                    break
                git(["reset", "-q", "big.bin"], cwd=repo, env=env)
        if payload is None:
            raise TestFailure("no seed produced a >64 MiB serialized xorb in 60 tries")
        with timings.measure("oversize-xorb: push + cold clone"):
            git(["commit", "-m", "big"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
            clone, clone_env, _cache = init_repo_for_clone(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_OVERSIZE_REPO,
                name="oversize-clone",
            )
            git(["checkout", "main"], cwd=clone, env=clone_env)
            verify_worktree(
                clone,
                "big.bin",
                expected_sha=sha256_bytes(payload),
                expected_size=len(payload),
                label="oversize-xorb clone",
            )
        info(f"  oversize-xorb: found after {seed + 1} seed(s)")
    finally:
        server.stop()


def phase_large_file(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """Files past 2 × xet's min reconstruction fetch size (256 MiB) are fetched
    in byte-range blocks, so /v1/reconstructions must honor `Range` (terms
    overlapping the block + offset_into_first_range, 416 past EOF) or a cold
    clone of a large file can't be reconstructed at all. Own container, g3."""
    phase_root = work_root / "large-file"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=secrets.token_bytes(32).hex(),
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_LARGE_REPO}"],
        name_suffix="large-file",
    )
    try:
        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_LARGE_REPO,
            name="large",
        )
        payload = deterministic_payload(LARGE_FILE_BYTES, seed=b"large-file")
        (repo / "large.bin").write_bytes(payload)
        with timings.measure("large-file: add + push", bytes_moved=LARGE_FILE_BYTES):
            git(["add", "large.bin"], cwd=repo, env=env)
            git(["commit", "-m", "large"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        with timings.measure("large-file: cold clone", bytes_moved=LARGE_FILE_BYTES):
            clone, clone_env, _cache = init_repo_for_clone(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_LARGE_REPO,
                name="large-clone",
            )
            git(["checkout", "main"], cwd=clone, env=clone_env)
            verify_worktree(
                clone,
                "large.bin",
                expected_sha=sha256_bytes(payload),
                expected_size=len(payload),
                label="large-file clone",
            )
    finally:
        server.stop()


def resolve_e2e_tools() -> Path:
    """The `bale-e2e-tools` helper (xet hashing for crafted xorbs/shards)."""
    exe = "bale-e2e-tools.exe" if os.name == "nt" else "bale-e2e-tools"
    path = Path(__file__).resolve().parents[4] / "target" / "release" / exe
    if not path.is_file():
        raise TestFailure(
            f"missing {path}; build it first: cargo build --release -p bale-e2e-tools"
        )
    return path


def _tools(*args: str) -> dict:
    out = subprocess.run(
        [str(resolve_e2e_tools()), *args], capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        raise TestFailure(f"bale-e2e-tools {args[0]} failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


def phase_fetch_overlap(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """A file whose terms overlap within one xorb ([X 0..5] then [X 0..10]) must
    reconstruct. xet binds each term to the first fetch entry containing it and
    dedups blocks by (xorb, range start), so per-term (overlapping) fetch
    entries made it slice a 5-chunk block for the 10-chunk term and panic; the
    server must emit disjoint merged ranges. Built with bale-e2e-tools, pushed
    as a hand-made pointer, cold-cloned. Own container, g3."""
    phase_root = work_root / "fetch-overlap"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_OVERLAP_REPO}"],
        name_suffix="fetch-overlap",
    )
    try:
        token = mint_bale_jwt(
            secret=bytes.fromhex(jwt_secret),
            sub=E2E_USER,
            repo_type="model",
            repo_id=f"{E2E_OWNER}/{SG_OVERLAP_REPO}",
            revision="main",
            scope="write",
            ttl_secs=3600,
        )
        base = server.public_host_url
        chunk_dir = phase_root / "chunks"
        chunk_dir.mkdir()
        chunks = []
        for i in range(10):
            data = deterministic_payload(8 * 1024, seed=f"overlap-{i}".encode())
            (chunk_dir / f"{i}").write_bytes(data)
            chunks.append(data)
        body_path = phase_root / "xorb.bin"
        xorb = _tools(
            "xorb", str(body_path), *[str(chunk_dir / f"{i}") for i in range(10)]
        )
        spec = {
            "files": [
                {
                    "terms": [
                        {
                            "xorb": xorb["hash"],
                            "start": 0,
                            "end": 5,
                            "chunks": xorb["chunks"],
                        },
                        {
                            "xorb": xorb["hash"],
                            "start": 0,
                            "end": 10,
                            "chunks": xorb["chunks"],
                        },
                    ]
                }
            ]
        }
        spec_path = phase_root / "spec.json"
        spec_path.write_text(json.dumps(spec))
        shard_path = phase_root / "shard.bin"
        file_info = _tools("shard", str(shard_path), str(spec_path))["files"][0]
        content = b"".join(chunks[:5]) + b"".join(chunks)
        if file_info["size"] != len(content):
            raise TestFailure(f"helper size {file_info['size']} != {len(content)}")

        with timings.measure("fetch-overlap: register overlapping-term file"):
            _expect_status(
                "xorb upload",
                _http(
                    "POST",
                    f"{base}/v1/xorbs/default/{xorb['hash']}",
                    bearer=token,
                    body=body_path.read_bytes(),
                ),
                200,
            )
            _expect_status(
                "shard upload",
                _http(
                    "POST", f"{base}/shards", bearer=token, body=shard_path.read_bytes()
                ),
                200,
            )

        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_OVERLAP_REPO,
            name="overlap",
        )
        pointer = (
            "{\n"
            f'  "hash": "{file_info["hash"]}",\n'
            f'  "file_size": {len(content)},\n'
            f'  "sha256": "{sha256_bytes(content)}"\n'
            "}\n"
        )
        oid = (
            subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                input=pointer.encode(),
                cwd=repo,
                env=env,
                capture_output=True,
                check=True,
            )
            .stdout.decode()
            .strip()
        )
        git(
            ["update-index", "--add", "--cacheinfo", f"100644,{oid},o.bin"],
            cwd=repo,
            env=env,
        )
        git(["commit", "-m", "overlap"], cwd=repo, env=env)
        with timings.measure("fetch-overlap: push + cold clone"):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
            clone, clone_env, _cache = init_repo_for_clone(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_OVERLAP_REPO,
                name="overlap-clone",
            )
            git(["checkout", "main"], cwd=clone, env=clone_env)
            verify_worktree(
                clone,
                "o.bin",
                expected_sha=sha256_bytes(content),
                expected_size=len(content),
                label="fetch-overlap clone",
            )
    finally:
        server.stop()


def _dedup_cas_lengths(shard: bytes) -> list[list[int]]:
    """Per CAS block in a /v1/chunks response shard: each entry's unpacked
    length, in position order (mirrors bale-server-shard's serializer)."""
    pos = 48
    while shard[pos : pos + 32] != b"\xff" * 32:  # file-info section (empty)
        pos += 48
    pos += 48
    blocks = []
    while shard[pos : pos + 32] != b"\xff" * 32:
        n = struct.unpack_from("<I", shard, pos + 36)[0]
        pos += 48
        lens = [struct.unpack_from("<I", shard, pos + 48 * k + 36)[0] for k in range(n)]
        blocks.append(lens)
        pos += 48 * n
    return blocks


def phase_dedup_repeated_chunk(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """A xorb may hold the same chunk twice (xet dedups repeats only within one
    file's new data). Clients dedup against a /v1/chunks response by chunk
    *position*, so the response must list every position — the chunks table's
    (chunk_hash, xorb) key collapses the repeat, and a list built from it
    shifts every later index (silent wrong bytes). Also cold-clones a file that
    references the repeated chunk. Own container, g3."""
    phase_root = work_root / "dedup-repeated-chunk"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_REPEAT_REPO}"],
        name_suffix="dedup-repeated-chunk",
    )
    try:
        token = mint_bale_jwt(
            secret=bytes.fromhex(jwt_secret),
            sub=E2E_USER,
            repo_type="model",
            repo_id=f"{E2E_OWNER}/{SG_REPEAT_REPO}",
            revision="main",
            scope="write",
            ttl_secs=3600,
        )
        base = server.public_host_url
        chunk_dir = phase_root / "chunks"
        chunk_dir.mkdir()
        # Distinct sizes make positions checkable from lengths alone.
        sizes = {"a": 8000, "b": 8100, "c": 8200}
        data = {
            k: deterministic_payload(n, seed=f"repeat-{k}".encode())
            for k, n in sizes.items()
        }
        for k, v in data.items():
            (chunk_dir / k).write_bytes(v)
        order = ["a", "b", "a", "c"]
        body_path = phase_root / "xorb.bin"
        xorb = _tools("xorb", str(body_path), *[str(chunk_dir / k) for k in order])
        _expect_status(
            "xorb upload",
            _http(
                "POST",
                f"{base}/v1/xorbs/default/{xorb['hash']}",
                bearer=token,
                body=body_path.read_bytes(),
            ),
            200,
        )
        with timings.measure(
            "dedup-repeated-chunk: dedup response keeps every position"
        ):
            chunk_a = _raw_to_wire(bytes.fromhex(xorb["chunks"][0]["hash"]))
            status, shard = _http(
                "GET", f"{base}/v1/chunks/default/{chunk_a}", bearer=token
            )
            if status != 200:
                raise TestFailure(f"dedup lookup of a stored chunk returned {status}")
            want = [sizes[k] for k in order]
            got = _dedup_cas_lengths(shard)
            if got != [want]:
                raise TestFailure(f"dedup CAS block lengths {got}, want [{want}]")

        spec = {
            "files": [
                {
                    "terms": [
                        {
                            "xorb": xorb["hash"],
                            "start": 1,
                            "end": 4,
                            "chunks": xorb["chunks"],
                        }
                    ]
                }
            ]
        }
        spec_path = phase_root / "spec.json"
        spec_path.write_text(json.dumps(spec))
        shard_path = phase_root / "shard.bin"
        file_info = _tools("shard", str(shard_path), str(spec_path))["files"][0]
        _expect_status(
            "shard upload",
            _http("POST", f"{base}/shards", bearer=token, body=shard_path.read_bytes()),
            200,
        )
        content = data["b"] + data["a"] + data["c"]
        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=SG_REPEAT_REPO,
            name="repeat",
        )
        pointer = (
            "{\n"
            f'  "hash": "{file_info["hash"]}",\n'
            f'  "file_size": {len(content)},\n'
            f'  "sha256": "{sha256_bytes(content)}"\n'
            "}\n"
        )
        oid = (
            subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                input=pointer.encode(),
                cwd=repo,
                env=env,
                capture_output=True,
                check=True,
            )
            .stdout.decode()
            .strip()
        )
        git(
            ["update-index", "--add", "--cacheinfo", f"100644,{oid},r.bin"],
            cwd=repo,
            env=env,
        )
        git(["commit", "-m", "repeat"], cwd=repo, env=env)
        with timings.measure("dedup-repeated-chunk: push + cold clone"):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
            clone, clone_env, _cache = init_repo_for_clone(
                work_root=phase_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=SG_REPEAT_REPO,
                name="repeat-clone",
            )
            git(["checkout", "main"], cwd=clone, env=clone_env)
            verify_worktree(
                clone,
                "r.bin",
                expected_sha=sha256_bytes(content),
                expected_size=len(content),
                label="dedup-repeated-chunk clone",
            )
    finally:
        server.stop()


def phase_quota_atomic(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """(1) Two shards that each fit an owner's quota but together don't, posted
    at the same instant: the in-transaction recheck must let exactly one
    through. (2) Xorbs uploaded without ever registering a file are charged to
    the uploader, so they can't grow storage past the quota. Crafted with
    bale-e2e-tools over direct HTTP. Own container, g3."""
    del client
    phase_root = work_root / "quota-atomic"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    admin_hex = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=data_root,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=secrets.token_bytes(32).hex(),
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{SG_QUOTA_REPO}"],
        admin_token_hex=admin_hex,
        name_suffix="quota-atomic",
    )
    try:
        base = server.public_host_url

        def jwt(owner: str) -> str:
            return mint_bale_jwt(
                secret=bytes.fromhex(jwt_secret),
                sub=E2E_USER,
                repo_type="model",
                repo_id=f"{owner}/{SG_QUOTA_REPO}",
                revision="main",
                scope="write",
                ttl_secs=3600,
            )

        def set_quota(owner: str, limit: int) -> None:
            _expect_status(
                f"set quota for {owner}",
                _http(
                    "PUT",
                    f"{base}/v1/quotas/{owner}",
                    bearer=admin_hex,
                    body=json.dumps({"limit_bytes": limit}).encode(),
                    headers={"Content-Type": "application/json"},
                ),
                204,
            )

        def make_xorb(tag: str) -> tuple[dict, bytes]:
            d = phase_root / f"chunks-{tag}"
            d.mkdir()
            paths = []
            for i in range(3):
                (d / f"{i}").write_bytes(
                    deterministic_payload(8000, seed=f"quota-{tag}-{i}".encode())
                )
                paths.append(str(d / f"{i}"))
            body_path = phase_root / f"xorb-{tag}.bin"
            info_ = _tools("xorb", str(body_path), *paths)
            return info_, body_path.read_bytes()

        def make_shard(tag: str, xorb: dict) -> bytes:
            spec_path = phase_root / f"spec-{tag}.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "files": [
                            {
                                "terms": [
                                    {
                                        "xorb": xorb["hash"],
                                        "start": 0,
                                        "end": 3,
                                        "chunks": xorb["chunks"],
                                    }
                                ]
                            }
                        ]
                    }
                )
            )
            out = phase_root / f"shard-{tag}.bin"
            _tools("shard", str(out), str(spec_path))
            return out.read_bytes()

        xorb_bytes = 3 * (8000 + 8)
        uploader, registrant, hoarder = (
            "quota-uploader",
            "quota-registrant",
            "quota-hoarder",
        )
        x1, b1 = make_xorb("1")
        x2, b2 = make_xorb("2")
        for x, b in [(x1, b1), (x2, b2)]:
            _expect_status(
                "uploader xorb",
                _http(
                    "POST",
                    f"{base}/v1/xorbs/default/{x['hash']}",
                    bearer=jwt(uploader),
                    body=b,
                ),
                200,
            )
        limit = xorb_bytes + xorb_bytes // 2
        set_quota(registrant, limit)
        with timings.measure("quota-atomic: concurrent shards past quota"):
            results = _race_posts_full(
                [f"{base}/shards"] * 2,
                jwt(registrant),
                [make_shard("1", x1), make_shard("2", x2)],
            )
            statuses = sorted(st for st, _ in results)
            if statuses != [200, 413]:
                raise TestFailure(
                    f"concurrent over-quota shards returned {statuses}, want exactly one "
                    "200 and one 413 — the quota recheck isn't atomic"
                )
            # Both fit the pre-check alone; only the in-transaction recheck
            # (whose message differs) can refuse one of them.
            refused = next(b for st, b in results if st == 413).decode(errors="replace")
            if "bytes would exceed" not in refused:
                raise TestFailure(
                    f"413 didn't come from the in-transaction check: {refused[:200]}"
                )
            usage = json.loads(
                _expect_status(
                    "registrant usage",
                    _http("GET", f"{base}/v1/usage/{registrant}", bearer=admin_hex),
                    200,
                )
            )
            if usage["stored_bytes"] > limit:
                raise TestFailure(
                    f"registrant stored {usage['stored_bytes']} > quota {limit}"
                )

        pusher = "quota-pusher"
        set_quota(pusher, limit)
        with timings.measure("quota-atomic: own push under quota succeeds"):
            # Two-thirds of the quota: the owner's just-uploaded xorb must not
            # be charged twice (as its own upload and again as new delta).
            x5, b5 = make_xorb("5")
            _expect_status(
                "pusher xorb",
                _http(
                    "POST",
                    f"{base}/v1/xorbs/default/{x5['hash']}",
                    bearer=jwt(pusher),
                    body=b5,
                ),
                200,
            )
            _expect_status(
                "pusher shard",
                _http(
                    "POST",
                    f"{base}/shards",
                    bearer=jwt(pusher),
                    body=make_shard("5", x5),
                ),
                200,
            )

        racer = "quota-racer"
        set_quota(racer, limit)
        with timings.measure("quota-atomic: concurrent new-xorb uploads past quota"):
            x6, b6 = make_xorb("6")
            x7, b7 = make_xorb("7")
            results = _race_posts_full(
                [
                    f"{base}/v1/xorbs/default/{x6['hash']}",
                    f"{base}/v1/xorbs/default/{x7['hash']}",
                ],
                jwt(racer),
                [b6, b7],
            )
            statuses = sorted(st for st, _ in results)
            if statuses != [200, 413]:
                raise TestFailure(
                    f"concurrent over-quota xorb uploads returned {statuses}, want exactly "
                    "one 200 and one 413 — upload reservations aren't atomic"
                )

        set_quota(hoarder, limit)
        with timings.measure("quota-atomic: unreferenced uploads are charged"):
            x3, b3 = make_xorb("3")
            x4, b4 = make_xorb("4")
            _expect_status(
                "first unreferenced xorb",
                _http(
                    "POST",
                    f"{base}/v1/xorbs/default/{x3['hash']}",
                    bearer=jwt(hoarder),
                    body=b3,
                ),
                200,
            )
            _expect_status(
                "unreferenced xorb past quota",
                _http(
                    "POST",
                    f"{base}/v1/xorbs/default/{x4['hash']}",
                    bearer=jwt(hoarder),
                    body=b4,
                ),
                413,
            )
    finally:
        server.stop()


def phase_canonical_scope(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """The authority's canonical scope key and accounting owner win over the
    client-typed repo name: with a forge that resolves names case-insensitively
    and keys repos by immutable id (`id/42`, owner `7`, as the gitea fork does),
    a push via `canon/repo` must be readable via `Canon/Repo`, charged to owner
    `7`, and stay readable after a simulated transfer to owner `8`. Mock
    /check_access, own container, g3."""
    phase_root = work_root / "canonical-scope"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    admin_hex = secrets.token_bytes(32).hex()
    owner = {"id": "7"}

    def decide(bearer: str, repo_id: str, scope: str) -> tuple[int, dict]:
        del scope
        if bearer != E2E_HUB_TOKEN or repo_id.lower() != "canon/repo":
            return 401, {"error": "denied"}
        return 200, {"user_id": "alice", "repo_id": "id/42", "owner": owner["id"]}

    mock = MockAuthzServer(decide)
    mock.start()
    server = None
    try:
        server = start_container(
            rt,
            image_tag=image_tag,
            data_root=data_root,
            jwt_secret_hex=secrets.token_bytes(32).hex(),
            transfer_secret_hex=secrets.token_bytes(32).hex(),
            ssh_public_key=ssh_public_key,
            test_repos=["canon/repo"],
            admin_token_hex=admin_hex,
            name_suffix="canonical-scope",
            extra_env={"BALE_AUTHZ_HTTP_URL": mock.url},
        )
        base = server.public_host_url
        repo, env = init_repo_for_push(
            work_root=phase_root,
            client=client,
            server=server,
            owner="canon",
            repo="repo",
            name="canon",
        )
        payload = deterministic_payload(RACE_FILE_BYTES, seed=b"canonical-scope")
        (repo / "c.bin").write_bytes(payload)
        with timings.measure("canonical-scope: push via canon/repo"):
            git(["add", "c.bin"], cwd=repo, env=env)
            git(["commit", "-m", "c"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        file_hex = pointer_hash_at(repo, env, "HEAD:c.bin", label="canonical-scope")

        def read_via(typed: str) -> int:
            status, body = _http(
                "GET",
                f"{base}/api/models/{typed}/bale-read-token/main",
                bearer=E2E_HUB_TOKEN,
            )
            if status != 200:
                raise TestFailure(f"token exchange as {typed} returned {status}")
            token = json.loads(body)["accessToken"]
            return _http("GET", f"{base}/v1/reconstructions/{file_hex}", bearer=token)[
                0
            ]

        with timings.measure("canonical-scope: case variant + accounting owner"):
            if read_via("Canon/Repo") != 200:
                raise TestFailure(
                    "file pushed via canon/repo not readable via Canon/Repo"
                )

            def stored(o: str) -> int:
                return json.loads(
                    _expect_status(
                        f"usage of {o}",
                        _http("GET", f"{base}/v1/usage/{o}", bearer=admin_hex),
                        200,
                    )
                )["stored_bytes"]

            if stored("7") <= 0 or stored("canon") != 0:
                raise TestFailure(
                    f"accounting owner wrong: owner 7={stored('7')}, canon={stored('canon')}"
                )
        with timings.measure("canonical-scope: readable after transfer"):
            owner["id"] = "8"
            if read_via("canon/repo") != 200:
                raise TestFailure("file not readable after the repo's owner changed")
    finally:
        if server is not None:
            server.stop()
        mock.stop()


def phase_file_hasher_selfcheck(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
) -> None:
    """The server verifies file hashes with an incremental merkle hasher; it
    must equal xet's own file_hash on every sequence length (no container)."""
    del rt, image_tag, work_root, client, ssh_public_key
    with timings.measure("file-hasher-selfcheck"):
        checked = _tools("selfcheck")["checked"]
        info(f"  file-hasher-selfcheck: {checked} sequences match xet")
