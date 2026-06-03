"""Adversarial phases (wrong token, tampered xorb, quota exceeded)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from baleharness.client import ClientEnv
from baleharness.config import (
    BIG_FILE_BYTES,
    E2E_OWNER,
    E2E_REPO,
    E2E_REPO_2,
    E2E_USER,
    SIZE_TOLERANCE_BYTES,
    SMALL_FILE_BYTES,
)
from baleharness.gitutil import git, pointer_hash_at, verify_pointer_at, verify_worktree
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, fmt_bytes, info
from baleharness.phases.failure import fail_fast_xet_env
from baleharness.payloads import deterministic_payload
from baleharness.proc import sha256_bytes, sha256_file
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings


def phase_adversarial_wrong_token(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
) -> None:
    """A repo whose bale.serverUrl/token are overridden to a deliberately
    wrong token: the push should fail before any data is corrupted."""
    repo, env = init_repo_for_push(
        work_root=work_root,
        client=client,
        server=server,
        owner=E2E_OWNER,
        repo=E2E_REPO,
        name="wrong-token",
    )
    # Pin a known-bad token so the resolver fast-paths to it (skipping SSH
    # forge auth). The server's verify_xet_token will reject it.
    git(
        ["config", "--local", "bale.serverUrl", server.public_host_url],
        cwd=repo,
        env=env,
    )
    git(
        ["config", "--local", "bale.token", "this-is-not-a-valid-jwt"],
        cwd=repo,
        env=env,
    )
    payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"wrongtoken")
    payload_sha = sha256_bytes(payload)
    (repo / "wrongtoken.bin").write_bytes(payload)
    with timings.measure("adversarial: stage with wrong token (offline)"):
        # Stage succeeds — clean is offline.
        git(["add", "wrongtoken.bin"], cwd=repo, env=env)
        verify_pointer_at(
            repo,
            env,
            spec=":wrongtoken.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="wrongtoken:after-stage",
        )
        git(["commit", "-m", "wrongtoken"], cwd=repo, env=env)
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:wrongtoken.bin",
            expected_sha=payload_sha,
            expected_size=SMALL_FILE_BYTES,
            label="wrongtoken:after-commit",
        )
    disk_before = server.disk_total_bytes()
    with timings.measure("adversarial: push fails (wrong token)"):
        completed = git(
            ["push", "-u", "origin", "main"],
            cwd=repo,
            env=env,
            expect_fail=True,
        )
        if completed.returncode == 0:
            raise TestFailure(
                "push with a bogus bale.token unexpectedly succeeded — "
                "verify_xet_token isn't blocking unauthorized uploads"
            )
    disk_after = server.disk_total_bytes()
    if abs(disk_after - disk_before) > SIZE_TOLERANCE_BYTES:
        raise TestFailure(
            "server disk changed during a push that should have been rejected: "
            f"{disk_before} → {disk_after}"
        )
    # A rejected push must not corrupt the client's worktree or its index/HEAD.
    verify_worktree(
        repo,
        "wrongtoken.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="wrongtoken:after-failed-push",
    )
    verify_pointer_at(
        repo,
        env,
        spec="HEAD:wrongtoken.bin",
        expected_sha=payload_sha,
        expected_size=SMALL_FILE_BYTES,
        label="wrongtoken:after-failed-push",
    )


def _fs_writer(path: Path) -> Callable[[bytes], None]:
    return lambda data: path.write_bytes(data)


def _s3_writer(minio, key: str) -> Callable[[bytes], None]:
    return lambda data: minio.put_object(key, data)


def phase_adversarial_tampered_xorb(
    *,
    timings: Timings,
    server: ServerHandle,
    client: ClientEnv,
    work_root: Path,
    rev_state: dict,
) -> None:
    """Corrupt the stored xorbs (we own both the bind-mounted fs data dir and
    the MinIO bucket), then cold-clone in a fresh worktree. The smudge must
    NOT silently produce wrong bytes — it must either error or produce content
    whose sha256 the test detects as wrong."""
    # Backend-agnostic corrupt/restore. Corrupt EVERY stored xorb — flip a
    # window in the middle of each. Corrupting just one is fragile: HEAD's
    # reconstruction (rev v3 of bigfile) only reads a subset of any single
    # xorb's chunks (e.g. the chunk at the v1 xorb's middle is exactly the
    # region v3 replaced, so it's never read), and an xorb's trailing footer
    # isn't covered by any chunk byte-range either. Hitting all of them
    # guarantees at least one corrupted chunk lands on HEAD's read path. S3
    # mode pokes bucket objects; fs mode pokes files under data_root/xorbs.
    victims: list[tuple[str, bytes, Callable[[bytes], None]]] = []
    if server.s3_view is not None:
        minio = server.s3_view.minio
        for key, size in minio.list_objects(f"{server.s3_view.prefix}xorbs/"):
            if size <= 0:
                continue
            victims.append(
                (f"s3://{key}", minio.get_object(key), _s3_writer(minio, key))
            )
        if not victims:
            raise TestFailure("no xorb in bucket to tamper with")
    else:
        xorbs_dir = server.data_root / "xorbs"
        for cur, _dirs, names in os.walk(xorbs_dir):
            for name in names:
                p = Path(cur) / name
                if p.stat().st_size > 0:
                    victims.append(
                        (
                            str(p.relative_to(server.data_root)),
                            p.read_bytes(),
                            _fs_writer(p),
                        )
                    )
        if not victims:
            raise TestFailure("no xorb on disk to tamper with")

    def corrupt(data: bytes) -> bytes:
        window = min(4096, len(data))
        start = (len(data) - window) // 2
        out = bytearray(data)
        for i in range(start, start + window):
            out[i] ^= 0xFF
        return bytes(out)

    for label, original, write in victims:
        info(f"  corrupting {label} ({len(original)}B)")
        write(corrupt(original))

    try:
        clone_path, env, _cache = init_repo_for_clone(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO_2,
            name="tampered",
        )
        bytes_match = False
        with timings.measure("adversarial: smudge a tampered xorb"):
            completed = git(
                ["checkout", "main"],
                cwd=clone_path,
                env=env,
                expect_fail=True,
            )
            if completed.returncode == 0 and (clone_path / "bigfile.bin").exists():
                got_sha = sha256_file(clone_path / "bigfile.bin")
                bytes_match = got_sha == rev_state["shas"][-1]
        if bytes_match:
            raise TestFailure(
                "tampered xorb still produced matching bytes — chunk-hash "
                "verification isn't catching corruption"
            )
    finally:
        # Restore so downstream phases aren't poisoned.
        for _label, original, write in victims:
            write(original)


def phase_adversarial_quota_exceeded(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Spin up a SEPARATE container with a tiny quota and confirm push fails
    cleanly instead of corrupting metadata. Uses a fresh data dir so it can't
    interfere with the main test's measurements."""
    quota_data = work_root / "quota-server-data"
    quota_data.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server = start_container(
        rt,
        image_tag=image_tag,
        data_root=quota_data,
        jwt_secret_hex=jwt_secret,
        transfer_secret_hex=transfer_secret,
        ssh_public_key=ssh_public_key,
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        quota_bytes=1024,  # 1 KiB — anything more than a trivial blob trips it.
        admin_token_hex=admin_token_hex,
        name_suffix="quota",
    )
    try:
        # `server` here is the quota-specific container; init_repo_for_push
        # bakes its SSH port into the remote URL, so no extra ssh-config
        # plumbing is needed.
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="quota-client",
        )
        payload = deterministic_payload(BIG_FILE_BYTES, seed=b"quota-test")
        payload_sha = sha256_bytes(payload)
        (repo / "fatfile.bin").write_bytes(payload)
        disk_before = server.disk_total_bytes()
        with timings.measure("adversarial: push past quota (must fail)"):
            git(["add", "fatfile.bin"], cwd=repo, env=env)
            verify_pointer_at(
                repo,
                env,
                spec=":fatfile.bin",
                expected_sha=payload_sha,
                expected_size=BIG_FILE_BYTES,
                label="quota:after-stage",
            )
            git(["commit", "-m", "fatfile"], cwd=repo, env=env)
            verify_pointer_at(
                repo,
                env,
                spec="HEAD:fatfile.bin",
                expected_sha=payload_sha,
                expected_size=BIG_FILE_BYTES,
                label="quota:after-commit",
            )
            completed = git(
                ["push", "-u", "origin", "main"],
                cwd=repo,
                # 429 is retried by xet; fail-fast keeps the phase from hanging ~tens of seconds.
                env=fail_fast_xet_env(env),
                expect_fail=True,
            )
        if completed.returncode == 0:
            raise TestFailure("push past the 1 KiB quota unexpectedly succeeded")
        push_output = (completed.stdout or b"") + (completed.stderr or b"")
        push_text = push_output.decode(errors="replace")
        if "over your storage quota" not in push_text.lower():
            raise TestFailure(
                "over-quota push did not surface the client-friendly quota "
                "message (429 → rewrite path broken); push output was:\n"
                f"{push_text[:2000]}"
            )
        # Server should still be healthy after the rejected push.
        with urllib.request.urlopen(server.healthz_url, timeout=5) as resp:
            if resp.status != 200:
                raise TestFailure(
                    f"server unhealthy after rejected push: {resp.status}"
                )
        # The rejected push must leave server storage and client worktree
        # both intact — a partial upload that broke the quota check would
        # show up as a disk delta here.
        disk_after = server.disk_total_bytes()
        if disk_after - disk_before > SIZE_TOLERANCE_BYTES:
            raise TestFailure(
                "quota-rejected push grew server disk by "
                f"{fmt_bytes(disk_after - disk_before)} — quota enforcement "
                "is leaking xorbs through"
            )
        verify_worktree(
            repo,
            "fatfile.bin",
            expected_sha=payload_sha,
            expected_size=BIG_FILE_BYTES,
            label="quota:after-failed-push",
        )
        verify_pointer_at(
            repo,
            env,
            spec="HEAD:fatfile.bin",
            expected_sha=payload_sha,
            expected_size=BIG_FILE_BYTES,
            label="quota:after-failed-push",
        )
    finally:
        server.stop()


def _http(
    method: str,
    url: str,
    *,
    bearer: Optional[str] = None,
    body: Optional[bytes] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> tuple[int, bytes]:
    """Raw HTTP that returns (status, body) for both 2xx and 4xx so the caller
    can assert on rejections."""
    h = dict(headers or {})
    if bearer is not None:
        h["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _sign_transfer(secret: bytes, hash_hex: str, s: int, e: int, x: int) -> str:
    # Must byte-for-byte match the server's `sign()` in bale-server-http:
    # HMAC-SHA256 over `hash_hex | start | end_inclusive | exp`, lowercase hex.
    msg = b"|".join(
        [hash_hex.encode(), str(s).encode(), str(e).encode(), str(x).encode()]
    )
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _one_stored_xorb_body(server: ServerHandle) -> bytes:
    """Read one real, well-formed xorb body straight out of the blob store
    (fs file or S3 object). A genuine body parses into frames, so POSTing it
    under a *wrong* URL hash reaches `verify_xorb_body`'s HashMismatch arm
    rather than dying earlier in `parse_xorb_frames`."""
    if server.s3_view is not None:
        minio = server.s3_view.minio
        for key, size in minio.list_objects(f"{server.s3_view.prefix}xorbs/"):
            if size > 0:
                return minio.get_object(key)
        raise TestFailure("no xorb in bucket to read")
    for cur, _dirs, names in os.walk(server.data_root / "xorbs"):
        for name in names:
            p = Path(cur) / name
            if p.stat().st_size > 0:
                return p.read_bytes()
    raise TestFailure("no xorb on disk to read")


def _corrupt_frame_length(body: bytes) -> Optional[bytes]:
    """Flip the low bit of the first frame's declared *uncompressed_length*
    (header bytes 5-7), leaving the compressed payload and every framing length
    intact. `parse_xorb_frames` still succeeds, but `verify_xorb_body`
    decompresses to the real length and the `declared != actual` check fires —
    the LengthMismatch arm (a `verify_xorb_body` rejection distinct from
    HashMismatch). xet's decompressors tolerate raw payload corruption and emit
    right-length garbage, so tampering the declared length is the deterministic
    way to reach this arm. Mirrors the 8-byte frame header in xorb.rs. Returns
    None if the body has no parseable leading frame."""
    out = bytearray(body)
    if len(out) < 8 or out[0] != 0:
        return None
    out[5] ^= 0x01
    return bytes(out)


def phase_adversarial_upload_guards(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Negative tests for the server's load-bearing auth/integrity guards that
    the happy-path suite never trips (see docs/E2E_COVERAGE_TODO.md, Tier 1):

      1. Upload-time CAS integrity gate — `verify_xorb_body` rejection. POSTing
         a real xorb body under a wrong URL hash (HashMismatch), or a corrupted
         body, must 400 and write nothing. The `tampered-xorb` phase only tests
         the *download* side; this is the *upload* gate that stops CAS poisoning.
      2. Signed transfer-URL enforcement — forged sig, expired, and Range
         mismatch must each 401 (fs backend only; S3 presigns bypass the
         handler).
      3. Scope enforcement — a read-scope token doing a POST must 403.

    Own container + data dir (g3) so the direct uploads can't perturb other
    phases' storage-accounting assertions.
    """
    phase_root = work_root / "upload-guards"
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
        test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
        admin_token_hex=admin_token_hex,
        name_suffix="upload-guards",
    )
    try:
        # Seed one real file so the store holds well-formed xorbs and a
        # registered file (needed for the reconstruction in part 2).
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="upload-guards-client",
        )
        payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"upload-guards")
        (repo / "g.bin").write_bytes(payload)
        with timings.measure("upload-guards: seed push"):
            git(["add", "g.bin"], cwd=repo, env=env)
            git(["commit", "-m", "seed"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)
        file_id = pointer_hash_at(repo, env, "HEAD:g.bin", label="upload-guards:seed")

        secret = bytes.fromhex(jwt_secret)
        write_jwt = mint_bale_jwt(
            secret=secret,
            sub=E2E_USER,
            repo_type="model",
            repo_id=f"{E2E_OWNER}/{E2E_REPO}",
            revision="main",
            scope="write",
            ttl_secs=3600,
        )
        read_jwt = mint_bale_jwt(
            secret=secret,
            sub=E2E_USER,
            repo_type="model",
            repo_id=f"{E2E_OWNER}/{E2E_REPO}",
            revision="main",
            scope="read",
            ttl_secs=3600,
        )
        base = server.public_host_url
        wrong_hex = "11" * 32

        # --- Part 3: a read-scope token must not be allowed to POST. ---
        with timings.measure("upload-guards: read token write rejected (403)"):
            status, _ = _http(
                "POST",
                f"{base}/v1/xorbs/default/{wrong_hex}",
                bearer=read_jwt,
                body=b"",
            )
            if status != 403:
                raise TestFailure(
                    f"read-scope token POST to /v1/xorbs returned {status}, "
                    "want 403 — write-scope enforcement is broken"
                )

        # --- Part 1: upload-time xorb integrity gate. ---
        good_body = _one_stored_xorb_body(server)
        disk_before = server.disk_total_bytes()
        with timings.measure("upload-guards: xorb body vs wrong hash (400)"):
            status, resp = _http(
                "POST",
                f"{base}/v1/xorbs/default/{wrong_hex}",
                bearer=write_jwt,
                body=good_body,
            )
            text = resp.decode(errors="replace").lower()
            if status != 400 or "does not match url hash" not in text:
                raise TestFailure(
                    "valid xorb body under a wrong URL hash should 400 "
                    f"'does not match URL hash'; got {status}: {text[:300]}"
                )
        # A body that parses but whose first frame's declared uncompressed
        # length is wrong must be rejected by verify_xorb_body's length check
        # (the LengthMismatch arm, distinct from HashMismatch). Fall back to a
        # plain byte flip if the body has no parseable leading frame.
        corrupt = _corrupt_frame_length(good_body)
        if corrupt is None:
            tmp = bytearray(good_body)
            tmp[len(tmp) * 3 // 4] ^= 0xFF
            corrupt = bytes(tmp)
        with timings.measure("upload-guards: corrupted xorb body (400)"):
            status, resp = _http(
                "POST",
                f"{base}/v1/xorbs/default/{'22' * 32}",
                bearer=write_jwt,
                body=corrupt,
            )
            if status != 400:
                raise TestFailure(
                    f"corrupted xorb body should 400; got {status}: "
                    f"{resp.decode(errors='replace')[:300]}"
                )
        disk_after = server.disk_total_bytes()
        if disk_after - disk_before > SIZE_TOLERANCE_BYTES:
            raise TestFailure(
                "rejected xorb uploads grew server disk by "
                f"{fmt_bytes(disk_after - disk_before)} — the integrity gate "
                "is letting unverified bytes through to the blob store"
            )

        # --- Part 2: signed transfer-URL enforcement (fs backend only). ---
        # S3 presigns its own URLs, so get_xorb_transfer (and its guards) is
        # never on the path there.
        if server.s3_view is None:
            recon = _http(
                "GET",
                f"{base}/v1/reconstructions/{file_id}",
                bearer=write_jwt,
            )
            if recon[0] != 200:
                raise TestFailure(
                    f"reconstruction of seed file returned {recon[0]}, want 200"
                )
            fetch_info = json.loads(recon[1].decode("utf-8")).get("fetch_info", {})
            if not fetch_info:
                raise TestFailure("reconstruction response had no fetch_info")
            xorb_hex, infos = next(iter(fetch_info.items()))
            rng = infos[0]["url_range"]
            s, e = int(rng["start"]), int(rng["end"])
            tsecret = bytes.fromhex(transfer_secret)

            def transfer(s_: int, e_: int, x_: int, sig_: str, range_hdr: str):
                url = f"{base}/xorb/default/{xorb_hex}?s={s_}&e={e_}&x={x_}&sig={sig_}"
                return _http("GET", url, headers={"Range": range_hdr})

            now = int(time.time())
            range_hdr = f"bytes={s}-{e}"

            # Happy path first — proves our request shape matches the server's
            # signing, so the negative assertions below are meaningful.
            valid_x = now + 3600
            valid_sig = _sign_transfer(tsecret, xorb_hex, s, e, valid_x)
            with timings.measure("upload-guards: signed URL happy (206)"):
                status, _ = transfer(s, e, valid_x, valid_sig, range_hdr)
                if status != 206:
                    raise TestFailure(
                        f"correctly-signed transfer URL returned {status}, want 206"
                    )

            with timings.measure("upload-guards: forged signature (401)"):
                bad_sig = valid_sig[:-1] + ("0" if valid_sig[-1] != "0" else "1")
                status, _ = transfer(s, e, valid_x, bad_sig, range_hdr)
                if status != 401:
                    raise TestFailure(
                        f"forged transfer signature returned {status}, want 401 "
                        "— constant-time signature check not enforcing"
                    )

            with timings.measure("upload-guards: expired signature (401)"):
                # Sign over a past exp so the sig check passes and the expiry
                # branch is what rejects.
                past_x = now - 3600
                past_sig = _sign_transfer(tsecret, xorb_hex, s, e, past_x)
                status, _ = transfer(s, e, past_x, past_sig, range_hdr)
                if status != 401:
                    raise TestFailure(
                        f"expired transfer URL returned {status}, want 401"
                    )

            with timings.measure("upload-guards: Range mismatch (401)"):
                # Validly signed for s..e, but the Range header asks for s..e+1.
                status, _ = transfer(s, e, valid_x, valid_sig, f"bytes={s}-{e + 1}")
                if status != 401:
                    raise TestFailure(
                        f"Range not matching the signed range returned {status}, "
                        "want 401 — signed-Range binding not enforced"
                    )
    finally:
        server.stop()
