"""Coverage-only phases (https-origin, authz-http, otlp telemetry, postgres)."""

from __future__ import annotations

import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from baleharness.client import ClientEnv
from baleharness.config import (
    E2E_HUB_TOKEN,
    E2E_OWNER,
    E2E_REPO,
    E2E_USER,
    JWT_TTL_YEARS,
    SMALL_FILE_BYTES,
)
from baleharness.gitutil import (
    force_resmudge_cold,
    git,
    verify_pointer_at,
    verify_worktree,
)
from baleharness.jwtutil import mint_bale_jwt
from baleharness.logutil import TestFailure, info
from baleharness.mocks import MockAuthzServer, MockForgeServer, OtlpCollector
from baleharness.payloads import deterministic_payload
from baleharness.pgbackend import PostgresGuard
from baleharness.proc import run, sha256_bytes
from baleharness.repo import init_repo_for_clone, init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.s3backend import Network
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings
from baleharness.usage import fetch_repo_usage


AUTHZ_HTTP_REPOS = ["authz-http/allow", "authz-http/denied", "authz-http/error"]


def _authz_http_decide(bearer: str, repo_id: str, scope: str) -> tuple[int, dict]:
    """Decision function the MockAuthzServer uses in the authz-http phase.
    Drives every branch of `HttpAuthz::check_repo_access`:
      - 200 success  -> exercise the happy path + JWT mint
      - 403 denied   -> exercise the Forbidden branch
      - 500 internal -> exercise the catch-all upstream-error branch
      - 401 unauth   -> tested via direct curl with an unknown bearer
    """
    if bearer != E2E_HUB_TOKEN:
        return 401, {"error": "unknown bearer"}
    if repo_id == "authz-http/allow":
        return 200, {"user_id": "alice"}
    if repo_id == "authz-http/denied":
        return 403, {"error": "no write grant"}
    if repo_id == "authz-http/error":
        return 500, {"error": "upstream broken"}
    return 403, {"error": f"unknown repo {repo_id!r}"}


HTTP_ORIGIN_REPO = f"{E2E_OWNER}/http-origin"


def phase_https_origin_coverage(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drive the git-bale resolver's HTTP(S)-origin auth branch. When `origin`
    is an `http://` URL the resolver POSTs the forge's `/info/bale/authenticate`
    then exchanges the forge bearer for a bale token — versus the SSH
    `git-bale-authenticate` command every other phase uses. The mock forge runs
    with enforce_auth (private repo), so this covers resolver.rs `Http | Https`
    arm, `authenticate_http` (both the anonymous probe and the credential'd
    retry), `authenticate_http_with_fallback`'s 401→retry branch, and
    `git_credential_fill`.

    `git-bale push-pending` (op=upload) and a cold smudge (op=download) both
    read `origin` and take the HTTP branch. Upload goes straight to Basic;
    download probes anonymously first, gets 401, then falls back to Basic —
    exercising both scope arms. Neither transfers git refs, so a single mock
    endpoint suffices — no git smart-HTTP server needed.
    """
    owner, name = HTTP_ORIGIN_REPO.split("/", 1)
    phase_root = work_root / "https-origin"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server: Optional[ServerHandle] = None
    forge: Optional[MockForgeServer] = None
    try:
        with timings.measure("https-origin: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[HTTP_ORIGIN_REPO],
                admin_token_hex=admin_token_hex,
                name_suffix="https-origin",
            )
        # enforce_auth=True + private (public=False): the download scope's
        # anonymous probe gets 401, forcing the resolver's git_credential_fill
        # fallback — the branch a public-repo (anon-accepted) forge never hits.
        forge = MockForgeServer(
            bale_href=server.public_host_url,
            hub_token=E2E_HUB_TOKEN,
            enforce_auth=True,
        )
        forge.start()
        info(f"https-origin: mock forge at {forge.base_url}")

        env = client.make_env()
        # The credential helper always supplies creds, but belt-and-suspenders
        # against a hang if it ever doesn't.
        env["GIT_TERMINAL_PROMPT"] = "0"
        work = work_root / "https-origin-client"
        work.mkdir()
        git(["init", "-b", "main", "."], cwd=work, env=env)
        run([str(client.git_bale_bin), "install", "--local"], cwd=work, env=env)
        cache_dir = work_root / "cache-https-origin"
        cache_dir.mkdir(exist_ok=True)
        git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=work, env=env)
        # git_credential_fill reads credential.helper from local config; this
        # canned helper hands back fixed Basic creds (the mock forge accepts
        # any) so the resolver never blocks on an interactive prompt.
        git(
            [
                "config",
                "--local",
                "credential.helper",
                "!f() { echo username=e2e; echo password=pw; }; f",
            ],
            cwd=work,
            env=env,
        )
        origin = f"{forge.base_url}/{owner}/{name}.git"
        git(["remote", "add", "origin", origin], cwd=work, env=env)
        (work / ".gitattributes").write_text("*.bin filter=bale -text\n")
        git(["add", ".gitattributes"], cwd=work, env=env)
        git(["commit", "-m", "enable bale filter"], cwd=work, env=env)

        payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"http-origin")
        sha = sha256_bytes(payload)
        (work / "f.bin").write_bytes(payload)
        git(["add", "f.bin"], cwd=work, env=env)  # clean → staging (offline)
        git(["commit", "-m", "add f.bin"], cwd=work, env=env)

        # Upload: push-pending resolves origin over HTTP (op=upload) and POSTs
        # xorbs/shards to the bale href the forge returned, draining staging.
        with timings.measure("https-origin: push-pending (HTTP resolve + upload)"):
            run([str(client.git_bale_bin), "push-pending"], cwd=work, env=env)

        # Download: with staging drained + caches wiped, the smudge must
        # resolve origin over HTTP (op=download) and reconstruct over the wire.
        with timings.measure("https-origin: cold smudge (HTTP resolve + reconstruct)"):
            force_resmudge_cold(
                work,
                env,
                "f.bin",
                expected_sha=sha,
                expected_size=SMALL_FILE_BYTES,
                label="https-origin",
            )

        upload = [had_basic for op, had_basic in forge.calls if op == "upload"]
        download = [had_basic for op, had_basic in forge.calls if op == "download"]
        if not upload or not download:
            raise TestFailure(
                f"https-origin: forge ops {sorted({o for o, _ in forge.calls})} "
                "missing upload/download — the HTTP resolver branch didn't drive "
                "both scopes"
            )
        # Upload never probes anonymously: every upload authenticate must be Basic.
        if not all(upload):
            raise TestFailure(
                "https-origin: an upload authenticate arrived without Basic auth "
                "— upload must skip the anon probe and use git_credential_fill"
            )
        # Download must show the anon-first probe (no Basic) AND the
        # git_credential_fill fallback after the 401 (Basic) — the whole point
        # of this phase post anon-first.
        if not (any(not b for b in download) and any(b for b in download)):
            raise TestFailure(
                "https-origin: download didn't exercise anon-probe → "
                f"git_credential_fill fallback (download had_basic flags: {download})"
            )
        info(
            f"https-origin: forge recorded {len(forge.calls)} authenticate calls "
            f"(upload={upload}, download={download})"
        )
    finally:
        if forge is not None:
            forge.stop()
        if server is not None:
            server.stop()


def phase_authz_http_coverage(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drive `bale-server-authz-http::HttpAuthz` via a Python mock of the
    upstream /check_access endpoint. The server container is brought up
    with `BALE_AUTHZ_HTTP_URL` set, which makes the bin choose the HTTP
    branch in main.rs (winning over `BALE_GRANTS`). One container, three
    push attempts against three repos so the mock can vary the response.
    Plus one direct probe with a bogus bearer to hit the 401 branch."""
    phase_root = work_root / "authz-http"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()

    mock = MockAuthzServer(_authz_http_decide)
    mock.start()
    info(f"authz-http: mock listening at {mock.url}")
    server: Optional[ServerHandle] = None
    try:
        with timings.measure("authz-http: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=AUTHZ_HTTP_REPOS,
                admin_token_hex=admin_token_hex,
                name_suffix="authz-http",
                extra_env={"BALE_AUTHZ_HTTP_URL": mock.url},
            )

        def _push_small(repo_name: str, *, expect_fail: bool, label: str) -> None:
            owner, name = repo_name.split("/", 1)
            repo, env = init_repo_for_push(
                work_root=work_root,
                client=client,
                server=server,
                owner=owner,
                repo=name,
                name=f"authz-http-{name}",
            )
            payload = deterministic_payload(SMALL_FILE_BYTES, seed=label.encode())
            (repo / "f.bin").write_bytes(payload)
            git(["add", "f.bin"], cwd=repo, env=env)
            git(["commit", "-m", label], cwd=repo, env=env)
            with timings.measure(f"authz-http: push {label}"):
                completed = git(
                    ["push", "-u", "origin", "main"],
                    cwd=repo,
                    env=env,
                    expect_fail=True,
                )
            if expect_fail and completed.returncode == 0:
                raise TestFailure(
                    f"authz-http: push to {repo_name} unexpectedly succeeded ({label})"
                )
            if not expect_fail and completed.returncode != 0:
                raise TestFailure(
                    f"authz-http: push to {repo_name} failed (exit "
                    f"{completed.returncode}):\nstdout={completed.stdout!r}\n"
                    f"stderr={completed.stderr!r}"
                )

        _push_small("authz-http/allow", expect_fail=False, label="allow")
        _push_small("authz-http/denied", expect_fail=True, label="denied")
        _push_small("authz-http/error", expect_fail=True, label="error")

        # 401 branch — direct token-mint probe with an unknown hub bearer.
        # Going via the git client would require overriding the baked-in
        # `git-bale-authenticate` script in the image, which isn't worth
        # the complexity for a single status-code branch.
        with timings.measure("authz-http: 401 probe (unknown bearer)"):
            req = urllib.request.Request(
                f"{server.public_host_url}/api/models/authz-http/allow/"
                f"bale-write-token/main",
                headers={"Authorization": "Bearer not-the-right-bearer"},
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    raise TestFailure(
                        f"authz-http: 401 probe unexpectedly got {resp.status}"
                    )
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    raise TestFailure(
                        f"authz-http: 401 probe got HTTP {e.code}, expected 401"
                    )

        statuses = [s for *_, s in mock.calls]
        info(f"authz-http: mock recorded {len(mock.calls)} calls, statuses={statuses}")
        for expected in (200, 401, 403, 500):
            if expected not in statuses:
                raise TestFailure(
                    f"authz-http: mock never returned {expected} — "
                    f"branch coverage incomplete (saw {statuses})"
                )
    finally:
        if server is not None:
            server.stop()
        mock.stop()


def phase_otlp_telemetry(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Boot the server with the OTLP env vars pointed at a host-side collector,
    push a small file to generate request spans, and confirm the exporter
    pipeline fires. Covers `telemetry.rs`'s endpoint-configured init (span +
    metric provider build, the tracing→OTel bridge) and both arms of the
    signal-endpoint URL resolver — all no-ops when the env is unset, which is
    why every other phase leaves them uncovered.

    Traces use the per-signal `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (verbatim
    URL); metrics fall back to appending `/v1/metrics` onto the base
    `OTEL_EXPORTER_OTLP_ENDPOINT` — between them they hit both branches of
    `signal_endpoint`."""
    phase_root = work_root / "otlp"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()

    collector = OtlpCollector()
    collector.start()
    info(f"otlp: collector listening at {collector.url}")
    server: Optional[ServerHandle] = None
    try:
        with timings.measure("otlp: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
                admin_token_hex=admin_token_hex,
                name_suffix="otlp",
                extra_env={
                    "OTEL_EXPORTER_OTLP_ENDPOINT": collector.url,
                    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": f"{collector.url}/v1/traces",
                    # Flush promptly instead of on the multi-second SDK defaults
                    # so the assert below doesn't wait a whole batch interval.
                    "OTEL_BSP_SCHEDULE_DELAY": "500",
                    "OTEL_METRIC_EXPORT_INTERVAL": "500",
                },
            )

        # A real push drives the SSH authenticate + xorb/shard POST handlers,
        # each carrying a tower_http request span → exported to /v1/traces.
        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="otlp-client",
        )
        payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"otlp")
        (repo / "f.bin").write_bytes(payload)
        git(["add", "f.bin"], cwd=repo, env=env)
        git(["commit", "-m", "add f.bin"], cwd=repo, env=env)
        with timings.measure("otlp: push (generates request spans)"):
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)

        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if collector.hit_count("/v1/traces") > 0:
                break
            time.sleep(0.25)
        traces = collector.hit_count("/v1/traces")
        metrics = collector.hit_count("/v1/metrics")
        info(f"otlp: collector hits — /v1/traces={traces} /v1/metrics={metrics}")
        if traces == 0:
            raise TestFailure(
                "otlp: collector never received a /v1/traces export — the "
                "server's OTLP span pipeline did not fire"
            )
    finally:
        # Clean stop (SIGTERM) lets main return so the OTLP Guard flushes a
        # final batch AND the llvm atexit hook writes this container's profraws.
        if server is not None:
            server.stop()
        collector.stop()


def phase_postgres_coverage(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """Drive a server backed by the Postgres `MetadataStore` so
    `bale-server-meta-postgres` shows up in the report. The whole suite runs on
    Postgres via `run.py --meta postgres`, but that's mutually exclusive with
    `--coverage`; this is the metadata-store analogue of the s3-basic/s3-dedup
    phases — one focused push + re-push + cold clone + usage query against an
    instrumented server with `BALE_POSTGRES_URL` set, covering register_files
    (insert + content-addressed dedup), the reconstruction lookup, and the
    usage aggregation SQL.

    The blob store stays fs (the container's local data dir) — only the
    metadata path is swapped to Postgres. The sidecar is brought up on its own
    podman network and the server is attached to it so it reaches Postgres via
    the host bridge route (same trick as the s3/MinIO and --meta postgres
    plumbing in pgbackend.py)."""
    phase_root = work_root / "postgres"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    network: Optional[Network] = None
    pg: Optional[PostgresGuard] = None
    server: Optional[ServerHandle] = None
    try:
        with timings.measure("postgres: sidecar"):
            network = Network.create(rt)
            pg = PostgresGuard.start(rt, network)
            dbname = "bale_coverage"
            pg.ensure_database(dbname)
        with timings.measure("postgres: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[f"{E2E_OWNER}/{E2E_REPO}"],
                admin_token_hex=admin_token_hex,
                name_suffix="postgres",
                extra_env={"BALE_POSTGRES_URL": pg.url_for_db(dbname)},
                extra_run_args=["--network", network.name],
            )

        repo, env = init_repo_for_push(
            work_root=work_root,
            client=client,
            server=server,
            owner=E2E_OWNER,
            repo=E2E_REPO,
            name="postgres-client",
        )

        # v1 → push: exercises register_files INSERT + blob registration.
        payload_v1 = deterministic_payload(SMALL_FILE_BYTES, seed=b"pg-cov-v1")
        sha_v1 = sha256_bytes(payload_v1)
        (repo / "f.bin").write_bytes(payload_v1)
        with timings.measure("postgres: v1 push", bytes_moved=SMALL_FILE_BYTES):
            git(["add", "f.bin"], cwd=repo, env=env)
            verify_pointer_at(
                repo,
                env,
                spec=":f.bin",
                expected_sha=sha_v1,
                expected_size=SMALL_FILE_BYTES,
                label="postgres:after-stage",
            )
            git(["commit", "-m", "postgres v1"], cwd=repo, env=env)
            git(["push", "-u", "origin", "main"], cwd=repo, env=env)

        # v2 (8-byte poke) → re-push: a distinct file_hash that shares chunks,
        # so register_files takes the content-addressed dedup path.
        payload_v2 = (
            payload_v1[:1024] + b"\xde\xad\xbe\xef\x01\x02\x03\x04" + payload_v1[1032:]
        )
        sha_v2 = sha256_bytes(payload_v2)
        if sha_v2 == sha_v1:
            raise TestFailure("postgres v2: sha256 unchanged after poke")
        (repo / "f.bin").write_bytes(payload_v2)
        with timings.measure("postgres: v2 push", bytes_moved=SMALL_FILE_BYTES):
            git(["add", "f.bin"], cwd=repo, env=env)
            git(["commit", "-m", "postgres v2"], cwd=repo, env=env)
            git(["push", "origin", "main"], cwd=repo, env=env)

        # Cold clone HEAD: the smudge hits /v1/reconstructions/ → the Postgres
        # reconstruction lookup must reassemble v2's bytes.
        with timings.measure(
            "postgres: cold clone + checkout", bytes_moved=SMALL_FILE_BYTES
        ):
            clone_path, clone_env, _ = init_repo_for_clone(
                work_root=work_root,
                client=client,
                server=server,
                owner=E2E_OWNER,
                repo=E2E_REPO,
                name="postgres-clone",
            )
            git(["checkout", "main"], cwd=clone_path, env=clone_env)
        verify_worktree(
            clone_path,
            "f.bin",
            expected_sha=sha_v2,
            expected_size=SMALL_FILE_BYTES,
            label="postgres:after-clone",
        )

        # /v1/usage/repo: exercises the Postgres usage-aggregation SQL.
        admin_jwt = mint_bale_jwt(
            secret=bytes.fromhex(jwt_secret),
            sub=E2E_USER,
            repo_type="model",
            repo_id=f"{E2E_OWNER}/{E2E_REPO}",
            revision="main",
            scope="write",
            ttl_secs=JWT_TTL_YEARS * 365 * 24 * 3600,
        )
        usage = fetch_repo_usage(
            server, token=admin_jwt, owner=E2E_OWNER, repo=E2E_REPO
        )
        if int(usage["raw_bytes"]) <= 0 or int(usage["stored_bytes"]) <= 0:
            raise TestFailure(
                f"postgres: /v1/usage/repo returned non-positive bytes — the "
                f"Postgres usage aggregation isn't seeing the two pushes: {usage}"
            )
        info(
            f"postgres: usage raw={usage['raw_bytes']} stored={usage['stored_bytes']}, "
            "register/reconstruct/usage paths exercised"
        )
    finally:
        if server is not None:
            server.stop()
        if pg is not None:
            pg.stop()
        if network is not None:
            network.destroy()
