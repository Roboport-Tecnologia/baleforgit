"""Coverage-only phases (https-origin, authz-http, otlp telemetry)."""
from __future__ import annotations

import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from baleharness.client import ClientEnv
from baleharness.config import E2E_HUB_TOKEN, E2E_OWNER, E2E_REPO, SMALL_FILE_BYTES
from baleharness.gitutil import force_resmudge_cold, git
from baleharness.logutil import TestFailure, info
from baleharness.mocks import MockAuthzServer, MockForgeServer, OtlpCollector
from baleharness.payloads import deterministic_payload
from baleharness.proc import run, sha256_bytes
from baleharness.repo import init_repo_for_push
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings


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
    is an `http://` URL the resolver gets Basic creds from `git credential
    fill`, POSTs the forge's `/info/bale/authenticate`, then exchanges the
    forge bearer for a bale token — versus the SSH `git-bale-authenticate`
    command every other phase uses. Covers resolver.rs `Http | Https` arm,
    `authenticate_http`, and `git_credential_fill`.

    `git-bale push-pending` (op=upload) and a cold smudge (op=download) both
    read `origin` and take the HTTP branch, exercising both scope arms. Neither
    transfers git refs, so a single mock endpoint suffices — no git smart-HTTP
    server needed.
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
        forge = MockForgeServer(
            bale_href=server.public_host_url, hub_token=E2E_HUB_TOKEN
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
                "config", "--local", "credential.helper",
                "!f() { echo username=e2e; echo password=pw; }; f",
            ],
            cwd=work, env=env,
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
                work, env, "f.bin",
                expected_sha=sha, expected_size=SMALL_FILE_BYTES,
                label="https-origin",
            )

        ops = {op for op, _ in forge.calls}
        if "upload" not in ops or "download" not in ops:
            raise TestFailure(
                f"https-origin: forge ops {sorted(ops)} missing upload/download "
                "— the HTTP resolver branch didn't drive both scopes"
            )
        if not forge.calls or not all(had_basic for _, had_basic in forge.calls):
            raise TestFailure(
                "https-origin: a forge authenticate call arrived without Basic "
                "auth — git_credential_fill path not exercised"
            )
        info(
            f"https-origin: forge recorded {len(forge.calls)} authenticate "
            f"calls, ops={sorted(ops)}"
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
                work_root=work_root, client=client, server=server,
                owner=owner, repo=name, name=f"authz-http-{name}",
            )
            payload = deterministic_payload(SMALL_FILE_BYTES, seed=label.encode())
            (repo / "f.bin").write_bytes(payload)
            git(["add", "f.bin"], cwd=repo, env=env)
            git(["commit", "-m", label], cwd=repo, env=env)
            with timings.measure(f"authz-http: push {label}"):
                completed = git(
                    ["push", "-u", "origin", "main"],
                    cwd=repo, env=env, expect_fail=True,
                )
            if expect_fail and completed.returncode == 0:
                raise TestFailure(
                    f"authz-http: push to {repo_name} unexpectedly succeeded "
                    f"({label})"
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
                        f"authz-http: 401 probe unexpectedly got "
                        f"{resp.status}"
                    )
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    raise TestFailure(
                        f"authz-http: 401 probe got HTTP {e.code}, "
                        f"expected 401"
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
            work_root=work_root, client=client, server=server,
            owner=E2E_OWNER, repo=E2E_REPO, name="otlp-client",
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
