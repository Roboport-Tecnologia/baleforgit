"""Anonymous clone of a public repo (Bale download with no credentials)."""

from __future__ import annotations

import secrets
from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import E2E_HUB_TOKEN, E2E_OWNER, SMALL_FILE_BYTES
from baleharness.gitutil import force_resmudge_cold, git
from baleharness.logutil import TestFailure, info
from baleharness.mocks import MockForgeServer
from baleharness.payloads import deterministic_payload
from baleharness.proc import run, sha256_bytes
from baleharness.runtime import Runtime
from baleharness.server import ServerHandle, start_container
from baleharness.timing import Timings

ANON_REPO = f"{E2E_OWNER}/anon-public"

_CRED_HELPER = "!f() { echo username=e2e; echo password=pw; }; f"


def phase_anonymous_public_clone(
    *,
    timings: Timings,
    rt: Runtime,
    image_tag: str,
    work_root: Path,
    client: ClientEnv,
    ssh_public_key: str,
    admin_token_hex: str,
) -> None:
    """A public repo's Bale content downloads WITHOUT credentials.

    The resolver probes `/info/bale/authenticate?op=download` anonymously and
    only falls back to `git credential fill` on 401/403:

      1. public  → a cold smudge with no credential helper succeeds and the forge
         sees only credential-less `download` calls.
      2. private → the anonymous probe gets 401, the resolver retries with Basic
         auth and the smudge succeeds.

    Upload always authenticates. Covers resolver.rs
    `authenticate_http_with_fallback` and the anonymous arm of `authenticate_http`.
    """
    owner, name = ANON_REPO.split("/", 1)
    phase_root = work_root / "anon-public"
    phase_root.mkdir()
    data_root = phase_root / "data"
    data_root.mkdir()
    jwt_secret = secrets.token_bytes(32).hex()
    transfer_secret = secrets.token_bytes(32).hex()
    server: ServerHandle | None = None
    forge: MockForgeServer | None = None
    try:
        with timings.measure("anon-public: container start"):
            server = start_container(
                rt,
                image_tag=image_tag,
                data_root=data_root,
                jwt_secret_hex=jwt_secret,
                transfer_secret_hex=transfer_secret,
                ssh_public_key=ssh_public_key,
                test_repos=[ANON_REPO],
                admin_token_hex=admin_token_hex,
                name_suffix="anon-public",
            )
        forge = MockForgeServer(
            bale_href=server.public_host_url,
            hub_token=E2E_HUB_TOKEN,
            enforce_auth=True,
            public=True,
        )
        forge.start()
        info(f"anon-public: mock forge at {forge.base_url}")

        env = client.make_env()
        # The anonymous path must complete without ever blocking on a prompt.
        env["GIT_TERMINAL_PROMPT"] = "0"
        work = work_root / "anon-public-client"
        work.mkdir()
        git(["init", "-b", "main", "."], cwd=work, env=env)
        run([str(client.git_bale_bin), "install", "--local"], cwd=work, env=env)
        cache_dir = work_root / "cache-anon-public"
        cache_dir.mkdir(exist_ok=True)
        git(["config", "--local", "bale.cacheDir", str(cache_dir)], cwd=work, env=env)
        origin = f"{forge.base_url}/{owner}/{name}.git"
        git(["remote", "add", "origin", origin], cwd=work, env=env)
        (work / ".gitattributes").write_text("*.bin filter=bale -text\n")
        git(["add", ".gitattributes"], cwd=work, env=env)
        git(["commit", "-m", "enable bale filter"], cwd=work, env=env)

        payload = deterministic_payload(SMALL_FILE_BYTES, seed=b"anon-public")
        sha = sha256_bytes(payload)
        (work / "f.bin").write_bytes(payload)
        git(["add", "f.bin"], cwd=work, env=env)
        git(["commit", "-m", "add f.bin"], cwd=work, env=env)

        # op=upload always authenticates; drop the helper afterwards so the
        # download leg is genuinely credential-less.
        git(["config", "--local", "credential.helper", _CRED_HELPER], cwd=work, env=env)
        with timings.measure("anon-public: seed (authenticated upload)"):
            run([str(client.git_bale_bin), "push-pending"], cwd=work, env=env)
        git(["config", "--local", "--unset", "credential.helper"], cwd=work, env=env)

        # Public: anonymous download succeeds with no credential fallback.
        forge.public = True
        forge.calls.clear()
        with timings.measure("anon-public: anonymous cold smudge (public)"):
            force_resmudge_cold(
                work,
                env,
                "f.bin",
                expected_sha=sha,
                expected_size=SMALL_FILE_BYTES,
                label="anon-public",
            )
        downloads = [had_basic for op, had_basic in forge.calls if op == "download"]
        if not downloads:
            raise TestFailure(
                "anon-public: forge saw no download authenticate call — the "
                "resolver didn't take the HTTP download path"
            )
        if any(downloads):
            raise TestFailure(
                "anon-public: a public-repo download authenticated with Basic "
                f"auth (calls={forge.calls}) — anonymous-first path not used"
            )
        info(f"anon-public: public download was anonymous (calls={forge.calls})")

        # Private: anonymous refused (401) → falls back to credentials.
        forge.public = False
        forge.calls.clear()
        git(["config", "--local", "credential.helper", _CRED_HELPER], cwd=work, env=env)
        # Fresh cache dir: re-wiping the one the public smudge populated trips the
        # harness rmtree on its write-only nested dirs.
        cache_dir_2 = work_root / "cache-anon-private"
        cache_dir_2.mkdir(exist_ok=True)
        git(["config", "--local", "bale.cacheDir", str(cache_dir_2)], cwd=work, env=env)
        with timings.measure("anon-public: private smudge falls back to creds"):
            force_resmudge_cold(
                work,
                env,
                "f.bin",
                expected_sha=sha,
                expected_size=SMALL_FILE_BYTES,
                label="anon-private",
            )
        dl = [had_basic for op, had_basic in forge.calls if op == "download"]
        if not (False in dl and True in dl):
            raise TestFailure(
                "anon-public: private-repo download did not show the anonymous "
                f"probe → credentialed retry sequence (calls={forge.calls})"
            )
        info(f"anon-public: private download fell back to Basic auth (downloads={dl})")
    finally:
        if forge is not None:
            forge.stop()
        if server is not None:
            server.stop()
