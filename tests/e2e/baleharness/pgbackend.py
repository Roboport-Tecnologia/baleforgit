"""Postgres metadata backend for `run.py --meta postgres` (analogue of `s3backend.py`).

One sidecar per run; every `start_container` injects `BALE_POSTGRES_URL` for a
per-`data_root` database: distinct so phases don't cross-contaminate accounting,
stable so a restart on the same dir (failure-kill, offline-restart) keeps its
metadata. Importable without `run`/`s3lib` to avoid an import cycle with
`server.py` and the failure phase.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from baleharness.logutil import TestFailure, info
from baleharness.proc import host_primary_ip, pick_free_port
from baleharness.runtime import Runtime
from baleharness.s3backend import Network  # shared with `--backend s3`

PG_IMAGE = "docker.io/library/postgres:16-alpine"
PG_USER = "bale"
PG_PASSWORD = "bale-e2e-pw"
PG_INTERNAL_PORT = 5432
# Covers a cold image pull on a fresh runner.
PG_READY_TIMEOUT_S = 180


class PostgresGuard:
    """Like `MinioGuard`, the server connects via the host's primary IP and a
    published port to dodge flaky container-to-container DNS on macOS rootless
    podman; the harness provisions over `podman exec psql` instead.
    """

    def __init__(
        self,
        rt: Runtime,
        network: Network,
        container: str,
        host_port: int,
        host_ip: str,
    ) -> None:
        self.rt = rt
        self.network = network
        self.container = container
        self.host_port = host_port
        self.host_ip = host_ip

    @classmethod
    def start(cls, rt: Runtime, network: Network) -> PostgresGuard:
        host_port = pick_free_port()
        host_ip = host_primary_ip()
        container = f"bale-e2e-pg-{secrets.token_hex(4)}"
        info(
            f"launching {PG_IMAGE} as {container} on 0.0.0.0:{host_port} "
            f"(connect host {host_ip}:{host_port})"
        )
        completed = subprocess.run(
            rt.cmd(
                "run",
                "-d",
                "--rm",
                "--name",
                container,
                "--network",
                network.name,
                "-p",
                f"{host_port}:{PG_INTERNAL_PORT}",
                "-e",
                f"POSTGRES_USER={PG_USER}",
                "-e",
                f"POSTGRES_PASSWORD={PG_PASSWORD}",
                "-e",
                "POSTGRES_DB=postgres",
                PG_IMAGE,
            ),
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise TestFailure(
                f"podman run postgres failed:\n"
                f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
            )
        guard = cls(rt, network, container, host_port, host_ip)
        try:
            guard.wait_ready()
        except Exception:
            guard.stop()
            raise
        return guard

    def wait_ready(self) -> None:
        deadline = time.monotonic() + PG_READY_TIMEOUT_S
        last_err: str | None = None
        while time.monotonic() < deadline:
            completed = subprocess.run(
                self.rt.cmd(
                    "exec",
                    self.container,
                    "pg_isready",
                    "-U",
                    PG_USER,
                    "-d",
                    "postgres",
                ),
                capture_output=True,
                check=False,
            )
            if completed.returncode == 0:
                info(f"postgres ready in {self.container}")
                return
            last_err = completed.stdout.decode("utf-8", "replace").strip() or (
                completed.stderr.decode("utf-8", "replace").strip()
            )
            time.sleep(0.3)
        raise TestFailure(
            f"postgres did not become ready within {PG_READY_TIMEOUT_S}s "
            f"(last: {last_err})"
        )

    def ensure_database(self, name: str) -> None:
        """Idempotent; `CREATE DATABASE` has no IF NOT EXISTS, so check first."""
        exists = subprocess.run(
            self.rt.cmd(
                "exec",
                self.container,
                "psql",
                "-U",
                PG_USER,
                "-d",
                "postgres",
                "-tAc",
                f"SELECT 1 FROM pg_database WHERE datname = '{name}'",
            ),
            capture_output=True,
            check=False,
        )
        if exists.returncode == 0 and exists.stdout.decode("utf-8", "replace").strip():
            return
        created = subprocess.run(
            self.rt.cmd(
                "exec",
                self.container,
                "psql",
                "-U",
                PG_USER,
                "-d",
                "postgres",
                "-c",
                f'CREATE DATABASE "{name}"',
            ),
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            stderr = created.stderr.decode("utf-8", "replace")
            # Losing a creation race is benign.
            if "already exists" not in stderr:
                raise TestFailure(f"create database {name!r} failed: {stderr}")

    def url_for_db(self, name: str) -> str:
        return (
            f"postgres://{PG_USER}:{PG_PASSWORD}@{self.host_ip}:{self.host_port}/{name}"
        )

    def stop(self) -> None:
        subprocess.run(
            self.rt.cmd("rm", "-f", self.container),
            capture_output=True,
            check=False,
        )


def db_for_data_root(data_root: Path, anchor: Path) -> str:
    """Database name keyed on `data_root` relative to the run tmpdir `anchor`:
    unique per server, identical across a restart; hashed to stay a valid,
    length-bounded identifier."""
    try:
        key = str(data_root.resolve().relative_to(anchor.resolve()))
    except ValueError:
        key = data_root.name
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9]+", "_", data_root.name.lower()).strip("_")[:24]
    return f"bale_{slug or 'root'}_{digest}"


@dataclass
class ActivePostgresBackend:
    """Process-global so `start_container` applies it to every container.
    `prefix_anchor` is the run's tmpdir (see `db_for_data_root`)."""

    guard: PostgresGuard
    network: Network
    prefix_anchor: Path


_ACTIVE_PG: ActivePostgresBackend | None = None


def set_active_postgres_backend(backend: ActivePostgresBackend | None) -> None:
    global _ACTIVE_PG
    _ACTIVE_PG = backend


def get_active_postgres_backend() -> ActivePostgresBackend | None:
    return _ACTIVE_PG
