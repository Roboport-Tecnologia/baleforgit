"""Postgres metadata-backend plumbing for the e2e harness.

The metadata-store analogue of `s3backend.py`. `run.py --meta postgres` brings
up a single Postgres sidecar on the per-run podman network and sets a
process-global `ActivePostgresBackend`; every `start_container` call — the
shared server and each phase's private one — then injects `BALE_POSTGRES_URL`
(pointed at a per-`data_root` database) and the shared-network arg, so the whole
fs/s3 phase registry runs with Postgres as the `MetadataStore` instead of the
default SQLite.

Per-`data_root` database isolation is the metadata-store analogue of the S3
backend's per-`data_root` bucket prefix and the fs suite's per-phase
`data_root/meta.db`: distinct across phases so they don't cross-contaminate
accounting, and *stable* per `data_root` so a restart on the same dir
(failure-kill, offline-restart) lands on the same database and its metadata
persists.

Importable without `run`/`s3lib`, so `server.py` and the failure phase can use
it without a cycle. Reuses `Network` from `s3backend` so `--backend s3 --meta
postgres` shares one network.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from baleharness.logutil import TestFailure, info
from baleharness.proc import host_primary_ip, pick_free_port
from baleharness.runtime import Runtime
from baleharness.s3backend import Network  # shared per-run podman network


# =============================================================================
# Constants
# =============================================================================

PG_IMAGE = "docker.io/library/postgres:16-alpine"
PG_USER = "bale"
PG_PASSWORD = "bale-e2e-pw"
PG_INTERNAL_PORT = 5432
# Generous: covers a cold image pull on a fresh runner.
PG_READY_TIMEOUT_S = 180


# =============================================================================
# Postgres sidecar
# =============================================================================


class PostgresGuard:
    """Single Postgres container + per-database provisioning helpers.

    Mirrors `MinioGuard`: publish on `0.0.0.0:<host_port>:5432` and connect via
    the host's primary IP, so the server (in its container) reaches Postgres
    through the bridge → host route — the same trick MinIO uses to side-step
    flaky container-to-container DNS on macOS rootless podman. The harness
    itself provisions databases over the in-container unix socket via
    `podman exec psql`, never the published port.
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
    def start(cls, rt: Runtime, network: Network) -> "PostgresGuard":
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
                # Default maintenance DB; per-phase databases are created on top.
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
        last_err: Optional[str] = None
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
        """Idempotently create database `name` (no-op if it already exists).

        `CREATE DATABASE` can't run inside a transaction and errors if the DB
        exists, so guard it with a `pg_database` existence check. `name` is a
        sanitized identifier (`[a-z0-9_]`), but quote it anyway for safety.
        Stable per `data_root`, so a restart re-uses the same database and its
        metadata survives.
        """
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
            # A concurrent creator winning the race is benign (the DB now exists).
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


# =============================================================================
# data_root -> database-name derivation
# =============================================================================


def db_for_data_root(data_root: Path, anchor: Path) -> str:
    """Stable, distinct, valid Postgres database name for a server's `data_root`.

    `anchor` is the run's tmpdir (an ancestor of every server's data_root), so
    the relative path is unique per server and identical across a restart on the
    same dir. A short hash of that key guarantees a valid, length-bounded
    identifier; a readable slug from the basename is prepended for debuggability.
    """
    try:
        key = str(data_root.resolve().relative_to(anchor.resolve()))
    except ValueError:
        key = data_root.name
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9]+", "_", data_root.name.lower()).strip("_")[:24]
    return f"bale_{slug or 'root'}_{digest}"


# =============================================================================
# Active Postgres backend (process-global; mirrors ActiveS3Backend)
# =============================================================================


@dataclass
class ActivePostgresBackend:
    """The Postgres metadata backend in force for the whole run, set by
    `run.py --meta postgres`. Held process-global so `start_container` picks it
    up for every container. `prefix_anchor` is the run's tmpdir; each server's
    database name is derived relative to it."""

    guard: PostgresGuard
    network: Network
    prefix_anchor: Path


_ACTIVE_PG: Optional[ActivePostgresBackend] = None


def set_active_postgres_backend(backend: Optional[ActivePostgresBackend]) -> None:
    global _ACTIVE_PG
    _ACTIVE_PG = backend


def get_active_postgres_backend() -> Optional[ActivePostgresBackend]:
    return _ACTIVE_PG
