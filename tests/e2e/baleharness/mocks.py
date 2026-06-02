"""Failure-injection + in-process mock servers (proxy, authz, forge, otlp)."""

from __future__ import annotations

import http.server
import json
import socket
import subprocess
import threading
import time
import urllib.parse
from contextlib import contextmanager
from typing import Callable, Iterator, Optional

from baleharness.logutil import TestFailure
from baleharness.pgbackend import (
    PG_USER,
    db_for_data_root,
    get_active_postgres_backend,
)
from baleharness.proc import host_primary_ip, pick_free_port
from baleharness.server import ServerHandle


class TcpProxy:
    """Pure-stdlib forwarding proxy used by the failure-recovery phases.
    Listens on 127.0.0.1:`listen_port` and shovels bytes to `upstream` in
    both directions. `kill()` slams every socket shut to simulate an abrupt
    connection drop (no FIN); `start()` may be called again afterwards to
    bring the proxy back up on the same listen port for the retry leg.

    `throttle_bytes_per_sec` rate-limits the *client → server* direction
    (the direction that carries xorb/shard upload bodies). Returning bytes
    are passed through at full speed. The throttle exists so the upload
    takes long enough for the harness to reliably interrupt it mid-flight
    on localhost, where an unthrottled 35 MiB push completes in well under
    a second and the race window vanishes.

    NOT a general-purpose proxy — only safe for use in this test harness.
    """

    def __init__(
        self,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        *,
        throttle_bytes_per_sec: Optional[int] = None,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self.listen_port = listen_port
        self.upstream = (upstream_host, upstream_port)
        self.throttle_bytes_per_sec = throttle_bytes_per_sec
        # bind_host is "127.0.0.1" for the existing client↔server drop phase,
        # and "0.0.0.0" for the S3-conndrop phase so the server container can
        # reach the proxy via host.containers.internal.
        self.bind_host = bind_host
        self._lock = threading.Lock()
        self._listen_sock: Optional[socket.socket] = None
        self._active: list[socket.socket] = []
        self._accept_thread: Optional[threading.Thread] = None
        self._stopped = True
        self._bytes_forwarded = 0
        self._connections = 0

    @property
    def bytes_forwarded(self) -> int:
        with self._lock:
            return self._bytes_forwarded

    @property
    def connections(self) -> int:
        """Count of inbound TCP connections accepted since the last
        reset_counters(). The offline-no-network phase asserts this stays
        0 across operations that must never touch the CAS server."""
        with self._lock:
            return self._connections

    def reset_counters(self) -> None:
        with self._lock:
            self._bytes_forwarded = 0
            self._connections = 0

    def start(self) -> None:
        with self._lock:
            if not self._stopped:
                return
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((self.bind_host, self.listen_port))
            ls.listen(16)
            self._listen_sock = ls
            self._stopped = False
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._accept_thread = t

    def _accept_loop(self) -> None:
        while True:
            with self._lock:
                ls = self._listen_sock
                stopped = self._stopped
            if stopped or ls is None:
                return
            try:
                client_sock, _ = ls.accept()
            except OSError:
                return
            with self._lock:
                self._connections += 1
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                upstream_sock.connect(self.upstream)
            except OSError:
                client_sock.close()
                continue
            with self._lock:
                self._active.extend((client_sock, upstream_sock))
            # Only throttle the client → server direction; responses get
            # passed through at full speed.
            threading.Thread(
                target=self._pump,
                args=(client_sock, upstream_sock),
                kwargs={"throttle": self.throttle_bytes_per_sec},
                daemon=True,
            ).start()
            threading.Thread(
                target=self._pump,
                args=(upstream_sock, client_sock),
                daemon=True,
            ).start()

    def _pump(
        self,
        a: socket.socket,
        b: socket.socket,
        *,
        throttle: Optional[int] = None,
    ) -> None:
        chunk_size = 16 * 1024 if throttle is not None else 64 * 1024
        try:
            while True:
                data = a.recv(chunk_size)
                if not data:
                    break
                b.sendall(data)
                with self._lock:
                    self._bytes_forwarded += len(data)
                if throttle is not None and throttle > 0:
                    time.sleep(len(data) / float(throttle))
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass

    def kill(self) -> None:
        """Slam all sockets. Active client/upstream sockets are closed without
        a FIN, simulating an abrupt drop from the client's perspective."""
        with self._lock:
            self._stopped = True
            ls, self._listen_sock = self._listen_sock, None
            active, self._active = self._active, []
        if ls is not None:
            try:
                ls.close()
            except OSError:
                pass
        for s in active:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None


class MockAuthzServer:
    """Stand-in for the upstream `/check_access` endpoint a real forge
    would expose. Used by the `authz-http` coverage phase to drive
    `bale-server-authz-http::HttpAuthz`.

    Wire contract (see `crates/bale-server-authz-http/src/lib.rs`):
        POST /check_access  { "hub_bearer": ..., "repo": {...}, "scope": ... }
        200 OK { "user_id": "alice" }   — known token + sufficient scope
        401 Unauthorized                — unknown hub_bearer
        403 Forbidden                   — known token, insufficient access
        any other (e.g. 500)            — upstream failure (HttpAuthz maps to Internal)

    Binds 0.0.0.0:port so the server container can reach it via the
    host's primary IP (the standard cross-bridge route).

    The decision function receives (hub_bearer, repo_id, scope_str) and
    returns (http_status:int, body_dict:dict). Each phase configures its
    own decision logic.
    """

    def __init__(
        self,
        decide: Callable[[str, str, str], tuple[int, dict]],
        *,
        port: Optional[int] = None,
    ) -> None:
        self.decide = decide
        self.port = port or pick_free_port()
        self.calls: list[
            tuple[str, str, str, int]
        ] = []  # (bearer, repo_id, scope, status)
        self._server: Optional["http.server.ThreadingHTTPServer"] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        # The container reaches us via the host's primary IP — the
        # bridge routes to it for free. 127.0.0.1 wouldn't work because
        # that's the container's own loopback inside its netns.
        return f"http://{host_primary_ip()}:{self.port}"

    def start(self) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: N802
                # http.server's default writes one stderr line per request,
                # which would drown our own info() output. Drop them.
                pass

            def do_POST(self):  # noqa: N802
                if self.path != "/check_access":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8"))
                    bearer = body.get("hub_bearer", "")
                    repo_id = body.get("repo", {}).get("repo_id", "")
                    scope = body.get("scope", "")
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                status, payload = outer.decide(bearer, repo_id, scope)
                with outer._lock:
                    outer.calls.append((bearer, repo_id, scope, status))
                body_bytes = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)

        self._server = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="MockAuthzServer"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


class MockForgeServer:
    """Stand-in for a git forge's `/<owner>/<repo>.git/info/bale/authenticate`
    endpoint — the HTTPS half of the forge protocol the git-bale resolver uses
    when `origin` is an `http(s)://` URL (instead of the SSH
    `git-bale-authenticate` command). A real forge verifies the user's password
    locally and returns the baleforgit-server href plus a short-lived Bearer;
    we return a fixed href + hub token (`docs/BALE_FORGE_PROTOCOL.md`).

    Wire shape the resolver expects (resolver.rs `authenticate_http`):
        POST /<owner>/<repo>.git/info/bale/authenticate?op=upload|download
        Authorization: Basic <base64(user:pass)>
        200 { "href": "<bale-server-url>", "header": {"Authorization": "Bearer <tok>"} }

    We do NOT serve git smart-HTTP: the two operations that drive the HTTP
    resolver branch — `git-bale push-pending` and a cold smudge — only read
    `origin`'s URL and POST to this endpoint; they never transfer git refs.
    That keeps the mock to one endpoint instead of wrapping `git http-backend`.
    The client runs on the host, so it reaches us on 127.0.0.1.
    """

    def __init__(
        self,
        *,
        bale_href: str,
        hub_token: str,
        port: Optional[int] = None,
        enforce_auth: bool = False,
        public: bool = False,
    ) -> None:
        self.bale_href = bale_href.rstrip("/")
        self.hub_token = hub_token
        self.port = port or pick_free_port()
        # enforce_auth=False (default): every authenticate succeeds regardless
        # of credentials — a forge with no visibility model, which the
        # https-origin phase relies on. enforce_auth=True models a real forge:
        # an anonymous request (no Basic auth) is granted only for `op=download`
        # on a `public` repo; private downloads and every upload demand
        # credentials (401). `public` is mutable so one mock can serve a public
        # then a private sub-case. See `docs/BALE_FORGE_PROTOCOL.md`.
        self.enforce_auth = enforce_auth
        self.public = public
        self.calls: list[tuple[str, bool]] = []  # (op, had_basic_auth)
        self._server: Optional["http.server.ThreadingHTTPServer"] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: N802
                pass

            def do_POST(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if not parsed.path.endswith("/info/bale/authenticate"):
                    self.send_response(404)
                    self.end_headers()
                    return
                op = urllib.parse.parse_qs(parsed.query).get("op", [""])[0]
                had_basic = self.headers.get("Authorization", "").startswith("Basic ")
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with outer._lock:
                    outer.calls.append((op, had_basic))
                # Anonymous (no Basic auth) is granted only for a public-repo
                # download; private downloads and every upload get 401. This is
                # what lets the resolver's anon-first download path resolve a
                # public repo and fall back to Basic auth on a private one.
                if outer.enforce_auth and not had_basic:
                    if not (op == "download" and outer.public):
                        self.send_response(401)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                body = json.dumps(
                    {
                        "href": outer.bale_href,
                        "header": {"Authorization": f"Bearer {outer.hub_token}"},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", self.port), Handler
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="MockForgeServer"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


class OtlpCollector:
    """Minimal OTLP/HTTP collector for the telemetry phase. Binds 0.0.0.0 so
    the server container reaches it via the host's primary IP, accepts POSTs on
    any path (the exporter targets /v1/traces and /v1/metrics), drains the
    protobuf body, and answers 200 with an empty body — which the
    opentelemetry-rust HTTP exporter accepts as a successful export. Records a
    per-path hit count so the phase can assert the server's exporter pipeline
    actually fired."""

    def __init__(self, *, port: Optional[int] = None) -> None:
        self.port = port or pick_free_port()
        self._lock = threading.Lock()
        self.hits: dict[str, int] = {}
        self._server: Optional["http.server.ThreadingHTTPServer"] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        # Base endpoint; the server appends /v1/traces + /v1/metrics per the
        # OTLP/HTTP spec. 127.0.0.1 is the container's own loopback, so we hand
        # it the host's primary IP (same cross-bridge route as MockAuthzServer).
        return f"http://{host_primary_ip()}:{self.port}"

    def hit_count(self, path: str) -> int:
        with self._lock:
            return self.hits.get(path, 0)

    def start(self) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # noqa: N802
                pass

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with outer._lock:
                    outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="OtlpCollector"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def wait_for_server_progress(
    server: ServerHandle, *, min_bytes: int, timeout_s: float = 15.0
) -> int:
    """Poll the server's xorbs directory until at least `min_bytes` have
    landed. Returns the disk total seen. The wait window must be short
    enough that the in-flight push hasn't completed yet — we want to
    catch it mid-upload, not after."""
    deadline = time.monotonic() + timeout_s
    last = 0
    while time.monotonic() < deadline:
        last = server.disk_xorb_bytes()
        if last >= min_bytes:
            return last
        time.sleep(0.05)
    raise TestFailure(
        f"server xorb bytes did not reach {min_bytes} within {timeout_s}s "
        f"(stalled at {last})"
    )


@contextmanager
def hold_db_writer_lock(server: ServerHandle, hold_seconds: float) -> Iterator[None]:
    """Open the server's SQLite meta.db from a sidecar `sqlite3` shell INSIDE
    the container, take an IMMEDIATE write lock for `hold_seconds`, and
    yield. Used by the transient-db-failure phase to force the server's
    SQLite writes to hit SQLITE_BUSY transiently — sqlx's default 5s
    busy_timeout should turn the contention into a brief wait, not an
    error, so a concurrent client push sees no failure.

    The lock-holder runs inside the container (not on the host) because
    rootless podman bind mounts go through a VM on macOS, where host-side
    fcntl locks don't propagate to the in-VM SQLite.

    The sqlite3 CLI buffers its stdout when not on a TTY, so an
    interactive driver from outside can't reliably detect "lock held" via
    SELECT output. Instead, drive sqlite3 with a heredoc that touches a
    marker file after BEGIN IMMEDIATE returns — we poll for the marker
    to confirm the lock was acquired before yielding."""
    marker = "/tmp/bale-e2e-dblock-held"
    # Wipe any leftover marker from an earlier run inside the same container.
    subprocess.run(
        server.rt.cmd("exec", server.name, "rm", "-f", marker),
        capture_output=True,
        check=False,
    )
    script = (
        "sqlite3 /data/meta.db <<'EOF'\n"
        "BEGIN IMMEDIATE;\n"
        f".system touch {marker}\n"
        f".system sleep {hold_seconds}\n"
        "COMMIT;\n"
        "EOF\n"
    )
    completed = subprocess.run(
        server.rt.cmd("exec", "-d", server.name, "bash", "-c", script),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise TestFailure(
            f"detached sqlite3 lock-holder failed to start (exit "
            f"{completed.returncode}): "
            f"{completed.stderr.decode('utf-8', 'replace')}"
        )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        check = subprocess.run(
            server.rt.cmd("exec", server.name, "test", "-f", marker),
            capture_output=True,
            check=False,
        )
        if check.returncode == 0:
            break
        time.sleep(0.05)
    else:
        raise TestFailure(
            f"sidecar sqlite3 never created {marker} within 10s — "
            "BEGIN IMMEDIATE may have failed silently"
        )
    try:
        yield
    finally:
        # The detached sqlite3 will COMMIT and exit on its own once
        # `sleep hold_seconds` elapses; nothing to clean up here.
        pass


def meta_db_query(
    server: ServerHandle,
    *,
    sqlite_sql: str,
    pg_sql: str,
) -> subprocess.CompletedProcess:
    """Run one statement against the server's metadata store, picking the engine
    the run is using, and return the raw CompletedProcess. Rows come back
    '|'-separated, one per line, headerless. The query runs INSIDE a container
    (the server's for SQLite, the sidecar's for Postgres) because rootless podman
    bind mounts go through a VM on macOS where a host-side meta.db read is
    unreliable. Statements differ only where the dialect does (e.g. `hex(x)` vs
    `encode(x,'hex')`), so callers pass both forms; for dialect-neutral SQL pass
    the same string twice."""
    pg = get_active_postgres_backend()
    if pg is not None:
        # Same per-data_root database start_container pointed this server at.
        dbname = db_for_data_root(server.data_root, pg.prefix_anchor)
        cmd = server.rt.cmd(
            "exec",
            pg.guard.container,
            "psql",
            "-U",
            PG_USER,
            "-d",
            dbname,
            "-tA",  # tuples-only, unaligned: bare `val|val` rows, no header/padding
            "-F",
            "|",
            "-c",
            pg_sql,
        )
    else:
        cmd = server.rt.cmd(
            "exec",
            server.name,
            "sqlite3",
            "-noheader",
            "-separator",
            "|",
            "/data/meta.db",
            sqlite_sql,
        )
    return subprocess.run(cmd, capture_output=True, check=False)
