"""Failure-injection + in-process mock servers (proxy, authz, forge, otlp)."""

from __future__ import annotations

import http.server
import json
import socket
import subprocess
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from baleharness.logutil import TestFailure
from baleharness.pgbackend import (
    PG_USER,
    db_for_data_root,
    get_active_postgres_backend,
)
from baleharness.proc import host_primary_ip, pick_free_port
from baleharness.server import ServerHandle


class TcpProxy:
    """Forwarding proxy for the failure-recovery phases. `kill()` slams every
    socket shut to simulate an abrupt drop; `start()` may be called again to
    bring it back on the same port for the retry leg.

    `throttle_bytes_per_sec` slows only client → server (the upload bodies):
    an unthrottled 35 MiB push on localhost finishes in well under a second,
    too fast to interrupt mid-flight.
    """

    def __init__(
        self,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        *,
        throttle_bytes_per_sec: int | None = None,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self.listen_port = listen_port
        self.upstream = (upstream_host, upstream_port)
        self.throttle_bytes_per_sec = throttle_bytes_per_sec
        # "0.0.0.0" for failure-s3-conndrop, so the server container can reach
        # the proxy via host.containers.internal.
        self.bind_host = bind_host
        self._lock = threading.Lock()
        self._listen_sock: socket.socket | None = None
        self._active: list[socket.socket] = []
        self._accept_thread: threading.Thread | None = None
        self._stopped = True
        self._bytes_forwarded = 0
        self._connections = 0

    @property
    def bytes_forwarded(self) -> int:
        with self._lock:
            return self._bytes_forwarded

    @property
    def connections(self) -> int:
        """Inbound connections since the last reset_counters(); offline-no-network
        asserts it stays 0 across ops that must never touch the CAS server."""
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
        throttle: int | None = None,
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
        """Close every socket at once, simulating an abrupt connection drop."""
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
    """Stand-in for a forge's `/check_access`, driving `HttpAuthz` in the
    `authz-http` coverage phase.

    Wire contract (see `crates/bale-server-authz-http/src/lib.rs`):
        POST /check_access  { "hub_bearer": ..., "repo": {...}, "scope": ... }
        200 OK { "user_id": "alice" }   — known token + sufficient scope
        401 Unauthorized                — unknown hub_bearer
        403 Forbidden                   — known token, insufficient access
        any other (e.g. 500)            — upstream failure (HttpAuthz maps to Internal)

    `decide(hub_bearer, repo_id, scope)` returns `(status, body_dict)`.
    """

    def __init__(
        self,
        decide: Callable[[str, str, str], tuple[int, dict]],
        *,
        port: int | None = None,
    ) -> None:
        self.decide = decide
        self.port = port or pick_free_port()
        self.calls: list[
            tuple[str, str, str, int]
        ] = []  # (bearer, repo_id, scope, status)
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        # The server container reaches us via the host's primary IP; 127.0.0.1
        # would be its own loopback.
        return f"http://{host_primary_ip()}:{self.port}"

    def start(self) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                # The default per-request stderr line drowns our info() output.
                pass

            def do_POST(self):
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
    """Stand-in for a forge's `/<owner>/<repo>.git/info/bale/authenticate`, the
    HTTPS half of the forge protocol (`docs/BALE_FORGE_PROTOCOL.md`); returns a
    fixed href + hub token.

    Wire shape the resolver expects (resolver.rs `authenticate_http`):
        POST /<owner>/<repo>.git/info/bale/authenticate?op=upload|download
        Authorization: Basic <base64(user:pass)>
        200 { "href": "<bale-server-url>", "header": {"Authorization": "Bearer <tok>"} }

    No git smart-HTTP: push-pending and a cold smudge only read `origin`'s URL
    and POST here, so one endpoint suffices instead of wrapping
    `git http-backend`. The client runs on the host, hence 127.0.0.1.
    """

    def __init__(
        self,
        *,
        bale_href: str,
        hub_token: str,
        port: int | None = None,
        enforce_auth: bool = False,
        public: bool = False,
    ) -> None:
        self.bale_href = bale_href.rstrip("/")
        self.hub_token = hub_token
        self.port = port or pick_free_port()
        # enforce_auth=False: every request succeeds (https-origin relies on it).
        # True models a real forge: anonymous is granted only `op=download` on a
        # `public` repo, else 401. `public` is mutable so one mock can serve a
        # public then a private sub-case.
        self.enforce_auth = enforce_auth
        self.public = public
        self.calls: list[tuple[str, bool]] = []  # (op, had_basic_auth)
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
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
                # The 401 is what drives the resolver's anon-first download
                # path to fall back to Basic auth on a private repo.
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
    """Minimal OTLP/HTTP collector: answers every POST 200 with an empty body
    (which opentelemetry-rust accepts as a successful export) and counts hits
    per path so the phase can assert the exporter pipeline fired."""

    def __init__(self, *, port: int | None = None) -> None:
        self.port = port or pick_free_port()
        self._lock = threading.Lock()
        self.hits: dict[str, int] = {}
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        # Base endpoint; the exporter appends /v1/traces + /v1/metrics. Host IP
        # for the same reason as MockAuthzServer.url.
        return f"http://{host_primary_ip()}:{self.port}"

    def hit_count(self, path: str) -> int:
        with self._lock:
            return self.hits.get(path, 0)

    def start(self) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
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
    """Poll until at least `min_bytes` of xorbs are on the server's disk;
    returns the total seen. Keep `timeout_s` short enough to catch the push
    mid-upload."""
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
    """Hold an IMMEDIATE write lock on the server's meta.db for `hold_seconds`
    and yield, so failure-dbbusy's concurrent push hits SQLITE_BUSY; the
    server's busy_timeout must turn that into a brief wait, not an error.

    Runs inside the container: on macOS rootless podman bind mounts go through
    a VM, where host-side fcntl locks don't reach the in-VM SQLite. sqlite3
    buffers stdout off a TTY, so "lock held" is signalled by a marker file
    touched after BEGIN IMMEDIATE returns."""
    marker = "/tmp/bale-e2e-dblock-held"
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
        # The detached sqlite3 COMMITs and exits on its own after the sleep.
        pass


def meta_db_query(
    server: ServerHandle,
    *,
    sqlite_sql: str,
    pg_sql: str,
) -> subprocess.CompletedProcess:
    """Run one statement against whichever metadata engine the run uses; rows
    come back '|'-separated, headerless. Runs inside a container because a
    host-side meta.db read through the macOS podman VM is unreliable. Pass the
    same string twice for dialect-neutral SQL."""
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
