# Running `baleforgit-server`

Operating the server. The client is covered in [`README.md`](../README.md), internals in [`ARCHITECTURE.md`](ARCHITECTURE.md), and the forge integration contract in [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md).

## Install

Download the `bale-server-<version>-<target>` artifact from the [releases page](https://github.com/Roboport-Tecnologia/baleforgit/releases): a `.tar.gz` on Linux, or a signed `.pkg` on macOS (installs `baleforgit-server` to `/usr/local/bin`). Verify it first — see [Verifying release artifacts](#verifying-release-artifacts). No container image is published; see [Container](#container).

## Quick start

```bash
# Both secrets are hex; the transfer secret must be exactly 32 bytes (64 hex chars).
BALE_JWT_SECRET_HEX=$(printf '%064x' 1) \
BALE_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
BALE_GRANTS=token-alice:alice:alice/my-model:write \
./baleforgit-server

# In another shell, exchange your bearer token for a Bale token:
curl -i -H 'Authorization: Bearer token-alice' \
  http://127.0.0.1:8080/api/models/alice/my-model/bale-write-token/main

# Liveness probe (unauthenticated, not logged or metered):
curl http://127.0.0.1:8080/healthz
```

`SIGINT`/`SIGTERM` shut down gracefully: the listener closes at once, open connections get up to 25 s to finish, then detached xorb commits up to 2 min. Point an orchestrator's readiness probe at `GET /healthz`. Connection caps and timeouts are described in [`ARCHITECTURE.md` § Connection and request limits](ARCHITECTURE.md#connection-and-request-limits); put a reverse proxy in front for TLS and per-client rate limits.

## Container

Build an image from the repo's `Dockerfile` (compiles the server into a slim Debian image that runs as an unprivileged user, with `BALE_LISTEN=0.0.0.0:8080` and `BALE_DATA_ROOT=/var/lib/baleforgit-server/data` preset — mount a volume there to keep data):

```bash
docker build -t baleforgit-server .
docker run --rm -p 8080:8080 \
  -v bale-data:/var/lib/baleforgit-server/data \
  -e BALE_JWT_SECRET_HEX=$(printf '%064x' 1) \
  -e BALE_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
  -e BALE_GRANTS=token-alice:alice:alice/my-model:write \
  baleforgit-server
```

[`demo-docker/compose.yml`](../demo-docker/compose.yml) is a working example of the server behind a forge with a MinIO blob store.

## Configuration

All configuration is environment variables. Malformed secrets, numbers or grants, and a set-but-empty `BALE_POSTGRES_URL` / `BALE_S3_BUCKET` / `BALE_AUTHZ_HTTP_URL`, fail startup rather than falling back to a default.

| Variable | Default | Notes |
|----------|---------|-------|
| `BALE_LISTEN` | `127.0.0.1:8080` | host:port to bind. |
| `BALE_PUBLIC_URL` | `http://<BALE_LISTEN>` | Absolute base URL clients use: returned as `casUrl` by the token endpoint and written into signed transfer URLs. Set it whenever clients reach the server through anything other than `BALE_LISTEN` (a startup warning fires if it is unset and `BALE_LISTEN` isn't loopback). |
| `BALE_JWT_SECRET_HEX` | **required** | HS256 key for Bale tokens; must decode to ≥ 32 bytes. |
| `BALE_TRANSFER_SECRET_HEX` | **required** | HMAC key for signed transfer URLs; must decode to exactly 32 bytes (64 hex chars). |
| `BALE_DATA_ROOT` | `./xet-data` | Filesystem blob store root (created if missing; also holds the default SQLite file). |
| `BALE_DB_PATH` | `<BALE_DATA_ROOT>/meta.db` | SQLite metadata path. Ignored when `BALE_POSTGRES_URL` is set. |
| `BALE_POSTGRES_URL` | none | Store metadata in Postgres instead of SQLite, e.g. `postgres://user:pass@host:5432/baledb` (append `?sslmode=require` or `disable` to control TLS). The database must exist; the schema is created on first connect. |
| `BALE_AUTHZ_HTTP_URL` | none | Delegate repo access checks to a forge: the server POSTs to `<url>/check_access` (redirects are not followed). Contract in [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md#post-check_access-requestresponse). |
| `BALE_GRANTS` | none | Static authz for dev/test, used only when `BALE_AUTHZ_HTTP_URL` is unset: comma-separated `bearer_token:user:repo_id:read\|write` tuples (one bearer maps to one user). With neither set, every request is refused. |
| `BALE_S3_BUCKET` | none | Store blobs in this S3-compatible bucket instead of the filesystem. |
| `BALE_S3_REGION` | SDK default | Region for the S3 client. |
| `BALE_S3_ENDPOINT_URL` | none | API endpoint override (MinIO, R2, B2, …). Also used for client-facing presigned URLs unless `BALE_S3_PUBLIC_ENDPOINT_URL` is set. |
| `BALE_S3_PUBLIC_ENDPOINT_URL` | = `BALE_S3_ENDPOINT_URL` | Endpoint baked into client-facing presigned URLs, for when clients can't reach the address the server uses (e.g. a bundled MinIO at compose-internal `minio:9000` that clients see as `localhost:9000`). Empty counts as unset. |
| `BALE_S3_FORCE_PATH_STYLE` | `false` | Truthy (`1`/`true`/`yes`) for MinIO and other backends that need `https://host/{bucket}/{key}` addressing. |
| `BALE_S3_PREFIX` | empty | Key prefix inside the bucket (include a trailing `/` if you want one). |
| `BALE_S3_DISABLE_SSE` | `false` | PUTs request SSE-S3 (AES256) by default; set truthy for backends without server-side encryption (e.g. MinIO). |
| `BALE_S3_ACCESS_KEY_ID` / `BALE_S3_SECRET_ACCESS_KEY` / `BALE_S3_SESSION_TOKEN` | none | Explicit credentials. Unset → the standard AWS provider chain (env, `~/.aws/credentials`, IMDS). |
| `BALE_DEFAULT_QUOTA_BYTES` | none (unlimited) | Per-owner storage cap when no override is set via `PUT /v1/quotas/{owner}`. See [`ARCHITECTURE.md` § Owner accounting and quotas](ARCHITECTURE.md#owner-accounting-and-quotas). The server never deletes blobs, so this is what bounds disk growth. |
| `BALE_ADMIN_TOKEN_HEX` | none (`PUT /v1/quotas` returns 404) | 64 hex chars (32 bytes). Bearer for `PUT /v1/quotas/{owner}`; also reads any owner's or repo's `/v1/usage`. Constant-time compared; keep it distinct from the JWT secret. |
| `BALE_MAX_CONNECTIONS_PER_IP` | `512` | Open connections per client IP, an IPv6 client counted per /64 (`0` = unlimited). Behind a reverse proxy every client shares the proxy's IP, so raise it or set `0` and rate-limit at the proxy. |
| `RUST_LOG` | `info,sqlx=warn,tower_http::trace=info,bale_server_http=info` | Log filter ([`tracing-subscriber` `EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax). Access logs are at INFO; 4xx/5xx at WARN. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none (exporters off) | Export traces + metrics over OTLP HTTP/protobuf to `<endpoint>/v1/traces` and `<endpoint>/v1/metrics`, e.g. `http://localhost:4318`. See [Observability](#observability). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | none | Per-signal override, used verbatim (no `/v1/...` appended). Either alone enables just that signal. |
| `OTEL_SERVICE_NAME` | `baleforgit-server` | Service name on exported telemetry. |

## Observability

OpenTelemetry export is **off by default**: with no `OTEL_EXPORTER_OTLP_ENDPOINT` (or per-signal variant) no provider is installed and every instrument is a no-op. Point it at an [OTel Collector](https://opentelemetry.io/docs/collector/) to turn it on:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
BALE_JWT_SECRET_HEX=$(printf '%064x' 1) \
BALE_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
BALE_GRANTS=token-alice:alice:alice/my-model:write \
./baleforgit-server
```

When enabled, the server exports:

- **Traces** — every `tracing` span in the request path (the access-log span records the path only, never the query string, which can carry bearers and transfer signatures).
- **Metrics**:
  - `http.server.requests` — counter, labelled `http.request.method`, `http.route` (the matched route pattern, not the raw URI), `http.response.status_code`.
  - `http.server.duration` — histogram in seconds, labelled method + route.
  - `bale.xorbs.uploaded` — counter, labelled `deduplicated=true|false` (`true` = re-upload of existing content).
  - `bale.shards.uploaded` — counter.
  - `bale.reconstructions.served` — counter of successful reconstructions (misses show up as `http.server.requests` with status 404).
  - `bale.upload.bytes` — counter in bytes, labelled `kind=xorb|shard`.

Standard OTel env vars (`OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`, …) apply. `/healthz` is never traced or metered. Implementation notes are in [`ARCHITECTURE.md` § Observability](ARCHITECTURE.md#observability).

## Verifying release artifacts

Every release archive (`bale-*` `.tar.gz` / `.pkg` / `.zip`) carries a [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance) attestation tying it to the workflow run, commit and repository that built it, plus an attested SPDX SBOM (`SBOM.spdx.json`) of the workspace dependency graph. Verify with the GitHub CLI:

```bash
gh attestation verify bale-server-<version>-<target>.tar.gz \
  --repo Roboport-Tecnologia/baleforgit
# the SBOM attestation:
gh attestation verify bale-server-<version>-<target>.tar.gz \
  --repo Roboport-Tecnologia/baleforgit \
  --predicate-type https://spdx.dev/Document
```

Independently of GitHub's attestation API, `SHA256SUMS` (covering every archive) is signed with [cosign](https://docs.sigstore.dev/) keyless; the Sigstore bundle ships as `SHA256SUMS.cosign.bundle`:

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/Roboport-Tecnologia/baleforgit/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c SHA256SUMS
```
