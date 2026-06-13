# Running `baleforgit-server`

This document covers operating the server side. For the user-facing client (`git-bale`), see the top-level [`README.md`](../README.md). For the trait surface, request flows, storage layout, and protocol notes, see [`ARCHITECTURE.md`](ARCHITECTURE.md). For the forge integration contract, see [`BALE_FORGE_PROTOCOL.md`](BALE_FORGE_PROTOCOL.md).

## Install

Download the `bale-server-<version>-<target>` artifact for your platform from the [releases page](https://github.com/davidrios/baleforgit/releases): a `.tar.gz` on Linux, or a signed `.pkg` on macOS (installs `baleforgit-server` to `/usr/local/bin`). Verify the artifact before running it — see "Verifying release artifacts" below. To run it in a container, build your own image as shown under "Container".

## Quick start

```bash
# Both secrets are hex; the transfer secret must be exactly 32 bytes (64 hex chars).
BALE_JWT_SECRET_HEX=$(printf '%064x' 1) \
BALE_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
BALE_GRANTS=token-alice:alice:alice/my-model:write \
./baleforgit-server

# In another shell, exchange your bearer token for a Bale token:
curl -i -X GET \
  -H 'Authorization: Bearer token-alice' \
  http://127.0.0.1:8080/api/models/alice/my-model/bale-write-token/main

# Liveness probe (unauthenticated, not access-logged):
curl http://127.0.0.1:8080/healthz
```

Send `SIGINT` (Ctrl-C) or `SIGTERM` to shut the server down gracefully — it stops accepting new connections and waits for in-flight requests to finish before exiting. Point an orchestrator's readiness probe at `GET /healthz`.

## Container

No image is published; build one from the repo's `Dockerfile` (it compiles the
server from source into a slim Debian image):

```bash
docker build -t baleforgit-server .
docker run --rm -p 8080:8080 \
  -e BALE_JWT_SECRET_HEX=$(printf '%064x' 1) \
  -e BALE_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
  -e BALE_GRANTS=token-alice:alice:alice/my-model:write \
  baleforgit-server
```

For a production setup that bind-mounts a release binary (no in-image build)
alongside a forge, see [`prod-docker/`](../prod-docker/).

## Configuration

| Variable | Default | Notes |
|----------|---------|-------|
| `BALE_LISTEN` | `127.0.0.1:8080` | host:port to bind |
| `BALE_DATA_ROOT` | `./xet-data` | blob storage root |
| `BALE_DB_PATH` | `<BALE_DATA_ROOT>/meta.db` | SQLite metadata path. Ignored when `BALE_POSTGRES_URL` is set. |
| `BALE_POSTGRES_URL` | none | If set, store metadata in Postgres instead of SQLite. libpq connection string, e.g. `postgres://user:pass@host:5432/baledb`. Append `?sslmode=require` (or `disable`) to control TLS. The target database must already exist; the schema is created on first connect. |
| `BALE_PUBLIC_URL` | `http://<BALE_LISTEN>` | absolute base URL written into signed download URLs |
| `BALE_JWT_SECRET_HEX` | **required** | HS256 secret for Xet JWTs (≥ 32 bytes hex) |
| `BALE_TRANSFER_SECRET_HEX` | **required** | HMAC secret for signed download URLs (exactly 32 bytes hex / 64 chars) |
| `BALE_AUTHZ_HTTP_URL` | none | If set, delegate `check_repo_access` to this URL (see [`bale-server-authz-http`](../crates/bale-server-authz-http/src/lib.rs)). |
| `BALE_GRANTS` | none | Used only when `BALE_AUTHZ_HTTP_URL` is unset. Comma-separated `bearer_token:user:repo_id:read\|write` tuples for the in-process static authz (dev/test). |
| `BALE_S3_BUCKET` | none | If set, switch blob storage from the local filesystem to an S3-compatible bucket. Picks up credentials from the standard AWS provider chain. |
| `BALE_S3_REGION` | SDK default | Region for the S3 client. |
| `BALE_S3_ENDPOINT_URL` | none | Override the API endpoint (e.g. `https://minio.example:9000` for MinIO, R2's endpoint for Cloudflare). The server uses this both to talk to the store and to sign client-facing download URLs. |
| `BALE_S3_PUBLIC_ENDPOINT_URL` | = `BALE_S3_ENDPOINT_URL` | Endpoint baked into client-facing presigned download URLs, for when the server reaches the store at an address clients can't (e.g. a bundled MinIO at the compose-internal `minio:9000` while clients need `localhost:9000`). Unset → presign against `BALE_S3_ENDPOINT_URL`, correct whenever that endpoint is reachable by both server and clients (real AWS S3, R2, B2). |
| `BALE_S3_FORCE_PATH_STYLE` | `false` | Set to `true` for MinIO and other backends that expect `https://host/{bucket}/{key}` rather than virtual-host addressing. |
| `BALE_S3_PREFIX` | empty | Optional key prefix inside the bucket (include a trailing `/` if you want one). |
| `BALE_S3_DISABLE_SSE` | `false` | PUTs request SSE-S3 (AES256) by default. Set truthy to disable, for backends that don't support server-side encryption (e.g. MinIO). |
| `BALE_S3_ACCESS_KEY_ID` / `BALE_S3_SECRET_ACCESS_KEY` / `BALE_S3_SESSION_TOKEN` | none | Explicit credentials. When unset, the SDK uses env vars, `~/.aws/credentials`, and IMDS as usual. |
| `BALE_DEFAULT_QUOTA_BYTES` | none (unlimited) | Default per-owner storage cap, applied when no per-owner override is set via `PUT /v1/quotas/{owner}`. See [`ARCHITECTURE.md`](ARCHITECTURE.md#owner-accounting-and-quotas). |
| `BALE_ADMIN_TOKEN_HEX` | none (admin endpoint disabled, returns 404) | 64-char hex (32 bytes) bearer for `PUT /v1/quotas/{owner}`. Constant-time compared. Keep separate from your JWT secret. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none (exporters disabled) | If set, the server exports traces + metrics over OTLP HTTP/protobuf to `<endpoint>/v1/traces` and `<endpoint>/v1/metrics`. Typical local-collector value: `http://localhost:4318`. See [Observability](#observability). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | none | Per-signal override; used verbatim (no `/v1/...` suffix appended). Either alone is enough to enable just that signal. |
| `OTEL_SERVICE_NAME` | `baleforgit-server` | Service-name resource attribute attached to all exported telemetry. |

## Observability

The server ships an [OpenTelemetry](https://opentelemetry.io) integration that is **off by default** — if no `OTEL_EXPORTER_OTLP_ENDPOINT` (or per-signal sibling) is set, no provider is installed, no background threads start, and every instrument in the request path is a global no-op. Point the env var at a running [OTel Collector](https://opentelemetry.io/docs/collector/) to turn it on:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
BALE_JWT_SECRET_HEX=$(printf '%064x' 1) \
BALE_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
BALE_GRANTS=token-alice:alice:alice/my-model:write \
./baleforgit-server
```

When enabled, the server emits:

- **Traces** — every `tracing` span from the request path (the existing `tower_http::trace` access-log span plus anything inside the handlers) is bridged into OTel and shipped via the OTLP HTTP/protobuf exporter.
- **Metrics** (instrument names):
  - `http.server.requests` — counter, labelled by `http.request.method`, `http.route` (axum's matched pattern, *not* the raw URI — keeps cardinality bounded), `http.response.status_code`.
  - `http.server.duration` — histogram in seconds, labelled by method + matched route.
  - `bale.xorbs.uploaded` — counter, labelled by `deduplicated=true|false` (a re-upload of existing content is `true`).
  - `bale.shards.uploaded` — counter.
  - `bale.reconstructions.served` — counter (only counts 200 responses; misses surface as `http.server.requests{status=404}`).
  - `bale.upload.bytes` — counter in bytes, labelled by `kind=xorb|shard`.

Standard OTel env vars apply: `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`, etc. The `/healthz` probe is deliberately not metered or traced — Kubernetes probes would otherwise dominate the volume.

## Verifying release artifacts

Each release tarball is covered by a [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance) attestation tying it back to the exact workflow run, commit SHA, and repository that produced it. Verify with the GitHub CLI (no extra signing keys to manage):

```bash
# Works on the file you just downloaded from the release page.
gh attestation verify bale-server-<version>-<target>.tar.gz \
  --repo davidrios/baleforgit
```

A passing verify means: the artifact was produced by this repo's GitHub Actions workflow at a specific commit, and nothing in transit has tampered with it. The release also ships a `SHA256SUMS` file covering every archive.

Each release additionally publishes an SPDX SBOM (`SBOM.spdx.json`) of the workspace dependency graph, attested the same way:

```bash
gh attestation verify bale-server-<version>-<target>.tar.gz \
  --repo davidrios/baleforgit \
  --predicate-type https://spdx.dev/Document
```

For verification that doesn't depend on GitHub's attestation API, `SHA256SUMS` is also signed with [cosign](https://docs.sigstore.dev/) keyless (Sigstore). The signature (`SHA256SUMS.sig`) and certificate (`SHA256SUMS.pem`) ship alongside it:

```bash
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/davidrios/baleforgit/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
