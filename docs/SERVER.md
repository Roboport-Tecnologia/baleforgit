# Running `xet-server`

This document covers operating the server side. For the user-facing client (`git-dfs`), see the top-level [`README.md`](../README.md). For the trait surface, request flows, storage layout, and protocol notes, see [`ARCHITECTURE.md`](ARCHITECTURE.md). For the forge integration contract, see [`DFS_FORGE_PROTOCOL.md`](DFS_FORGE_PROTOCOL.md).

## Install

Download the `xet-server-<version>-<target>.tar.gz` tarball for your platform from the [releases page](https://github.com/davidrios/git-xet-server/releases), or pull the container image from `ghcr.io/davidrios/git-xet-server`. Verify the artifact before running it — see "Verifying release artifacts" below.

## Quick start

```bash
# Both secrets are hex; the transfer secret must be exactly 32 bytes (64 hex chars).
XET_JWT_SECRET_HEX=$(printf '%064x' 1) \
XET_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
XET_GRANTS=token-alice:alice:alice/my-model:write \
./xet-server

# In another shell, exchange your bearer token for a Xet token:
curl -i -X GET \
  -H 'Authorization: Bearer token-alice' \
  http://127.0.0.1:8080/api/models/alice/my-model/xet-write-token/main

# Liveness probe (unauthenticated, not access-logged):
curl http://127.0.0.1:8080/healthz
```

Send `SIGINT` (Ctrl-C) or `SIGTERM` to shut the server down gracefully — it stops accepting new connections and waits for in-flight requests to finish before exiting. Point an orchestrator's readiness probe at `GET /healthz`.

## Container

```bash
docker run --rm -p 8080:8080 \
  -e XET_JWT_SECRET_HEX=$(printf '%064x' 1) \
  -e XET_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
  -e XET_GRANTS=token-alice:alice:alice/my-model:write \
  ghcr.io/davidrios/git-xet-server:latest
```

## Configuration

| Variable | Default | Notes |
|----------|---------|-------|
| `XET_LISTEN` | `127.0.0.1:8080` | host:port to bind |
| `XET_DATA_ROOT` | `./xet-data` | blob storage root |
| `XET_DB_PATH` | `<XET_DATA_ROOT>/meta.db` | SQLite metadata path |
| `XET_PUBLIC_URL` | `http://<XET_LISTEN>` | absolute base URL written into signed download URLs |
| `XET_JWT_SECRET_HEX` | **required** | HS256 secret for Xet JWTs (≥ 32 bytes hex) |
| `XET_TRANSFER_SECRET_HEX` | **required** | HMAC secret for signed download URLs (exactly 32 bytes hex / 64 chars) |
| `XET_AUTHZ_HTTP_URL` | none | If set, delegate `check_repo_access` to this URL (see [`xet-server-authz-http`](../crates/xet-server-authz-http/src/lib.rs)). |
| `XET_GRANTS` | none | Used only when `XET_AUTHZ_HTTP_URL` is unset. Comma-separated `bearer_token:user:repo_id:read\|write` tuples for the in-process static authz (dev/test). |
| `XET_S3_BUCKET` | none | If set, switch blob storage from the local filesystem to an S3-compatible bucket. Picks up credentials from the standard AWS provider chain. |
| `XET_S3_REGION` | SDK default | Region for the S3 client. |
| `XET_S3_ENDPOINT_URL` | none | Override the API endpoint (e.g. `https://minio.example:9000` for MinIO, R2's endpoint for Cloudflare). |
| `XET_S3_FORCE_PATH_STYLE` | `false` | Set to `true` for MinIO and other backends that expect `https://host/{bucket}/{key}` rather than virtual-host addressing. |
| `XET_S3_PREFIX` | empty | Optional key prefix inside the bucket (include a trailing `/` if you want one). |
| `XET_S3_ACCESS_KEY_ID` / `XET_S3_SECRET_ACCESS_KEY` / `XET_S3_SESSION_TOKEN` | none | Explicit credentials. When unset, the SDK uses env vars, `~/.aws/credentials`, and IMDS as usual. |

## Verifying release artifacts

Each release tarball and container digest is covered by a [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance) attestation tying it back to the exact workflow run, commit SHA, and repository that produced it. Verify with the GitHub CLI (no extra signing keys to manage):

```bash
# Tarball — works on the file you just downloaded from the release page.
gh attestation verify xet-server-<version>-<target>.tar.gz \
  --repo davidrios/git-xet-server

# Container image — pin to a digest, not a mutable tag.
gh attestation verify oci://ghcr.io/davidrios/git-xet-server@sha256:<digest> \
  --repo davidrios/git-xet-server
```

A passing verify means: the artifact was produced by this repo's GitHub Actions workflow at a specific commit, and nothing in transit has tampered with it. Pin to a digest (not `:latest`) when you care about reproducibility.
