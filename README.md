# xet-server

A self-hosted, Xet-protocol-compatible Content-Addressable Storage server.

## What this is

[Xet](https://huggingface.co/docs/xet/index) is Hugging Face's storage backend: a Git-LFS-style large-file system that does **content-defined chunking + chunk-level deduplication**. The official client (`git-xet`, `hf-xet`) is open source — the server is not, and Hugging Face only operates it as a hosted SaaS.

This repo is a from-scratch Rust implementation of the **server side** of the Xet protocol, so that an unmodified `git-xet` client can push to and pull from your own infrastructure. Everything is pluggable behind three traits (`BlobStore`, `MetadataStore`, `RepoAuthz`) so the same server can later sit on top of S3, Postgres, or any git forge — the forge integration contract lives in [`docs/DFS_FORGE_PROTOCOL.md`](docs/DFS_FORGE_PROTOCOL.md).

It also ships a native client (`crates/git-dfs/`) that installs as a Git filter driver and replaces `git-lfs` entirely — it speaks Git's long-running filter protocol and calls into `xet-core` directly, so there's no `.git/lfs/objects/` whole-file cache. A legacy Go bridge (`lfs-adapter/`) is retained for repos that need to keep using `git-lfs`.

## Status

| Milestone | Status | What it provides |
|-----------|--------|------------------|
| M1 — Wire types + shard parser | done | Hex encoding, JSON shapes, MDB shard binary format |
| M2 — Filesystem + SQLite stores | done | `BlobStore` on disk, `MetadataStore` on SQLite |
| M3 — Upload endpoints | done | `POST /v1/xorbs/{prefix}/{hash}`, `POST /shards` |
| M4 — Download endpoints | done | `GET /v1/reconstructions/...`, signed `/xorb/default/...` transfer |
| M5 — Auth + mock HF Hub token endpoint | done | HS256 JWTs, scope enforcement, `GET /api/{type}s/.../xet-{rw}-token/{rev}` |
| M6 — Global dedup endpoint | done | `GET /v1/chunks/{prefix}/{hash}` (per-response HMAC-wrapped shard) |
| M7 — End-to-end against `git-xet` | done | `m7_git_xet` drives the real `git-xet transfer` binary over the LFS custom-transfer JSON protocol; skips if the binary isn't on PATH |
| M8 — Pluggability sanity (alternate impls) | done | `xet-server-storage-mem` (in-memory `BlobStore`) + `xet-server-authz-http` (HTTP-backed `RepoAuthz` skeleton), exercised end-to-end by `m8_pluggability` |
| M9 — Real LFS push via Go adapter | done | `lfs-adapter/` (Go) bridges the standard git-lfs Batch API to xet-server; `m9_real_lfs_push` drives a real `git lfs push --all` through the full chain (git-lfs → adapter → xet-server → git-xet → CAS upload). Skips when `{go, git, git-lfs, git-xet}` aren't all on PATH. |
| M10 — Real LFS pull via Go adapter | done | Symmetric `git lfs pull` path: adapter advertises `transfer="basic"` for downloads, serves bytes itself by querying xet-server's new `/v1/reconstructions/by-sha256/{oid}` endpoint, then streams xorb frames (LZ4 / raw / BG4-LZ4) chunk-by-chunk back to git-lfs. `m10_real_lfs_pull` round-trips a 300 KiB payload through push then pull and byte-compares. |
| M11 — Native filter (`git-dfs`) | done | New `crates/git-dfs` binary implements Git's long-running filter protocol directly. No `.git/lfs/objects/` whole-file cache — content lives only as the worktree file, a shared chunk cache (`~/.cache/dfs/chunks` by default), and a per-repo manifest cache (`.git/dfs/manifests/`). `m11_native_filter` drives `git add` + `git checkout` round-trips and asserts the hot path (cached manifest + cached chunks) makes **zero** calls to `/v1/reconstructions/`. |
| M12 — Per-repo scope check on reconstruction | done | `/v1/reconstructions/*` now requires a `(file_hash, repo_id=claims.repo)` row in the `files` table — returns 404 on miss (no existence leak). The `files` PK is `(file_hash, repo_id)`, so the same content registered in multiple repos grants independent read access (cross-repo dedup). `m12_repo_scope` covers isolation, dedup, and the 404-vs-403 distinction. |


## Quick start

Requires Rust 1.88+

```bash
# Build everything
cargo build --workspace

# Run the test suite
cargo test --workspace

# Start the server (the two secrets must each be hex; transfer secret = exactly 32 bytes)
XET_JWT_SECRET_HEX=$(printf '%064x' 1) \
XET_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
XET_GRANTS=hub-alice:alice:alice/my-model:write \
cargo run -p xet-server-bin

# In another shell, exchange your hub bearer for a Xet token:
curl -i -X GET \
  -H 'Authorization: Bearer hub-alice' \
  http://127.0.0.1:8080/api/models/alice/my-model/xet-write-token/main

# Liveness probe (unauthenticated, not access-logged):
curl http://127.0.0.1:8080/healthz
```

Send `SIGINT` (Ctrl-C) or `SIGTERM` to shut the server down gracefully — it stops accepting new connections and waits for in-flight requests to finish before exiting.

Environment variables understood by the binary:

| Variable | Default | Notes |
|----------|---------|-------|
| `XET_LISTEN` | `127.0.0.1:8080` | host:port to bind |
| `XET_DATA_ROOT` | `./xet-data` | blob storage root |
| `XET_DB_PATH` | `<XET_DATA_ROOT>/meta.db` | SQLite metadata path |
| `XET_PUBLIC_URL` | `http://<XET_LISTEN>` | absolute base URL written into signed download URLs |
| `XET_JWT_SECRET_HEX` | **required** | HS256 secret for Xet JWTs (≥ 32 bytes hex) |
| `XET_TRANSFER_SECRET_HEX` | **required** | HMAC secret for signed download URLs (exactly 32 bytes hex / 64 chars) |
| `XET_AUTHZ_HTTP_URL` | none | If set, delegate `check_repo_access` to this URL (see [`xet-server-authz-http`](crates/xet-server-authz-http/src/lib.rs)). |
| `XET_GRANTS` | none | Used only when `XET_AUTHZ_HTTP_URL` is unset. Comma-separated `hub_token:user:repo_id:read\|write` tuples for the in-process static authz (dev/test). |
| `XET_S3_BUCKET` | none | If set, switch blob storage from the local filesystem to an S3-compatible bucket. Picks up credentials from the standard AWS provider chain. |
| `XET_S3_REGION` | SDK default | Region for the S3 client. |
| `XET_S3_ENDPOINT_URL` | none | Override the API endpoint (e.g. `https://minio.example:9000` for MinIO, R2's endpoint for Cloudflare). |
| `XET_S3_FORCE_PATH_STYLE` | `false` | Set to `true` for MinIO and other backends that expect `https://host/{bucket}/{key}` rather than virtual-host addressing. |
| `XET_S3_PREFIX` | empty | Optional key prefix inside the bucket (include a trailing `/` if you want one). |
| `XET_S3_ACCESS_KEY_ID` / `XET_S3_SECRET_ACCESS_KEY` / `XET_S3_SESSION_TOKEN` | none | Explicit credentials. When unset, the SDK uses env vars, `~/.aws/credentials`, and IMDS as usual. |

## Repo layout

```
crates/
├── xet-server-core/         # Trait definitions + domain types
├── xet-server-wire/         # JSON shapes + Xet hash hex encoding
├── xet-server-shard/        # MDB shard binary parser + xorb chunk-frame parser
├── xet-server-storage-fs/   # BlobStore on the local filesystem
├── xet-server-storage-mem/  # BlobStore in memory (test / pluggability check)
├── xet-server-storage-s3/   # BlobStore on any S3-compatible API (real presigned URLs)
├── xet-server-meta-sqlite/  # MetadataStore on SQLite
├── xet-server-authz-mem/    # In-memory RepoAuthz (AlwaysAllow, ConfigAuthz)
├── xet-server-authz-http/   # RepoAuthz that delegates check_repo_access to an HTTP upstream
├── xet-server-tokens/       # HS256 Xet JWT mint/verify
├── xet-server-http/         # Axum router, handlers, middleware
├── xet-server-bin/          # The `xet-server` binary
├── xet-server-tests/        # Cross-crate integration tests (m2..m12)
└── git-dfs/                 # Native Git filter — bypasses LFS entirely.
                             #   `git-dfs install` registers `filter.dfs.process`.
                             #   `git-dfs track '*.bin'` enables it for matching paths.
                             #   Auto-resolves server URL + token from the
                             #   `origin` remote via the forge's
                             #   /info/dfs/authenticate endpoint (or SSH
                             #   `git-dfs-authenticate`); pointers are pretty
                             #   JSON; chunks live in a shared user-global
                             #   cache (`~/.cache/dfs/chunks` by default,
                             #   overridable via `dfs.cacheDir` or `DFS_CACHE_DIR`).

lfs-adapter/                 # Go: standalone git-lfs Batch API → xet-server bridge.
                             # Legacy path; retained for users on git-lfs.
```

The workspace `Cargo.toml` `exclude`s sibling clones of `xet-core/`, `git-lfs/`, and `lfs-adapter/` from `cargo build --workspace`. `git-dfs` depends on `xet-core/` via path deps; the legacy LFS bridge is built by its own `go build` from inside `lfs-adapter/`.

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — request flows, trait surface, storage layout, and protocol notes.
- [`docs/DFS_FORGE_PROTOCOL.md`](docs/DFS_FORGE_PROTOCOL.md) — what a git forge has to implement to support `git-dfs`.
- [`lfs-adapter/README.md`](lfs-adapter/README.md) — the legacy LFS bridge.

## Using the native filter (`git-dfs`)

The LFS path (M9 / M10 above) stores a whole-file copy of every tracked blob in
`.git/lfs/objects/` — git-lfs's design forces this and it defeats Xet's
chunk-level dedup locally. The `git-dfs` filter is the newer, dedup-preserving
path:

```bash
cargo build -p git-dfs
# put target/debug on PATH, or use absolute paths below

# Inside an existing repo cloned from a DFS-enabled forge:
git-dfs install --local        # writes filter.dfs.process to .git/config
git-dfs track '*.bin'          # appends '*.bin filter=dfs -text' to .gitattributes
git add .gitattributes && git commit -m 'enable dfs'

cp ~/some-big-model.safetensors models/big.bin
git add models/big.bin && git commit -m 'add model'
# git-dfs auto-resolves auth from `origin` on first use:
#  - HTTPS remotes → git credential fill → forge's /info/dfs/authenticate
#  - SSH remotes   → ssh git@host git-dfs-authenticate <owner>/<repo> upload
# The forge mints a short-lived JWT, git-dfs exchanges it for a Xet token,
# uploads chunks, and replaces the worktree blob with a JSON pointer.
```

For a self-hosted dev loop without a forge (m11-style), skip the auth resolver
by pinning the server URL and a static token in local git config:

```bash
git config --local dfs.serverUrl http://127.0.0.1:8080
git config --local dfs.token "<a Xet JWT minted out-of-band>"
```

Local layout after a `git add` + `git checkout`:

```
my-repo/big.bin                              # worktree (one copy)
my-repo/.git/dfs/manifests/<file_id>.json    # per-file reconstruction terms (cached)
~/.cache/dfs/chunks/                         # shared chunk pool (deduped across files & repos)
                                             # No .git/lfs/objects/. No second whole-file copy.
```

Want to integrate a forge with `git-dfs`? See [`docs/DFS_FORGE_PROTOCOL.md`](docs/DFS_FORGE_PROTOCOL.md) — the surface is one HTTPS endpoint (`/info/dfs/authenticate`), an SSH command (`git-dfs-authenticate`), and the existing `/check_access` callback on the xet-server side.

## Development

Install the [pre-commit](https://pre-commit.com) framework once (`brew install pre-commit` or `pipx install pre-commit`), then in this repo run:

```bash
pre-commit install
```

That wires up `.pre-commit-config.yaml`, which on every commit runs `cargo fmt --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## CI and release artifacts

GitHub Actions workflows live under `.github/workflows/`:

- **`ci.yml`** — on every push to `main` and every PR, runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test --workspace`, then the `#[ignore]`d MinIO integration test (`cargo test -p xet-server-storage-s3 --test minio -- --ignored`). The test job installs `git-xet` from upstream releases (`GIT_XET_VERSION` env at the top of the job) and relies on `git`, `git-lfs`, `go`, and `podman` being preinstalled on `ubuntu-latest`, so m7/m9/m10/m11 and the S3 path all run end-to-end rather than skipping.
- **`release.yml`** — on a `v*` tag push, builds the `xet-server` and `git-dfs` binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`, then creates a GitHub release with one `.tar.gz` per binary per target (each paired with its own `.sha256`) attached. Each tarball is also signed via [GitHub artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) — `actions/attest-build-provenance` mints an unforgeable [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance) statement, signed by Sigstore, recorded in the public transparency log, and reachable from the GitHub Attestations API.
- **`docker.yml`** — on a push to `main` or a `v*` tag, builds a multi-arch (`linux/amd64`, `linux/arm64`) image from `Dockerfile` and pushes it to `ghcr.io/<owner>/<repo>` with `branch`, `sha-<short>`, semver, and `latest` tags as appropriate. Same SLSA Build Provenance is generated and pushed alongside the image as an OCI referrer, so `gh attestation verify oci://…` and `cosign verify-attestation` both find it.

All three workflows are also runnable manually from the Actions tab via **Run workflow** (`workflow_dispatch`):

- `ci.yml` takes no inputs — useful for re-running the test matrix on demand.
- `release.yml` takes a `tag` input (default `v0.0.0-test`); the release is created as a **draft prerelease**, which means the git tag is *not* materialized in the repo until you click Publish on the resulting draft. Re-dispatching with the same tag overwrites the prior draft so you don't accumulate test releases. Delete the draft when done and nothing is left behind. Attestations are still minted normally.
- `docker.yml` takes a `tag` input (default `test`); the image is pushed with that tag *and* the usual `sha-<short>` tag, so you can pull `ghcr.io/<owner>/<repo>:test` to try a manual build without touching the `:latest` tag.

### Verifying release artifacts

Each release tarball and container digest is covered by a SLSA Build Provenance attestation tying it back to the exact workflow run, commit SHA, and repository that produced it. Verify with the GitHub CLI (no extra signing keys to manage):

```bash
# Tarball — works on the file you just downloaded from the release page.
gh attestation verify xet-server-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo davidrios/git-xet-server

# Container image — pin to a digest, not a mutable tag.
gh attestation verify oci://ghcr.io/davidrios/git-xet-server@sha256:<digest> \
  --repo davidrios/git-xet-server
```

A passing verify means: the artifact was produced by this repo's GitHub Actions workflow at a specific commit, and nothing in transit has tampered with it. Pin to a digest (not `:latest`) when you care about reproducibility.

To run the container locally:

```bash
docker run --rm -p 8080:8080 \
  -e XET_JWT_SECRET_HEX=$(printf '%064x' 1) \
  -e XET_TRANSFER_SECRET_HEX=$(printf '%064x' 2) \
  -e XET_GRANTS=hub-alice:alice:alice/my-model:write \
  ghcr.io/davidrios/git-xet-server:latest
```

Point an orchestrator's readiness probe at `GET /healthz`.

## License

Apache-2.0.
