# xet-server

A self-hosted, Xet-protocol-compatible Content-Addressable Storage server.

## What this is

[Xet](https://huggingface.co/docs/xet/index) is Hugging Face's storage backend: a Git-LFS-style large-file system that does **content-defined chunking + chunk-level deduplication**. The official client (`git-xet`, `hf-xet`) is open source — the server is not, and Hugging Face only operates it as a hosted SaaS.

This repo is a from-scratch Rust implementation of the **server side** of the Xet protocol, so that an unmodified `git-xet` client can push to and pull from your own infrastructure. Everything is pluggable behind three traits (`BlobStore`, `MetadataStore`, `RepoAuthz`) so the same server can later sit on top of S3, Postgres, GitLab/Gitea, etc.

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
```

Environment variables understood by the binary:

| Variable | Default | Notes |
|----------|---------|-------|
| `XET_LISTEN` | `127.0.0.1:8080` | host:port to bind |
| `XET_DATA_ROOT` | `./xet-data` | blob storage root |
| `XET_DB_PATH` | `<XET_DATA_ROOT>/meta.db` | SQLite metadata path |
| `XET_PUBLIC_URL` | `http://<XET_LISTEN>` | absolute base URL written into signed download URLs |
| `XET_JWT_SECRET_HEX` | **required** | HS256 secret for Xet JWTs (≥ 32 bytes hex) |
| `XET_TRANSFER_SECRET_HEX` | **required** | HMAC secret for signed download URLs (exactly 32 bytes hex / 64 chars) |
| `XET_GRANTS` | none | comma-separated `hub_token:user:repo_id:read\|write` tuples |

## Repo layout

```
crates/
├── xet-server-core/         # Trait definitions + domain types
├── xet-server-wire/         # JSON shapes + Xet hash hex encoding
├── xet-server-shard/        # MDB shard binary parser + serializer
├── xet-server-storage-fs/   # BlobStore on the local filesystem
├── xet-server-storage-mem/  # BlobStore in memory (test / pluggability check)
├── xet-server-meta-sqlite/  # MetadataStore on SQLite
├── xet-server-authz-mem/    # In-memory RepoAuthz (AlwaysAllow, ConfigAuthz)
├── xet-server-authz-http/   # RepoAuthz skeleton that proxies to an upstream HTTP service
├── xet-server-tokens/       # HS256 Xet JWT mint/verify
├── xet-server-http/         # Axum router, handlers, middleware
├── xet-server-bin/          # The `xet-server` binary
└── xet-server-tests/        # Cross-crate integration tests

lfs-adapter/                 # Go: standalone git-lfs Batch API → xet-server bridge
                             # (the reference shape for GitLab/Gitea integration)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for request flows, trait surface, storage layout, and protocol notes.
See [lfs-adapter/README.md](lfs-adapter/README.md) for the LFS bridge.

## Development

Install the [pre-commit](https://pre-commit.com) framework once (`brew install pre-commit` or `pipx install pre-commit`), then in this repo run:

```bash
pre-commit install
```

That wires up `.pre-commit-config.yaml`, which on every commit runs `cargo fmt --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## License

Apache-2.0.
