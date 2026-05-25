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

crates/
└── git-dfs/                  # Native Git filter — bypasses LFS entirely.
                              #   `git-dfs install` registers the `dfs` filter
                              #   driver; `git-dfs track '*.bin'` enables it
                              #   for matching paths. Pointers are pretty-
                              #   printed JSON; chunks live in a shared
                              #   user-global cache (`~/.cache/dfs/chunks` by
                              #   default, overridable via `dfs.cacheDir` or
                              #   `DFS_CACHE_DIR`).

lfs-adapter/                 # Go: standalone git-lfs Batch API → xet-server bridge
                             # (legacy path; retained for users on git-lfs)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for request flows, trait surface, storage layout, and protocol notes.
See [lfs-adapter/README.md](lfs-adapter/README.md) for the legacy LFS bridge.

## Using the native filter (`git-dfs`)

The LFS path (M9 / M10 above) stores a whole-file copy of every tracked blob in
`.git/lfs/objects/` — git-lfs's design forces this and it defeats Xet's
chunk-level dedup locally. The `git-dfs` filter is the newer, dedup-preserving
path:

```bash
cargo build -p git-dfs
# put target/debug on PATH, or use absolute paths below

git init my-repo && cd my-repo
git config --local dfs.serverUrl http://127.0.0.1:8080
git config --local dfs.token "<a Xet JWT>"
git-dfs install --local
git-dfs track '*.bin'
git add .gitattributes && git commit -m 'enable dfs'
# now any *.bin you add is chunked, uploaded, and replaced with a JSON pointer
```

Local layout after a `git add` + `git checkout`:

```
my-repo/big.bin              # worktree (one copy)
~/.cache/dfs/chunks/         # shared chunk pool (deduped across files & repos)
                             # No .git/lfs/objects/. No second whole-file copy.
```

## Development

Install the [pre-commit](https://pre-commit.com) framework once (`brew install pre-commit` or `pipx install pre-commit`), then in this repo run:

```bash
pre-commit install
```

That wires up `.pre-commit-config.yaml`, which on every commit runs `cargo fmt --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## License

Apache-2.0.
