# Development

This document covers building, testing, and shipping the project. For consumer docs, see the top-level [`README.md`](../README.md).

## Toolchain

Rust 1.88+. The Go LFS adapter (legacy path, exercised by `m9`/`m10`) needs a Go toolchain when you want those tests to run instead of skip.

## Common commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p bale-server-tests --test m4_download_roundtrip          # one integration test file
cargo test -p bale-server-tests --test m5_auth_flow -- forged_jwt     # one named test
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The pre-commit hook (`.pre-commit-config.yaml`) runs `cargo fmt --check` and the clippy command above with `-D warnings`. **Both must pass before declaring a code task done.**

Install [pre-commit](https://pre-commit.com) once (`brew install pre-commit` or `pipx install pre-commit`), then in this repo:

```bash
pre-commit install
```

## Repo layout

```
crates/
├── bale-server-core/         # Trait definitions + domain types
├── bale-server-wire/         # JSON shapes + Xet hash hex encoding
├── bale-server-shard/        # MDB shard binary parser + xorb chunk-frame parser
├── bale-server-storage-fs/   # BlobStore on the local filesystem
├── bale-server-storage-mem/  # BlobStore in memory (test / pluggability check)
├── bale-server-storage-s3/   # BlobStore on any S3-compatible API (real presigned URLs)
├── bale-server-meta-sqlite/  # MetadataStore on SQLite
├── bale-server-authz-mem/    # In-memory RepoAuthz (AlwaysAllow, ConfigAuthz)
├── bale-server-authz-http/   # RepoAuthz that delegates check_repo_access to an HTTP upstream
├── bale-server-tokens/       # HS256 Xet JWT mint/verify
├── bale-server-http/         # Axum router, handlers, middleware
├── bale-server-bin/          # The `baleforgit-server` binary
├── bale-server-tests/        # Cross-crate integration tests (m2..m12)
└── git-bale/                 # Native Git filter — bypasses LFS entirely

lfs-adapter/                 # Go: standalone git-lfs Batch API → baleforgit-server bridge.
                             # Legacy path; retained for users on git-lfs.
```

The workspace `Cargo.toml` `exclude`s sibling clones of `xet-core/`, `git-lfs/`, and `lfs-adapter/` from `cargo build --workspace`. `git-bale` depends on `xet-core/` via path deps; the legacy LFS bridge is built by its own `go build` from inside `lfs-adapter/`.

## Test conventions

- Integration tests live in `crates/bale-server-tests/tests/m*.rs`, one file per milestone. Most drive the axum router via `tower::ServiceExt::oneshot` — no real HTTP server.
- `m7_git_xet.rs` is the exception: it binds the router to an ephemeral TCP port via `tokio::net::TcpListener` + `axum::serve` and spawns the real `git-xet transfer` subprocess. It **skips with an eprintln** when `git-xet` isn't on PATH, so don't be surprised if it's a no-op on a clean machine.
- `m8_pluggability.rs` drives the same `tower::oneshot` flow as M3–M6 but wired to the alternate trait impls (`MemBlobStore` + `HttpAuthz`). The HTTP-backed `RepoAuthz` makes real outbound HTTP calls to an in-process mock upstream via `reqwest`, so this test does need a working network stack (loopback only).
- `m9_real_lfs_push.rs` and `m10_real_lfs_pull.rs` share scaffolding via `tests/common/mod.rs` (a `mod common;` submodule — Cargo only treats top-level files in `tests/` as test binaries). Both build the Go adapter at `lfs-adapter/` via `go build`, spawn it as a subprocess, and drive real git/git-lfs against it. **Both skip silently** if any of `{go, git, git-lfs, git-xet}` isn't on PATH. Push uses `git lfs push --all` (not `git push`) because git-xet rejects `file://` remotes; the http(s) remote URL doesn't need to be reachable since refs never get pushed. Pull uses `git lfs pull` after wiping `.git/lfs/objects/` and the worktree file so bytes must come from the server.
- `m11_native_filter.rs` builds `crates/git-bale` via `cargo build -p git-bale` at test setup and invokes it via the absolute path written into `filter.bale.process` in the local git config. **Skips silently** if `git` or `cargo` isn't on PATH, *or* if the build itself fails (defensive — keeps a transient cargo failure from masquerading as a real product bug). The test drives `git add` (which Git fans out to a long-running `git-bale filter-process` subprocess), commits, wipes the worktree file, the shared chunk cache, *and* `.git/bale/manifests/` and does `git checkout --` to force a cold smudge that must round-trip to the server; then repeats the wipe-and-smudge without touching the manifests/chunks directories to assert the hot path makes zero `/v1/reconstructions/*` calls. Asserts the staged blob is a JSON pointer (not the original bytes) and that `.git/lfs/` does not exist.
- `m12_repo_scope.rs` covers the reconstruction scope check end-to-end: same content registered in two repos, cross-repo dedup at the chunk layer, and the 404-vs-403 distinction on miss. Drives the same `tower::oneshot` flow as the other M3–M6 tests.
- `crates/bale-server-storage-s3/tests/minio.rs` drives `S3BlobStore` end-to-end against a MinIO container launched via `podman run --rm -d`. Marked `#[ignore]` so `cargo test --workspace` doesn't pull a ~100 MiB image — invoke with `cargo test -p bale-server-storage-s3 --test minio -- --ignored` (also how CI runs it). Probes `podman info` (not just `podman --version`) so it skips when the macOS `podman machine` VM is stopped instead of hanging on `podman run`. Covers idempotent puts, NotFound on missing xorbs, presigned-GET fetched over the wire, and verifies S3 rejects a presigned URL replayed with a different `Range:` header (the property the reconstruction handler relies on).
- Adapter subprocess stdout/stderr is forwarded to the test's stderr (`[adapter stdout] …`, `[adapter stderr] …`), so when an m9/m10 assertion fails the captured output makes the adapter-side error visible without needing `--nocapture` or a manual rerun.
- SQLite tests use `:memory:` via `SqliteMetadataStore::open_path(":memory:")`.
- Filesystem tests use `tempfile::tempdir().keep()`. Do NOT use `into_path` — it's deprecated and clippy will reject it under `-D warnings`.

## CI and release artifacts

GitHub Actions workflows live under `.github/workflows/`:

- **`ci.yml`** — on every push to `main` and every PR, runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test --workspace`, then the `#[ignore]`d MinIO integration test (`cargo test -p bale-server-storage-s3 --test minio -- --ignored`). The test job installs `git-xet` from upstream releases (`GIT_XET_VERSION` env at the top of the job) and relies on `git`, `git-lfs`, `go`, and `podman` being preinstalled on `ubuntu-latest`, so m7/m9/m10/m11 and the S3 path all run end-to-end rather than skipping.
- **`release.yml`** — on a `v*` tag push, builds the `baleforgit-server` and `git-bale` binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`, then creates a GitHub release with one `.tar.gz` per binary per target (each paired with its own `.sha256`) attached. Each tarball is also signed via [GitHub artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) — `actions/attest-build-provenance` mints an unforgeable [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance) statement, signed by Sigstore, recorded in the public transparency log, and reachable from the GitHub Attestations API.
- **`docker.yml`** — on a push to `main` or a `v*` tag, builds a multi-arch (`linux/amd64`, `linux/arm64`) image from `Dockerfile` and pushes it to `ghcr.io/<owner>/<repo>` with `branch`, `sha-<short>`, semver, and `latest` tags as appropriate. Same SLSA Build Provenance is generated and pushed alongside the image as an OCI referrer, so `gh attestation verify oci://…` and `cosign verify-attestation` both find it.

All three workflows are also runnable manually from the Actions tab via **Run workflow** (`workflow_dispatch`):

- `ci.yml` takes no inputs — useful for re-running the test matrix on demand.
- `release.yml` takes a `tag` input (default `v0.0.0-test`); the release is created as a **draft prerelease**, which means the git tag is *not* materialized in the repo until you click Publish on the resulting draft. Re-dispatching with the same tag overwrites the prior draft so you don't accumulate test releases. Delete the draft when done and nothing is left behind. Attestations are still minted normally.
- `docker.yml` takes a `tag` input (default `test`); the image is pushed with that tag *and* the usual `sha-<short>` tag, so you can pull `ghcr.io/<owner>/<repo>:test` to try a manual build without touching the `:latest` tag.
