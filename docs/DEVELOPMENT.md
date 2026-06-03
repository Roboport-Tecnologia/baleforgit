# Development

This document covers building, testing, and shipping the project. For consumer docs, see the top-level [`README.md`](../README.md).

## Toolchain

Rust 1.94+.

## Common commands

```bash
cargo build --workspace
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Behavior is verified end-to-end only — there are no Rust unit or integration tests. See [Out-of-band full e2e harness](#out-of-band-full-e2e-harness) below.

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
├── bale-server-meta-postgres/# MetadataStore on Postgres (BALE_POSTGRES_URL)
├── bale-server-authz-mem/    # In-memory RepoAuthz (AlwaysAllow, ConfigAuthz)
├── bale-server-authz-http/   # RepoAuthz that delegates check_repo_access to an HTTP upstream
├── bale-server-tokens/       # HS256 Xet JWT mint/verify
├── bale-server-http/         # Axum router, handlers, middleware
├── bale-server-bin/          # The `baleforgit-server` binary
└── git-bale/                 # Native Git filter (filter.bale.process driver)
```

`git-bale` depends on `xet-data`, `xet-client`, `xet-core-structures`, and `xet-runtime` from crates.io, pinned to `=1.5.2`. The sibling `xet-core/` clone is a source reference only — the workspace `Cargo.toml` `exclude`s it from `cargo build --workspace`.

## Tests

There are **no Rust unit or integration tests**. `cargo test --workspace` builds clean but runs nothing. Behavior is verified purely from the user's perspective by the e2e harness described below — prove behavior changes there, not with `#[cfg(test)]` modules.

## Out-of-band full e2e harness

`tests/e2e/run.py` is a Python harness that exercises the release `git-bale` binary against a podman container bundling `baleforgit-server` + `openssh-server`. It runs end-to-end over real SSH (both git push/clone and the Bale forge-auth handshake), covers the user-facing operations (stage / unstage / stash / pop / commit / push / clone) on a 35 MB binary with two slight modifications, verifies the `/v1/usage/...` API numbers agree with on-disk storage, and includes adversarial cases (wrong token, tampered xorb on disk, quota exceeded, and `upload-guards`: direct-HTTP negative tests of the upload-time xorb integrity gate, the signed transfer-URL guards, and write-scope enforcement). Prints a per-phase timing + throughput summary at the end.

It is **not** invoked by `cargo test --workspace` — run it explicitly, and only after producing a release binary:

```bash
cargo build --release -p git-bale
python3 tests/e2e/run.py
```

The harness exits 77 when the environment can't host it (no podman daemon, no release binary, etc.), so CI can distinguish "skipped" from "failed". See [`tests/e2e/README.md`](../tests/e2e/README.md) for full prereqs, flags, and the phase list.

## CI and release artifacts

GitHub Actions workflows live under `.github/workflows/`:

- **`ci.yml`** — on every push to `main` and every PR, runs `cargo fmt --check`, `cargo clippy -D warnings`, and the `tests/e2e/run.py` harness (after `cargo build --release -p git-bale`). Relies on `git` and `podman` being preinstalled on `ubuntu-latest`, so the harness runs end-to-end rather than skipping.
- **`release.yml`** — on a `v*` tag push, builds the `baleforgit-server` and `git-bale` binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`, then creates a GitHub release with one `.tar.gz` per binary per target (each paired with its own `.sha256`) attached. Each tarball is also signed via [GitHub artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) — `actions/attest-build-provenance` mints an unforgeable [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance) statement, signed by Sigstore, recorded in the public transparency log, and reachable from the GitHub Attestations API.
- **`docker.yml`** — on a push to `main` or a `v*` tag, builds a multi-arch (`linux/amd64`, `linux/arm64`) image from `Dockerfile` and pushes it to `ghcr.io/<owner>/<repo>` with `branch`, `sha-<short>`, semver, and `latest` tags as appropriate. Same SLSA Build Provenance is generated and pushed alongside the image as an OCI referrer, so `gh attestation verify oci://…` and `cosign verify-attestation` both find it.

All three workflows are also runnable manually from the Actions tab via **Run workflow** (`workflow_dispatch`):

- `ci.yml` takes no inputs — useful for re-running the test matrix on demand.
- `release.yml` takes a `tag` input (default `v0.0.0-test`); the release is created as a **draft prerelease**, which means the git tag is *not* materialized in the repo until you click Publish on the resulting draft. Re-dispatching with the same tag overwrites the prior draft so you don't accumulate test releases. Delete the draft when done and nothing is left behind. Attestations are still minted normally.
- `docker.yml` takes a `tag` input (default `test`); the image is pushed with that tag *and* the usual `sha-<short>` tag, so you can pull `ghcr.io/<owner>/<repo>:test` to try a manual build without touching the `:latest` tag.
