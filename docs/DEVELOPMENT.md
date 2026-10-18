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

GitHub Actions workflows live under `.github/workflows/`. Releases are driven by
a label-gated PR, never a bare tag push:

- **`build.yml`** — a reusable workflow (`workflow_call`) that does the actual
  compilation. Takes a `version` string and builds across the release matrix:
  `x86_64`/`aarch64-unknown-linux-musl` (static, native runners), `x86_64`/
  `aarch64-apple-darwin` (native), and `x86_64-pc-windows-gnu` (cross-compiled
  with [`cross`](https://github.com/cross-rs/cross)). Linux/macOS ship both
  binaries; Windows ships `git-bale` only. Each component is packaged on its own
  as `bale-server-<version>-<suffix>` / `bale-client-<version>-<suffix>`, where
  `<suffix>` is a friendly target name like `x86_64-linux-musl`, `aarch64-macos`,
  or `x86_64-windows`. Packaging differs per OS: **Linux** → `.tar.gz` with a
  `VERSION.txt`; **macOS** → a `.pkg` that installs the binary to
  `/usr/local/bin`, codesigned (hardened runtime; `git-bale` gets the
  library-validation opt-out for its dlopened FUSE dylib), notarized, and
  stapled when the `MACOS_CERT_*` / `AC_API_*` secrets are set (otherwise an
  unsigned `.pkg`); **Windows** → `.zip` with a `VERSION.txt`. The Build step
  exports `BALE_GIT_SHA` (short commit) and `SOURCE_DATE_EPOCH` (commit time) so
  each crate's `build.rs` bakes commit + reproducible date + target triple into
  the binary — surfaced by `git-bale --version` and `baleforgit-server --version`
  (and logged at server startup). `Cross.toml` forwards both into the `cross`
  container for the Windows build. Locally, `build.rs` falls back to `git`.
- **`release-prep.yml`** — manual (`workflow_dispatch`) with a `version` input.
  Validates the version, bumps `[workspace.package].version`, refreshes
  `Cargo.lock`, regenerates `CHANGELOG.md` via [git-cliff](https://git-cliff.org),
  and opens a `release`-labelled PR (branch `release/v<version>`). Nothing is
  tagged or published yet — review the PR, then merge it.
- **`release.yml`** — on a **merged** PR carrying the `release` label, reads the
  version from `Cargo.toml`, creates and pushes the `v<version>` tag, calls
  `build.yml`, generates `SHA256SUMS`, mints a [SLSA Build Provenance v1](https://slsa.dev/spec/v1.0/provenance)
  attestation (`actions/attest-build-provenance`, verifiable with
  `gh attestation verify`), generates and attests an SPDX SBOM
  (`anchore/sbom-action` + `actions/attest-sbom`), signs `SHA256SUMS` with
  cosign keyless (`SHA256SUMS.sig`/`.pem`), and publishes the GitHub release
  with git-cliff notes.
- **`edge.yml`** — manual (`workflow_dispatch`). Builds the current `main` via
  `build.yml` with version `edge`, force-moves the `edge` tag, and publishes (or
  updates) a single rolling **prerelease** with the same checksums, provenance,
  SBOM, and cosign signature.

`ci.yml` (fmt / clippy / e2e harness) runs on pushes and PRs to `main`, and via
`workflow_dispatch`. No container image is published — build one locally from
`Dockerfile` if you want one (see [`docs/SERVER.md`](SERVER.md)). The macOS
`.pkg` flow needs **both** a Developer ID Application and a Developer ID
Installer certificate in the `MACOS_CERT_P12` secret (plus the App Store Connect
API key in `AC_API_*`); the build fails fast if the installer cert is missing
rather than shipping something that can't be notarized.
