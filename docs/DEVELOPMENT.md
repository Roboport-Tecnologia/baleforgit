# Development

Building, testing and releasing. User docs are in [`README.md`](../README.md).

## Toolchain and checks

Rust 1.94+ (`rust-version` in the workspace `Cargo.toml`) builds the workspace; the Docker images build on 1.94. Development and CI use the exact toolchain pinned in `rust-toolchain.toml` (rustup installs it on first use) so local clippy matches CI. To upgrade, bump it there and in every `dtolnay/rust-toolchain@<version>` in `.github/workflows/`, then fix any new lints.

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The [pre-commit](https://pre-commit.com) hook (`.pre-commit-config.yaml`) runs the fmt check and clippy with `-D warnings`; both must pass. Install pre-commit once (`brew install pre-commit` or `pipx install pre-commit`), then run `pre-commit install` in the repo.

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
├── bale-server-meta-common/  # Row decoders + conversions shared by the SQLite and Postgres stores
├── bale-server-authz-mem/    # In-memory RepoAuthz (AlwaysAllow, ConfigAuthz)
├── bale-server-authz-http/   # RepoAuthz that delegates check_repo_access to an HTTP upstream
├── bale-server-tokens/       # HS256 Bale-token (JWT) mint/verify
├── bale-server-http/         # Axum router, handlers, middleware
├── bale-server-bin/          # The `baleforgit-server` binary
├── git-bale/                 # Native Git filter (filter.bale.process driver)
└── bale-e2e-tools/           # Test-only: crafts xorbs/shards with xet's hashing for the e2e harness
```

`git-bale` depends on `xet-data`, `xet-client`, `xet-core-structures` and `xet-runtime` from crates.io, pinned to `=1.5.2` (on-disk shard format). A local `xet-core/` clone, if present, is a gitignored source reference only; the workspace `Cargo.toml` `exclude`s it.

`Dockerfile` builds the server image (see [`SERVER.md`](SERVER.md#container)). `Dockerfile.musl` and `Dockerfile.windows` are local podman cross-build recipes for the static Linux binaries and `git-bale.exe`; CI doesn't use them.

## Tests

There are **no Rust unit or integration tests** — `cargo test --workspace` builds clean but runs nothing. Behavior is verified from the user's side by the e2e harness in `tests/e2e/`; prove behavior changes there, not with `#[cfg(test)]` modules. The harness drives the prebuilt release binaries over real SSH against a podman container running `baleforgit-server` + `openssh-server`, including adversarial, race and no-server fully-local phases:

```bash
cargo build --release -p git-bale -p bale-e2e-tools   # the harness doesn't build them
python3 tests/e2e/run.py                  # fs blob store + SQLite
python3 tests/e2e/run.py --backend s3     # whole suite on an S3 (MinIO) blob store
python3 tests/e2e/run.py --meta postgres  # whole suite on Postgres metadata (composes with --backend s3)
```

It exits 77 when the environment can't host it (no podman, no release binary). Prereqs, flags and the phase list are in [`tests/e2e/README.md`](../tests/e2e/README.md).

## CI and release artifacts

Workflows live in `.github/workflows/`. Releases go through a reviewed PR, never a bare tag push.

- **`ci.yml`** — fmt, clippy and the e2e harness (default backends) on pushes and PRs to `main`, and on `workflow_dispatch`.
- **`build.yml`** — reusable (`workflow_call`, input `version`); does the compilation. Matrix: `x86_64`/`aarch64-unknown-linux-musl` (static, native runners), `x86_64`/`aarch64-apple-darwin` (native), and `x86_64-pc-windows-gnu` (cross-compiled with [`cross`](https://github.com/cross-rs/cross); client only). Each component is packaged separately as `bale-server-<version>-<suffix>` / `bale-client-<version>-<suffix>`, where `<suffix>` is `x86_64-linux-musl`, `aarch64-linux-musl`, `x86_64-macos`, `aarch64-macos` or `x86_64-windows`:
  - **Linux** → `.tar.gz` with a `VERSION.txt`.
  - **macOS** → a `.pkg` installing to `/usr/local/bin`. When `MACOS_CERT_P12` is set, binaries are codesigned with the hardened runtime (`git-bale` gets the library-validation opt-out in `packaging/macos/git-bale.entitlements` for its dlopened FUSE dylib), the `.pkg` is signed with the Developer ID Installer identity from `MACOS_INSTALLER_CERT_P12`, then notarized (`AC_API_*`) and stapled. The build fails fast if either identity is missing. Without `MACOS_CERT_P12` everything ships unsigned.
  - **Windows** → `.zip` with a `VERSION.txt`.

  The build exports `BALE_GIT_SHA` and `SOURCE_DATE_EPOCH` (commit time), which each binary's `build.rs` bakes into `--version` along with the target triple (`Cross.toml` forwards both into the `cross` container; locally `build.rs` falls back to `git`).
- **`release-prep.yml`** — manual (`workflow_dispatch`, input `version`). Validates the version, bumps `[workspace.package].version`, refreshes `Cargo.lock`, regenerates `CHANGELOG.md` with [git-cliff](https://git-cliff.org), and pushes branch `release/v<version>`; the run summary links to open the PR with suggested notes. Review and merge it.
- **`release.yml`** — on a **merged** PR labelled `release` or whose branch starts with `release/v`: reads the version from `Cargo.toml`, tags and pushes `v<version>`, calls `build.yml`, writes `SHA256SUMS`, attests SLSA build provenance (`actions/attest-build-provenance`) and an SPDX SBOM (`anchore/sbom-action` + `actions/attest-sbom`) for every `bale-*` artifact, signs `SHA256SUMS` with cosign keyless (`SHA256SUMS.cosign.bundle`), and publishes the GitHub release with git-cliff notes. Verification: [`SERVER.md` § Verifying release artifacts](SERVER.md#verifying-release-artifacts).
- **`edge.yml`** — manual. Builds `main` with version `edge`, force-moves the `edge` tag, and publishes (or updates) a rolling **prerelease** with the same checksums, attestations and signature.

No container image is published.
