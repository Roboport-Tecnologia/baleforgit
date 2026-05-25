# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

- **`docs/ARCHITECTURE.md`** — read this before making non-trivial changes. It covers the three pluggable traits (`BlobStore`, `MetadataStore`, `RepoAuthz`), upload/download/global-dedup flows, the wire surface, storage layout, auth flow, the native `git-dfs` filter, and a "Tricky bits" section calling out the parts of the Xet protocol that are easy to get wrong (hex encoding, `url_range` end-inclusivity, signed-URL Range matching, idempotency, shard magic tag).
- **`docs/DFS_FORGE_PROTOCOL.md`** — the contract a git forge has to implement to support `git-dfs`: an HTTPS `/info/dfs/authenticate` endpoint, an SSH `git-dfs-authenticate` command, and a `POST /check_access` callback consumed by `xet-server-authz-http`. Read before touching the `git-dfs` auth resolver or `HttpAuthz`.
- **Milestones (M1–M12)** are all done. M1–M6 are the server itself; M7 drives real `git-xet`; M8 swaps in alternate trait impls; M9/M10 add real-LFS push/pull through the Go adapter; M11 is the native `git-dfs` filter; M12 is the per-repo scope check on reconstruction. Each has a `crates/xet-server-tests/tests/m<N>_*.rs` integration test.
- **`crates/git-dfs/`** — native Git filter (`filter.dfs.process`). Replaces the LFS adapter for repos that don't need git-lfs compatibility. Pretty-printed JSON pointer with stable key order (`hash`, `file_size`, `sha256`), shared chunk cache (`~/.cache/dfs/chunks` by default), per-repo manifest cache (`.git/dfs/manifests/`), no `.git/lfs/objects/`. Auto-resolves `server_url` + token from `origin` via the forge protocol (HTTPS Basic via `git credential fill`, or SSH `git-dfs-authenticate`); falls back to `dfs.serverUrl` + `dfs.token` from local git config when both are set. Drives the m11 integration test. Depends on `xet-core/` (a sibling clone of `huggingface/xet-core`) via path deps; `xet-core/`, `git-lfs/`, and `lfs-adapter/` are all `exclude`d from this workspace via the root `Cargo.toml`.
- **`lfs-adapter/README.md`** — **legacy** Go LFS-to-Xet bridge. Retained for users on git-lfs; new repos should use `git-dfs install` instead. Drives the m9 (push) and m10 (pull) integration tests.
- **`git-lfs/`** — sibling clone of the official git-lfs Go source, used purely as a *reference* when working on `git-dfs`. The Go code is not compiled by us. Useful references: `lfs/pointer.go`, `git/filter_process_scanner.go`, `commands/command_install.go`, `commands/command_track.go`.

## Common commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p xet-server-tests --test m4_download_roundtrip          # one integration test file
cargo test -p xet-server-tests --test m5_auth_flow -- forged_jwt     # one named test
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The pre-commit hook (`.pre-commit-config.yaml`) runs `cargo fmt --check` and the clippy command above with `-D warnings`. **Both must pass before declaring a code task done** — run them yourself, don't wait for the user's commit to find out.

Running the binary needs two hex secrets and either `XET_GRANTS` (static dev authz) or `XET_AUTHZ_HTTP_URL` (delegate to an upstream `/check_access`); see `README.md` "Quick start".

## Test conventions

- Integration tests live in `crates/xet-server-tests/tests/m*.rs`, one file per milestone. Most drive the axum router via `tower::ServiceExt::oneshot` — no real HTTP server.
- `m7_git_xet.rs` is the exception: it binds the router to an ephemeral TCP port via `tokio::net::TcpListener` + `axum::serve` and spawns the real `git-xet transfer` subprocess. It **skips with an eprintln** when `git-xet` isn't on PATH, so don't be surprised if it's a no-op on a clean machine.
- `m8_pluggability.rs` drives the same `tower::oneshot` flow as M3–M6 but wired to the alternate trait impls (`MemBlobStore` + `HttpAuthz`). The HTTP-backed `RepoAuthz` makes real outbound HTTP calls to an in-process mock upstream via `reqwest`, so this test does need a working network stack (loopback only).
- `m9_real_lfs_push.rs` and `m10_real_lfs_pull.rs` share scaffolding via `tests/common/mod.rs` (a `mod common;` submodule — Cargo only treats top-level files in `tests/` as test binaries). Both build the Go adapter at `lfs-adapter/` via `go build`, spawn it as a subprocess, and drive real git/git-lfs against it. **Both skip silently** if any of `{go, git, git-lfs, git-xet}` isn't on PATH. Push uses `git lfs push --all` (not `git push`) because git-xet rejects `file://` remotes; the http(s) remote URL doesn't need to be reachable since refs never get pushed. Pull uses `git lfs pull` after wiping `.git/lfs/objects/` and the worktree file so bytes must come from the server.
- `m11_native_filter.rs` builds `crates/git-dfs` via `cargo build -p git-dfs` at test setup and invokes it via the absolute path written into `filter.dfs.process` in the local git config. **Skips silently** if `git` or `cargo` isn't on PATH. The test drives `git add` (which Git fans out to a long-running `git-dfs filter-process` subprocess), commits, wipes the worktree file, the shared chunk cache, *and* `.git/dfs/manifests/` and does `git checkout --` to force a cold smudge that must round-trip to the server; then repeats the wipe-and-smudge without touching the manifests/chunks directories to assert the hot path makes zero `/v1/reconstructions/*` calls. Asserts the staged blob is a JSON pointer (not the original bytes) and that `.git/lfs/` does not exist.
- `m12_repo_scope.rs` covers the reconstruction scope check end-to-end: same content registered in two repos, cross-repo dedup at the chunk layer, and the 404-vs-403 distinction on miss. Drives the same `tower::oneshot` flow as the other M3–M6 tests.
- Adapter subprocess stdout/stderr is forwarded to the test's stderr (`[adapter stdout] …`, `[adapter stderr] …`), so when an m9/m10 assertion fails the captured output makes the adapter-side error visible without needing `--nocapture` or a manual rerun.
- SQLite tests use `:memory:` via `SqliteMetadataStore::open_path(":memory:")`.
- Filesystem tests use `tempfile::tempdir().keep()`. Do NOT use `into_path` — it's deprecated and clippy will reject it under `-D warnings`.

## Engineering guidelines

- **Comments earn their place.** Prefer self-explanatory code. Only add a comment for the non-obvious *why* — a hidden constraint, a workaround, a load-bearing invariant, an interaction with the wire protocol. No paragraphs, no docstrings that restate the function signature, no "this function does X" headers. Recent commits ("Trim comments a bit", "Optimize comments") deliberately deleted a lot of noise; don't reintroduce it.
- **Update the docs in the same change.** Any change that touches a trait signature, a wire endpoint, an env var, the storage schema, the auth flow, or a "Tricky bits" item must update `docs/ARCHITECTURE.md`, `docs/DFS_FORGE_PROTOCOL.md`, `lfs-adapter/README.md`, `README.md`, and/or this file as appropriate. Stale docs are worse than no docs.
- **Treat user data as load-bearing.** This system is a primary store for large binary artifacts — corruption is not recoverable from git history. Be paranoid about:
  - **Consistency** — writes that span the blob store and the metadata store must remain correct under partial failure. Prefer content-addressed idempotency (re-upload returns success) over locks. When persisting on the filesystem, write to `tmp/` then `rename(2)`. Never leave a half-written xorb or shard visible.
  - **Concurrency** — handlers are `async` and the router is shared across requests. Don't assume serialised access. Verify that two concurrent uploads of the same content, two concurrent reconstructions of the same file, or an upload racing a dedup query all converge to a consistent state.
  - **Security** — the M12 scope check is load-bearing; don't relax it (404, not 403, on cross-repo probes). Signed transfer URLs must enforce the `Range` match and use constant-time signature compare. Never log JWTs, hub bearers, or signing keys. New endpoints default to *inside* the auth middleware; opting out is a deliberate decision that needs justification in the code.
- **Avoid crashes.** No `unwrap` / `expect` / `panic!` / `unreachable!` on inputs that can come from the network, the filesystem, env vars, or another process. Use `?` with a typed error (`CoreError`, `ApiError`, `anyhow::Error` at binary edges). `expect` is only acceptable for invariants the compiler can't prove but the surrounding code does — leave a one-line comment saying why it can't fail. A server crash kills every in-flight request; a returned error doesn't.

## Don't "fix" these without being asked

`Range:`-on-request support on `/v1/reconstructions/*` is intentionally absent — the prototype always returns the full file's terms. The native `git-dfs` smudge handler passes `0..file_size` (not `FileRange::full()`) when calling `xet-data` to avoid tripping the prefetcher; don't "simplify" that range cap without reading the comment in `crates/git-dfs/src/filter_process.rs`.
