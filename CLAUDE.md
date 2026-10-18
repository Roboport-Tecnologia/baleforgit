# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Prime directives

- data corruption is not allowed ever
- data races are not allowed ever
- race conditions are not allowed ever
- every feature or implementation plan should take into account data corruption and race risks
- after every feature implemented the code should be audited for data corruption and race risks
- this is not a v1, this is production, no data loss ever

## Start here

- **`docs/ARCHITECTURE.md`** — read before any non-trivial change. Traits (`BlobStore`, `MetadataStore`, `RepoAuthz`), upload/download/dedup flows, wire surface, storage layout, auth, quotas, observability, the whole `git-bale` client (clean/smudge, pointer cache, push-pending, gc, fully-local mode, store lock, auth resolution, mounts), and **"Tricky bits"**.
- **`docs/BALE_FORGE_PROTOCOL.md`** — what a forge implements (`/info/bale/authenticate`, SSH `git-bale-authenticate`, `POST /check_access`). Read before touching `resolver.rs` or `HttpAuthz`.
- **`tests/e2e/README.md`** — the harness and every phase. Read its **Design** section before changing the harness, its `Dockerfile`/`entrypoint.sh`, or any wire bit it depends on (scp-style URL parser, JSON pointer shape, `BALE_GRANTS` format, `/v1/usage` response shape, `clean-cache` schema).
- `docs/SERVER.md` (ops + env vars), `docs/DEVELOPMENT.md` (layout, CI, releases), `docs/STATUS.md` (what's shipped). `xet-core/` is a source-reference clone only — not in the build graph (root `Cargo.toml` `exclude`s it).

## git-bale invariants that are easy to break

Each is load-bearing for "no data loss" and is detailed in `docs/ARCHITECTURE.md` § "Native filter: `git-bale`". Re-read the relevant section before touching it.

- **Clean is offline** and only ever *adds* to staging / the local store. Objects are the only copy until pushed (forever in local mode): new xorbs/shards are fsynced and referenced xorbs validated *before* the marker is written; all bookkeeping writes go through `fs_util::write_durable`.
- **All `.git/bale/` state keys on the common git dir** (`store::common_git_dir`) so linked worktrees share one inventory.
- **Every smudge path verifies size + sha256** before `status=success`; bad bytes never reach the worktree or the clean-cache. Cold path runs under the no-progress watchdog (`BALE_DOWNLOAD_STALL_SECS`).
- **push-pending** uploads only what the pushed ref delta advertises (plus staged content the target already references), re-cleans through an online session so server dedup + `/shards` registration under the *push target's* repo happen, and auths against the push target (`resolve_for_remote`), not `origin`.
- **gc liveness = git's liveness** (all refs incl. remote-tracking, all reflogs, every worktree's HEAD/index, stopped rebase/merge/autostash state), fails closed on any error, skips while a git op is in flight, respects the reclaim grace (`BALE_GC_GRACE_SECS`), and invalidates clean-cache entries for every hash it drops. Remote-tracking reachability is not proof of upload.
- **Store lock** is taken per file by clean (never for the filter-process lifetime — that deadlocks); the marker-vs-index window is closed by the `*.lock` in-flight check plus the grace, not by the lock.
- **Local stores**: only `init-local` creates one; non-shared stores are owned (`.bale-owner`), shared ones are append-only and reclaimed only by `prune --shared`; a crashed prune swap makes everything refuse rather than recreate an empty store.
- **Auth**: a lone `bale.serverUrl` or `bale.token` is ignored (never send a static token to a forge-discovered server); cleartext `http://` is refused for non-loopback https/ssh remotes; ssh honors `GIT_SSH_COMMAND`/`core.sshCommand`.

## Common commands

```bash
cargo build --workspace
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Behavior is verified end-to-end only — there are no Rust tests.
cargo build --release -p git-bale -p bale-e2e-tools   # the harness drives these prebuilt binaries
python3 tests/e2e/run.py                  # full harness (needs podman)
python3 tests/e2e/run.py --backend s3     # whole suite on an S3/MinIO blob store
python3 tests/e2e/run.py --meta postgres  # whole suite on a Postgres metadata store (composes with --backend s3)
```

The pre-commit hook (`.pre-commit-config.yaml`) runs `cargo fmt --check` and the clippy command above with `-D warnings`. **Both must pass before declaring a code task done** — run them yourself, don't wait for the user's commit to find out.

Running the server needs two hex secrets and either `BALE_GRANTS` (static dev authz) or `BALE_AUTHZ_HTTP_URL` (delegate to an upstream `/check_access`); see `docs/SERVER.md`.

## Tests

There are **no Rust unit or integration tests** — `cargo test --workspace` builds clean but runs nothing. Prove behavior changes by extending the e2e harness under `tests/e2e/` (pure-stdlib Python), not by adding `#[cfg(test)]` modules. Server phases live in `tests/e2e/run.py` + `baleharness/`; the no-server fully-local phases (group g3) in `tests/e2e/baleharness/phases/local.py`. Deterministic race phases widen windows with `BALE_TEST_*_DELAY_MS` hooks. Phases that craft xorbs/shards use the test-only `bale-e2e-tools` binary, which shares the server's exact hashing code. When adding a phase, list it in `tests/e2e/README.md`.

## Engineering guidelines

- **Comments earn their place.** Prefer self-explanatory code. Only add a comment for the non-obvious *why* — a hidden constraint, a workaround, a load-bearing invariant, an interaction with the wire protocol. No paragraphs, no docstrings that restate the function signature, no "this function does X" headers. Recent commits ("Trim comments a bit", "Optimize comments") deliberately deleted a lot of noise; don't reintroduce it.
- **Trim comments on every code change.** After writing or editing code, do a dedicated pass over the diff to simplify, trim, or remove comments and docstrings — *before* reporting the task done, not as a follow-up the user has to request. Drop function-shape docstrings, "what" comments that restate code, and section banners inside function bodies. Keep only *why* comments, and tighten the survivors (one line, name the actual failure mode in concrete terms).
- **Update the docs in the same change.** Any change that touches a trait signature, a wire endpoint, an env var, the storage schema, the auth flow, client behavior, or a "Tricky bits" item must update `docs/ARCHITECTURE.md`, `docs/BALE_FORGE_PROTOCOL.md`, `docs/SERVER.md`, `README.md`, and/or `tests/e2e/README.md` as appropriate. Design detail belongs in those docs, not in this file. Stale docs are worse than no docs.
- **Treat user data as load-bearing.** This system is a primary store for large binary artifacts — corruption is not recoverable from git history. Be paranoid about:
  - **Consistency** — writes that span the blob store and the metadata store must remain correct under partial failure. Prefer content-addressed idempotency (re-upload returns success) over locks. When persisting on the filesystem, write to `tmp/` then `rename(2)`. Never leave a half-written xorb or shard visible.
  - **Concurrency** — handlers are `async` and the router is shared across requests. Don't assume serialised access. Verify that two concurrent uploads of the same content, two concurrent reconstructions of the same file, or an upload racing a dedup query all converge to a consistent state.
  - **Security** — the per-repo scope check is load-bearing; don't relax it (404, not 403, on cross-repo probes). Signed transfer URLs must enforce the `Range` match and use constant-time signature compare. Never log JWTs, hub bearers, or signing keys. New endpoints default to *inside* the auth middleware; opting out is a deliberate decision that needs justification in the code.
- **Avoid crashes.** No `unwrap` / `expect` / `panic!` / `unreachable!` on inputs that can come from the network, the filesystem, env vars, or another process. Use `?` with a typed error (`CoreError`, `ApiError`, `anyhow::Error` at binary edges). `expect` is only acceptable for invariants the compiler can't prove but the surrounding code does — leave a one-line comment saying why it can't fail. A server crash kills every in-flight request; a returned error doesn't.

## Don't "fix" these without being asked

`/v1/reconstructions/*` must keep honoring `Range` (terms overlapping the range + `offset_into_first_range`, 416 past EOF): xet-data fetches every file over 2 × 256 MiB in Range blocks even when asked for `0..file_size`, and the old "always return the full file's terms" behavior made such files unclonable (the `large-file` e2e phase guards it). Don't remove it on the theory that the client's `0..file_size` cap avoids block fetches — it doesn't.

libfuse in `mount/backend/libfuse.rs` (and WinFsp in `mount/backend/winfsp.rs`) is loaded with `libloading` at runtime, not linked at build time. Don't switch either to `extern "C"` linkage or a `-sys`/SDK crate — that would force every developer to install the FS driver (libfuse / the WinFsp SDK) just to build the workspace, even if they never run a mount.

Don't "simplify" the client's dependency choices either: git access stays on `gix` except the deliberate subprocesses (`git credential fill`, `ssh`, `git config` writes, and push-pending's `git cat-file --batch-check` partial-clone fetch), and the `xet-*` crates stay pinned to `=1.5.2` (on-disk shard format).
