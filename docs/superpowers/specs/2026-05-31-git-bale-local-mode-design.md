# git-bale fully-local (no-server) mode — design

**Date:** 2026-05-31
**Status:** Approved, pending implementation plan

## Problem

`git-bale` today requires a Bale CAS server: `git add` chunks files offline into a
transient staging area, but the data only becomes durable once `git-bale push-pending`
(the pre-push hook) uploads it to a server, and `gc` treats the server as the
source of truth (it hides remote-tracking refs and only keeps objects referenced by
*unpushed* commits). There is no way to use `git-bale` purely locally, with the
chunked big-file data persisted on the machine and no server in the loop.

This feature adds an explicit **fully-local mode**: chunked object data lives in a
durable on-disk store (default per-repo under `.git/bale/store`, optionally a shared
store across all repos on the machine, default `~/bale-local`), reconstruction reads
straight from that store, and push/pull never contact a server for big-file data.

## Goals

- A repo can be put into fully-local mode explicitly; nothing about it is automatic.
- `git add` / commit / checkout / stash / clone-on-the-same-machine of big files all
  work with **no server** running.
- Object data is **durable** — it is the only copy. It must never live in the volatile
  chunk cache (`~/.cache/bale/chunks`), and `gc` must never delete the only copy of a
  file's data.
- Optional shared store (`~/bale-local`) gives cross-repo dedup.
- Maximal reuse of the existing offline clean path and "lukewarm" smudge path; no new
  CAS storage format.

## Non-goals (v1)

- **Same-machine clone portability for the per-repo store.** `git clone /path/to/repo
  dest` does not carry `.git/bale/store`; `dest` cannot reconstruct its big files.
  Documented limitation; use `--shared` for multiple working copies. No clone-copy
  logic is built in v1.
- **Cross-repo refcounting** for the shared store. The shared store is append-only;
  reclamation is a manual `git-bale prune --shared` that scans all registered repos.
- **Auto-fallback to local when a server is unreachable.** Mode is always explicit, so
  a misconfigured/unreachable server never silently writes load-bearing data to a
  different place.
- Mixing modes in one repo (local store *and* a server). Local mode is standalone.

## Decisions (resolved during brainstorming)

1. **Default store location:** per-repo, under `.git/bale/store`. The shared store is
   opt-in; when chosen its default path is `~/bale-local`.
2. **Activation:** explicit, via a setup command. No auto-detection.
3. **Per-repo gc policy:** keep any object reachable from any local ref, the index, or
   a stash. No remote-tracking-ref hiding, no "pushed" concept. Delete only
   truly-orphaned objects.
4. **Shared-store reclamation:** append-only. Auto-gc never deletes shared objects; a
   manual `git-bale prune --shared` walks every registered repo before deleting.

## Architecture

The store is an xet-data `LocalClient` directory — the **same layout** the staging area
already uses (`xet/xorbs/xorbs/default.<hex>`, `xet/xorbs/shards/<hex>.mdb`, plus the
`file-index/<file_hex>` sidecar markers). Local mode does not invent a new format; it
makes that directory durable and points the existing clean/smudge/gc code at it.

A single place resolves *mode* and *store path*, so the rest of the code branches
cleanly instead of sprinkling `if local` checks.

### Components

**`config.rs` — mode & store resolution.**
`RawConfig` / `BaleConfig` gain:
- `local_mode: bool` — from `BALE_LOCAL` env or `bale.local` git config.
- `store_root: PathBuf` — from `BALE_LOCAL_STORE` / `bale.localStore`; default
  `<git_dir>/bale/store`. A shared store is this key pointed at `~/bale-local` (or any
  path).

A helper `store_root(cfg) -> PathBuf` returns the durable store in local mode, else the
existing transient `staging_root(git_dir)`. The volatile chunk cache is untouched and
keeps acting as a pure perf layer.

In local mode, smudge/clean **never resolve forge auth** and never need `server_url` /
`token`.

**`init-local` — setup command** (new subcommand on the clap surface).
`git-bale init-local [--store <path>] [--shared [<path>]]`:
1. Installs the `bale` filter + the gc hooks (`post-checkout`/`post-commit`/
   `post-merge`) into local git config, reusing `install` machinery with
   `Scope::Local`.
2. Sets `bale.local true`.
3. Sets `bale.localStore` to the resolved store path (`.git/bale/store` by default;
   `~/bale-local` for `--shared` with no explicit path; `<path>` if given).
4. **Does not** install the pre-push drain hook (nothing to drain).
5. For `--shared`: registers this repo in the shared store's registry (§ Shared store).

Dedicated subcommand name (`init-local`, not `install --local`) avoids colliding with
the existing `install --local`, which means "write to the *local git config* scope."

**Clean (`git add`)** — `filter_process::do_clean` / `handle_clean[_in_memory]`.
Unchanged except the target directory comes from `store_root(cfg)` rather than a
hardcoded `staging_root`. xet-data's `LocalClient` already writes xorbs/shards
atomically (tmp + rename) and is content-addressed, so concurrent or repeated
`git add` of identical content converges idempotently. The `file-index/<file_hex>`
marker is still written; in local mode it persists (never drained) and is the per-file
record gc reconciles against.

**Smudge (checkout/clone)** — `filter_process::handle_smudge`.
In local mode the path is: hot path (manifest cache + chunk cache) → reconstruct from
`store_root` via `FileDownloadSession` + `TranslatorConfig::local_config`. **There is
no cold/network path and no auth resolution.** Reconstruction output is verified to be
exactly `file_size` bytes; a missing object or size mismatch is a **hard error** — never
a silent short/empty worktree file. Server-mode smudge is unchanged (hot → lukewarm
staging → cold network).

**`push_pending`** — a no-op in local mode (objects are already durable). `git push` to
a git remote still works for the small pointer commits; only big-file data stays
machine-local.

**`gc.rs` — per-repo reclamation (local mode).**
Compute the live set by walking *all* local refs + the index + stashes and collecting
the bale-pointer file-hashes they reference — **without** hiding remote-tracking refs
and **without** any "pushed" gate. Keep markers/objects for live hashes; sweep objects
referenced by nothing (e.g. an abandoned `git add` followed by `git reset`). Operates on
`store_root`. Shared objects are deduped across files, so per-file deletion stays gated
on "no marker references this hash" exactly as today.

**Shared store — registry & `prune --shared`.**
- Registry: `<store>/repos/` containing one file per registered repo (filename = a hash
  of the repo's git-dir path; body = the absolute git-dir path). Written by
  `init-local --shared`.
- In shared mode, auto-`gc` is **append-only**: it forgets only *this repo's* markers
  and never deletes shared objects.
- `git-bale prune --shared`: read the registry, walk each registered repo's reachability
  (refs + index + stash), union the live file-hashes, and delete store objects
  referenced by none. Safety: hold a lockfile at the shared store for the duration;
  **skip and warn** on registered repos whose path is missing (a moved/unmounted repo
  must not cause deletion of its objects); **skip objects modified within a short recent
  window** to avoid racing a concurrent `git add`. Prune is manual and intended to run
  when repos are idle.

## Data flow

```
git add big.bin
  └─ clean: CDC + xorb/shard → store_root(cfg)  (durable; no upload)
            write file-index/<file_hex> marker
            write pointer to git index

git commit / git push (git remote)
  └─ pointer blobs travel via git as usual; push-pending is a no-op (local mode)

git checkout / git clone (same machine, --shared)
  └─ smudge: hot (manifest+chunk cache) → reconstruct from store_root
             verify size == file_size; missing/short ⇒ hard error

git reset (abandon a staged add) → post-checkout/commit/merge hook
  └─ gc: walk all local refs+index+stash; object referenced by nothing ⇒ swept
         (shared store: only this repo's markers forgotten; objects kept)

git-bale prune --shared   (manual)
  └─ union live hashes across all registered repos; delete unreferenced objects
```

## Error handling

- Missing/short reconstruction in local mode → hard error from smudge (no silent data).
- Store path unwritable / unreadable → typed error, surfaced per-request as
  `status=error` on the filter protocol (does not tear down filter-process).
- `prune --shared` with a missing registered repo → skip + warn, never delete on its
  behalf.
- All network/filesystem/env inputs use `?` with typed errors; no new
  `unwrap`/`expect`/`panic` on external input (project rule).

## Testing

No Rust tests (project convention). New `tests/e2e/run.py` phases, all with **no server
container**:

- `local-basic` — `init-local`; add + commit a big file; fresh checkout reconstructs
  byte-for-byte with no server.
- `local-shared-dedup` — two repos sharing one `~/bale-local`; assert on-disk object
  count reflects cross-repo dedup.
- `local-gc-abandon` — `git add` then `git reset`; gc sweeps the orphaned object;
  a still-referenced object survives.
- `local-prune-shared` — `prune --shared` deletes an orphan but keeps an object still
  referenced by a second registered repo; missing registered repo is skipped (warned),
  not acted on.

## Docs to update in the same change

- `docs/ARCHITECTURE.md` — local mode, store layout vs staging, the mode/store
  resolution, gc policy differences, `prune --shared`.
- `README.md` — `git-bale init-local` quick start, `--shared`, the clone-portability
  limitation.
- `CLAUDE.md` — local-mode summary in the `crates/git-bale/` and tests sections.
- `tests/e2e/README.md` — the new no-server phases.

## Open questions / follow-ups (out of scope for v1)

- Same-machine clone portability for the per-repo store (copy `.git/bale/store`, or have
  a clone read its local-path `origin`'s store).
- Cross-repo refcounting to make shared-store reclamation automatic.
