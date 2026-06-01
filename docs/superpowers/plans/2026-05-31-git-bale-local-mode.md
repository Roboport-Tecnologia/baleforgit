# git-bale fully-local (no-server) mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a repo store chunk-deduplicated big-file data in a durable on-disk store (per-repo `.git/bale/store` by default, optional shared `~/bale-local`) with no Bale server in the loop for add/commit/checkout/clone.

**Architecture:** Reuse the existing offline clean path and the "lukewarm" staging-reconstruct smudge path. A repo enters local mode explicitly via `git-bale init-local`, which sets `bale.local`/`bale.localStore` and installs the filter + gc hooks but **not** the pre-push drain hook. Object data (xorbs/shards) relocates from the transient staging dir to the configured durable store; per-repo bookkeeping (file-index markers, clean-cache, manifests) stays under `.git/bale/`. Smudge in local mode reconstructs only from the store (no network, no auth) and hard-errors on a miss. gc gains a no-remote-hiding policy for the per-repo store and is a no-op on a shared store, which is reclaimed by a manual `git-bale prune --shared` that compacts the store down to the files reachable across all registered repos.

**Tech Stack:** Rust (clap, gix, anyhow, xet-data/xet-client/xet-runtime `=1.5.2`), Python stdlib e2e harness (`tests/e2e/baleharness`), podman.

---

## Testing model (READ FIRST — overrides the skill's default TDD step)

This repo has **no Rust unit/integration tests** by project rule (`CLAUDE.md`: "Prove behavior changes by extending the e2e harness, not by adding `#[cfg(test)]` modules"). Per the superpowers instruction-priority rule, the user's CLAUDE.md wins over the skill's "write a `#[test]` first" step. So:

- The **test artifact for each behavior is an e2e phase** under `tests/e2e/baleharness/phases/`.
- TDD shape is preserved: write/extend the phase first, run it and watch it fail, implement, watch it pass.
- **Per-task code gates** (run every task that touches Rust):
  - `cargo fmt --all`
  - `cargo build --workspace`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- **Per-phase gate** (run for tasks that add/modify a phase): build the release client once, then iterate the phase:
  - `cargo build --release -p git-bale`
  - `python3 tests/e2e/run.py --state-dir "$HOME/bale-e2e-state" --only <phase> --no-build` (after the first run that builds the image; `--state-dir` must be under `$HOME`/`/Users`, **not** `/tmp` — the podman VM can't mount `/tmp` on macOS).
- The local-mode phases do not need the server, but the harness still starts the shared container; phases just ignore `server`.

Commit after every task (frequent commits). Branch is `feat/local-mode`.

---

## File structure

**Rust (`crates/git-bale/src/`)**
- `store.rs` — **new.** Resolve the object-store root for the current mode; tilde expansion; shared-store registry read/write; small mode predicate helpers. One responsibility: "where do objects live, and who shares them."
- `config.rs` — **modify.** Parse `bale.local` / `bale.localStore` / `bale.localShared` (+ `BALE_LOCAL*` env) into `RawConfig`.
- `main.rs` — **modify.** Add `init-local` and `prune` subcommands.
- `install.rs` — **modify.** `init_local()` setup (filter + gc hooks, no pre-push) and config writes.
- `filter_process.rs` — **modify.** Clean writes to the store root; smudge gets a local-mode branch (store-only, hard error, no auth).
- `push_pending.rs` — **modify.** No-op in local mode.
- `gc.rs` — **modify.** Local per-repo policy (no remote hiding, all dead = orphaned); no-op on a shared store.
- `prune.rs` — **new.** `git-bale prune --shared`: compact the shared store to the union of live files across all registered repos.

**Python e2e (`tests/e2e/baleharness/`)**
- `repo.py` — **modify.** Add `init_repo_local(...)` (no server remote; runs `git-bale init-local`).
- `storage.py` — **modify.** Add `local_store_objects(store_dir)` and reuse `staged_markers`.
- `config.py` — **modify.** Add local-mode repo-name / payload constants.
- `phases/local.py` — **new.** `phase_local_basic`, `phase_local_shared_dedup`, `phase_local_gc_abandon`, `phase_local_prune_shared`.
- `cli.py` — **modify.** Import + register the four phases (group `g3`).

**Docs**
- `docs/ARCHITECTURE.md`, `README.md`, `CLAUDE.md`, `tests/e2e/README.md` — **modify** (Task 10).

---

## Conventions used below

- `git_dir` = `.git` for a normal repo (gix resolves it).
- Marker bookkeeping stays under `.git/bale/staging/file-index/` **in every mode** (it is per-repo; a shared object store must not hold one repo's markers). Only xorbs/shards relocate to the store root. This is the load-bearing decision that keeps a shared store safe.
- "store root" = the dir handed to `TranslatorConfig::local_config(...)`. Server mode: `.git/bale/staging` (unchanged). Local per-repo: `.git/bale/store`. Local shared: e.g. `~/bale-local`.

---

## Task 1: Config — parse local-mode keys

**Files:**
- Modify: `crates/git-bale/src/config.rs`

- [ ] **Step 1: Add fields to `RawConfig`**

In `crates/git-bale/src/config.rs`, extend the struct (after `git_dir`):

```rust
#[derive(Clone, Debug)]
pub struct RawConfig {
    pub server_url: Option<String>,
    pub token: Option<String>,
    pub token_expiration: Option<u64>,
    pub cache_dir: PathBuf,
    pub git_dir: Option<PathBuf>,
    /// Fully-local (no-server) mode: `bale.local` / `BALE_LOCAL`.
    pub local_mode: bool,
    /// Configured durable object store (`bale.localStore` / `BALE_LOCAL_STORE`),
    /// tilde-expanded. `None` means "use the per-repo default" — resolved lazily
    /// by `store::object_store_root` so a missing git_dir is a per-call error,
    /// not a load() failure.
    pub local_store: Option<PathBuf>,
    /// `bale.localShared` / `BALE_LOCAL_SHARED`: the store is shared across
    /// repos, so gc must not delete objects (see `prune`).
    pub local_shared: bool,
}
```

- [ ] **Step 2: Populate them in `RawConfig::load`**

Inside `load`, after `token_expiration` is computed and before the `Ok(Self { ... })`, add:

```rust
        let local_mode = bool_from("BALE_LOCAL", snapshot.as_ref(), "bale.local");
        let local_shared = bool_from("BALE_LOCAL_SHARED", snapshot.as_ref(), "bale.localShared");
        let local_store = env_or_cfg("BALE_LOCAL_STORE", snapshot.as_ref(), "bale.localStore")
            .map(|s| expand_tilde(&s));
```

Add `local_mode`, `local_store`, `local_shared` to the returned `Self { ... }`.

- [ ] **Step 3: Add the helpers**

At the bottom of `config.rs`:

```rust
fn bool_from(env_key: &str, snapshot: Option<&gix::config::Snapshot<'_>>, key: &str) -> bool {
    match env_or_cfg(env_key, snapshot, key) {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => false,
    }
}

/// Expand a leading `~` to the home dir. Leaves the path unchanged if there is
/// no home (the caller will surface a clear error when it can't be created).
pub fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/").or_else(|| (s == "~").then_some("")) {
        if let Some(home) = home_dir() {
            return if rest.is_empty() { home } else { home.join(rest) };
        }
    }
    PathBuf::from(s)
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env::var_os("USERPROFILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
}
```

- [ ] **Step 4: Build + lint**

Run:
```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS (fields unused for now is fine — they're `pub`).

- [ ] **Step 5: Commit**

```bash
git add crates/git-bale/src/config.rs
git commit -m "config: parse bale.local / localStore / localShared"
```

---

## Task 2: `store.rs` — resolve the object store root + shared registry

**Files:**
- Create: `crates/git-bale/src/store.rs`
- Modify: `crates/git-bale/src/lib.rs` (add `pub mod store;`)

- [ ] **Step 1: Create `crates/git-bale/src/store.rs`**

```rust
//! Where chunk-deduplicated objects (xorbs/shards) live, and who shares them.
//!
//! Server mode: the transient per-repo staging dir (`.git/bale/staging`),
//! drained by `git-bale push-pending`. Local mode: a durable store —
//! `.git/bale/store` per-repo by default, or a shared dir (e.g. `~/bale-local`)
//! used by every repo on the machine.
//!
//! Per-repo bookkeeping (file-index markers, clean-cache, manifests) always
//! stays under `.git/bale/` even when the object store is shared: a shared store
//! must never hold one repo's markers (see `crate::gc` / `crate::prune`).

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::config::RawConfig;
use crate::staging::staging_root;

/// Per-repo default store when `bale.localStore` is unset.
pub fn default_local_store(git_dir: &Path) -> PathBuf {
    git_dir.join("bale").join("store")
}

/// The dir handed to `TranslatorConfig::local_config`. Server mode → staging;
/// local mode → configured store (or per-repo default). Errors only when local
/// mode has no resolvable git dir and no explicit store path.
pub fn object_store_root(raw: &RawConfig) -> Result<PathBuf> {
    if raw.local_mode {
        if let Some(p) = &raw.local_store {
            return Ok(p.clone());
        }
        let git_dir = raw
            .git_dir
            .as_deref()
            .ok_or_else(|| anyhow!("local mode needs a git repo or an explicit bale.localStore"))?;
        Ok(default_local_store(git_dir))
    } else {
        let git_dir = raw
            .git_dir
            .as_deref()
            .ok_or_else(|| anyhow!("no git directory resolved from cwd"))?;
        Ok(staging_root(git_dir))
    }
}

/// Directory of per-repo registration files for a shared store. Each file is
/// named by a stable hash of the repo's git-dir path; its body is that absolute
/// path. `prune --shared` walks these.
pub fn registry_dir(store_root: &Path) -> PathBuf {
    store_root.join("repos")
}

/// Register `git_dir` (absolute) as a user of the shared store. Idempotent.
pub fn register_repo(store_root: &Path, git_dir: &Path) -> Result<()> {
    let dir = registry_dir(store_root);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating shared-store registry {}", dir.display()))?;
    let abs = std::fs::canonicalize(git_dir)
        .with_context(|| format!("canonicalizing git dir {}", git_dir.display()))?;
    let name = registry_key(&abs);
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(abs.to_string_lossy().as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(name))?;
    Ok(())
}

/// Every git-dir path currently registered against `store_root`.
pub fn registered_repos(store_root: &Path) -> Result<Vec<PathBuf>> {
    let dir = registry_dir(store_root);
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context(format!("reading registry {}", dir.display())),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue; // skip half-written tmp files
        }
        let body = std::fs::read_to_string(entry.path())?;
        let p = body.trim();
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Lowercase-hex BLAKE3 of the path bytes — collision-free filename for a path
/// that may contain `/` or non-portable chars.
fn registry_key(abs: &Path) -> String {
    blake3::hash(abs.to_string_lossy().as_bytes()).to_hex().to_string()
}
```

- [ ] **Step 2: Confirm `blake3` is available**

Run:
```bash
grep -n '^blake3' crates/git-bale/Cargo.toml || grep -rn 'blake3::' crates/git-bale/src | head
```
Expected: a hit (the clean-cache already uses blake3). If `blake3` is not a direct dependency, add `blake3 = "1"` under `[dependencies]` in `crates/git-bale/Cargo.toml`.

- [ ] **Step 3: Register the module**

In `crates/git-bale/src/lib.rs` add `pub mod store;` in alphabetical position (after `pub mod staging;`).

- [ ] **Step 4: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/git-bale/src/store.rs crates/git-bale/src/lib.rs crates/git-bale/Cargo.toml
git commit -m "store: object-store-root resolution + shared-store registry"
```

---

## Task 3: `init-local` setup (install + main wiring)

**Files:**
- Modify: `crates/git-bale/src/install.rs`
- Modify: `crates/git-bale/src/main.rs`

- [ ] **Step 1: Add `init_local` to `install.rs`**

Add this function (after `install`), reusing the existing `install_managed_hook`, `set_config`, `GC_HOOKS`:

```rust
/// Put the repo at `repo` (or cwd) into fully-local mode: register the filter,
/// install only the gc hooks (no pre-push drain — nothing to drain), and write
/// `bale.local* ` config. `store` is the resolved, tilde-expanded store path;
/// `shared` marks it as a cross-repo store.
pub fn init_local(repo: Option<&Path>, store: &Path, shared: bool) -> Result<()> {
    set_config(Scope::Local, repo, "process", PROCESS_VALUE)?;
    set_config(Scope::Local, repo, "required", "true")?;
    set_config(Scope::Local, repo, "local", "true")?;
    set_config(Scope::Local, repo, "localStore", &store.to_string_lossy())?;
    if shared {
        set_config(Scope::Local, repo, "localShared", "true")?;
    }
    for hook in GC_HOOKS {
        install_managed_hook(
            repo,
            hook,
            "git-bale gc || true",
            "Reclaim local-store objects for bale files that were unstaged or discarded.",
            OnConflict::Skip,
        )?;
    }
    Ok(())
}
```

Note: `set_config`'s key is `filter.bale.<key>`, so these land as `filter.bale.local` etc. **The config reader in Task 1 looks up `bale.local`, not `filter.bale.local`.** Fix the mismatch now: in `install.rs`, add a helper that writes a bare `bale.*` key, and use it for the three local keys:

```rust
fn set_bale_config(scope: Scope, repo: Option<&Path>, key: &str, value: &str) -> Result<()> {
    let full_key = format!("bale.{key}");
    let out = run_git_config(scope, repo, &[&full_key, value])?;
    if !out.status.success() {
        return Err(anyhow!(
            "git config {} {full_key} {value} failed: {}",
            scope_flag(scope),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
```

Then in `init_local` replace the three `set_config(Scope::Local, repo, "local", ...)` / `"localStore"` / `"localShared"` calls with `set_bale_config(scope, repo, "local"/"localStore"/"localShared", ...)`. Keep `process` and `required` on `set_config` (those are genuinely `filter.bale.*`).

- [ ] **Step 2: Wire the subcommand in `main.rs`**

Add to the `Command` enum:

```rust
    /// Put this repo into fully-local (no-server) mode: durable object store on
    /// disk, no server required. See `--shared` for a cross-repo store.
    InitLocal(InitLocalArgs),
    /// Reclaim a shared local store (delete objects no registered repo
    /// references). Only meaningful with `--shared`.
    Prune(PruneArgs),
```

Add the arg structs:

```rust
#[derive(Args, Debug)]
struct InitLocalArgs {
    /// Object store directory. Default: `.git/bale/store` (per-repo), or
    /// `~/bale-local` when `--shared` is given with no path.
    #[arg(long)]
    store: Option<PathBuf>,
    /// Share one store across all local repos. With no `--store`, defaults to
    /// `~/bale-local`. Registers this repo for `git-bale prune --shared`.
    #[arg(long)]
    shared: bool,
}

#[derive(Args, Debug)]
struct PruneArgs {
    /// Reclaim the shared store (required — per-repo stores are reclaimed by gc).
    #[arg(long)]
    shared: bool,
    /// Proceed even if a registered repo's path is missing (its objects may be
    /// deleted). Default: abort, to avoid deleting another repo's only copy.
    #[arg(long)]
    force: bool,
}
```

Add match arms in `main()`:

```rust
        Command::InitLocal(a) => {
            let cwd = std::env::current_dir()?;
            let store = git_bale::store::resolve_init_store(&cwd, a.store.as_deref(), a.shared)?;
            install::init_local(Some(cwd.as_path()), &store, a.shared)?;
            if a.shared {
                let git_dir = git_bale::store::repo_git_dir(&cwd)?;
                git_bale::store::register_repo(&store, &git_dir)?;
            }
            println!(
                "git-bale local mode enabled (store: {}{})",
                store.display(),
                if a.shared { ", shared" } else { "" }
            );
            Ok(())
        }
        Command::Prune(a) => {
            if !a.shared {
                anyhow::bail!("`git-bale prune` currently only supports --shared");
            }
            git_bale::prune::run(a.force)
        }
```

- [ ] **Step 3: Add the two store helpers used above**

In `store.rs`:

```rust
/// Resolve the store path for `git-bale init-local`, tilde-expanded and made
/// absolute. `explicit` wins; else `~/bale-local` for `--shared`, else the
/// per-repo default.
pub fn resolve_init_store(cwd: &Path, explicit: Option<&Path>, shared: bool) -> Result<PathBuf> {
    if let Some(p) = explicit {
        let expanded = crate::config::expand_tilde(&p.to_string_lossy());
        return absolutize(cwd, &expanded);
    }
    if shared {
        let home = crate::config::expand_tilde("~");
        if home == Path::new("~") {
            return Err(anyhow!("cannot resolve ~ for default shared store; pass --store"));
        }
        return Ok(home.join("bale-local"));
    }
    Ok(default_local_store(&repo_git_dir(cwd)?))
}

pub fn repo_git_dir(cwd: &Path) -> Result<PathBuf> {
    let repo = gix::discover(cwd).with_context(|| format!("opening repo at {}", cwd.display()))?;
    Ok(repo.git_dir().to_path_buf())
}

fn absolutize(cwd: &Path, p: &Path) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(cwd.join(p))
    }
}
```

Add `pub mod prune;` to `lib.rs` now (the module is created in Task 8; add a stub so this task builds). Create `crates/git-bale/src/prune.rs` with a stub:

```rust
//! `git-bale prune --shared` — see Task 8.
use anyhow::Result;
pub fn run(_force: bool) -> Result<()> {
    anyhow::bail!("prune --shared not yet implemented")
}
```

- [ ] **Step 4: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS.

- [ ] **Step 5: Manual smoke test**

```bash
tmp=$(mktemp -d "$HOME/bale-smoke.XXXX"); git -C "$tmp" init -q
( cd "$tmp" && cargo run -q -p git-bale -- init-local )
git -C "$tmp" config --local --get bale.local        # → true
git -C "$tmp" config --local --get bale.localStore    # → <tmp>/.git/bale/store
test -f "$tmp/.git/hooks/post-checkout" && echo "gc hook present"
test ! -f "$tmp/.git/hooks/pre-push" && echo "no pre-push (correct)"
rm -rf "$tmp"
```
Expected: prints `true`, the store path, `gc hook present`, `no pre-push (correct)`.

- [ ] **Step 6: Commit**

```bash
git add crates/git-bale/src/install.rs crates/git-bale/src/main.rs crates/git-bale/src/store.rs crates/git-bale/src/prune.rs crates/git-bale/src/lib.rs
git commit -m "init-local subcommand + prune stub wiring"
```

---

## Task 4: Clean writes to the store root

**Files:**
- Modify: `crates/git-bale/src/filter_process.rs`

- [ ] **Step 1: Resolve the store root once in `do_clean`**

In `do_clean`, replace the `git_dir` extraction block so the store root comes from `store::object_store_root`. Find:

```rust
    let git_dir = raw.git_dir.as_deref().ok_or_else(|| {
        anyhow!("clean: cannot stage upload — no git directory resolved from cwd")
    })?;
    let cache_key = clean_cache::path_key(pathname);
```

Replace with:

```rust
    let git_dir = raw.git_dir.as_deref().ok_or_else(|| {
        anyhow!("clean: cannot stage upload — no git directory resolved from cwd")
    })?;
    let store = crate::store::object_store_root(raw).context("resolving object store root")?;
    let cache_key = clean_cache::path_key(pathname);
```

- [ ] **Step 2: Thread `store` into the two clean handlers**

Change the calls at the bottom of `do_clean`:

```rust
    let rt = ensure_runtime(rt_slot)?;
    match payload {
        CleanPayload::InMemory(buf) => {
            handle_clean_in_memory(rt, git_dir, &store, buf, writer, pathname, &cache_key, file_size)
        }
        CleanPayload::Spilled(tmp) => {
            handle_clean(rt, git_dir, &store, tmp, writer, pathname, &cache_key, file_size)
        }
    }
```

Update both signatures to take `store: &Path` after `git_dir: &Path`, and inside each replace:

```rust
    crate::fs_util::create_bale_subdir(git_dir, "staging")
        .with_context(|| format!("creating staging dir under {}", git_dir.display()))?;
    let staging = staging_root(git_dir);
    let translator =
        TranslatorConfig::local_config(&staging).context("building local TranslatorConfig")?;
```

with:

```rust
    // Markers stay per-repo under .git/bale/staging/file-index even when the
    // object store is shared; only xorbs/shards go to `store`.
    crate::fs_util::create_bale_subdir(git_dir, "staging")
        .with_context(|| format!("creating staging dir under {}", git_dir.display()))?;
    std::fs::create_dir_all(store)
        .with_context(|| format!("creating object store {}", store.display()))?;
    let translator =
        TranslatorConfig::local_config(store).context("building local TranslatorConfig")?;
```

(The `mark_file_staged(git_dir, ...)` calls stay unchanged — markers remain per-repo.)

- [ ] **Step 3: Drop the now-unused `staging_root` import if clean was its only user**

Keep the import — smudge still uses `staging_root` (Task 5 keeps it for the server lukewarm path). Verify with the build.

- [ ] **Step 4: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/git-bale/src/filter_process.rs
git commit -m "clean: write objects to the resolved store root"
```

---

## Task 5: Smudge — local-mode store reconstruction (no network, hard error)

**Files:**
- Modify: `crates/git-bale/src/filter_process.rs`

- [ ] **Step 1: Generalize `try_smudge_from_staging` to any store path**

Rename it and parameterize the store dir. Replace the function:

```rust
fn try_smudge_from_staging(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    info: &xet_data::processing::XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<bool> {
    let Some(git_dir) = raw.git_dir.as_deref() else {
        return Ok(false);
    };
    let staging = staging_root(git_dir);
    ...
```

with:

```rust
fn try_smudge_from_store(
    rt: &Arc<XetRuntime>,
    store: &Path,
    info: &xet_data::processing::XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<bool> {
    if !store.exists() {
        return Ok(false);
    }
    let translator =
        TranslatorConfig::local_config(store).context("building local TranslatorConfig")?;
    let dest_file = tmp.reopen()?;
    let info_for_dl = info.clone();
    rt.bridge_sync(async move {
        let session = FileDownloadSession::new(Arc::new(translator), None).await?;
        let (_id, _n) = session
            .download_to_writer(&info_for_dl, 0..file_size, dest_file)
            .await?;
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
    Ok(true)
}
```

- [ ] **Step 2: Update the server-mode lukewarm caller**

Find the `staging_hit` block and change the call:

```rust
        match try_smudge_from_staging(rt, raw, &info, file_size, &tmp) {
```
to
```rust
        match try_smudge_from_store(rt, &staging_root(gd_for_staging), &info, file_size, &tmp) {
```

To get `gd_for_staging`, adjust the surrounding `is_some_and(|gd| file_is_staged(gd, ...))` block to capture the git_dir. Replace the whole `staging_hit` let-binding with:

```rust
    // Lukewarm path (server mode only): bytes still staged locally, not yet
    // pushed. Gated on the per-file marker (see staging::mark_file_staged).
    let staging_hit = if !cache_hit
        && !raw.local_mode
        && raw
            .git_dir
            .as_deref()
            .is_some_and(|gd| file_is_staged(gd, &file_id_hex))
    {
        let gd = raw.git_dir.as_deref().unwrap();
        match try_smudge_from_store(rt, &staging_root(gd), &info, file_size, &tmp) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::debug!("staging reconstruction failed for {file_id_hex}: {e:#}");
                false
            }
        }
    } else {
        false
    };
```

- [ ] **Step 3: Add the local-mode branch before the cold path**

Immediately after the `staging_hit` block and **before** `if !cache_hit && !staging_hit {` (the cold path), insert a local-mode short-circuit:

```rust
    // Local mode: reconstruct only from the durable store. No network, no auth,
    // no silent fallback — a miss or short read is a hard error.
    if raw.local_mode && !cache_hit {
        let store = crate::store::object_store_root(raw).context("resolving object store root")?;
        // Reset any partial bytes from a failed hot-path attempt.
        let mut trunc = tmp.reopen()?;
        trunc.set_len(0)?;
        std::io::Seek::seek(&mut trunc, std::io::SeekFrom::Start(0))?;
        drop(trunc);

        let ok = try_smudge_from_store(rt, &store, &info, file_size, &tmp)
            .with_context(|| format!("reconstructing {file_id_hex} from local store"))?;
        let written = std::fs::metadata(tmp.path()).map(|m| m.len()).unwrap_or(0);
        if !ok || written != file_size {
            return Err(anyhow!(
                "local store at {} cannot reconstruct {} ({} of {} bytes); the object \
                 data is missing — was this repo copied without its store, or the store pruned?",
                store.display(),
                file_id_hex,
                written,
                file_size
            ));
        }
        if let Some(git_dir) = raw.git_dir.as_deref() {
            populate_clean_cache_from_smudge(git_dir, pathname, tmp.path(), &pointer_buf, file_size);
        }
        return finish_smudge(writer, tmp.path());
    }
```

(The existing cold-path block already begins with `if !cache_hit && !staging_hit {`; in local mode we return before reaching it, so it never resolves auth.)

- [ ] **Step 4: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS. (If `Path` is not imported in scope, it already is — `use std::path::Path;` is at the top.)

- [ ] **Step 5: Commit**

```bash
git add crates/git-bale/src/filter_process.rs
git commit -m "smudge: local-mode store-only reconstruction with hard error on miss"
```

---

## Task 6: push-pending is a no-op in local mode

**Files:**
- Modify: `crates/git-bale/src/push_pending.rs`

- [ ] **Step 1: Early-return in local mode**

In `push_pending::run`, right after `let raw = RawConfig::load(...)?;`, add:

```rust
    if raw.local_mode {
        // Objects are already durable in the local store; nothing to upload.
        tracing::debug!("git-bale push-pending: local mode, nothing to drain");
        return Ok(());
    }
```

(`init-local` doesn't install a pre-push hook, so this is belt-and-suspenders for a user who runs it by hand or kept a server-mode hook.)

- [ ] **Step 2: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/git-bale/src/push_pending.rs
git commit -m "push-pending: no-op in local mode"
```

---

## Task 7: e2e harness plumbing + `local-basic` phase

**Files:**
- Modify: `tests/e2e/baleharness/config.py`
- Modify: `tests/e2e/baleharness/repo.py`
- Modify: `tests/e2e/baleharness/storage.py`
- Create: `tests/e2e/baleharness/phases/local.py`
- Modify: `tests/e2e/baleharness/cli.py`

- [ ] **Step 1: Constants**

In `tests/e2e/baleharness/config.py`, add near the other `E2E_REPO*` / `*_BYTES` constants:

```python
LOCAL_PAYLOAD_BYTES = 6 * 1024 * 1024  # big enough to chunk into several xorbs
```

- [ ] **Step 2: `init_repo_local` helper**

In `tests/e2e/baleharness/repo.py`, add (mirroring `init_repo_for_push` but with no server remote and `init-local` instead of `install --local`):

```python
def init_repo_local(
    *,
    work_root: Path,
    client: ClientEnv,
    name: str,
    shared_store: Path | None = None,
    track_glob: str = "*.bin",
) -> tuple[Path, dict]:
    """Init a working repo in fully-local mode. No server remote is configured.
    With `shared_store`, all such repos point at one store dir."""
    work = work_root / name
    work.mkdir(parents=True)
    env = client.make_env(work)
    run(["git", "init", "-q"], cwd=work, env=env)
    run(["git", "config", "user.email", "e2e@example.com"], cwd=work, env=env)
    run(["git", "config", "user.name", "e2e"], cwd=work, env=env)
    cmd = [str(client.git_bale_bin), "init-local"]
    if shared_store is not None:
        cmd += ["--shared", "--store", str(shared_store)]
    run(cmd, cwd=work, env=env)
    run([str(client.git_bale_bin), "track", track_glob], cwd=work, env=env)
    run(["git", "add", ".gitattributes"], cwd=work, env=env)
    run(["git", "commit", "-m", "track"], cwd=work, env=env)
    return work, env
```

Check the actual `make_env` signature in `repo.py`/`client.py` and match it; if `make_env` injects `BALE_SERVER_URL`, ensure local repos still work (local mode ignores it — smudge never reaches the cold path). If a server URL would interfere, pop it: `env.pop("BALE_SERVER_URL", None)` before returning.

- [ ] **Step 3: Store-inspection helper**

In `tests/e2e/baleharness/storage.py`, add:

```python
def local_store_objects(store_dir: Path) -> list[Path]:
    """xorbs/shards under an arbitrary local store dir (per-repo or shared)."""
    if not store_dir.exists():
        return []
    out: list[Path] = []
    for cur, _dirs, files in os.walk(store_dir):
        for f in files:
            is_xorb = f.startswith("default.") and _is_64_lower_hex(f[len("default.") :])
            is_shard = f.endswith(".mdb") and _is_64_lower_hex(f[: -len(".mdb")])
            if is_xorb or is_shard:
                out.append(Path(cur) / f)
    return out


def per_repo_store(repo: Path) -> Path:
    return repo / ".git" / "bale" / "store"
```

- [ ] **Step 4: Write the `local-basic` phase (the failing test)**

Create `tests/e2e/baleharness/phases/local.py`:

```python
"""Fully-local (no-server) mode phases. These never touch `server`."""

from __future__ import annotations

from pathlib import Path

from baleharness.client import ClientEnv
from baleharness.config import LOCAL_PAYLOAD_BYTES
from baleharness.gitutil import git, verify_worktree
from baleharness.logutil import TestFailure, info
from baleharness.payloads import deterministic_payload
from baleharness.proc import run, sha256_bytes
from baleharness.repo import init_repo_local
from baleharness.storage import local_store_objects, per_repo_store, staged_markers
from baleharness.timing import Timings


def phase_local_basic(*, timings: Timings, client: ClientEnv, work_root: Path) -> None:
    """init-local → add + commit a big file → fresh checkout reconstructs it,
    with no server anywhere in the loop."""
    with timings.measure("local-basic"):
        repo, env = init_repo_local(work_root=work_root, client=client, name="local-basic")
        rel = "big.bin"
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-basic")

        (repo / rel).write_bytes(payload)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "add big"], cwd=repo, env=env)

        store = per_repo_store(repo)
        if not local_store_objects(store):
            raise TestFailure("[local-basic] add wrote no objects to .git/bale/store")
        if not staged_markers(repo):
            raise TestFailure("[local-basic] add wrote no file-index marker")

        # Force a real smudge: drop the worktree file + caches, re-checkout.
        (repo / rel).unlink()
        run(["rm", "-rf", str(repo / ".git" / "bale" / "manifests")], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)

        verify_worktree(
            repo, rel,
            expected_sha=sha256_bytes(payload),
            expected_size=len(payload),
            label="local-basic",
        )
        info("[local-basic] reconstructed from .git/bale/store with no server")
```

- [ ] **Step 5: Register the phase in `cli.py`**

In `cli.py`, import it (near the other phase imports):

```python
from baleharness.phases.local import phase_local_basic
```

Add a thunk next to the gc thunks:

```python
        def _phase_local_basic() -> None:
            phase_local_basic(timings=timings, client=client, work_root=work_root)
```

Add to `REGISTRY` in group `g3` (independent — own repo, no server):

```python
            "local-basic": ("g3", False, _phase_local_basic),
```

- [ ] **Step 6: Run it — watch it pass (Tasks 1–6 implement it)**

```bash
cargo build --release -p git-bale
python3 tests/e2e/run.py --state-dir "$HOME/bale-e2e-state" --only local-basic
```
Expected: `[local-basic] reconstructed from .git/bale/store with no server`, phase PASS. (First run builds the image; later iterations may add `--no-build`.)

If it fails because `make_env` forces a server URL into the smudge cold path, apply the `env.pop("BALE_SERVER_URL", None)` fix from Step 2 and re-run.

- [ ] **Step 7: Lint the Python**

```bash
cd tests/e2e && uvx ruff check --fix . && uvx ruff format . && cd -
```

- [ ] **Step 8: Commit**

```bash
git add tests/e2e/baleharness/
git commit -m "e2e: local-basic phase + init_repo_local / store helpers"
```

---

## Task 8: gc local-mode policy + shared store no-op, and `prune --shared`

**Files:**
- Modify: `crates/git-bale/src/gc.rs`
- Replace: `crates/git-bale/src/prune.rs` (real implementation)
- Create: `tests/e2e/baleharness/phases/local.py` additions (`phase_local_gc_abandon`, `phase_local_shared_dedup`, `phase_local_prune_shared`)
- Modify: `tests/e2e/baleharness/cli.py` (register them)

### 8a — gc

- [ ] **Step 1: Branch `reconcile` on mode**

In `gc.rs`, after `let git_dir = repo.git_dir().to_path_buf();`, load config to learn the mode + store:

```rust
    let raw = crate::config::RawConfig::load(Some(start_dir)).unwrap_or_else(|e| {
        tracing::debug!("git-bale gc: config load failed ({e}); assuming server mode");
        // A minimal server-mode RawConfig so the rest of gc behaves as before.
        crate::config::RawConfig {
            server_url: None,
            token: None,
            token_expiration: None,
            cache_dir: PathBuf::from("."),
            git_dir: Some(git_dir.clone()),
            local_mode: false,
            local_store: None,
            local_shared: false,
        }
    });

    // Shared local store: append-only. gc must not delete objects another repo
    // may reference, and markers are the only record of what's in the store, so
    // keep them too. `git-bale prune --shared` reclaims. Just tidy empty dirs.
    if raw.local_mode && raw.local_shared {
        let _ = remove_empty_dirs(&staging_root(&git_dir));
        return Ok(());
    }

    let store = crate::store::object_store_root(&raw).unwrap_or_else(|_| staging_root(&git_dir));
```

(Move the existing `let staging = staging_root(&git_dir);` to be `let staging = staging_root(&git_dir);` for markers, and use `store` for object sweeps below. Keep both.)

- [ ] **Step 2: No remote-hiding when local**

Replace the live-set computation:

```rust
    let (local_tips, remote_tips) = ref_tips(&repo);
    let live = reachable_hashes(&repo, &want, &local_tips, &remote_tips);
```

with:

```rust
    let (local_tips, remote_tips) = ref_tips(&repo);
    // Local mode: the store is the only copy, so liveness = reachable from ANY
    // ref (no remote-tracking hiding) + index. Server mode: hide remotes (the
    // server is the source of truth for already-pushed content).
    let live = if raw.local_mode {
        let mut all = local_tips.clone();
        all.extend(remote_tips.iter().copied());
        reachable_hashes(&repo, &want, &all, &[])
    } else {
        reachable_hashes(&repo, &want, &local_tips, &remote_tips)
    };
```

- [ ] **Step 3: All dead hashes are orphaned in local mode**

Replace the `orphaned` computation:

```rust
    let orphaned: BTreeSet<String> = if remote_tips.is_empty() {
        dead.iter().cloned().collect()
    } else {
        ...
    };
```

with:

```rust
    let orphaned: BTreeSet<String> = if raw.local_mode || remote_tips.is_empty() {
        // No server to fall back to (or no remote at all): every dead hash's
        // bytes exist only in the store we're about to sweep.
        dead.iter().cloned().collect()
    } else {
        let mut all_tips = local_tips;
        all_tips.extend(remote_tips);
        let reachable_anywhere = reachable_hashes(&repo, &want, &all_tips, &[]);
        dead.iter()
            .filter(|h| !reachable_anywhere.contains(*h))
            .cloned()
            .collect()
    };
```

- [ ] **Step 4: Sweep the store, not staging, for objects**

At the end, replace the object sweep target:

```rust
    let remaining = list_staged_files(&git_dir).map(|v| v.len()).unwrap_or(0);
    if remaining == 0 {
        let _ = clear_file_markers(&git_dir);
        if let Err(e) = remove_all_staged_objects(&staging) {
            tracing::warn!("git-bale gc: sweeping staged objects: {e}");
        }
        let _ = remove_empty_dirs(&staging);
    }
```

with (note `&store`):

```rust
    let remaining = list_staged_files(&git_dir).map(|v| v.len()).unwrap_or(0);
    if remaining == 0 {
        let _ = clear_file_markers(&git_dir);
        if let Err(e) = remove_all_staged_objects(&store) {
            tracing::warn!("git-bale gc: sweeping store objects: {e}");
        }
        let _ = remove_empty_dirs(&store);
        if store != staging {
            let _ = remove_empty_dirs(&staging);
        }
    }
```

Add `use std::path::PathBuf;` if not present.

- [ ] **Step 5: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS.

### 8b — prune

- [ ] **Step 6: Implement `prune.rs` (compaction)**

Replace `crates/git-bale/src/prune.rs` with:

```rust
//! `git-bale prune --shared` — reclaim a shared local store by compacting it
//! down to the files reachable across every registered repo.
//!
//! Precise per-xorb CAS sweeping would require parsing xet shards; instead we
//! rebuild the store: reconstruct each live file from the old store and re-clean
//! it into a fresh one (deterministic CDC re-dedups), then atomically swap. This
//! reuses the same local→local round-trip push-pending uses and is obviously
//! correct. Holds a lockfile; aborts if a registered repo is missing (its
//! objects might be the only copy) unless `--force`.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tempfile::NamedTempFile;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::clean_file;
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::pointer;
use crate::staging::list_staged_files;
use crate::store::{self, object_store_root};

pub fn run(force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = RawConfig::load(Some(cwd.as_path()))?;
    if !raw.local_mode || !raw.local_shared {
        bail!("`git-bale prune --shared` must run in a repo using a shared local store");
    }
    let store = object_store_root(&raw)?;

    let lock = LockFile::acquire(&store)?;
    let repos = store::registered_repos(&store)?;
    if repos.is_empty() {
        bail!("no repos registered against {}", store.display());
    }

    // Live file-hashes = union, across all registered repos, of marker hashes
    // reachable from that repo's refs+index. Markers are never gc'd in shared
    // mode, so the union of all repos' markers is the complete candidate set.
    let mut live: BTreeSet<String> = BTreeSet::new();
    let mut want_all: BTreeSet<String> = BTreeSet::new();
    for repo_git_dir in &repos {
        if !repo_git_dir.exists() {
            if force {
                eprintln!(
                    "git-bale prune: registered repo missing, skipping: {}",
                    repo_git_dir.display()
                );
                continue;
            }
            bail!(
                "registered repo {} is missing; its objects might be the only copy. \
                 Re-attach it, deregister it, or pass --force to prune anyway.",
                repo_git_dir.display()
            );
        }
        let markers: BTreeSet<String> = list_staged_files(repo_git_dir)
            .unwrap_or_default()
            .into_iter()
            .map(|(h, _)| h)
            .collect();
        want_all.extend(markers.iter().cloned());
        let reachable = reachable_in_repo(repo_git_dir, &markers)?;
        live.extend(reachable);
    }

    let dead = want_all.difference(&live).count();
    if dead == 0 {
        println!("git-bale prune: nothing to reclaim ({} live files)", live.len());
        return Ok(());
    }

    // Need per-file sizes to reconstruct. Build hash -> size from any repo's marker.
    let sizes = collect_sizes(&repos, &live)?;

    // Compact: rebuild a fresh store containing only `live`.
    let rt = XetRuntime::new().context("starting xet runtime")?;
    let new_store = store.with_file_name(format!(
        "{}.compact.{}",
        store
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("store"),
        std::process::id()
    ));
    std::fs::create_dir_all(&new_store)
        .with_context(|| format!("creating temp store {}", new_store.display()))?;

    let old_cfg = TranslatorConfig::local_config(&store)
        .context("building download config for old store")?;
    let new_cfg = TranslatorConfig::local_config(&new_store)
        .context("building upload config for new store")?;

    let live_sized: Vec<(String, u64)> = live
        .iter()
        .map(|h| {
            let sz = sizes
                .get(h)
                .copied()
                .ok_or_else(|| anyhow!("no size for live file {h}"))?;
            Ok((h.clone(), sz))
        })
        .collect::<Result<_>>()?;

    rt.bridge_sync(async move {
        let dl = FileDownloadSession::new(Arc::new(old_cfg), None).await?;
        let up = FileUploadSession::new(Arc::new(new_cfg)).await?;
        for (file_hex, size) in &live_sized {
            let tmp = NamedTempFile::new().context("temp file for compaction")?;
            let writer = tmp.reopen()?;
            let info = XetFileInfo::new(file_hex.clone(), *size);
            dl.download_to_writer(&info, 0..*size, writer)
                .await
                .with_context(|| format!("reconstructing {file_hex} from old store"))?;
            let (new_info, _m) = clean_file(up.clone(), tmp.path(), Sha256Policy::Compute)
                .await
                .with_context(|| format!("re-cleaning {file_hex} into new store"))?;
            if new_info.hash() != *file_hex {
                bail!(
                    "compaction hash mismatch for {file_hex} (got {}); aborting before swap",
                    new_info.hash()
                );
            }
        }
        up.finalize().await?;
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error during prune: {e:?}"))??;

    // Carry the registry over, then atomic-ish swap: move old aside, new in.
    let new_registry = store::registry_dir(&new_store);
    std::fs::create_dir_all(&new_registry).ok();
    if let Ok(rd) = std::fs::read_dir(store::registry_dir(&store)) {
        for e in rd.flatten() {
            let _ = std::fs::copy(e.path(), new_registry.join(e.file_name()));
        }
    }
    let backup = store.with_file_name(format!(
        "{}.old.{}",
        store.file_name().and_then(|s| s.to_str()).unwrap_or("store"),
        std::process::id()
    ));
    std::fs::rename(&store, &backup)
        .with_context(|| format!("moving old store {} aside", store.display()))?;
    if let Err(e) = std::fs::rename(&new_store, &store) {
        // Roll back so we never leave the store missing.
        let _ = std::fs::rename(&backup, &store);
        return Err(e).context("swapping compacted store into place");
    }
    std::fs::remove_dir_all(&backup).ok();

    drop(lock);
    println!(
        "git-bale prune: reclaimed {dead} unreferenced file(s); {} live remain",
        live.len()
    );
    Ok(())
}

/// hash -> size, read from whichever registered repo has a sized marker for it.
fn collect_sizes(
    repos: &[std::path::PathBuf],
    live: &BTreeSet<String>,
) -> Result<std::collections::HashMap<String, u64>> {
    let mut sizes = std::collections::HashMap::new();
    for repo_git_dir in repos {
        if !repo_git_dir.exists() {
            continue;
        }
        for (h, sz) in list_staged_files(repo_git_dir).unwrap_or_default() {
            if let Some(sz) = sz {
                if live.contains(&h) {
                    sizes.entry(h).or_insert(sz);
                }
            }
        }
    }
    for h in live {
        if !sizes.contains_key(h) {
            bail!("live file {h} has no sized marker in any registered repo; cannot reconstruct");
        }
    }
    Ok(sizes)
}

/// File-hashes in `want` reachable from this repo's index or any ref.
fn reachable_in_repo(git_dir: &Path, want: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let repo = match gix::open(git_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("prune: opening {} failed: {e}; treating as no refs", git_dir.display());
            return Ok(BTreeSet::new());
        }
    };
    // Reuse gc's reachability over all refs (no hiding) + index.
    Ok(crate::gc::reachable_all(&repo, want))
}

/// Exclusive lock so two prunes don't race the swap. Best-effort: a stale lock
/// from a crashed prune is surfaced, not silently stolen.
struct LockFile {
    path: std::path::PathBuf,
}
impl LockFile {
    fn acquire(store: &Path) -> Result<Self> {
        std::fs::create_dir_all(store)?;
        let path = store.join(".prune.lock");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{}", std::process::id());
                Ok(Self { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(anyhow!(
                "another prune holds {} (remove it if no prune is running)",
                path.display()
            )),
            Err(e) => Err(e).context("creating prune lock"),
        }
    }
}
impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Quick pointer sniff so callers can pre-filter (kept here to avoid leaking
/// gc internals). Unused outside tests today but cheap.
#[allow(dead_code)]
fn is_pointer(data: &[u8]) -> bool {
    pointer::parse_pointer(data).is_ok()
}
```

- [ ] **Step 7: Expose a reachability helper from `gc.rs`**

`prune` calls `crate::gc::reachable_all`. Add to `gc.rs`:

```rust
/// File-hashes in `want` reachable from `repo`'s index or ANY ref (no hiding).
/// Shared by `git-bale prune`.
pub fn reachable_all(repo: &gix::Repository, want: &BTreeSet<String>) -> HashSet<String> {
    let (local_tips, remote_tips) = ref_tips(repo);
    let mut all = local_tips;
    all.extend(remote_tips);
    reachable_hashes(repo, want, &all, &[])
}
```

- [ ] **Step 8: Build + lint**

```bash
cargo fmt --all && cargo build --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: PASS. Remove the `is_pointer`/`pointer` import if clippy flags them as truly dead; they're a convenience and may be dropped.

### 8c — e2e phases for gc + shared + prune

- [ ] **Step 9: Add three phases to `phases/local.py`**

Append:

```python
def phase_local_gc_abandon(*, timings: Timings, client: ClientEnv, work_root: Path) -> None:
    """Abandoned `git add` in a per-repo local store is swept by gc; a committed
    file survives."""
    with timings.measure("local-gc-abandon"):
        repo, env = init_repo_local(work_root=work_root, client=client, name="local-gc")
        rel = "big.bin"
        v1 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-gc-v1")
        v2 = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"local-gc-v2")

        (repo / rel).write_bytes(v1)
        git(["add", rel], cwd=repo, env=env)
        git(["commit", "-m", "v1"], cwd=repo, env=env)
        store = per_repo_store(repo)
        after_commit = len(local_store_objects(store))
        if after_commit == 0:
            raise TestFailure("[local-gc] commit left no objects")

        (repo / rel).write_bytes(v2)
        git(["add", rel], cwd=repo, env=env)
        git(["reset"], cwd=repo, env=env)
        git(["checkout", "--", rel], cwd=repo, env=env)  # fires post-checkout gc

        # v1 still committed → its objects must remain and reconstruct.
        verify_worktree(
            repo, rel, expected_sha=sha256_bytes(v1), expected_size=len(v1), label="local-gc"
        )
        if not local_store_objects(store):
            raise TestFailure("[local-gc] gc wrongly swept the committed v1 objects")
        info("[local-gc] abandoned add reconciled; committed v1 intact")


def phase_local_shared_dedup(*, timings: Timings, client: ClientEnv, work_root: Path) -> None:
    """Two repos on one shared store: the second add of identical content writes
    no new xorbs."""
    with timings.measure("local-shared-dedup"):
        shared = work_root / "shared-store"
        r1, e1 = init_repo_local(
            work_root=work_root, client=client, name="shared-a", shared_store=shared
        )
        rel = "big.bin"
        payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"shared")
        (r1 / rel).write_bytes(payload)
        git(["add", rel], cwd=r1, env=e1)
        git(["commit", "-m", "a"], cwd=r1, env=e1)
        after_first = len(local_store_objects(shared))

        r2, e2 = init_repo_local(
            work_root=work_root, client=client, name="shared-b", shared_store=shared
        )
        (r2 / rel).write_bytes(payload)
        git(["add", rel], cwd=r2, env=e2)
        git(["commit", "-m", "b"], cwd=r2, env=e2)
        after_second = len(local_store_objects(shared))

        if after_second != after_first:
            raise TestFailure(
                f"[shared-dedup] identical content re-stored: {after_first} -> {after_second}"
            )
        verify_worktree(
            r2, rel, expected_sha=sha256_bytes(payload), expected_size=len(payload),
            label="shared-dedup",
        )
        info(f"[shared-dedup] dedup held across repos ({after_first} objects)")


def phase_local_prune_shared(*, timings: Timings, client: ClientEnv, work_root: Path) -> None:
    """prune --shared keeps an object referenced by a second repo and removes a
    truly-orphaned one."""
    with timings.measure("local-prune-shared"):
        shared = work_root / "prune-store"
        keep_repo, ke = init_repo_local(
            work_root=work_root, client=client, name="prune-keep", shared_store=shared
        )
        orphan_repo, oe = init_repo_local(
            work_root=work_root, client=client, name="prune-orphan", shared_store=shared
        )
        keep_payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"prune-keep")
        orphan_payload = deterministic_payload(LOCAL_PAYLOAD_BYTES, seed=b"prune-orphan")

        (keep_repo / "k.bin").write_bytes(keep_payload)
        git(["add", "k.bin"], cwd=keep_repo, env=ke)
        git(["commit", "-m", "keep"], cwd=keep_repo, env=ke)

        # Orphan: add then hard-reset so nothing references it (objects persist
        # in the shared store — gc is append-only in shared mode).
        (orphan_repo / "o.bin").write_bytes(orphan_payload)
        git(["add", "o.bin"], cwd=orphan_repo, env=oe)
        git(["reset", "--hard"], cwd=orphan_repo, env=oe)

        before = len(local_store_objects(shared))
        run([str(client.git_bale_bin), "prune", "--shared"], cwd=keep_repo, env=ke)
        after = len(local_store_objects(shared))

        if after >= before:
            raise TestFailure(f"[prune] expected reclamation: {before} -> {after}")
        # The kept file must still reconstruct from the compacted store.
        (keep_repo / "k.bin").unlink()
        run(["rm", "-rf", str(keep_repo / ".git" / "bale" / "manifests")], cwd=keep_repo, env=ke)
        git(["checkout", "--", "k.bin"], cwd=keep_repo, env=ke)
        verify_worktree(
            keep_repo, "k.bin", expected_sha=sha256_bytes(keep_payload),
            expected_size=len(keep_payload), label="prune",
        )
        info(f"[prune] orphan reclaimed, kept file intact ({before} -> {after} objects)")
```

- [ ] **Step 10: Register the three phases in `cli.py`**

Extend the import:

```python
from baleharness.phases.local import (
    phase_local_basic,
    phase_local_gc_abandon,
    phase_local_prune_shared,
    phase_local_shared_dedup,
)
```

Thunks:

```python
        def _phase_local_gc() -> None:
            phase_local_gc_abandon(timings=timings, client=client, work_root=work_root)

        def _phase_local_shared() -> None:
            phase_local_shared_dedup(timings=timings, client=client, work_root=work_root)

        def _phase_local_prune() -> None:
            phase_local_prune_shared(timings=timings, client=client, work_root=work_root)
```

REGISTRY (group `g3`):

```python
            "local-gc-abandon": ("g3", False, _phase_local_gc),
            "local-shared-dedup": ("g3", False, _phase_local_shared),
            "local-prune-shared": ("g3", False, _phase_local_prune),
```

- [ ] **Step 11: Run the local-mode phases**

```bash
cargo build --release -p git-bale
python3 tests/e2e/run.py --state-dir "$HOME/bale-e2e-state" --only local-basic --only local-gc-abandon --only local-shared-dedup --only local-prune-shared --no-build
```
Expected: all four PASS.

- [ ] **Step 12: Lint Python + commit**

```bash
cd tests/e2e && uvx ruff check --fix . && uvx ruff format . && cd -
cargo fmt --all
git add crates/git-bale/src/gc.rs crates/git-bale/src/prune.rs tests/e2e/baleharness/
git commit -m "gc: local-mode policy + shared no-op; prune --shared (compaction) + e2e"
```

---

## Task 9: Full e2e regression (server mode unbroken)

**Files:** none (verification only)

- [ ] **Step 1: Confirm server-mode phases still pass**

The clean/smudge/gc/push-pending edits must not regress server mode. Run the standard suite:

```bash
cargo build --release -p git-bale
python3 tests/e2e/run.py --state-dir "$HOME/bale-e2e-state"
```
Expected: all phases PASS (including the existing `gc-*`, `push-pending-*`, `bigfile`, `clone`).

- [ ] **Step 2: If any server-mode phase regressed**

Use superpowers:systematic-debugging. The likeliest culprits: (a) markers still under `staging_root` but objects moved — confirm server mode still uses `staging_root` for *both* (it does: `object_store_root` returns `staging_root` when `!local_mode`); (b) the `staging_hit` guard now requires `!raw.local_mode` — confirm server config has `local_mode=false`.

- [ ] **Step 3: Commit (if any fix was needed)**

```bash
git add -A && git commit -m "fix: <describe server-mode regression fix>"
```

---

## Task 10: Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `tests/e2e/README.md`

- [ ] **Step 1: `docs/ARCHITECTURE.md`**

Add a "Fully-local mode" section covering: `bale.local`/`localStore`/`localShared` config; `object_store_root` resolution (server=staging, local per-repo=`.git/bale/store`, shared=`~/bale-local`); the invariant that **markers/clean-cache/manifests stay per-repo under `.git/bale/` even with a shared store**; smudge is store-only + hard-error + no auth in local mode; gc policy (no remote hiding per-repo; no-op on shared); `prune --shared` compaction (reconstruct+re-clean live files, atomic swap, lockfile, abort-on-missing-repo unless `--force`). Add a "Tricky bits" entry: a per-repo local store is **not** carried by `git clone`; use `--shared` for multiple working copies.

- [ ] **Step 2: `README.md`**

Add a quick-start block:

```bash
git init myrepo && cd myrepo
git-bale init-local            # per-repo store at .git/bale/store, no server
git-bale init-local --shared   # shared store at ~/bale-local across all repos
git-bale track '*.bin'
git add big.bin && git commit -m "add"   # data stays local, no upload
git-bale prune --shared        # reclaim a shared store (per-repo: handled by gc)
```

Note the clone-portability limitation for the per-repo store.

- [ ] **Step 3: `CLAUDE.md`**

In the `crates/git-bale/` bullet, add one sentence on local mode (`init-local`, store relocation vs per-repo markers, store-only smudge, `prune --shared`). In the tests section, add the four `local-*` phases to the list.

- [ ] **Step 4: `tests/e2e/README.md`**

Document the four no-server `local-*` phases in the phase list / Design section.

- [ ] **Step 5: Commit**

```bash
git add docs/ARCHITECTURE.md README.md CLAUDE.md tests/e2e/README.md
git commit -m "docs: fully-local mode (init-local, store, gc/prune, limitations)"
```

---

## Final verification checklist

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo build --workspace` clean
- [ ] `python3 tests/e2e/run.py --state-dir "$HOME/bale-e2e-state"` — all phases pass (server + the four `local-*`)
- [ ] `git-bale init-local` then add/commit/checkout works with no server process running
- [ ] `git-bale init-local --shared` gives cross-repo dedup; `git-bale prune --shared` reclaims orphans and keeps cross-referenced files
- [ ] Docs updated (ARCHITECTURE, README, CLAUDE, e2e README)

---

## Self-review notes (author)

- **Spec coverage:** store location (Tasks 1–2, 4), explicit activation (Task 3), per-repo gc no-hiding (8a), shared append-only + manual prune (8a no-op + 8b), durable-not-volatile (store separate from chunk cache, Task 4), hard-error smudge (Task 5), push no-op (Task 6), clone-portability limitation (docs, Task 10), e2e-only verification (Tasks 7–9). All spec sections map to a task.
- **Risk hot-spots to watch during execution:** (1) `make_env` may inject a server URL — local smudge must never reach the cold path; the `raw.local_mode` early return in Task 5 guarantees this, but Task 7 Step 2 has the `env.pop` fallback. (2) prune compaction holds a lock but is not safe against a *concurrent `git add`* to the shared store — documented as "run when idle"; acceptable for v1 per the spec. (3) `prune` aborts on a missing registered repo unless `--force` — deliberately safe-by-default. (4) markers stay per-repo: the single most important invariant for shared-store safety — verified by `local-shared-dedup` + `local-prune-shared`.
