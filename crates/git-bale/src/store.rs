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
use fs4::fs_std::FileExt;

use crate::config::RawConfig;
use crate::staging::staging_root;

use gix;

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
            return Err(anyhow!(
                "cannot resolve ~ for default shared store; pass --store"
            ));
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

/// Lowercase-hex BLAKE3 of the path bytes — collision-free filename for a path
/// that may contain `/` or non-portable chars.
fn registry_key(abs: &Path) -> String {
    blake3::hash(abs.to_string_lossy().as_bytes())
        .to_hex()
        .as_str()
        .to_owned()
}

/// Sibling lockfile for `store`, OUTSIDE the dir so a `prune` swap (which
/// renames the store dir) never moves it. All store-mutating ops lock this.
pub fn lock_path(store: &Path) -> PathBuf {
    let parent = store.parent().unwrap_or_else(|| Path::new("."));
    let name = store
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("store");
    parent.join(format!(".{name}.lock"))
}

/// Exclusive advisory lock serializing mutations to one store (clean writes,
/// gc sweeps, prune swaps, push-pending drains). Held only around local
/// filesystem work. The OS releases the lock when the process dies, so a crash
/// never leaves a stale lock (unlike a create_new lockfile). Reads (smudge) do
/// not lock. Different stores have different lockfiles, so unrelated repos never
/// contend. `acquire_exclusive` blocks; `try_exclusive` returns None immediately
/// if the lock is held. Use the try variant in best-effort contexts (post-commit
/// gc hooks) where blocking would deadlock against the filter that holds the lock.
pub struct StoreLock {
    // Holding the File keeps the flock; dropping it (closing the fd) releases.
    _file: std::fs::File,
}

impl StoreLock {
    pub fn acquire_exclusive(store: &Path) -> Result<Self> {
        let path = lock_path(store);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating lock dir {}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening store lock {}", path.display()))?;
        // Blocks until any other holder releases. flock(2) on unix,
        // LockFileEx on Windows — both released when the fd closes.
        <std::fs::File as FileExt>::lock_exclusive(&file)
            .with_context(|| format!("acquiring exclusive store lock {}", path.display()))?;
        Ok(Self { _file: file })
    }

    /// Non-blocking variant: returns `None` immediately if another holder has
    /// the lock. `Some(lock)` on success. Errors on open/syscall failure (not
    /// on lock contention — that returns `None`).
    pub fn try_exclusive(store: &Path) -> Result<Option<Self>> {
        let path = lock_path(store);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating lock dir {}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening store lock {}", path.display()))?;
        match <std::fs::File as FileExt>::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { _file: file })),
            // EWOULDBLOCK (unix) / ERROR_LOCK_VIOLATION (Windows): lock is held.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("trying exclusive store lock {}", path.display()))
            }
        }
    }
}
