//! Where chunk-deduplicated objects (xorbs/shards) live, and who shares them.
//!
//! Server mode: the transient per-repo staging dir (`.git/bale/staging`),
//! drained by `git-bale push-pending`. Local mode: a durable store —
//! `.git/bale/store` per-repo by default, or a shared dir (e.g. `~/bale-local`)
//! used by every repo on the machine.
//!
//! Per-repo bookkeeping (file-index markers, clean-cache, manifests) always
//! stays under the COMMON git dir's `bale/` even when the object store is
//! shared: a shared store must never hold one repo's markers (see `crate::gc` /
//! `crate::prune`), and linked worktrees must share one inventory.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use fs4::fs_std::FileExt;

use crate::config::RawConfig;
use crate::staging::staging_root;

/// Per-repo default store when `bale.localStore` is unset.
pub fn default_local_store(git_dir: &Path) -> PathBuf {
    git_dir.join("bale").join("store")
}

/// The repo's common git dir, canonicalized. All bale bookkeeping keys on it:
/// a linked worktree's own git dir (`.git/worktrees/<id>`) would give each
/// worktree a private inventory that the others' gc can't see.
pub fn common_git_dir(repo: &gix::Repository) -> PathBuf {
    let common = repo.common_dir();
    dunce::canonicalize(common).unwrap_or_else(|_| common.to_path_buf())
}

/// `p` with symlinks and `..` resolved, even when `p` (or some of its parents)
/// doesn't exist yet: canonicalize the nearest existing ancestor and re-append
/// the rest. Two spellings of one store must map to one lockfile. `dunce`
/// avoids Windows `\\?\` verbatim paths, which subprocess cwds and users choke on.
pub fn canonical_path(p: &Path) -> PathBuf {
    if let Ok(c) = dunce::canonicalize(p) {
        return c;
    }
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => return p.to_path_buf(),
        }
    };
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.as_path();
    loop {
        if let Ok(c) = dunce::canonicalize(cur) {
            let mut out = c;
            for comp in tail.iter().rev() {
                out.push(comp);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                cur = parent;
            }
            _ => return abs,
        }
    }
}

/// The dir handed to `TranslatorConfig::local_config`. Server mode → staging;
/// local mode → configured store (or per-repo default), canonicalized and
/// checked for an interrupted `prune` swap.
pub fn object_store_root(raw: &RawConfig) -> Result<PathBuf> {
    if raw.local_mode {
        let store = match &raw.local_store {
            Some(p) => canonical_path(p),
            None => {
                let git_dir = raw.git_dir.as_deref().ok_or_else(|| {
                    anyhow!("local mode needs a git repo or an explicit bale.localStore")
                })?;
                canonical_path(&default_local_store(git_dir))
            }
        };
        ensure_store_not_mid_swap(&store)?;
        ensure_store_initialized(&store)?;
        Ok(store)
    } else {
        let git_dir = raw
            .git_dir
            .as_deref()
            .ok_or_else(|| anyhow!("no git directory resolved from cwd"))?;
        Ok(staging_root(git_dir))
    }
}

/// `<store>.old.*` / `<store>.compact.*` siblings left by an interrupted
/// `prune --shared`, sorted.
pub fn swap_leftovers(store: &Path) -> Result<Vec<PathBuf>> {
    let (Some(parent), Some(name)) = (store.parent(), store.file_name().and_then(|n| n.to_str()))
    else {
        return Ok(Vec::new());
    };
    let rd = match std::fs::read_dir(parent) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", parent.display())),
    };
    let old_prefix = format!("{name}.old.");
    let compact_prefix = format!("{name}.compact.");
    let mut leftovers = Vec::new();
    for entry in rd {
        let entry = entry?;
        let fname = entry.file_name();
        let Some(f) = fname.to_str() else { continue };
        // prune names them `<store>.{old,compact}.<pid>`; anything else is the user's.
        let suffix = f
            .strip_prefix(&old_prefix)
            .or_else(|| f.strip_prefix(&compact_prefix));
        if suffix.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) {
            leftovers.push(entry.path());
        }
    }
    leftovers.sort();
    Ok(leftovers)
}

/// Only `init-local` creates a store. A missing or never-claimed one here means
/// the configured path no longer holds it (repo moved, disk unmounted):
/// silently starting an empty store there would hide every committed file and
/// put new content where nobody looks for it.
fn ensure_store_initialized(store: &Path) -> Result<()> {
    if store.join(OWNER_FILE).is_file() || registry_dir(store).is_dir() {
        return Ok(());
    }
    bail!(
        "local store {} is missing or was never initialized (moved repo? unmounted disk?). \
         Restore it (move it back / remount it). Only if its content is truly gone, \
         `git-bale init-local` starts a new empty store — files committed into the old \
         one won't be recoverable from it.",
        store.display()
    )
}

/// `prune` swaps the store by renaming it to `<store>.old.<pid>` and the
/// compacted copy into place. A crash between the two renames leaves the store
/// path missing; silently recreating it empty would orphan every committed
/// pointer, so refuse until the user restores it.
fn ensure_store_not_mid_swap(store: &Path) -> Result<()> {
    if store.exists() {
        return Ok(());
    }
    let Some(name) = store.file_name().and_then(|n| n.to_str()) else {
        return Ok(());
    };
    let mut leftovers = swap_leftovers(store)?;
    if leftovers.is_empty() {
        return Ok(());
    }
    leftovers.sort();
    bail!(
        "local store {} is missing but an interrupted `git-bale prune --shared` left {:?}. \
         Refusing to continue (an empty store would lose every committed file). Restore it: \
         rename the `{name}.old.*` directory back to {} (or, if only a `.compact.*` exists, \
         that one), then retry.",
        store.display(),
        leftovers,
        store.display()
    )
}

/// Directory of per-repo registration files for a shared store. Each file is
/// named by a stable hash of the repo's git-dir path; its body is that absolute
/// path. `prune --shared` walks these.
pub fn registry_dir(store_root: &Path) -> PathBuf {
    store_root.join("repos")
}

/// Register `git_dir` (absolute) as a user of the shared store. Idempotent.
/// Under the store lock so it can't race a `prune` copying the registry.
pub fn register_repo(store_root: &Path, git_dir: &Path) -> Result<()> {
    let lock = StoreLock::acquire_exclusive(store_root)
        .context("locking shared store to register repo")?;
    register_repo_locked(store_root, git_dir, &lock)
}

/// [`register_repo`] for a caller already holding the store lock. clean and gc
/// call it on every run so a moved or copied repo is registered under its
/// current path before `prune` could mistake its content for unreferenced.
pub fn register_repo_locked(store_root: &Path, git_dir: &Path, _held: &StoreLock) -> Result<()> {
    ensure_store_not_mid_swap(store_root)?;
    let abs = dunce::canonicalize(git_dir)
        .with_context(|| format!("canonicalizing git dir {}", git_dir.display()))?;
    let owner = store_owner(store_root)?;
    if let Some(owner) = &owner {
        if !owned_by(owner, store_root, &abs) {
            bail!(
                "store {} is a non-shared store owned by {}; its gc would sweep \
                 content other repos put there. Use a different store for --shared.",
                store_root.display(),
                describe_owner(owner, store_root)
            );
        }
    }
    let dir = registry_dir(store_root);
    let name = registry_key(&abs);
    let body = abs.to_string_lossy();
    ensure_store_id(store_root, _held)?;
    if owner.is_none() && std::fs::read_to_string(dir.join(&name)).is_ok_and(|b| b.trim() == body) {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating shared-store registry {}", dir.display()))?;
    crate::fs_util::write_durable(
        &dir,
        &format!(".{name}.tmp.{}", std::process::id()),
        &dir.join(&name),
        abs.to_string_lossy().as_bytes(),
    )?;
    // The owner converting its own store to shared: registered first, so the
    // store is never both unowned and unregistered.
    if owner.is_some() {
        let path = store_root.join(OWNER_FILE);
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        crate::fs_util::fsync_dir(store_root)
            .with_context(|| format!("fsync {}", store_root.display()))?;
    }
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
        return Ok(canonical_path(&absolutize(cwd, &expanded)));
    }
    if shared {
        let home = crate::config::expand_tilde("~");
        if home == Path::new("~") {
            return Err(anyhow!(
                "cannot resolve ~ for default shared store; pass --store"
            ));
        }
        return Ok(canonical_path(&home.join("bale-local")));
    }
    Ok(default_local_store(&repo_git_dir(cwd)?))
}

/// The common git dir of the repo containing `cwd`.
pub fn repo_git_dir(cwd: &Path) -> Result<PathBuf> {
    let repo = gix::discover(cwd).with_context(|| format!("opening repo at {}", cwd.display()))?;
    Ok(common_git_dir(&repo))
}

fn absolutize(cwd: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
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
    let store = canonical_path(store);
    let parent = store.parent().unwrap_or_else(|| Path::new("."));
    let name = store
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("store");
    parent.join(format!(".{name}.lock"))
}

/// Exclusive advisory lock serializing mutations to one store (clean writes,
/// gc sweeps, prune swaps, push-pending drains), held only around local
/// filesystem work. The OS drops it when the process dies, so a crash never
/// leaves a stale lock. Reads (smudge) don't lock. `try_exclusive` is for
/// best-effort callers (gc hooks, smudge's clean-cache seed) that must never
/// block behind a held lock. flock is per open file description: never take
/// it twice in one process.
pub struct StoreLock {
    // Holding the File keeps the flock; dropping it (closing the fd) releases.
    _file: std::fs::File,
}

impl StoreLock {
    fn open(store: &Path) -> Result<(std::fs::File, PathBuf)> {
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
        Ok((file, path))
    }

    pub fn acquire_exclusive(store: &Path) -> Result<Self> {
        let (file, path) = Self::open(store)?;
        <std::fs::File as FileExt>::lock_exclusive(&file)
            .with_context(|| format!("acquiring exclusive store lock {}", path.display()))?;
        Ok(Self { _file: file })
    }

    /// `None` if another holder has the lock.
    pub fn try_exclusive(store: &Path) -> Result<Option<Self>> {
        let (file, path) = Self::open(store)?;
        match <std::fs::File as FileExt>::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("trying exclusive store lock {}", path.display()))
            }
        }
    }
}

/// xet's local client writes objects without fsync. Names of the xorb/shard
/// files present before a clean, so exactly the new ones can be fsynced
/// (content-addressed: an existing name is never rewritten) before the marker
/// that vouches for them is written.
pub struct ObjectSnapshot {
    before: std::collections::HashSet<std::ffi::OsString>,
}

fn object_dirs(store: &Path) -> [PathBuf; 2] {
    let base = store.join("xet").join("xorbs");
    [base.join("xorbs"), base.join("shards")]
}

fn list_names(dir: &Path) -> Result<Vec<std::ffi::OsString>> {
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| Ok(e?.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("listing {}", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("listing {}", dir.display())),
    }
}

impl ObjectSnapshot {
    pub fn take(store: &Path) -> Result<Self> {
        let mut before = std::collections::HashSet::new();
        for dir in object_dirs(store) {
            before.extend(
                list_names(&dir)?
                    .into_iter()
                    .map(|n| dir.join(n).into_os_string()),
            );
        }
        Ok(Self { before })
    }

    /// fsync every object created since `take` (verifying every xorb a new
    /// shard references), then the dirs holding them.
    pub fn sync_new(&self, store: &Path) -> Result<()> {
        for dir in object_dirs(store) {
            for name in list_names(&dir)? {
                let path = dir.join(&name);
                if !self.before.contains(path.as_os_str()) && path.is_file() {
                    crate::fs_util::fsync_file(&path)
                        .with_context(|| format!("fsync {}", path.display()))?;
                    if path.extension().is_some_and(|e| e == "mdb") {
                        verify_referenced_xorbs(store, &path)?;
                    }
                }
            }
            // Also persists dir entries of older, re-verified xorbs never synced.
            if dir.is_dir() {
                crate::fs_util::fsync_dir(&dir)
                    .with_context(|| format!("fsync {}", dir.display()))?;
            }
        }
        for dir in [
            store.join("xet").join("xorbs"),
            store.join("xet"),
            store.to_path_buf(),
        ] {
            if dir.is_dir() {
                crate::fs_util::fsync_dir(&dir)
                    .with_context(|| format!("fsync {}", dir.display()))?;
            }
        }
        crate::fs_util::fsync_ancestors(store, 3)
            .with_context(|| format!("fsync parents of {}", store.display()))?;
        Ok(())
    }
}

const OWNER_FILE: &str = ".bale-owner";
pub const ID_FILE: &str = ".bale-id";

/// The store's identity, distinguishing it from an earlier store at the same
/// path (wiped and re-created, or a remounted disk's empty mountpoint).
pub fn store_id(store: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(store.join(ID_FILE)) {
        Ok(id) => Ok(Some(id.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading id of {}", store.display())),
    }
}

/// Give a new store its id. Uniqueness, not secrecy, is what matters. Caller
/// holds the store lock.
fn ensure_store_id(store: &Path, _held: &StoreLock) -> Result<()> {
    if store_id(store)?.is_some() {
        return Ok(());
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{nanos}:{}:{}", std::process::id(), store.display());
    let id = blake3::hash(seed.as_bytes()).to_hex();
    std::fs::create_dir_all(store)
        .with_context(|| format!("creating object store {}", store.display()))?;
    crate::fs_util::write_durable(
        store,
        &format!("{ID_FILE}.tmp.{}", std::process::id()),
        &store.join(ID_FILE),
        id.as_bytes(),
    )
    .with_context(|| format!("recording id of {}", store.display()))
}
/// Owner-file body for a store inside its owner's own git dir: the owner is
/// whichever repo contains it, so the claim survives moving/copying the repo.
const SELF_OWNER: &str = "@containing-git-dir";

/// A non-shared local store belongs to exactly one repo: gc sweeps it once
/// that repo's markers are gone, which would destroy any other repo's content
/// in it. `init-local` (or the first clean) records the owner in `.bale-owner`, which is
/// authoritative — even for a store inside a repo's git dir, since another
/// repo can be pointed at that path with `--store`. Caller holds the store lock.
pub fn claim_store(store: &Path, common: &Path, _held: &StoreLock) -> Result<()> {
    ensure_store_not_mid_swap(store)?;
    let others: Vec<PathBuf> = registered_repos(store)?
        .into_iter()
        .filter(|r| r != common)
        .collect();
    if !others.is_empty() {
        bail!(
            "local store {} is a shared store (registered repos: {others:?}); use \
             `git-bale init-local --shared --store {}`",
            store.display(),
            store.display()
        );
    }
    match store_owner(store)? {
        Some(owner) if owned_by(&owner, store, common) => ensure_store_id(store, _held),
        Some(owner) => bail!(
            "local store {} belongs to repo {}; a non-shared store can serve only one repo \
             (gc would sweep the other's content). Use `git-bale init-local --shared --store {}` \
             in every repo that shares it, or give this repo its own store.",
            store.display(),
            describe_owner(&owner, store),
            store.display()
        ),
        None => {
            std::fs::create_dir_all(store)
                .with_context(|| format!("creating object store {}", store.display()))?;
            let body = if in_own_git_dir(store, common) {
                SELF_OWNER.to_string()
            } else {
                common.to_string_lossy().into_owned()
            };
            crate::fs_util::write_durable(
                store,
                &format!("{OWNER_FILE}.tmp.{}", std::process::id()),
                &store.join(OWNER_FILE),
                body.as_bytes(),
            )
            .with_context(|| format!("recording owner of {}", store.display()))?;
            ensure_store_id(store, _held)
        }
    }
}

fn owned_by(owner: &str, store: &Path, common: &Path) -> bool {
    if owner == SELF_OWNER {
        in_own_git_dir(store, common)
    } else {
        owner == common.to_string_lossy()
    }
}

/// `<common>/bale/...`, not merely under `common`: a superproject's git dir
/// also contains its submodules' (`modules/<sub>/bale/store`).
fn in_own_git_dir(store: &Path, common: &Path) -> bool {
    store.starts_with(common.join("bale"))
}

/// Human-readable owner for error messages.
pub fn describe_owner(owner: &str, store: &Path) -> String {
    if owner == SELF_OWNER {
        format!("the repo whose git dir contains {}", store.display())
    } else {
        owner.to_string()
    }
}

/// Whether gc may sweep `store`: only a non-shared store this repo has claimed.
pub fn owns_store(store: &Path, common: &Path) -> Result<bool> {
    Ok(store_owner(store)?.is_some_and(|o| owned_by(&o, store, common)))
}

/// The raw `.bale-owner` body of a claimed non-shared store, if any.
pub fn store_owner(store: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(store.join(OWNER_FILE)) {
        Ok(owner) => Ok(Some(owner.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading owner of {}", store.display())),
    }
}

/// Every xorb a new shard's files reference must exist, parse and be durable
/// before a marker vouches for them. A clean can dedup against chunks in an
/// xorb from an earlier, unsynced session that a power loss tore or lost while
/// the redb index and shard naming it survived.
fn verify_referenced_xorbs(store: &Path, shard_path: &Path) -> Result<()> {
    use xet_core_structures::metadata_shard::MDBShardFile;
    use xet_core_structures::xorb_object::XorbObject;
    let shard = MDBShardFile::load_from_file(shard_path)
        .map_err(|e| anyhow!("reading shard {}: {e}", shard_path.display()))?;
    let files = shard
        .read_all_file_info_sections()
        .map_err(|e| anyhow!("reading shard {}: {e}", shard_path.display()))?;
    let mut xorbs = std::collections::BTreeSet::new();
    for f in &files {
        xorbs.extend(f.segments.iter().map(|seg| seg.xorb_hash));
    }
    let dir = store.join("xet").join("xorbs").join("xorbs");
    for hash in xorbs {
        let path = dir.join(format!("default.{}", hash.hex()));
        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("xorb {} referenced by a new shard is missing", hash.hex()))?;
        let valid = XorbObject::validate_xorb_object(&mut file, &hash)
            .map_err(|e| anyhow!("validating xorb {}: {e}", path.display()))?;
        if valid.is_none() {
            bail!("xorb {} is corrupt (failed validation)", path.display());
        }
        crate::fs_util::fsync_file(&path).with_context(|| format!("fsync {}", path.display()))?;
    }
    Ok(())
}
