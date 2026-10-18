//! `git-bale gc` — reconcile the per-repo object store against git
//! reachability, dropping markers (and, once none remain, objects) that
//! nothing references.
//!
//! `git add` stages a bale file's xorbs/shards offline (see [`crate::staging`])
//! plus a `<file_hex>` marker. Without gc, content `git add`ed then abandoned
//! (`git reset`, `git checkout`) lingers forever. Wired into
//! post-checkout/-commit/-merge hooks; safe to run by hand.
//!
//! Liveness mirrors git's own gc: a staged file is live if any pointer to it is
//! reachable from any ref (local OR remote-tracking), any reflog entry (incl.
//! `stash@{n}`), any worktree's HEAD or index. Remote-tracking reachability is
//! NOT proof of upload (`push --no-verify`, plain-git remotes); in server mode
//! the only thing that releases committed staged content is push-pending's
//! drain after a successful upload. Every error while computing liveness
//! aborts gc and keeps everything — an unreadable ref must never read as
//! "unreferenced".
//!
//! Xorbs are shared across files by xet-data's local dedup, so per-xorb deletion
//! is unsafe: the object sweep runs only once no marker remains (and, in local
//! mode, nothing the store holds is reachable).

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use gix::ObjectId;

use crate::clean_cache;
use crate::pointer;
use crate::staging::{list_staged_files, remove_empty_dirs, remove_marker, staging_root};
use crate::store::{self, StoreLock};

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    reconcile(&cwd)
}

pub fn reconcile(start_dir: &Path) -> Result<()> {
    let repo = match gix::discover(start_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("git-bale gc: not in a git repo ({e}); nothing to do");
            return Ok(());
        }
    };
    let common = store::common_git_dir(&repo);
    let raw = crate::config::RawConfig::load(Some(start_dir))
        .context("git-bale gc: loading config (nothing reclaimed)")?;
    let store = store::object_store_root(&raw)?;
    let staging = staging_root(&common);

    // Held across {read markers → remove dead → sweep objects} so a concurrent
    // `clean` (which holds the same lock across its object+marker write) can't
    // have a just-written object swept before its marker lands. Non-blocking:
    // a held lock means a `git add` is mid-write, so skip (hooks run `|| true`).
    let Some(lock) = StoreLock::try_exclusive(&store)? else {
        tracing::debug!(
            "git-bale gc: store {} locked by a concurrent add; skipping",
            store.display()
        );
        return Ok(());
    };

    // Checked AFTER taking the store lock — order is load-bearing. A clean that
    // already wrote its marker has released the store lock while its git op
    // still holds an index/ref `*.lock` (we skip); one that hasn't is blocked
    // on the store lock (no marker for us to misjudge).
    if git_op_in_flight(&common)? {
        tracing::debug!("git-bale gc: a git index/ref update is in flight; skipping");
        return Ok(());
    }

    // Shared local store: append-only. Other repos may reference these
    // objects and markers are the only record of what's in the store;
    // `git-bale prune --shared` reclaims.
    if raw.local_mode && raw.local_shared {
        store::register_repo_locked(&store, &common, &lock)?;
        let _ = remove_empty_dirs(&staging);
        return Ok(());
    }
    // A non-shared store is swept whole; never one another repo owns (or one
    // no clean of ours has claimed yet).
    if raw.local_mode && !store::owns_store(&store, &common)? {
        if let Some(owner) = store::store_owner(&store)? {
            bail!(
                "local store {} belongs to {}; refusing to reclaim it from {}",
                store.display(),
                store::describe_owner(&owner, &store),
                common.display()
            );
        }
        return Ok(());
    }

    let staged = list_staged_files(&common).context("listing staged markers")?;
    if staged.is_empty() {
        // No marker vouches for anything left here (e.g. push-pending skipped
        // its sweep because a git op was in flight); we hold the lock and no op
        // is in flight now, so reclaim it.
        sweep_store(&repo, &common, &raw, &store, &staging)?;
        return Ok(());
    }

    // Reclaim grace: a marker cleaned within the window is kept regardless —
    // the backstop for the one gap `git_op_in_flight` can't see (a `git
    // stash`'s lock-free commit-object write). Filtering BEFORE the scan keeps
    // hooks cheap: young markers (every `git status` re-clean makes one) would
    // otherwise force a full-history walk on every checkout/commit.
    let grace = reclaim_grace();
    let now = SystemTime::now();
    let candidates: BTreeSet<String> = staged
        .into_iter()
        .map(|(h, _)| h)
        .filter(|h| marker_age_exceeds(&common, h, grace, now))
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    if is_partial_clone(&repo, &common) {
        // Missing blobs are indistinguishable from corruption: never reclaim,
        // and say so only at debug level since every hook would repeat it.
        tracing::debug!("git-bale gc: partial clone; not reclaiming anything");
        return Ok(());
    }
    let live = live_hashes(&repo, &common, &candidates)?;
    let dead: BTreeSet<String> = candidates
        .iter()
        .filter(|h| !live.contains(*h))
        .cloned()
        .collect();
    if dead.is_empty() {
        return Ok(());
    }

    // Clean-cache first: a surviving entry would let a later `git add` of the
    // same bytes short-circuit to a pointer whose bytes we're about to sweep.
    clean_cache::forget_hashes(&common, &dead).context("invalidating clean-cache")?;
    for h in &dead {
        remove_marker(&common, h).with_context(|| format!("removing stale marker {h}"))?;
    }
    tracing::debug!("git-bale gc: dropped {} orphaned marker(s)", dead.len());

    if list_staged_files(&common)
        .context("re-listing staged markers")?
        .is_empty()
    {
        sweep_store(&repo, &common, &raw, &store, &staging)?;
    }
    drop(lock);
    Ok(())
}

/// Sweep the whole object store once no marker remains. In local mode the
/// store is the ONLY copy of committed content, and "no markers" doesn't mean
/// "nothing live" (a repo re-cloned at the same path re-claims its old store
/// with no markers), so it's swept only if nothing it holds is reachable.
/// Caller holds the store lock and has checked no git op is in flight.
fn sweep_store(
    repo: &gix::Repository,
    common: &Path,
    raw: &crate::config::RawConfig,
    store: &Path,
    staging: &Path,
) -> Result<()> {
    if store.join("xet").exists() {
        if raw.local_mode {
            if is_partial_clone(repo, common) {
                tracing::debug!("git-bale gc: partial clone; not sweeping the local store");
                return Ok(());
            }
            let held: BTreeSet<String> = crate::prune::stored_files(store)?.into_keys().collect();
            if !held.is_empty() {
                let live = live_hashes(repo, common, &held)?;
                if !live.is_empty() {
                    tracing::debug!(
                        "git-bale gc: local store holds {} reachable file(s); not sweeping",
                        live.len()
                    );
                    return Ok(());
                }
            }
        }
        crate::staging::sweep_objects(store)
            .with_context(|| format!("sweeping objects under {}", store.display()))?;
    }
    let _ = remove_empty_dirs(store);
    if store != staging {
        let _ = remove_empty_dirs(staging);
    }
    Ok(())
}

/// Subset of `want` referenced by any index, ref, reflog entry, worktree HEAD
/// or in-progress rebase/merge state of the repo whose common git dir is
/// `common`. Errors on anything it can't read. Stops once every wanted hash is
/// found.
pub fn live_hashes(
    repo: &gix::Repository,
    common: &Path,
    want: &BTreeSet<String>,
) -> Result<HashSet<String>> {
    Ok(scan(repo, common, Some(want))?.into_iter().collect())
}

/// Every bale file hash reachable the same way as [`live_hashes`], without a
/// candidate set. `prune` uses this: liveness can't depend on which repo's
/// markers happen to survive.
pub fn reachable_hashes(repo: &gix::Repository, common: &Path) -> Result<BTreeSet<String>> {
    scan(repo, common, None)
}

fn scan(
    repo: &gix::Repository,
    common: &Path,
    want: Option<&BTreeSet<String>>,
) -> Result<BTreeSet<String>> {
    if common.join("reftable").exists() {
        bail!("reftable ref storage is not supported by git-bale's liveness scan");
    }
    if is_partial_clone(repo, common) {
        bail!(
            "this is a partial clone (promisor remote): blobs may be missing locally, so \
             git-bale can't prove which bale files are unreferenced"
        );
    }
    let mut scan = Scan {
        repo,
        want,
        seen: HashSet::new(),
        found: BTreeSet::new(),
    };

    for index in index_files(repo, common)? {
        scan.index(&index)?;
        if scan.done() {
            return Ok(scan.found);
        }
    }

    let mut commits: Vec<ObjectId> = Vec::new();
    for id in tip_ids(repo, common)? {
        let header = repo
            .find_header(id)
            .with_context(|| format!("object {id} named by a ref/reflog is missing"))?;
        let (kind, id) = if header.kind() == gix::object::Kind::Tag {
            let peeled = repo
                .find_object(id)
                .and_then(|o| o.peel_tags_to_end())
                .with_context(|| format!("peeling tag {id}"))?;
            (peeled.kind, peeled.id)
        } else {
            (header.kind(), id)
        };
        match kind {
            gix::object::Kind::Commit => commits.push(id),
            gix::object::Kind::Tree => scan.whole_tree(id)?,
            gix::object::Kind::Blob => scan.blob(id)?,
            gix::object::Kind::Tag => {}
        }
        if scan.done() {
            return Ok(scan.found);
        }
    }
    commits.sort();
    commits.dedup();
    if !commits.is_empty() {
        scan.history(&commits)?;
    }
    Ok(scan.found)
}

/// Partial clones (`extensions.partialClone`, a `remote.*.promisor`, or
/// `*.promisor` packs) may lack blobs locally, which the scan can't tell apart
/// from corruption.
pub fn is_partial_clone(repo: &gix::Repository, common: &Path) -> bool {
    let snapshot = repo.config_snapshot();
    if snapshot.string("extensions.partialClone").is_some() {
        return true;
    }
    for name in repo.remote_names() {
        if snapshot
            .boolean(format!("remote.{name}.promisor").as_str())
            .unwrap_or(false)
        {
            return true;
        }
    }
    std::fs::read_dir(common.join("objects").join("pack")).is_ok_and(|rd| {
        rd.flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "promisor"))
    })
}

struct Scan<'r, 'w> {
    repo: &'r gix::Repository,
    want: Option<&'w BTreeSet<String>>,
    seen: HashSet<ObjectId>,
    found: BTreeSet<String>,
}

impl Scan<'_, '_> {
    fn done(&self) -> bool {
        self.want.is_some_and(|w| self.found.len() == w.len())
    }

    fn index(&mut self, path: &Path) -> Result<()> {
        let min_len = 12 + self.repo.object_hash().len_in_bytes() as u64;
        match std::fs::metadata(path) {
            Ok(m) if m.len() < min_len => bail!("index {} is truncated", path.display()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        }
        let index = gix::index::File::at(path, self.repo.object_hash(), false, Default::default())
            .with_context(|| format!("reading index {}", path.display()))?;
        use gix::index::entry::{Flags, Mode};
        for entry in index.entries() {
            // `git add -N` records the empty blob, which may not exist in the ODB.
            if entry.flags.contains(Flags::INTENT_TO_ADD) {
                continue;
            }
            if entry.mode == Mode::FILE || entry.mode == Mode::FILE_EXECUTABLE {
                self.blob(entry.id)?;
            } else if entry.mode == Mode::DIR {
                // Sparse-index directory entry: its whole subtree is in the index.
                self.whole_tree(entry.id)?;
            }
            if self.done() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Pointers each commit introduces, diffing against its first parent (a
    /// missing/unreadable parent diffs against the empty tree: a superset).
    fn history(&mut self, tips: &[ObjectId]) -> Result<()> {
        let walk = self
            .repo
            .rev_walk(tips.iter().copied())
            .all()
            .context("setting up history walk")?;
        for info in walk {
            let info = info.context("walking history")?;
            let commit = info
                .object()
                .with_context(|| format!("reading commit {}", info.id))?;
            let tree = commit
                .tree()
                .with_context(|| format!("reading tree of {}", info.id))?;
            let parent_tree = info
                .parent_ids()
                .next()
                .and_then(|pid| pid.object().ok())
                .and_then(|o| o.peel_to_commit().ok())
                .and_then(|c| c.tree().ok())
                .unwrap_or_else(|| self.repo.empty_tree());
            self.diff(&parent_tree, &tree)?;
            if self.done() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn whole_tree(&mut self, id: ObjectId) -> Result<()> {
        let tree = self
            .repo
            .find_tree(id)
            .with_context(|| format!("reading tree {id}"))?;
        let empty = self.repo.empty_tree();
        self.diff(&empty, &tree)
    }

    /// Record Added/Modified blobs between the trees that parse as a wanted
    /// pointer.
    fn diff(&mut self, from: &gix::Tree<'_>, to: &gix::Tree<'_>) -> Result<()> {
        let mut platform = from.changes().context("preparing tree diff")?;
        // No rename tracking (O(N²)): a moved pointer still surfaces as an
        // Addition carrying the same blob id.
        platform.options(|opts| {
            opts.track_rewrites(None);
        });
        let mut failure: Option<anyhow::Error> = None;
        let mut stopped = false;
        let result = platform.for_each_to_obtain_tree(
            to,
            |change| -> Result<gix::object::tree::diff::Action, std::convert::Infallible> {
                use gix::object::tree::diff::Change;
                if let Change::Addition { entry_mode, id, .. }
                | Change::Modification { entry_mode, id, .. } = change
                {
                    if entry_mode.is_blob() {
                        if let Err(e) = self.blob(id.detach()) {
                            failure = Some(e);
                        }
                        if failure.is_some() || self.done() {
                            stopped = true;
                            return Ok(std::ops::ControlFlow::Break(()));
                        }
                    }
                }
                Ok(std::ops::ControlFlow::Continue(()))
            },
        );
        if let Some(e) = failure {
            return Err(e);
        }
        // A deliberate Break surfaces as a "cancelled" error; anything else is real.
        if !stopped {
            result.context("diffing trees")?;
        }
        Ok(())
    }

    /// Record `oid`'s file hash if it's a small blob parsing as a (wanted)
    /// pointer.
    fn blob(&mut self, oid: ObjectId) -> Result<()> {
        if !self.seen.insert(oid) {
            return Ok(());
        }
        let header = self
            .repo
            .find_header(oid)
            .with_context(|| format!("blob {oid} is missing from the object database"))?;
        if header.kind() != gix::object::Kind::Blob
            || header.size() == 0
            || header.size() > pointer::POINTER_MAX_BYTES as u64
        {
            return Ok(());
        }
        let obj = self
            .repo
            .find_object(oid)
            .with_context(|| format!("reading blob {oid}"))?;
        if let Ok(info) = pointer::parse_pointer(&obj.data) {
            let h = info.hash();
            if pointer::is_safe_file_id(h) && self.want.is_none_or(|w| w.contains(h)) {
                self.found.insert(h.to_string());
            }
        }
        Ok(())
    }
}

/// Linked worktrees' private git dirs (`<common>/worktrees/<id>`).
fn worktree_dirs(common: &Path) -> Result<Vec<PathBuf>> {
    let rd = match std::fs::read_dir(common.join("worktrees")) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("listing linked worktrees"),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// Every worktree's index (main + linked), plus an explicit GIT_INDEX_FILE.
fn index_files(repo: &gix::Repository, common: &Path) -> Result<Vec<PathBuf>> {
    let mut out = vec![common.join("index"), repo.index_path()];
    for wt in worktree_dirs(common)? {
        out.push(wt.join("index"));
    }
    if let Some(p) = std::env::var_os("GIT_INDEX_FILE") {
        out.push(PathBuf::from(p));
    }
    let mut canon: Vec<PathBuf> = out.iter().map(|p| store::canonical_path(p)).collect();
    canon.sort();
    canon.dedup();
    Ok(canon)
}

const PSEUDO_REFS: [&str; 8] = [
    "HEAD",
    "ORIG_HEAD",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "REBASE_HEAD",
    "BISECT_HEAD",
    "AUTO_MERGE",
];

const OP_STATE_REFS: [&str; 11] = [
    "MERGE_AUTOSTASH",
    "rebase-merge/autostash",
    "rebase-merge/orig-head",
    "rebase-merge/onto",
    "rebase-merge/stopped-sha",
    "rebase-merge/amend",
    "rebase-apply/autostash",
    "rebase-apply/orig-head",
    "rebase-apply/onto",
    "sequencer/head",
    "sequencer/abort-safety",
];

/// A multi-step op (rebase, am, cherry-pick/revert sequence, autostash merge)
/// is stopped mid-way: its state may name commits nothing else does.
const OP_STATE_PATHS: [&str; 4] = [
    "rebase-merge",
    "rebase-apply",
    "sequencer",
    "MERGE_AUTOSTASH",
];

/// Object ids named by every ref, every reflog entry, and every worktree's
/// HEAD / pseudo-refs / per-worktree refs / rebase-merge-sequencer state.
fn tip_ids(repo: &gix::Repository, common: &Path) -> Result<Vec<ObjectId>> {
    let mut ids: Vec<ObjectId> = Vec::new();

    let platform = repo.references().context("opening refs")?;
    for r in platform.all().context("listing refs")? {
        let r = r.map_err(|e| anyhow!("reading a ref: {e}"))?;
        // Symbolic refs point at refs listed on their own (or dangle, like a
        // stale refs/remotes/origin/HEAD) — skip rather than fail.
        if let gix::refs::TargetRef::Object(id) = r.target() {
            ids.push(id.to_owned());
        }
    }

    let mut git_dirs = vec![common.to_path_buf()];
    git_dirs.extend(worktree_dirs(common)?);
    for dir in &git_dirs {
        for name in PSEUDO_REFS {
            ids.extend(read_ref_file(&dir.join(name))?);
        }
        // A stopped `rebase --autostash` / `merge --autostash` holds the
        // user's uncommitted changes ONLY here, in no ref or reflog.
        for name in OP_STATE_REFS {
            ids.extend(read_ref_file(&dir.join(name))?);
        }
        ids.extend(loose_refs(&dir.join("refs"))?);
        ids.extend(reflog_ids(&dir.join("logs"))?);
    }
    ids.retain(|id| !id.is_null());
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Object ids in a ref-like file (one `<hex>[ ...]` per line; `ref:` lines are
/// symbolic and skipped). Missing file → none.
fn read_ref_file(path: &Path) -> Result<Vec<ObjectId>> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) if path.is_dir() => {
            tracing::debug!("{} is a directory: {e}", path.display());
            return Ok(Vec::new());
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("ref:") {
            continue;
        }
        let tok = line.split_whitespace().next().unwrap_or("");
        out.push(
            ObjectId::from_hex(tok.as_bytes())
                .with_context(|| format!("malformed object id in {}", path.display()))?,
        );
    }
    Ok(out)
}

fn loose_refs(dir: &Path) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    for f in walk_files(dir)? {
        if f.extension().is_some_and(|e| e == "lock") {
            continue;
        }
        out.extend(read_ref_file(&f)?);
    }
    Ok(out)
}

/// Both sides of every reflog entry (`<old> <new> <ident> <ts> <tz>\t<msg>`).
fn reflog_ids(dir: &Path) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    for f in walk_files(dir)? {
        if f.extension().is_some_and(|e| e == "lock") {
            continue;
        }
        let body = std::fs::read(&f).with_context(|| format!("reading reflog {}", f.display()))?;
        for line in body.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let mut toks = line.split(|b| *b == b' ');
            for _ in 0..2 {
                let tok = toks.next().unwrap_or(b"");
                out.push(
                    ObjectId::from_hex(tok)
                        .with_context(|| format!("malformed reflog entry in {}", f.display()))?,
                );
            }
        }
    }
    Ok(out)
}

fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        // Stray dotfiles (e.g. `.DS_Store`) are never refs or reflogs.
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            out.extend(walk_files(&entry.path())?);
        } else if ft.is_file() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// True if any git operation that could be cleaning bale content and recording
/// it (in an index or a ref) is in flight in ANY worktree, detected by its
/// `*.lock` file. gc reads liveness from indexes + refs, both of which lag the
/// clean filter, so it must defer or it may sweep an in-flight file's only copy.
///
/// Covers `git add`/`commit` (`index.lock`), `git stash` (a temporary
/// `index.<temp>.lock` during the clean, then `refs/stash.lock` — stash does NOT
/// use the main `index.lock`), and ref updates generally. The lock-free
/// residual (a stash's commit-object write) is covered by the reclaim grace.
/// A stopped rebase/am/sequencer/autostash merge also counts. An unreadable
/// dir counts as "in flight" (skip, never guess).
pub fn git_op_in_flight(common: &Path) -> Result<bool> {
    if let Some(idx) = std::env::var_os("GIT_INDEX_FILE") {
        let mut lock = idx;
        lock.push(".lock");
        if Path::new(&lock).exists() {
            return Ok(true);
        }
    }
    let mut dirs = vec![common.to_path_buf()];
    dirs.extend(worktree_dirs(common)?);
    for dir in &dirs {
        if dir_has_lock(dir, false) || dir_has_lock(&dir.join("refs"), true) {
            return Ok(true);
        }
        if OP_STATE_PATHS.iter().any(|p| dir.join(p).exists()) {
            return Ok(true);
        }
    }
    Ok(dir_has_lock(&common.join("reftable"), true))
}

fn dir_has_lock(dir: &Path, recurse: bool) -> bool {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    for entry in rd {
        let Ok(entry) = entry else { return true };
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            return true;
        };
        if ft.is_dir() {
            if recurse && dir_has_lock(&path, true) {
                return true;
            }
        } else if path.extension().is_some_and(|e| e == "lock") {
            return true;
        }
    }
    false
}

/// Grace before an unreferenced marker may be reclaimed. `BALE_GC_GRACE_SECS`
/// overrides. Default matches git's `gc.pruneExpire` (2 weeks), with the same
/// clock: git prunes an unreachable loose object once its mtime (written or
/// last freshened) is older than that, not counting from when it became
/// unreachable; ours counts from the marker's mtime (last clean). So content
/// is reclaimable no earlier than git would drop a dangling commit naming it.
pub fn reclaim_grace() -> Duration {
    let secs = std::env::var("BALE_GC_GRACE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_GRACE_SECS);
    Duration::from_secs(secs)
}

const DEFAULT_GRACE_SECS: u64 = 14 * 24 * 60 * 60;

/// Whether `h`'s marker is older than `grace`. An unreadable or future
/// (clock-skewed) mtime counts as too young — never sweep on an uncertain age.
pub fn marker_age_exceeds(git_dir: &Path, h: &str, grace: Duration, now: SystemTime) -> bool {
    match crate::staging::marker_mtime(git_dir, h) {
        Some(mtime) => now
            .duration_since(mtime)
            .map(|age| age > grace)
            .unwrap_or(false),
        None => false,
    }
}
