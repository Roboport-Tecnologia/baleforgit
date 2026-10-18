//! `git-bale prune --shared` — reclaim a shared local store by compacting it
//! down to the files any present registered repo still reaches.
//!
//! Holds the shared `StoreLock` for the whole run (excludes gc/clean/
//! push-pending/other prunes). Liveness is the same as gc's (refs, reflogs,
//! indexes, worktree HEADs, rebase/merge state) unioned over every present
//! repo, plus young markers — never "which repo holds a marker": content
//! cleaned by repo B may be referenced only by repo A, and B may be gone. The
//! store's own shards say which files it holds and their sizes.
//!
//! Precise per-xorb CAS sweeping would require rewriting xet shards; instead we
//! rebuild the store: reconstruct each live file from the old store and re-clean
//! it into a fresh one (deterministic CDC re-dedups), then swap. Aborts on any
//! liveness error, and if a registered repo path is missing: `--force` skips
//! it, which DELETES content only that repo referenced. A repo that was merely
//! moved or copied re-registers under its new path on its next clean or gc
//! (`store::register_repo_locked`), so run one there before `--force`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use tempfile::NamedTempFile;
use xet_core_structures::metadata_shard::MDBShardFile;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::clean_file;
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::fs_util::{fsync_dir, fsync_tree};
use crate::gc::{git_op_in_flight, marker_age_exceeds, reachable_hashes, reclaim_grace};
use crate::staging::{list_staged_files, remove_marker};
use crate::store::{self, object_store_root};

/// One present registered repo, keyed by its common git dir.
struct Member {
    common: PathBuf,
    repo: gix::Repository,
    markers: BTreeSet<String>,
}

pub fn run(force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = RawConfig::load(Some(cwd.as_path()))?;
    if !raw.local_mode || !raw.local_shared {
        bail!("`git-bale prune --shared` must run in a repo using a shared local store");
    }
    let store = object_store_root(&raw)?;

    let (lock, members) = lock_quiescent(&store, force)?;
    // Under the lock, so these are a dead prune's. Another swap on top would
    // leave several `.old.*` dirs and make the restore choice ambiguous.
    let leftovers = store::swap_leftovers(&store)?;
    if !leftovers.is_empty() {
        bail!(
            "an earlier `git-bale prune --shared` left {leftovers:?} next to {}; inspect and \
             remove them (the store itself is intact) before pruning again",
            store.display()
        );
    }

    let mut live: BTreeSet<String> = BTreeSet::new();
    for m in &members {
        live.extend(
            reachable_hashes(&m.repo, &m.common)
                .with_context(|| format!("computing liveness in {}", m.common.display()))?,
        );
    }
    // Same reclaim grace as gc: a just-cleaned marker may not be in any index
    // or ref yet.
    let grace = reclaim_grace();
    let now = SystemTime::now();
    for m in &members {
        for h in &m.markers {
            if !marker_age_exceeds(&m.common, h, grace, now) {
                live.insert(h.clone());
            }
        }
    }

    let in_store = stored_files(&store)?;
    let keep: Vec<(String, u64)> = in_store
        .iter()
        .filter(|(h, _)| live.contains(*h))
        .map(|(h, sz)| (h.clone(), *sz))
        .collect();
    let mut retire: BTreeSet<String> = in_store
        .keys()
        .filter(|h| !live.contains(*h))
        .cloned()
        .collect();
    let reclaimed = retire.len();
    for m in &members {
        retire.extend(m.markers.iter().filter(|h| !live.contains(*h)).cloned());
    }

    // Retire dead bookkeeping BEFORE the swap. If anything after this fails,
    // the dead objects just linger unreferenced; the reverse order could leave
    // a marker or clean-cache entry vouching for bytes the swap deleted.
    for m in &members {
        crate::clean_cache::forget_hashes(&m.common, &retire)
            .with_context(|| format!("invalidating clean-cache in {}", m.common.display()))?;
        for h in m.markers.iter().filter(|h| retire.contains(*h)) {
            remove_marker(&m.common, h)
                .with_context(|| format!("removing marker {h} in {}", m.common.display()))?;
        }
    }
    if reclaimed == 0 {
        println!(
            "git-bale prune: nothing to reclaim ({} live files)",
            keep.len()
        );
        return Ok(());
    }

    let store_name = store
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("store")
        .to_string();
    let new_store = store.with_file_name(format!("{store_name}.compact.{}", std::process::id()));
    std::fs::create_dir_all(&new_store)
        .with_context(|| format!("creating temp store {}", new_store.display()))?;
    let live_sized = keep;
    let kept = live_sized.len();

    if let Err(e) = compact_into(&store, &new_store, live_sized) {
        let _ = std::fs::remove_dir_all(&new_store);
        return Err(e);
    }

    if let Err(e) = copy_registry(
        &store::registry_dir(&store),
        &store::registry_dir(&new_store),
    ) {
        let _ = std::fs::remove_dir_all(&new_store);
        return Err(e).context("copying shared-store registry into the compacted store");
    }
    // Same store, compacted: keep its id, or every repo's clean-cache would
    // read as backed by some other store. Not after `--force` skipped a repo:
    // its clean-cache wasn't retired, so a fresh id (minted by the next
    // clean/register) must make it miss and re-stage instead of re-emitting
    // pointers to content just dropped.
    let skipped_any = store::registered_repos(&store)?.iter().any(|p| !p.exists());
    let id_src = store.join(store::ID_FILE);
    if id_src.exists() && !skipped_any {
        if let Err(e) = std::fs::copy(&id_src, new_store.join(store::ID_FILE)) {
            let _ = std::fs::remove_dir_all(&new_store);
            return Err(e).context("copying the store id into the compacted store");
        }
    }
    // xet doesn't fsync: the compacted copy must be on disk before the old
    // (only other) copy is renamed away and deleted.
    if let Err(e) = fsync_tree(&new_store) {
        let _ = std::fs::remove_dir_all(&new_store);
        return Err(e).context("syncing the compacted store to disk");
    }

    // A crash between these two renames leaves the store path missing; every
    // store user then refuses to run (`store::object_store_root`) until it's
    // restored, rather than recreating an empty store.
    let backup = store.with_file_name(format!("{store_name}.old.{}", std::process::id()));
    std::fs::rename(&store, &backup)
        .with_context(|| format!("moving old store {} aside", store.display()))?;
    if let Err(e) = std::fs::rename(&new_store, &store) {
        if let Err(rb) = std::fs::rename(&backup, &store) {
            return Err(anyhow!(
                "swapping compacted store into place failed ({e}) AND restoring the old \
                 store failed ({rb}); your data is intact at {} — rename it back to {}",
                backup.display(),
                store.display()
            ));
        }
        return Err(e).context("swapping compacted store into place");
    }
    if let Some(parent) = store.parent() {
        fsync_dir(parent).context("syncing the store swap")?;
    }
    if let Err(e) = std::fs::remove_dir_all(&backup) {
        eprintln!(
            "git-bale prune: compacted, but could not delete the old store {}: {e}",
            backup.display()
        );
    }
    drop(lock);

    println!("git-bale prune: reclaimed {reclaimed} unreferenced file(s); {kept} live remain");
    Ok(())
}

/// Take the store lock at a moment no registered repo has a git index/ref
/// update in flight (its clean may have written a marker git hasn't recorded
/// yet). Never waits while holding the lock: that in-flight op's next clean
/// may be blocked on it.
fn lock_quiescent(store: &Path, force: bool) -> Result<(store::StoreLock, Vec<Member>)> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let lock =
            store::StoreLock::acquire_exclusive(store).context("locking shared store for prune")?;
        if let Some(members) = collect_members(store, force, &lock)? {
            return Ok((lock, members));
        }
        drop(lock);
        if Instant::now() > deadline {
            bail!(
                "git operations kept running in a registered repo; re-run \
                 `git-bale prune --shared` when they finish"
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `None` if some registered repo has a git operation in flight.
fn collect_members(
    store: &Path,
    force: bool,
    _held: &store::StoreLock,
) -> Result<Option<Vec<Member>>> {
    let registered = store::registered_repos(store)?;
    if registered.is_empty() {
        bail!("no repos registered against {}", store.display());
    }
    let mut members: Vec<Member> = Vec::new();
    for path in &registered {
        if !path.exists() {
            if force {
                eprintln!(
                    "git-bale prune: registered repo missing, skipping: {}",
                    path.display()
                );
                continue;
            }
            bail!(
                "registered repo {} is missing; content only it references would be deleted. \
                 If it was moved, run `git-bale gc` in its new location (re-registers it); \
                 pass --force only if it is truly gone.",
                path.display()
            );
        }
        let repo = gix::open(path).with_context(|| format!("opening {}", path.display()))?;
        let common = store::common_git_dir(&repo);
        if members.iter().any(|m| m.common == common) {
            continue;
        }
        if git_op_in_flight(&common)? {
            tracing::debug!("prune: git op in flight in {}; waiting", common.display());
            return Ok(None);
        }
        let markers = list_staged_files(&common)
            .with_context(|| format!("listing markers of {}", common.display()))?
            .into_iter()
            .map(|(h, _)| h)
            .collect();
        members.push(Member {
            common,
            repo,
            markers,
        });
    }
    Ok(Some(members))
}

fn compact_into(old: &Path, new: &Path, live_sized: Vec<(String, u64)>) -> Result<()> {
    let rt = XetRuntime::new().context("starting xet runtime")?;
    let old_cfg =
        TranslatorConfig::local_config(old).context("building download config for old store")?;
    let new_cfg =
        TranslatorConfig::local_config(new).context("building upload config for new store")?;
    rt.bridge_sync(async move {
        let dl = FileDownloadSession::new(Arc::new(old_cfg), None).await?;
        let up = FileUploadSession::new(Arc::new(new_cfg)).await?;
        for (file_hex, size) in &live_sized {
            let tmp = NamedTempFile::new().context("temp file for compaction")?;
            let info = XetFileInfo::new(file_hex.clone(), *size);
            let writer = tmp
                .reopen()
                .context("reopening temp file for download write")?;
            dl.download_to_writer(&info, 0..*size, writer)
                .await
                .with_context(|| format!("reconstructing {file_hex} from old store"))?;
            let (new_info, _metrics) = clean_file(up.clone(), tmp.path(), Sha256Policy::Compute)
                .await
                .with_context(|| format!("re-cleaning {file_hex} into new store"))?;
            // Deterministic CDC means the hash must round-trip; a mismatch is
            // corruption or xet version skew — abort before the swap.
            if new_info.hash() != file_hex.as_str() {
                bail!(
                    "compaction hash mismatch for {file_hex} (got {}); aborting before swap",
                    new_info.hash()
                );
            }
        }
        up.finalize().await?;
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error during prune: {e:?}"))?
}

/// Every file the store's shards can reconstruct: hash → size.
pub(crate) fn stored_files(store: &Path) -> Result<BTreeMap<String, u64>> {
    let dir = store.join("xet").join("xorbs").join("shards");
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    let mut out = BTreeMap::new();
    for entry in rd {
        let path = entry?.path();
        if path.extension().is_none_or(|e| e != "mdb") {
            continue;
        }
        let shard = MDBShardFile::load_from_file(&path)
            .map_err(|e| anyhow!("reading shard {}: {e}", path.display()))?;
        for f in shard
            .read_all_file_info_sections()
            .map_err(|e| anyhow!("reading shard {}: {e}", path.display()))?
        {
            out.insert(f.metadata.file_hash.hex(), f.file_size());
        }
    }
    Ok(out)
}

/// Copy every registry file from `src` to `dst`. A failure here must abort the
/// prune before the swap, or repos silently lose their registration.
fn copy_registry(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("creating registry dir {}", dst.display()))?;
    let rd = match std::fs::read_dir(src) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(format!("reading registry {}", src.display())),
    };
    for entry in rd {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        std::fs::copy(entry.path(), dst.join(entry.file_name()))
            .with_context(|| format!("copying registry entry {}", entry.path().display()))?;
    }
    Ok(())
}
