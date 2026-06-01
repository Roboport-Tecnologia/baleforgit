//! `git-bale prune --shared` — reclaim a shared local store by compacting it
//! down to the files reachable across every registered repo.
//!
//! Must run when no `git add` operations are in flight on any registered repo:
//! it holds the shared `StoreLock` (excludes gc/clean/push-pending/other prunes)
//! and aborts if the store changes mid-run (defense-in-depth fingerprint guard).
//!
//! Precise per-xorb CAS sweeping would require parsing xet shards; instead we
//! rebuild the store: reconstruct each live file from the old store and re-clean
//! it into a fresh one (deterministic CDC re-dedups), then atomically swap. This
//! reuses the same local→local round-trip push-pending uses and is obviously
//! correct. Holds a lockfile; aborts if a registered repo is missing (its
//! objects might be the only copy) unless `--force`.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tempfile::NamedTempFile;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::clean_file;
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::staging::list_staged_files;
use crate::store::{self, object_store_root};

pub fn run(force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = RawConfig::load(Some(cwd.as_path()))?;
    if !raw.local_mode || !raw.local_shared {
        bail!("`git-bale prune --shared` must run in a repo using a shared local store");
    }
    let store = object_store_root(&raw)?;

    let _store_lock = crate::store::StoreLock::acquire_exclusive(&store)
        .context("locking shared store for prune")?;
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
        println!(
            "git-bale prune: nothing to reclaim ({} live files)",
            live.len()
        );
        return Ok(());
    }

    let sizes = collect_sizes(&repos, &live)?;

    // Snapshot the store contents now; we'll re-check just before the swap to
    // detect a concurrent `git add` that would otherwise be silently destroyed.
    let before = object_fingerprint(&store);

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

    let old_cfg =
        TranslatorConfig::local_config(&store).context("building download config for old store")?;
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
            let info = XetFileInfo::new(file_hex.clone(), *size);
            let writer = tmp
                .reopen()
                .context("reopening temp file for download write")?;
            let (_id, _n) = dl
                .download_to_writer(&info, 0..*size, writer)
                .await
                .with_context(|| format!("reconstructing {file_hex} from old store"))?;
            let (new_info, _metrics) = clean_file(up.clone(), tmp.path(), Sha256Policy::Compute)
                .await
                .with_context(|| format!("re-cleaning {file_hex} into new store"))?;
            // Deterministic CDC means the hash must round-trip; a mismatch
            // indicates corruption or xet version skew — abort before swap.
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
    .map_err(|e| anyhow!("xet runtime error during prune: {e:?}"))??;

    // Abort if the store changed while we were reconstructing — a concurrent
    // `git add` landed new objects that would be destroyed by the swap.
    let after = object_fingerprint(&store);
    if before != after {
        let _ = std::fs::remove_dir_all(&new_store);
        bail!(
            "the shared store at {} changed during prune (a concurrent `git add`?) — \
             no changes made. Re-run `git-bale prune --shared` when no git operations \
             are in flight.",
            store.display()
        );
    }

    // Carry the registry over — failure here aborts before the swap; the old
    // store is still intact so aborting is safe.
    let new_registry = store::registry_dir(&new_store);
    if let Err(e) = copy_registry(&store::registry_dir(&store), &new_registry) {
        let _ = std::fs::remove_dir_all(&new_store);
        return Err(e).context("copying shared-store registry into the compacted store");
    }

    let backup = store.with_file_name(format!(
        "{}.old.{}",
        store
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("store"),
        std::process::id()
    ));
    std::fs::rename(&store, &backup)
        .with_context(|| format!("moving old store {} aside", store.display()))?;
    if let Err(e) = std::fs::rename(&new_store, &store) {
        // Roll back: never leave the store missing.
        let _ = std::fs::rename(&backup, &store);
        return Err(e).context("swapping compacted store into place");
    }
    std::fs::remove_dir_all(&backup).ok();

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
) -> Result<HashMap<String, u64>> {
    let mut sizes: HashMap<String, u64> = HashMap::new();
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
            tracing::warn!(
                "prune: opening {} failed: {e}; treating as no refs",
                git_dir.display()
            );
            return Ok(BTreeSet::new());
        }
    };
    Ok(crate::gc::reachable_all(&repo, want).into_iter().collect())
}

/// Sorted names of every xorb/shard object anywhere under `dir` — a cheap
/// fingerprint of store contents to detect a concurrent `git add` mid-prune.
fn object_fingerprint(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in walkdir_files(dir) {
        let fname = entry.file_name();
        if let Some(name) = fname.to_str() {
            if name.starts_with("default.") || name.ends_with(".mdb") {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// Recursive file-entry walk under `dir`; NotFound yields empty, per-entry
/// errors are logged at debug and skipped.
fn walkdir_files(dir: &Path) -> Vec<std::fs::DirEntry> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::debug!("prune fingerprint: read_dir {}: {e}", dir.display());
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for entry in rd {
        match entry {
            Ok(e) => {
                let ft = match e.file_type() {
                    Ok(ft) => ft,
                    Err(e) => {
                        tracing::debug!("prune fingerprint: file_type: {e}");
                        continue;
                    }
                };
                if ft.is_dir() {
                    out.extend(walkdir_files(&e.path()));
                } else {
                    out.push(e);
                }
            }
            Err(e) => tracing::debug!("prune fingerprint: entry: {e}"),
        }
    }
    out
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
