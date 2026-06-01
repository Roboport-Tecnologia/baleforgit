//! `git-bale gc` — reconcile the per-repo staging area against git
//! reachability, dropping xorbs/shards/markers that nothing references.
//!
//! `git add` stages a bale file's xorbs/shards offline (see [`crate::staging`])
//! plus a `<file_hex>` marker; only `git push` (via [`crate::push_pending`])
//! drains them. Without gc, content `git add`ed then abandoned (`git reset`,
//! `git checkout`) lingers forever. Wired into post-checkout/-commit/-merge
//! hooks; safe to run by hand.
//!
//! Safety: everything in staging is unpushed (push-pending wipes the whole dir
//! on success). A staged file is needed iff some pointer git could push
//! references it — in the index, or introduced by a local-but-not-remote commit.
//! Never *under*-count: dropping a marker for committed-but-unpushed content
//! strands it (push-pending drains by marker; lukewarm smudge is marker-gated),
//! so a later push advertises a pointer the server can't reconstruct. Hence we
//! diff each unpushed commit against its first parent and over-retain freely
//! (pruning by remotes only shrinks the live set toward already-pushed content).
//!
//! Xorbs are shared across files by xet-data's local dedup, so per-xorb deletion
//! is unsafe: the object sweep runs only once no marker remains.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use gix::ObjectId;

use crate::clean_cache;
use crate::pointer;
use crate::staging::{
    clear_file_markers, list_staged_files, remove_all_staged_objects, remove_empty_dirs,
    remove_marker, staging_root,
};

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    reconcile(&cwd)
}

/// Reconcile staging for the repo at `start_dir`. Best-effort: any open/read
/// error degrades to "keep more" rather than risk deleting live content.
pub fn reconcile(start_dir: &Path) -> Result<()> {
    let repo = match gix::discover(start_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("git-bale gc: not in a git repo ({e}); nothing to do");
            return Ok(());
        }
    };
    let git_dir = repo.git_dir().to_path_buf();

    let raw = crate::config::RawConfig::load(Some(start_dir)).unwrap_or_else(|e| {
        tracing::debug!("git-bale gc: config load failed ({e}); assuming server mode");
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

    let staging = staging_root(&git_dir);

    let staged = list_staged_files(&git_dir).unwrap_or_default();
    if staged.is_empty() {
        // Common case: nothing pending. Tidy stray empty dirs and exit.
        let _ = remove_empty_dirs(&staging);
        return Ok(());
    }
    let want: BTreeSet<String> = staged.into_iter().map(|(h, _)| h).collect();

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
    let dead: Vec<String> = want
        .iter()
        .filter(|h| !live.contains(*h))
        .cloned()
        .collect();
    if dead.is_empty() {
        return Ok(());
    }

    for h in &dead {
        if let Err(e) = remove_marker(&git_dir, h) {
            tracing::warn!("git-bale gc: removing stale marker {h}: {e}");
        }
    }
    tracing::debug!(
        "git-bale gc: dropped {} orphaned staging marker(s)",
        dead.len()
    );

    // A dropped marker is either pushed (commit on a remote) or orphaned
    // (abandoned before any push). For orphaned hashes the staged bytes are
    // about to be swept and exist nowhere else, yet the clean-cache still maps
    // those worktree bytes to the pointer — so a later `git add` short-circuits
    // to a pointer with no backing (the stage→unstage→stash data-loss bug).
    // Invalidate them; pushed hashes keep their cache (smudge falls to server).
    let orphaned: BTreeSet<String> = if raw.local_mode || remote_tips.is_empty() {
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
    match clean_cache::forget_hashes(&git_dir, &orphaned) {
        Ok(n) if n > 0 => {
            tracing::debug!("git-bale gc: invalidated {n} stale clean-cache entr(ies)")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("git-bale gc: invalidating clean-cache: {e}"),
    }

    // No marker left → nothing references the staged xorbs/shards; sweep them.
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
    Ok(())
}

/// Subset of `want` reachable from the index or commits in `tips`, with
/// `hidden`'s ancestors pruned. Live set: `tips=local, hidden=remotes` ("index
/// or unpushed commit"); orphan check: all refs as tips, nothing hidden
/// ("reachable anywhere"). Stops once every wanted hash is found.
fn reachable_hashes(
    repo: &gix::Repository,
    want: &BTreeSet<String>,
    tips: &[ObjectId],
    hidden: &[ObjectId],
) -> HashSet<String> {
    let mut live = HashSet::new();
    let mut seen_blobs: HashSet<ObjectId> = HashSet::new();

    // Index covers staged-but-uncommitted pointers.
    if let Ok(index) = repo.index_or_empty() {
        use gix::index::entry::Mode;
        for entry in index.entries() {
            if entry.mode != Mode::FILE && entry.mode != Mode::FILE_EXECUTABLE {
                continue;
            }
            consider_blob(repo, entry.id, want, &mut seen_blobs, &mut live);
            if live.len() == want.len() {
                return live;
            }
        }
    }

    // Pointers each walked commit introduces: diff against first parent so we
    // only read the blobs it changed.
    if tips.is_empty() {
        return live;
    }
    let walk = match repo
        .rev_walk(tips.iter().copied())
        .with_hidden(hidden.iter().copied())
        .all()
    {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!("git-bale gc: rev walk failed ({e}); keeping index-reachable only");
            return live;
        }
    };
    for info in walk {
        let Ok(info) = info else { continue };
        let Ok(commit) = info.object() else { continue };
        let Ok(commit_tree) = commit.tree() else {
            continue;
        };
        let parent_tree = info
            .parent_ids()
            .next()
            .and_then(|pid| pid.object().ok())
            .and_then(|o| o.peel_to_commit().ok())
            .and_then(|c| c.tree().ok())
            .unwrap_or_else(|| repo.empty_tree());
        collect_changed_pointers(
            repo,
            &parent_tree,
            &commit_tree,
            want,
            &mut seen_blobs,
            &mut live,
        );
        if live.len() == want.len() {
            return live;
        }
    }
    live
}

/// Split commit ref tips into `(local, remote)`: non-remote refs (plus HEAD for
/// detached) are local, `refs/remotes/*` are remote.
fn ref_tips(repo: &gix::Repository) -> (Vec<ObjectId>, Vec<ObjectId>) {
    let mut tips = Vec::new();
    let mut hidden = Vec::new();

    if let Ok(id) = repo.head_id() {
        let id = id.detach();
        if is_commit(repo, id) {
            tips.push(id);
        }
    }

    let platform = match repo.references() {
        Ok(p) => p,
        Err(_) => return (tips, hidden),
    };
    let iter = match platform.all() {
        Ok(i) => i,
        Err(_) => return (tips, hidden),
    };
    for r in iter {
        let mut r = match r {
            Ok(r) => r,
            Err(_) => continue,
        };
        let is_remote = r.name().as_bstr().starts_with(b"refs/remotes/");
        let id = match r.peel_to_id() {
            Ok(id) => id.detach(),
            Err(_) => continue,
        };
        if !is_commit(repo, id) {
            continue;
        }
        if is_remote {
            hidden.push(id);
        } else {
            tips.push(id);
        }
    }
    (tips, hidden)
}

/// Record Added/Modified blobs between the trees that parse as a wanted pointer.
fn collect_changed_pointers(
    repo: &gix::Repository,
    parent_tree: &gix::Tree<'_>,
    commit_tree: &gix::Tree<'_>,
    want: &BTreeSet<String>,
    seen: &mut HashSet<ObjectId>,
    live: &mut HashSet<String>,
) {
    let mut platform = match parent_tree.changes() {
        Ok(p) => p,
        Err(_) => return,
    };
    // Skip rename tracking (O(N²) similarity): a moved pointer still surfaces
    // as a Deletion + Addition carrying the same blob id.
    platform.options(|opts| {
        opts.track_rewrites(None);
    });
    let _ = platform.for_each_to_obtain_tree(
        commit_tree,
        |change| -> Result<gix::object::tree::diff::Action, std::convert::Infallible> {
            use gix::object::tree::diff::Change;
            if let Change::Addition { entry_mode, id, .. }
            | Change::Modification { entry_mode, id, .. } = change
            {
                if entry_mode.is_blob() {
                    consider_blob(repo, id.detach(), want, seen, live);
                    if live.len() == want.len() {
                        return Ok(std::ops::ControlFlow::Break(()));
                    }
                }
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    );
}

/// Record `oid`'s file hash as live if it's a small blob parsing as a wanted
/// pointer. Pre-filters (seen dedup, header size/kind) avoid inflating non-pointers.
fn consider_blob(
    repo: &gix::Repository,
    oid: ObjectId,
    want: &BTreeSet<String>,
    seen: &mut HashSet<ObjectId>,
    live: &mut HashSet<String>,
) {
    if !seen.insert(oid) {
        return;
    }
    let header = match repo.find_header(oid) {
        Ok(h) => h,
        Err(_) => return,
    };
    if header.kind() != gix::object::Kind::Blob
        || header.size() == 0
        || header.size() > pointer::POINTER_MAX_BYTES as u64
    {
        return;
    }
    let obj = match repo.find_object(oid) {
        Ok(o) => o,
        Err(_) => return,
    };
    if let Ok(info) = pointer::parse_pointer(&obj.data) {
        let h = info.hash().to_string();
        if want.contains(&h) {
            live.insert(h);
        }
    }
}

/// File-hashes in `want` reachable from `repo`'s index or ANY ref (no hiding).
/// Shared by `git-bale prune`.
pub fn reachable_all(repo: &gix::Repository, want: &BTreeSet<String>) -> HashSet<String> {
    let (local_tips, remote_tips) = ref_tips(repo);
    let mut all = local_tips;
    all.extend(remote_tips);
    reachable_hashes(repo, want, &all, &[])
}

fn is_commit(repo: &gix::Repository, oid: ObjectId) -> bool {
    repo.find_header(oid)
        .is_ok_and(|h| h.kind() == gix::object::Kind::Commit)
}
