//! `git-bale gc` — reconcile the per-repo staging area against git
//! reachability, dropping xorbs/shards/markers that nothing references.
//!
//! `git add` stages a bale file's xorbs/shards offline (see [`crate::staging`])
//! and writes a `<file_hex>` marker; only a successful `git push` (via
//! [`crate::push_pending`]) drains them. If you `git add` a change and then
//! abandon it (`git reset`, `git checkout`), the staged bytes used to linger
//! forever. This command finds staged file hashes that no longer appear in the
//! index or any *unpushed* commit and forgets them. It's wired into
//! post-checkout/post-commit/post-merge hooks by `git-bale install --local`,
//! and is safe to run by hand anytime.
//!
//! ## Why reachability, and why it's safe
//!
//! Everything in staging is, by construction, unpushed: push-pending wipes the
//! whole dir on success, so anything present was `git add`ed since the last
//! push. A staged file is therefore still needed iff some pointer git could
//! push references it — i.e. it's in the index or introduced by a commit
//! reachable from a local ref but not yet on a remote. We compute that set and
//! keep its markers; the rest are dangling and safe to forget.
//!
//! The set must never *under*-count: dropping a marker for committed-but-
//! unpushed content would strand that content (push-pending drains by marker;
//! the lukewarm smudge path is gated on the marker), so a later push would
//! advertise a pointer the server can't reconstruct. To stay conservative we
//! diff each unpushed commit against its first parent — covering stacked
//! commits whose tip no longer names an older version — and we over-retain
//! freely (pruning by remotes only ever *shrinks* the live set toward content
//! the server already has, which is safe to drop).
//!
//! Xorbs are shared across files by xet-data's local dedup, so we never delete
//! an individual xorb while any marker survives. The object sweep runs only
//! once no marker remains — the same all-or-nothing wipe push-pending does.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;

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

/// Reconcile staging for the repo containing `start_dir`. Best-effort: a repo
/// that can't be opened, or any per-object read error, degrades to "keep more"
/// rather than risking deletion of live content.
pub fn reconcile(start_dir: &Path) -> Result<()> {
    let repo = match gix::discover(start_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("git-bale gc: not in a git repo ({e}); nothing to do");
            return Ok(());
        }
    };
    let git_dir = repo.git_dir().to_path_buf();
    let staging = staging_root(&git_dir);

    let staged = list_staged_files(&git_dir).unwrap_or_default();
    if staged.is_empty() {
        // Common case (most checkouts): nothing pending. Tidy any empty tree
        // a prior partial run may have left, then exit cheaply.
        let _ = remove_empty_dirs(&staging);
        return Ok(());
    }
    let want: BTreeSet<String> = staged.into_iter().map(|(h, _)| h).collect();

    let (local_tips, remote_tips) = ref_tips(&repo);
    let live = reachable_hashes(&repo, &want, &local_tips, &remote_tips);
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

    // A dropped marker means the content is either pushed (its commit is on a
    // remote) or genuinely orphaned (unstaged/abandoned before any push). In the
    // orphaned case the staged bytes are about to be swept and exist nowhere
    // else — yet the path-keyed clean-cache still maps the same worktree bytes
    // to that pointer, so a later `git add` would short-circuit to a pointer
    // with no retrievable backing (the stage→unstage→stash data-loss bug).
    // Invalidate those entries so the re-add does a full clean + re-stage.
    // Pushed hashes keep their cache: their smudge correctly falls to the server.
    let orphaned: BTreeSet<String> = if remote_tips.is_empty() {
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

    // No marker left → nothing references the staged xorbs/shards. Sweep them
    // (same wipe push-pending performs after a successful drain).
    let remaining = list_staged_files(&git_dir).map(|v| v.len()).unwrap_or(0);
    if remaining == 0 {
        let _ = clear_file_markers(&git_dir);
        if let Err(e) = remove_all_staged_objects(&staging) {
            tracing::warn!("git-bale gc: sweeping staged objects: {e}");
        }
        let _ = remove_empty_dirs(&staging);
    }
    Ok(())
}

/// Returns the subset of `want` (staged file hashes) reachable from the index
/// or from commits in `tips` (with `hidden`'s ancestors pruned). The live set
/// passes `tips = local refs`, `hidden = remotes` to mean "index or unpushed
/// commit"; the orphan check passes all refs as tips with nothing hidden to
/// mean "reachable anywhere". Stops as soon as every wanted hash is accounted
/// for — the common "you just staged it" case resolves from the index without
/// touching history.
fn reachable_hashes(
    repo: &gix::Repository,
    want: &BTreeSet<String>,
    tips: &[ObjectId],
    hidden: &[ObjectId],
) -> HashSet<String> {
    let mut live = HashSet::new();
    let mut seen_blobs: HashSet<ObjectId> = HashSet::new();

    // 1. Index — covers staged-but-uncommitted pointers.
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

    // 2. Pointers introduced by the walked commits, diffing each against its
    //    first parent so we only read the blobs it actually changed.
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

/// Split commit ref tips into `(local, remote)`: every non-remote ref (plus
/// HEAD, for a detached checkout) is local; `refs/remotes/*` are remote. The
/// live walk uses remotes as `hidden` (prune content already pushed); the
/// orphan check walks local+remote as tips (reachable anywhere).
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

/// Walk the Added/Modified blobs between `parent_tree` and `commit_tree`,
/// recording any that parse as a bale pointer whose hash is wanted.
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
    // Rename tracking would force an O(N²) similarity pass we don't need — a
    // moved pointer still surfaces as a Deletion + Addition, and the Addition
    // carries the same blob id we'd inspect anyway.
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

/// If `oid` is a small blob that parses as a bale pointer whose file hash is in
/// `want`, record that hash as live. Cheap pre-filters first: dedup via `seen`,
/// then a header-only size/kind check so we never inflate a non-pointer blob.
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

fn is_commit(repo: &gix::Repository, oid: ObjectId) -> bool {
    repo.find_header(oid)
        .is_ok_and(|h| h.kind() == gix::object::Kind::Commit)
}
