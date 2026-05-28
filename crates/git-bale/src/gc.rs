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

    let live = collect_live_hashes(&repo, &want);
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

/// Returns the subset of `want` (staged file hashes) that is still referenced
/// by the index or an unpushed commit. Stops as soon as every wanted hash is
/// accounted for — the common "you just staged it" case resolves from the
/// index without touching history.
fn collect_live_hashes(repo: &gix::Repository, want: &BTreeSet<String>) -> HashSet<String> {
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

    // 2. Pointers introduced by unpushed commits: walk local refs, hide what
    //    the remotes already have, and diff each commit against its first
    //    parent so we only read the blobs it actually changed.
    let (tips, hidden) = ref_tips(repo);
    if tips.is_empty() {
        return live;
    }
    let walk = match repo.rev_walk(tips).with_hidden(hidden).all() {
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

/// Collect ref tips for the rev walk: every non-remote ref (plus HEAD, for a
/// detached checkout) becomes a starting tip; remote-tracking refs become
/// "hidden" so their ancestors — content already on a remote — are pruned.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    use xet_data::processing::XetFileInfo;

    use crate::staging::{file_is_staged, mark_file_staged};

    fn git(args: &[&str], dir: &Path) {
        let st = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?} failed");
    }

    fn init_repo(dir: &Path) {
        git(&["init", "-q", "-b", "main"], dir);
        git(&["config", "user.email", "a@b.c"], dir);
        git(&["config", "user.name", "Tester"], dir);
        git(&["config", "commit.gpgsign", "false"], dir);
    }

    /// Write a bale pointer file at `rel` whose merkle hash is `hash_hex`.
    fn write_pointer(dir: &Path, rel: &str, hash_hex: &str) {
        let info = XetFileInfo::new_with_sha256(hash_hex.to_string(), 4096, "0".repeat(64));
        let bytes = pointer::encode_pointer(&info).unwrap();
        std::fs::write(dir.join(rel), bytes).unwrap();
    }

    fn git_dir_of(dir: &Path) -> PathBuf {
        dir.join(".git")
    }

    fn stage_xorb(git_dir: &Path) -> PathBuf {
        let xorbs = staging_root(git_dir).join("xet/xorbs/xorbs");
        std::fs::create_dir_all(&xorbs).unwrap();
        let p = xorbs.join(format!("default.{}", "0".repeat(64)));
        std::fs::write(&p, b"xorb-bytes").unwrap();
        p
    }

    #[test]
    fn dangling_marker_triggers_full_sweep() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        // A commit with no bale pointers at all.
        std::fs::write(dir.path().join("readme.txt"), "hi\n").unwrap();
        git(&["add", "."], dir.path());
        git(&["commit", "-q", "-m", "init"], dir.path());

        let git_dir = git_dir_of(dir.path());
        let dangling = "a".repeat(64);
        mark_file_staged(&git_dir, &dangling, 4096).unwrap();
        let xorb = stage_xorb(&git_dir);

        reconcile(dir.path()).unwrap();

        assert!(
            !file_is_staged(&git_dir, &dangling),
            "dangling marker should be gone"
        );
        assert!(
            !xorb.exists(),
            "orphaned xorb should be swept once no marker remains"
        );
    }

    #[test]
    fn committed_pointer_marker_survives_and_xorb_kept() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let live_hash = "a".repeat(64);
        write_pointer(dir.path(), "f.bin", &live_hash);
        git(&["add", "f.bin"], dir.path());
        git(&["commit", "-q", "-m", "add pointer"], dir.path());

        let git_dir = git_dir_of(dir.path());
        let dangling = "b".repeat(64);
        mark_file_staged(&git_dir, &live_hash, 4096).unwrap();
        mark_file_staged(&git_dir, &dangling, 4096).unwrap();
        let xorb = stage_xorb(&git_dir);

        reconcile(dir.path()).unwrap();

        assert!(
            file_is_staged(&git_dir, &live_hash),
            "committed pointer's marker must survive"
        );
        assert!(
            !file_is_staged(&git_dir, &dangling),
            "dangling marker should be dropped"
        );
        // A live marker remains, so the shared xorb must NOT be swept.
        assert!(
            xorb.exists(),
            "xorb must be kept while a live marker remains"
        );
    }

    #[test]
    fn staged_in_index_but_uncommitted_survives() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let live_hash = "c".repeat(64);
        write_pointer(dir.path(), "f.bin", &live_hash);
        git(&["add", "f.bin"], dir.path()); // staged, never committed

        let git_dir = git_dir_of(dir.path());
        mark_file_staged(&git_dir, &live_hash, 4096).unwrap();

        reconcile(dir.path()).unwrap();
        assert!(
            file_is_staged(&git_dir, &live_hash),
            "index-staged pointer must survive gc"
        );
    }

    #[test]
    fn stacked_unpushed_commit_old_version_survives() {
        // C1 adds v1 (hash A); C2 rewrites the same path to v2 (hash B). The
        // tip only names B, but a push would upload C1 too, so A's staging
        // must survive — this is the data-loss guard.
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        write_pointer(dir.path(), "f.bin", &a);
        git(&["add", "f.bin"], dir.path());
        git(&["commit", "-q", "-m", "v1"], dir.path());
        write_pointer(dir.path(), "f.bin", &b);
        git(&["add", "f.bin"], dir.path());
        git(&["commit", "-q", "-m", "v2"], dir.path());

        let git_dir = git_dir_of(dir.path());
        mark_file_staged(&git_dir, &a, 4096).unwrap();
        mark_file_staged(&git_dir, &b, 4096).unwrap();

        reconcile(dir.path()).unwrap();
        assert!(
            file_is_staged(&git_dir, &a),
            "older unpushed version (C1) must survive gc"
        );
        assert!(
            file_is_staged(&git_dir, &b),
            "tip version (C2) must survive gc"
        );
    }

    #[test]
    fn pushed_commit_is_pruned_so_its_marker_is_dropped() {
        // Simulate "already pushed": a remote-tracking ref at the same commit
        // hides it from the walk. The pointer is committed but considered on
        // the server, so a leftover staging marker for it is safe to drop and
        // (being the only marker) triggers the sweep.
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let pushed = "d".repeat(64);
        write_pointer(dir.path(), "f.bin", &pushed);
        git(&["add", "f.bin"], dir.path());
        git(&["commit", "-q", "-m", "pushed"], dir.path());
        // Mark HEAD as already on a remote.
        git(
            &["update-ref", "refs/remotes/origin/main", "HEAD"],
            dir.path(),
        );
        // Move the local index off the pointer so it isn't kept via the index
        // scan — emulating a later checkout where the file is gone.
        std::fs::remove_file(dir.path().join("f.bin")).unwrap();
        git(&["rm", "-q", "--cached", "f.bin"], dir.path());

        let git_dir = git_dir_of(dir.path());
        mark_file_staged(&git_dir, &pushed, 4096).unwrap();
        let xorb = stage_xorb(&git_dir);

        reconcile(dir.path()).unwrap();
        assert!(
            !file_is_staged(&git_dir, &pushed),
            "pushed content's marker should be dropped"
        );
        assert!(!xorb.exists(), "xorb swept once the only marker is gone");
    }
}
