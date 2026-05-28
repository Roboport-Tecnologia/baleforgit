//! Compute the changed-files set between two commits using `gix` (pure Rust,
//! no shell-out).
//!
//! Each entry has an optional path/OID on each side. We never look at the
//! working tree — only committed trees are compared. Rename/copy detection
//! is on by default (matching `git diff`).

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use gix::bstr::ByteSlice;
use gix::object::tree::diff::{Action, Change};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffStatus {
    Added,
    Deleted,
    Modified,
    /// Mode-only changes etc.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    pub path_a: Option<String>,
    pub path_b: Option<String>,
    pub oid_a: Option<String>,
    pub oid_b: Option<String>,
    pub status: DiffStatus,
}

pub fn rev_parse_commit(repo_path: &Path, rev: &str) -> Result<String> {
    let repo = gix::open(repo_path)
        .with_context(|| format!("opening git repo at {}", repo_path.display()))?;
    let resolved = repo
        .rev_parse_single(rev)
        .with_context(|| format!("git rev-parse {rev}"))?;
    let obj = resolved
        .object()
        .with_context(|| format!("loading object for {rev}"))?;
    let commit = obj
        .peel_to_commit()
        .with_context(|| format!("{rev} does not point to a commit"))?;
    Ok(commit.id.to_string())
}

pub fn ensure_distinct_commits(repo_path: &Path, rev_a: &str, rev_b: &str) -> Result<()> {
    let a = rev_parse_commit(repo_path, rev_a)?;
    let b = rev_parse_commit(repo_path, rev_b)?;
    if a == b {
        return Err(anyhow!("{rev_a} and {rev_b} both resolve to {a}"));
    }
    Ok(())
}

pub fn run_diff(
    repo_path: &Path,
    rev_a: &str,
    rev_b: &str,
    paths: &[String],
) -> Result<Vec<DiffEntry>> {
    let repo = gix::open(repo_path)
        .with_context(|| format!("opening git repo at {}", repo_path.display()))?;
    let tree_a = resolve_tree(&repo, rev_a)?;
    let tree_b = resolve_tree(&repo, rev_b)?;

    let mut entries: Vec<DiffEntry> = Vec::new();
    let mut platform = tree_a.changes().context("starting tree diff")?;
    // Disable rename tracking. gix would otherwise run an O(N²) similarity
    // pass over every Del/Add pair after the walk to pair renames into
    // `Change::Rewrite`. mount-diff trades that pairing for the speedup —
    // a renamed file shows up as a Deletion at the old path and an Addition
    // at the new path, not as a labelled pair at related basenames.
    platform.options(|opts| {
        opts.track_rewrites(None);
    });
    platform
        .for_each_to_obtain_tree(
            &tree_b,
            |change| -> Result<Action, std::convert::Infallible> {
                // Apply the pathspec on the BStr location before we allocate
                // OID / path strings — for a wide diff with a narrow filter
                // that's most of the work.
                if !change_in_pathspec(&change, paths) {
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                if let Some(entry) = change_to_entry(change) {
                    entries.push(entry);
                }
                Ok(std::ops::ControlFlow::Continue(()))
            },
        )
        .context("walking tree diff")?;
    Ok(entries)
}

fn resolve_tree<'r>(repo: &'r gix::Repository, rev: &str) -> Result<gix::Tree<'r>> {
    let resolved = repo
        .rev_parse_single(rev)
        .with_context(|| format!("git rev-parse {rev}"))?;
    let obj = resolved
        .object()
        .with_context(|| format!("loading {rev}"))?;
    let commit = obj
        .peel_to_commit()
        .with_context(|| format!("{rev} does not point to a commit"))?;
    let tree = commit
        .tree()
        .with_context(|| format!("loading tree for {rev}"))?;
    Ok(tree)
}

fn change_to_entry(change: Change<'_, '_, '_>) -> Option<DiffEntry> {
    match change {
        Change::Addition {
            location,
            id,
            entry_mode,
            ..
        } => {
            if !entry_mode.is_blob() {
                return None;
            }
            Some(DiffEntry {
                path_a: None,
                path_b: Some(bstr_string(location)),
                oid_a: None,
                oid_b: Some(id.to_string()),
                status: DiffStatus::Added,
            })
        }
        Change::Deletion {
            location,
            id,
            entry_mode,
            ..
        } => {
            if !entry_mode.is_blob() {
                return None;
            }
            Some(DiffEntry {
                path_a: Some(bstr_string(location)),
                path_b: None,
                oid_a: Some(id.to_string()),
                oid_b: None,
                status: DiffStatus::Deleted,
            })
        }
        Change::Modification {
            location,
            previous_id,
            id,
            entry_mode,
            previous_entry_mode,
            ..
        } => {
            if !entry_mode.is_blob() && !previous_entry_mode.is_blob() {
                return None;
            }
            // Mode-only change → no point including in the mount, both
            // sides would show identical bytes.
            if previous_id.as_ref() == id.as_ref() {
                return None;
            }
            Some(DiffEntry {
                path_a: Some(bstr_string(location)),
                path_b: Some(bstr_string(location)),
                oid_a: Some(previous_id.to_string()),
                oid_b: Some(id.to_string()),
                status: DiffStatus::Modified,
            })
        }
        // Rename tracking is disabled in `run_diff`, so `Rewrite` is never
        // emitted by the walker. Explicit arm keeps the match exhaustive.
        Change::Rewrite { .. } => None,
    }
}

fn bstr_string(b: &gix::bstr::BStr) -> String {
    b.to_str_lossy().into_owned()
}

/// A change passes the pathspec if either side's location matches a filter.
/// Empty filter list lets everything through.
fn change_in_pathspec(change: &Change<'_, '_, '_>, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    match change {
        Change::Addition { location, .. }
        | Change::Modification { location, .. }
        | Change::Deletion { location, .. } => bstr_path_matches(location, filters),
        // Rewrites are disabled at the platform level — see `run_diff`.
        Change::Rewrite { .. } => false,
    }
}

/// Literal prefix matching on raw path bytes — no globbing. `src/` matches
/// anything under `src/`, `docs/foo.md` matches that exact file.
fn bstr_path_matches(location: &gix::bstr::BStr, filters: &[String]) -> bool {
    let bytes: &[u8] = location.as_ref();
    filters.iter().any(|f| {
        let f = f.trim_end_matches('/').as_bytes();
        if f.is_empty() {
            return true;
        }
        bytes == f || (bytes.len() > f.len() && bytes.starts_with(f) && bytes[f.len()] == b'/')
    })
}
