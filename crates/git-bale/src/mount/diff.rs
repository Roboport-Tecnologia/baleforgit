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
    Renamed,
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
    platform
        .for_each_to_obtain_tree(
            &tree_b,
            |change| -> Result<Action, std::convert::Infallible> {
                if let Some(entry) = change_to_entry(change) {
                    entries.push(entry);
                }
                Ok(std::ops::ControlFlow::Continue(()))
            },
        )
        .context("walking tree diff")?;

    if paths.is_empty() {
        Ok(entries)
    } else {
        Ok(entries
            .into_iter()
            .filter(|e| path_matches(e, paths))
            .collect())
    }
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
        Change::Rewrite {
            source_location,
            source_id,
            location,
            id,
            entry_mode,
            ..
        } => {
            if !entry_mode.is_blob() {
                return None;
            }
            Some(DiffEntry {
                path_a: Some(bstr_string(source_location)),
                path_b: Some(bstr_string(location)),
                oid_a: Some(source_id.to_string()),
                oid_b: Some(id.to_string()),
                status: DiffStatus::Renamed,
            })
        }
    }
}

fn bstr_string(b: &gix::bstr::BStr) -> String {
    b.to_str_lossy().into_owned()
}

/// Literal prefix matching only — no globbing. `src/` matches anything under
/// src/, `docs/foo.md` matches that exact file.
fn path_matches(entry: &DiffEntry, filters: &[String]) -> bool {
    let candidates: [Option<&String>; 2] = [entry.path_a.as_ref(), entry.path_b.as_ref()];
    for path_opt in candidates {
        let Some(path) = path_opt else { continue };
        for f in filters {
            let f = f.trim_end_matches('/');
            if path == f || path.starts_with(&format!("{f}/")) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn build_repo() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let p = dir.path();
        let run = |args: &[&str]| {
            let st = Command::new("git")
                .args(args)
                .current_dir(p)
                .status()
                .unwrap();
            assert!(st.success(), "git {args:?} failed");
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "a@b.c"]);
        run(&["config", "user.name", "Tester"]);
        run(&["config", "commit.gpgsign", "false"]);

        std::fs::write(p.join("a.txt"), "hello\n").unwrap();
        std::fs::write(p.join("b.txt"), "world\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "first"]);

        std::fs::write(p.join("a.txt"), "hello, world!\n").unwrap();
        std::fs::remove_file(p.join("b.txt")).unwrap();
        std::fs::write(p.join("c.txt"), "new\n").unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "second"]);
        dir
    }

    #[test]
    fn diffs_two_commits() {
        let dir = build_repo();
        let entries = run_diff(dir.path(), "HEAD~1", "HEAD", &[]).unwrap();
        let statuses: Vec<&DiffStatus> = entries.iter().map(|e| &e.status).collect();
        assert!(statuses.contains(&&DiffStatus::Modified));
        assert!(statuses.contains(&&DiffStatus::Deleted));
        assert!(statuses.contains(&&DiffStatus::Added));
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn rev_parse_resolves_short_refs() {
        let dir = build_repo();
        let head = rev_parse_commit(dir.path(), "HEAD").unwrap();
        assert_eq!(head.len(), 40);
        let main = rev_parse_commit(dir.path(), "main").unwrap();
        assert_eq!(head, main);
    }

    #[test]
    fn pathspec_filters_to_subset() {
        let dir = build_repo();
        let only_a = run_diff(dir.path(), "HEAD~1", "HEAD", &["a.txt".to_string()]).unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].path_b.as_deref(), Some("a.txt"));
    }

    #[test]
    fn equal_revs_are_caught() {
        let dir = build_repo();
        assert!(ensure_distinct_commits(dir.path(), "HEAD", "main").is_err());
    }

    #[test]
    fn rename_detected() {
        let dir = tempdir().unwrap();
        let p = dir.path();
        let run = |args: &[&str]| {
            let st = Command::new("git")
                .args(args)
                .current_dir(p)
                .status()
                .unwrap();
            assert!(st.success(), "git {args:?} failed");
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "a@b.c"]);
        run(&["config", "user.name", "Tester"]);
        run(&["config", "commit.gpgsign", "false"]);
        std::fs::write(p.join("old.txt"), "content\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "init"]);
        std::fs::rename(p.join("old.txt"), p.join("new.txt")).unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "rename"]);

        let entries = run_diff(p, "HEAD~1", "HEAD", &[]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, DiffStatus::Renamed);
        assert_eq!(entries[0].path_a.as_deref(), Some("old.txt"));
        assert_eq!(entries[0].path_b.as_deref(), Some("new.txt"));
    }
}
