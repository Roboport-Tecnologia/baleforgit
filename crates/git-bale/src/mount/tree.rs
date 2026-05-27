//! List every blob in a commit's tree. Used by `git-bale mount` (single-rev
//! mode) to enumerate the files to expose under the mount point.

use std::path::Path;

use anyhow::{Context, Result};
use gix::bstr::ByteSlice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub path: String,
    pub oid: String,
}

pub fn walk_rev(repo_path: &Path, rev: &str, paths: &[String]) -> Result<Vec<TreeEntry>> {
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
    let tree = commit
        .tree()
        .with_context(|| format!("loading tree for {rev}"))?;

    let files = tree
        .traverse()
        .breadthfirst
        .files()
        .with_context(|| format!("walking tree at {rev}"))?;

    let mut entries: Vec<TreeEntry> = files
        .into_iter()
        .filter(|e| e.mode.is_blob())
        .map(|e| TreeEntry {
            path: e.filepath.to_str_lossy().into_owned(),
            oid: e.oid.to_string(),
        })
        .collect();

    if !paths.is_empty() {
        entries.retain(|e| any_filter_matches(&e.path, paths));
    }
    Ok(entries)
}

fn any_filter_matches(path: &str, filters: &[String]) -> bool {
    for f in filters {
        let f = f.trim_end_matches('/');
        if path == f || path.starts_with(&format!("{f}/")) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn make_repo() -> tempfile::TempDir {
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
        std::fs::create_dir(p.join("src")).unwrap();
        std::fs::write(p.join("src/lib.rs"), "// lib\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "init"]);
        dir
    }

    #[test]
    fn walk_lists_all_blobs() {
        let dir = make_repo();
        let entries = walk_rev(dir.path(), "HEAD", &[]).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"a.txt"));
        assert!(paths.contains(&"src/lib.rs"));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn pathspec_filters() {
        let dir = make_repo();
        let entries = walk_rev(dir.path(), "HEAD", &["src".into()]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "src/lib.rs");
    }
}
