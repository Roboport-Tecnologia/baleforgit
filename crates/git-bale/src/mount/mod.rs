//! `git-bale mount-diff` — mounts a read-only virtual filesystem that exposes
//! both sides of a `git diff <revA> <revB>` as files named with the revision
//! label embedded in the basename (`foo__<labelA>.ext` / `foo__<labelB>.ext`).
//!
//! No bytes are copied to disk: each `read` call hits git's object database
//! (for non-Bale blobs) or the chunk cache + network reconstruction (for Bale
//! pointers).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use crate::config::RawConfig;
use crate::mount::backend::libfuse::LibfuseBackend;
use crate::mount::backend::MountBackend;
use crate::mount::diff::DiffEntry;
use crate::mount::vfs::{DiffVfs, ROOT_INODE};

pub mod backend;
pub mod diff;
pub mod reader;
pub mod vfs;

#[derive(Debug, Clone)]
pub struct MountDiffArgs {
    pub rev_a: String,
    pub rev_b: String,
    pub mount_point: PathBuf,
    pub label_a: Option<String>,
    pub label_b: Option<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MountRevArgs {
    pub rev: String,
    pub mount_point: PathBuf,
    pub paths: Vec<String>,
}

pub fn run_rev(args: MountRevArgs) -> Result<()> {
    if let Err(e) = backend::libfuse::ensure_available() {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let cwd = std::env::current_dir().context("resolving cwd")?;
    let repo = Arc::new(
        gix::ThreadSafeRepository::open(&cwd)
            .with_context(|| format!("opening git repo at {}", cwd.display()))?,
    );
    let (commit_id, tree_oid) = resolve_commit_and_tree(&repo, &args.rev)
        .with_context(|| format!("resolving {}", args.rev))?;

    let raw = RawConfig::load(Some(cwd.as_path())).context("loading bale config")?;
    let reader = Arc::new(reader::Reader::new(repo.clone(), raw).context("starting blob reader")?);
    let vfs = Arc::new(DiffVfs::build_single_lazy(
        repo,
        tree_oid,
        args.paths.clone(),
        reader,
    ));

    // Single eager probe of the root so an empty or mis-targeted mount fails
    // here with a clear message rather than mounting silently empty. Costs
    // one tree-object read; the populated children stay cached for the real
    // readdir later.
    if vfs
        .readdir(ROOT_INODE)
        .map(|e| e.is_empty())
        .unwrap_or(true)
    {
        return Err(anyhow!(
            "no files in {}{}",
            args.rev,
            if args.paths.is_empty() {
                String::new()
            } else {
                format!(" under {:?}", args.paths)
            }
        ));
    }

    eprintln!(
        "git-bale: mounting {} ({}) at {} (lazy)",
        args.rev,
        &commit_id.to_string()[..12.min(commit_id.to_string().len())],
        args.mount_point.display(),
    );

    let backend = LibfuseBackend::new();
    backend.mount(&args.mount_point, vfs)
}

fn resolve_commit_and_tree(
    repo: &gix::ThreadSafeRepository,
    rev: &str,
) -> Result<(gix::ObjectId, gix::ObjectId)> {
    let local = repo.to_thread_local();
    let resolved = local
        .rev_parse_single(rev)
        .with_context(|| format!("git rev-parse {rev}"))?;
    let obj = resolved
        .object()
        .with_context(|| format!("loading object for {rev}"))?;
    let commit = obj
        .peel_to_commit()
        .with_context(|| format!("{rev} does not point to a commit"))?;
    let tree_id = commit
        .tree_id()
        .with_context(|| format!("loading tree for {rev}"))?;
    Ok((commit.id, tree_id.detach()))
}

pub fn run(args: MountDiffArgs) -> Result<()> {
    // Fail fast with a friendly install hint if libfuse / fuse-t isn't on the
    // machine — don't validate refs and run the diff just to die at mount time.
    if let Err(e) = backend::libfuse::ensure_available() {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let cwd = std::env::current_dir().context("resolving cwd")?;

    diff::ensure_distinct_commits(&cwd, &args.rev_a, &args.rev_b)
        .context("validating revisions")?;

    let entries: Vec<DiffEntry> = diff::run_diff(&cwd, &args.rev_a, &args.rev_b, &args.paths)
        .context("running git diff --raw")?;
    if entries.is_empty() {
        return Err(anyhow!(
            "no files differ between {} and {}{}",
            args.rev_a,
            args.rev_b,
            if args.paths.is_empty() {
                String::new()
            } else {
                format!(" under {:?}", args.paths)
            }
        ));
    }

    let label_a = args
        .label_a
        .clone()
        .unwrap_or_else(|| sanitize_label(&args.rev_a));
    let label_b = args
        .label_b
        .clone()
        .unwrap_or_else(|| sanitize_label(&args.rev_b));
    if label_a == label_b {
        return Err(anyhow!(
            "labelA and labelB both resolve to {label_a:?}; pass --label-a/--label-b to disambiguate"
        ));
    }

    let raw = RawConfig::load(Some(cwd.as_path())).context("loading bale config")?;
    let repo = Arc::new(
        gix::ThreadSafeRepository::open(&cwd)
            .with_context(|| format!("opening git repo at {}", cwd.display()))?,
    );
    let reader = Arc::new(reader::Reader::new(repo, raw).context("starting blob reader")?);
    let vfs = Arc::new(DiffVfs::build(&entries, &label_a, &label_b, reader));

    eprintln!(
        "git-bale: mounting diff {} vs {} ({} entries) at {}",
        args.rev_a,
        args.rev_b,
        entries.len(),
        args.mount_point.display(),
    );

    // For now we only have one backend; later this becomes a selector.
    let backend = LibfuseBackend::new();
    backend.mount(&args.mount_point, vfs)
}

/// Conservative filesystem-safe label: keep alnum / `_`/`-`/`.`, replace the
/// rest with `_`. Avoids `/`, NUL, and anything weird in branch names like
/// `feature/x` (would otherwise create a directory in the filename).
fn sanitize_label(rev: &str) -> String {
    let mut out = String::with_capacity(rev.len());
    for c in rev.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "rev".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_label;

    #[test]
    fn sanitize_keeps_safe_chars() {
        assert_eq!(sanitize_label("main"), "main");
        assert_eq!(sanitize_label("v1.2.3"), "v1.2.3");
        assert_eq!(sanitize_label("topic-foo_bar"), "topic-foo_bar");
    }

    #[test]
    fn sanitize_replaces_slashes_and_weird() {
        assert_eq!(sanitize_label("feature/x"), "feature_x");
        assert_eq!(sanitize_label("HEAD~3"), "HEAD_3");
        assert_eq!(sanitize_label("origin/main"), "origin_main");
    }

    #[test]
    fn sanitize_handles_empty() {
        assert_eq!(sanitize_label(""), "rev");
    }
}
