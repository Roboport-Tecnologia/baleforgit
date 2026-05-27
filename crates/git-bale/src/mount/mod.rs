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
use crate::mount::vfs::DiffVfs;

pub mod backend;
pub mod diff;
pub mod reader;
pub mod tree;
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
    // Resolve the rev so we get a clear "no such ref" error before doing the
    // full tree walk.
    diff::rev_parse_commit(&cwd, &args.rev).with_context(|| format!("resolving {}", args.rev))?;

    let entries = tree::walk_rev(&cwd, &args.rev, &args.paths)
        .context("walking tree for single-rev mount")?;
    if entries.is_empty() {
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

    let raw = RawConfig::load(Some(cwd.as_path())).context("loading bale config")?;
    let reader = Arc::new(reader::Reader::new(cwd.clone(), raw).context("starting blob reader")?);
    let vfs = Arc::new(DiffVfs::build_single(&entries, reader));

    eprintln!(
        "git-bale: mounting {} ({} files) at {}",
        args.rev,
        entries.len(),
        args.mount_point.display(),
    );

    let backend = LibfuseBackend::new();
    backend.mount(&args.mount_point, vfs)
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
    let reader = Arc::new(reader::Reader::new(cwd.clone(), raw).context("starting blob reader")?);
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
