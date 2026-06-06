//! Git filter driver that stores file content as deduplicated chunks on a
//! Bale CAS server instead of as whole-file LFS blobs.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use git_bale::install::{self, Scope};
use git_bale::mount::{self, MountDiffArgs, MountRevArgs};
use git_bale::{filter_process, gc, push_pending, track};

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("BALE_GIT_SHA"),
    " ",
    env!("BALE_BUILD_DATE"),
    " ",
    env!("BALE_TARGET"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "git-bale",
    version = LONG_VERSION,
    about = "Git filter for chunk-deduplicated file storage"
)]
struct Cli {
    /// Increase log verbosity (`-v`, `-vv`, ...).
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Register `git-bale` as the `bale` filter driver in git config.
    Install(InstallArgs),
    /// Remove the `bale` filter driver from git config.
    Uninstall(UninstallArgs),
    /// Append patterns to .gitattributes with `filter=bale`.
    Track(TrackArgs),
    /// Run the long-running filter protocol. Invoked by Git, not by users.
    FilterProcess,
    /// Ensure every bale file the push advertises is present on (and scoped to)
    /// the remote being pushed to. Invoked from the pre-push hook installed by
    /// `git-bale install`, which passes the remote name + URL and pipes git's
    /// ref-update lines on stdin.
    PushPending(PushPendingArgs),
    /// Reconcile the staging area: forget xorbs/shards/markers that no longer
    /// belong to the index or an unpushed commit. Invoked from the
    /// post-checkout/post-commit/post-merge hooks installed by `git-bale
    /// install`; safe to run by hand.
    Gc,
    /// Mount a read-only virtual FS exposing both sides of a `git diff`.
    MountDiff(MountDiffCliArgs),
    /// Mount a read-only virtual FS exposing the files at one revision.
    Mount(MountCliArgs),
    /// Put this repo into fully-local (no-server) mode: durable object store on
    /// disk, no server required. See `--shared` for a cross-repo store.
    InitLocal(InitLocalArgs),
    /// Reclaim a shared local store (delete objects no registered repo
    /// references). Only meaningful with `--shared`.
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
struct InstallArgs {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    local: bool,
    /// Local repo path; only meaningful with --local.
    #[arg(long)]
    path: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct UninstallArgs {
    /// Remove from system, global, and local scopes.
    #[arg(long)]
    all: bool,
    #[arg(long)]
    system: bool,
    #[arg(long)]
    local: bool,
    #[arg(long)]
    path: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct PushPendingArgs {
    /// Remote name git is pushing to (pre-push hook `$1`). Omitted on manual
    /// invocation, where auth falls back to `origin`.
    remote_name: Option<String>,
    /// Remote URL git is pushing to (pre-push hook `$2`). Determines the
    /// server-side repo scope of any upload.
    remote_url: Option<String>,
}

#[derive(Args, Debug)]
struct TrackArgs {
    /// Patterns to add to .gitattributes (e.g. `*.bin`, `models/**/*.safetensors`).
    patterns: Vec<String>,
}

#[derive(Args, Debug)]
struct MountDiffCliArgs {
    /// "Old" side of the diff (rev, branch, tag, etc.).
    rev_a: String,
    /// "New" side of the diff (rev, branch, tag, etc.).
    rev_b: String,
    /// Directory to mount on. Must exist and be empty (or you'll mask its
    /// contents until unmount).
    #[arg(long)]
    mount: PathBuf,
    /// Override the label embedded in side-A filenames. Defaults to a
    /// filesystem-sanitised form of `rev_a`.
    #[arg(long = "label-a")]
    label_a: Option<String>,
    /// Override the label embedded in side-B filenames. Defaults to a
    /// filesystem-sanitised form of `rev_b`.
    #[arg(long = "label-b")]
    label_b: Option<String>,
    /// Optional path filters, like `git diff <revA> <revB> -- <paths>...`.
    #[arg(last = true)]
    paths: Vec<String>,
}

#[derive(Args, Debug)]
struct MountCliArgs {
    /// Revision to mount (commit, branch, tag, etc.). Files appear under the
    /// mount point with their original names.
    rev: String,
    /// Directory to mount on. Must exist and be empty (or you'll mask its
    /// contents until unmount).
    #[arg(long)]
    mount: PathBuf,
    /// Optional path filters, like `git diff <rev> -- <paths>...`.
    #[arg(last = true)]
    paths: Vec<String>,
}

#[derive(Args, Debug)]
struct InitLocalArgs {
    /// Object store directory. Default: `.git/bale/store` (per-repo), or
    /// `~/bale-local` when `--shared` is given with no path.
    #[arg(long)]
    store: Option<PathBuf>,
    /// Share one store across all local repos. With no `--store`, defaults to
    /// `~/bale-local`. Registers this repo for `git-bale prune --shared`.
    #[arg(long)]
    shared: bool,
}

#[derive(Args, Debug)]
struct PruneArgs {
    /// Reclaim the shared store (required — per-repo stores are reclaimed by gc).
    #[arg(long)]
    shared: bool,
    /// Proceed even if a registered repo's path is missing (its objects may be
    /// deleted). Default: abort, to avoid deleting another repo's only copy.
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    set_default_xet_cache_root();
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("git_bale={log_level}").into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Command::Install(a) => {
            let scope = pick_scope(a.system, a.local);
            install::install(scope, a.path.as_deref())?;
            println!("git-bale installed ({})", describe_scope(scope));
            Ok(())
        }
        Command::Uninstall(a) => {
            if a.all {
                install::uninstall_all(a.path.as_deref())?;
                println!("git-bale uninstalled from all scopes");
                return Ok(());
            }
            let scope = pick_scope(a.system, a.local);
            install::uninstall(scope, a.path.as_deref())?;
            println!("git-bale uninstalled ({})", describe_scope(scope));
            Ok(())
        }
        Command::Track(a) => {
            if a.patterns.is_empty() {
                anyhow::bail!("no patterns given; e.g. `git-bale track '*.bin'`");
            }
            let cwd = std::env::current_dir()?;
            track::track(&cwd, &a.patterns)
        }
        Command::FilterProcess => filter_process::run(),
        Command::PushPending(a) => push_pending::run(push_pending::Args {
            remote_name: a.remote_name,
            remote_url: a.remote_url,
        }),
        Command::Gc => gc::run(),
        Command::MountDiff(a) => mount::run(MountDiffArgs {
            rev_a: a.rev_a,
            rev_b: a.rev_b,
            mount_point: a.mount,
            label_a: a.label_a,
            label_b: a.label_b,
            paths: a.paths,
        }),
        Command::Mount(a) => mount::run_rev(MountRevArgs {
            rev: a.rev,
            mount_point: a.mount,
            paths: a.paths,
        }),
        Command::InitLocal(a) => {
            let cwd = std::env::current_dir()?;
            let store = git_bale::store::resolve_init_store(&cwd, a.store.as_deref(), a.shared)?;
            install::init_local(Some(cwd.as_path()), &store, a.shared)?;
            if a.shared {
                let git_dir = git_bale::store::repo_git_dir(&cwd)?;
                git_bale::store::register_repo(&store, &git_dir)?;
            }
            println!(
                "git-bale local mode enabled (store: {}{})",
                store.display(),
                if a.shared { ", shared" } else { "" }
            );
            Ok(())
        }
        Command::Prune(a) => {
            if !a.shared {
                anyhow::bail!("`git-bale prune` currently only supports --shared");
            }
            git_bale::prune::run(a.force)
        }
    }
}

/// Point xet-runtime's cache root at a bale-branded path instead of
/// `~/.cache/huggingface/xet`. Precedence: `BALE_XET_CACHE` (the bale-branded
/// knob) wins, mapped onto the `HF_XET_CACHE` xet actually reads; else a
/// directly-set `HF_XET_CACHE` is kept; else `<XDG_CACHE_HOME|~/.cache>/bale/xet`.
/// Must run before any threads spawn — `set_var` is UB in a multi-threaded
/// process on some platforms.
fn set_default_xet_cache_root() {
    if let Some(bale_cache) = std::env::var_os("BALE_XET_CACHE") {
        // SAFETY: called from main() before any threads or async runtime spawn.
        unsafe { std::env::set_var("HF_XET_CACHE", bale_cache) };
        return;
    }
    if std::env::var_os("HF_XET_CACHE").is_some() {
        return;
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(cache_home_fallback);
    let Some(base) = base else { return };
    let path = base.join("bale").join("xet");
    // SAFETY: called from main() before any threads or async runtime spawn.
    unsafe { std::env::set_var("HF_XET_CACHE", path) };
}

/// `~/.cache` on Unix; `%LOCALAPPDATA%` (then `%USERPROFILE%\.cache`) on
/// Windows, where `HOME` is usually unset.
fn cache_home_fallback() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return Some(PathBuf::from(local));
        }
        std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(".cache"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache"))
    }
}

fn pick_scope(system: bool, local: bool) -> Scope {
    if system as u8 + local as u8 > 1 {
        eprintln!("warning: --system and --local both set; using --local");
    }
    if local {
        Scope::Local
    } else if system {
        Scope::System
    } else {
        Scope::Global
    }
}

fn describe_scope(s: Scope) -> &'static str {
    match s {
        Scope::Global => "global config",
        Scope::System => "system config",
        Scope::Local => "local config",
    }
}
