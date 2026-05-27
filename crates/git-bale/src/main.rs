//! Git filter driver that stores file content as deduplicated chunks on a
//! Bale CAS server instead of as whole-file LFS blobs.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use git_bale::install::{self, Scope};
use git_bale::mount::{self, MountDiffArgs};
use git_bale::{filter_process, track};

#[derive(Parser, Debug)]
#[command(
    name = "git-bale",
    version,
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
    /// Mount a read-only virtual FS exposing both sides of a `git diff`.
    MountDiff(MountDiffCliArgs),
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

fn main() -> Result<()> {
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
        Command::MountDiff(a) => mount::run(MountDiffArgs {
            rev_a: a.rev_a,
            rev_b: a.rev_b,
            mount_point: a.mount,
            label_a: a.label_a,
            label_b: a.label_b,
            paths: a.paths,
        }),
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
