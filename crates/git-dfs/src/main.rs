//! `git-dfs` — Git filter driver that stores file content as deduplicated
//! chunks on a Xet-protocol CAS server instead of as whole-file LFS blobs.
//!
//! Subcommands:
//!
//! ```text
//!   git-dfs install [--system | --local [--path <repo>]]
//!   git-dfs uninstall [--all | --system | --local [--path <repo>]]
//!   git-dfs track <pattern>...
//!   git-dfs filter-process            # invoked by Git, not by users
//! ```

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use git_dfs::install::{self, Scope};
use git_dfs::{filter_process, track};

#[derive(Parser, Debug)]
#[command(
    name = "git-dfs",
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
    /// Register `git-dfs` as the `dfs` filter driver in git config.
    Install(InstallArgs),
    /// Remove the `dfs` filter driver from git config.
    Uninstall(UninstallArgs),
    /// Append patterns to .gitattributes with `filter=dfs`.
    Track(TrackArgs),
    /// Run the long-running filter protocol. Invoked by Git.
    FilterProcess,
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
                .unwrap_or_else(|_| format!("git_dfs={log_level}").into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Command::Install(a) => {
            let scope = pick_scope(a.system, a.local);
            install::install(scope, a.path.as_deref())?;
            println!("git-dfs installed ({})", describe_scope(scope));
            Ok(())
        }
        Command::Uninstall(a) => {
            if a.all {
                install::uninstall_all(a.path.as_deref())?;
                println!("git-dfs uninstalled from all scopes");
                return Ok(());
            }
            let scope = pick_scope(a.system, a.local);
            install::uninstall(scope, a.path.as_deref())?;
            println!("git-dfs uninstalled ({})", describe_scope(scope));
            Ok(())
        }
        Command::Track(a) => {
            if a.patterns.is_empty() {
                anyhow::bail!("no patterns given; e.g. `git-dfs track '*.bin'`");
            }
            let cwd = std::env::current_dir()?;
            track::track(&cwd, &a.patterns)
        }
        Command::FilterProcess => filter_process::run(),
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
