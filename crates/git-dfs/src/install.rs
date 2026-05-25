//! Install / uninstall the `dfs` filter driver in git config.
//!
//! We only set `filter.dfs.process` (not `clean`/`smudge`): Git prefers the
//! long-running process when present, and it's faster than spawning a fresh
//! `clean`/`smudge` subprocess per file.

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    Global,
    System,
    Local,
}

const SECTION: &str = "filter.dfs";
const PROCESS_VALUE: &str = "git-dfs filter-process";

pub fn install(scope: Scope, repo: Option<&Path>) -> Result<()> {
    set_config(scope, repo, "process", PROCESS_VALUE)?;
    set_config(scope, repo, "required", "true")?;
    Ok(())
}

pub fn uninstall(scope: Scope, repo: Option<&Path>) -> Result<()> {
    // --unset-all clears duplicated entries from older installs in one pass.
    let _ = unset_config(scope, repo, "process");
    let _ = unset_config(scope, repo, "required");
    Ok(())
}

pub fn uninstall_all(repo: Option<&Path>) -> Result<()> {
    let _ = uninstall(Scope::System, None);
    let _ = uninstall(Scope::Global, None);
    let _ = uninstall(Scope::Local, repo);
    Ok(())
}

fn scope_flag(scope: Scope) -> &'static str {
    match scope {
        Scope::Global => "--global",
        Scope::System => "--system",
        Scope::Local => "--local",
    }
}

fn run_git_config(
    scope: Scope,
    repo: Option<&Path>,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut cmd = Command::new("git");
    if let (Scope::Local, Some(path)) = (scope, repo) {
        cmd.current_dir(path);
    }
    cmd.arg("config").arg(scope_flag(scope));
    cmd.args(args);
    let out = cmd.output().with_context(|| "spawning git config")?;
    Ok(out)
}

fn set_config(scope: Scope, repo: Option<&Path>, key: &str, value: &str) -> Result<()> {
    let full_key = format!("{SECTION}.{key}");
    let out = run_git_config(scope, repo, &[&full_key, value])?;
    if !out.status.success() {
        return Err(anyhow!(
            "git config {} {full_key} {value} failed: {}",
            scope_flag(scope),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn unset_config(scope: Scope, repo: Option<&Path>, key: &str) -> Result<()> {
    let full_key = format!("{SECTION}.{key}");
    let out = run_git_config(scope, repo, &["--unset-all", &full_key])?;
    // Exit status 5 from `git config --unset-all` means "key not set" — fine.
    if !out.status.success() && out.status.code() != Some(5) {
        return Err(anyhow!(
            "git config {} --unset-all {full_key} failed: {}",
            scope_flag(scope),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
