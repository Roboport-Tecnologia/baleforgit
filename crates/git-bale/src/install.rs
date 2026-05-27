//! Install / uninstall the `bale` filter driver in git config.
//!
//! We only set `filter.bale.process` (not `clean`/`smudge`): Git prefers the
//! long-running process when present, and it's faster than spawning a fresh
//! `clean`/`smudge` subprocess per file.
//!
//! Local-scope install also writes a `pre-push` hook that runs
//! `git-bale push-pending` so xorbs/shards staged by `clean` (`git add`)
//! actually reach the server before `git push` advertises pointers that
//! reference them.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    Global,
    System,
    Local,
}

const SECTION: &str = "filter.bale";
const PROCESS_VALUE: &str = "git-bale filter-process";

/// Identifies a pre-push hook we wrote so `uninstall` can remove it without
/// clobbering a user-authored hook.
const HOOK_MARKER: &str = "# bale-marker: managed-by-git-bale-do-not-edit";

pub fn install(scope: Scope, repo: Option<&Path>) -> Result<()> {
    set_config(scope, repo, "process", PROCESS_VALUE)?;
    set_config(scope, repo, "required", "true")?;
    if matches!(scope, Scope::Local) {
        install_pre_push_hook(repo)?;
    }
    Ok(())
}

pub fn uninstall(scope: Scope, repo: Option<&Path>) -> Result<()> {
    // --unset-all clears duplicated entries from older installs in one pass.
    let _ = unset_config(scope, repo, "process");
    let _ = unset_config(scope, repo, "required");
    if matches!(scope, Scope::Local) {
        let _ = uninstall_pre_push_hook(repo);
    }
    Ok(())
}

pub fn uninstall_all(repo: Option<&Path>) -> Result<()> {
    let _ = uninstall(Scope::System, None);
    let _ = uninstall(Scope::Global, None);
    let _ = uninstall(Scope::Local, repo);
    Ok(())
}

fn install_pre_push_hook(repo: Option<&Path>) -> Result<()> {
    let hook_path = resolve_hook_path(repo, "pre-push")?;
    if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating hooks dir {}", parent.display()))?;
    }

    if hook_path.exists() {
        let existing = std::fs::read_to_string(&hook_path).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) {
            return Err(anyhow!(
                "refusing to overwrite existing pre-push hook at {}\n\
                 add this line to it manually:\n\
                 \texec git-bale push-pending\n\
                 (or move the existing hook aside and re-run `git-bale install --local`)",
                hook_path.display()
            ));
        }
    }

    let body = format!(
        "#!/bin/sh\n\
         {HOOK_MARKER}\n\
         # Drain xorbs/shards staged by `git add` to the bale server before\n\
         # git pushes refs that reference them. Aborts the push on failure.\n\
         exec git-bale push-pending\n"
    );
    write_atomic(&hook_path, body.as_bytes())
        .with_context(|| format!("writing pre-push hook to {}", hook_path.display()))?;
    let mut perms = std::fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&hook_path, perms)?;
    Ok(())
}

fn uninstall_pre_push_hook(repo: Option<&Path>) -> Result<()> {
    let hook_path = resolve_hook_path(repo, "pre-push")?;
    if !hook_path.exists() {
        return Ok(());
    }
    let existing = std::fs::read_to_string(&hook_path)?;
    if !existing.contains(HOOK_MARKER) {
        // Leave hand-written hooks alone.
        return Ok(());
    }
    std::fs::remove_file(&hook_path)
        .with_context(|| format!("removing pre-push hook {}", hook_path.display()))?;
    Ok(())
}

fn resolve_hook_path(repo: Option<&Path>, hook_name: &str) -> Result<PathBuf> {
    // gix gives us the git dir directly, including for worktrees. `core.hooksPath`
    // is honoured if the config has it set (we read the merged snapshot the same
    // way git does).
    let start_dir = repo
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow!("can't resolve cwd to anchor hook path"))?;
    let gix_repo =
        gix::discover(&start_dir).with_context(|| format!("opening repo at {start_dir:?}"))?;
    let snapshot = gix_repo.config_snapshot();
    let hooks_root = if let Some(p) = snapshot.string("core.hooksPath") {
        let s = p.to_string();
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            gix_repo.git_dir().join("hooks")
        }
    } else {
        gix_repo.git_dir().join("hooks")
    };
    Ok(hooks_root.join(hook_name))
}

fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("pre-push"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
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
