//! Install / uninstall the `bale` filter driver in git config.
//!
//! Sets only `filter.bale.process` (not `clean`/`smudge`): Git prefers the
//! long-running process and skips a per-file subprocess spawn.
//!
//! Local-scope install also writes hooks: `pre-push` runs `git-bale
//! push-pending` (xorbs/shards reach the server before push advertises pointers
//! to them), and `post-checkout`/`-commit`/`-merge` run `git-bale gc` (clean
//! only adds to staging; without gc, abandoned bytes linger until next push).

use std::io::Write;
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

/// Marks a hook as ours so uninstall/re-install don't clobber a user's hook.
const HOOK_MARKER: &str = "# bale-marker: managed-by-git-bale-do-not-edit";

const GC_HOOKS: [&str; 3] = ["post-checkout", "post-commit", "post-merge"];

#[derive(Clone, Copy)]
enum OnConflict {
    /// Abort: pre-push gates upload correctness, so skipping it is dangerous.
    Fail,
    /// Warn and leave the user's hook: gc is best-effort, not worth blocking on.
    Skip,
}

pub fn install(scope: Scope, repo: Option<&Path>) -> Result<()> {
    set_config(scope, repo, "process", PROCESS_VALUE)?;
    set_config(scope, repo, "required", "true")?;
    if matches!(scope, Scope::Local) {
        install_managed_hook(
            repo,
            "pre-push",
            "exec git-bale push-pending \"$@\"",
            "Ensure xorbs/shards for every bale file this push advertises reach the\n\
             # target remote (\"$@\" = remote name + URL; ref updates arrive on stdin)\n\
             # before git pushes refs that reference them. Aborts the push on failure.",
            OnConflict::Fail,
        )?;
        for hook in GC_HOOKS {
            install_managed_hook(
                repo,
                hook,
                "git-bale gc || true",
                "Reclaim staging for bale files that were unstaged or discarded.",
                OnConflict::Skip,
            )?;
        }
    }
    Ok(())
}

/// Put the repo at `repo` (or cwd) into fully-local mode: register the filter,
/// install only the gc hooks (no pre-push drain — nothing to drain), and write
/// `bale.local*` config. `store` is the resolved, tilde-expanded store path;
/// `shared` marks it as a cross-repo store.
pub fn init_local(repo: Option<&Path>, store: &Path, shared: bool) -> Result<()> {
    set_config(Scope::Local, repo, "process", PROCESS_VALUE)?;
    set_config(Scope::Local, repo, "required", "true")?;
    set_bale_config(Scope::Local, repo, "local", "true")?;
    set_bale_config(Scope::Local, repo, "localStore", &store.to_string_lossy())?;
    if shared {
        set_bale_config(Scope::Local, repo, "localShared", "true")?;
    }
    for hook in GC_HOOKS {
        install_managed_hook(
            repo,
            hook,
            "git-bale gc || true",
            "Reclaim local-store objects for bale files that were unstaged or discarded.",
            OnConflict::Skip,
        )?;
    }
    Ok(())
}

pub fn uninstall(scope: Scope, repo: Option<&Path>) -> Result<()> {
    // --unset-all clears duplicate entries from older installs in one pass.
    let _ = unset_config(scope, repo, "process");
    let _ = unset_config(scope, repo, "required");
    if matches!(scope, Scope::Local) {
        let _ = uninstall_managed_hook(repo, "pre-push");
        for hook in GC_HOOKS {
            let _ = uninstall_managed_hook(repo, hook);
        }
    }
    Ok(())
}

pub fn uninstall_all(repo: Option<&Path>) -> Result<()> {
    let _ = uninstall(Scope::System, None);
    let _ = uninstall(Scope::Global, None);
    let _ = uninstall(Scope::Local, repo);
    Ok(())
}

fn install_managed_hook(
    repo: Option<&Path>,
    hook_name: &str,
    command: &str,
    description: &str,
    on_conflict: OnConflict,
) -> Result<()> {
    let hook_path = resolve_hook_path(repo, hook_name)?;
    if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating hooks dir {}", parent.display()))?;
    }

    if hook_path.exists() {
        let existing = std::fs::read_to_string(&hook_path).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) {
            match on_conflict {
                OnConflict::Fail => {
                    return Err(anyhow!(
                        "refusing to overwrite existing {hook_name} hook at {}\n\
                         add this line to it manually:\n\
                         \t{command}\n\
                         (or move the existing hook aside and re-run `git-bale install --local`)",
                        hook_path.display()
                    ));
                }
                OnConflict::Skip => {
                    eprintln!(
                        "git-bale: leaving your existing {hook_name} hook at {} untouched; \
                         add `{command}` to it to enable automatic staging cleanup",
                        hook_path.display()
                    );
                    return Ok(());
                }
            }
        }
    }

    let body = format!("#!/bin/sh\n{HOOK_MARKER}\n# {description}\n{command}\n");
    write_atomic(&hook_path, body.as_bytes())
        .with_context(|| format!("writing {hook_name} hook to {}", hook_path.display()))?;
    // Git for Windows runs hooks through its bundled `sh` and ignores the
    // filesystem exec bit, so the chmod is Unix-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }
    Ok(())
}

fn uninstall_managed_hook(repo: Option<&Path>, hook_name: &str) -> Result<()> {
    let hook_path = resolve_hook_path(repo, hook_name)?;
    if !hook_path.exists() {
        return Ok(());
    }
    let existing = std::fs::read_to_string(&hook_path)?;
    if !existing.contains(HOOK_MARKER) {
        // Leave hand-written hooks alone.
        return Ok(());
    }
    std::fs::remove_file(&hook_path)
        .with_context(|| format!("removing {hook_name} hook {}", hook_path.display()))?;
    Ok(())
}

fn resolve_hook_path(repo: Option<&Path>, hook_name: &str) -> Result<PathBuf> {
    // gix resolves the git dir (incl. worktrees) and honours `core.hooksPath`
    // from the merged config snapshot.
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

fn set_bale_config(scope: Scope, repo: Option<&Path>, key: &str, value: &str) -> Result<()> {
    let full_key = format!("bale.{key}");
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
