//! Runtime configuration: where to send xorbs/shards, what bearer to use, and
//! where to keep the local chunk cache.
//!
//! Sources, in priority order:
//!   1. Environment variables (`DFS_*`, also accepting `XET_*` aliases for migration).
//!   2. Git config keys under `dfs.*` (read via `git config --get`).
//!   3. Built-in defaults (XDG cache dir; no default server URL or token).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug)]
pub struct DfsConfig {
    /// Base URL of the CAS server (e.g. `http://127.0.0.1:8080`).
    pub server_url: String,
    /// Static bearer token for `Authorization: Bearer <token>`. The MVP uses a
    /// long-lived JWT; a future `dfs.tokenHelper` config can mint short-lived
    /// tokens.
    pub token: String,
    /// Token expiration as a unix timestamp. Used by xet-client to decide when
    /// to refresh; with no helper we just push it far into the future.
    pub token_expiration: u64,
    /// Directory holding cached chunks. Shared across repos by default.
    pub cache_dir: PathBuf,
}

impl DfsConfig {
    pub fn load(repo: Option<&Path>) -> Result<Self> {
        let server_url = lookup(repo, "DFS_SERVER_URL", "XET_SERVER_URL", "dfs.serverUrl")?
            .ok_or_else(|| anyhow!("dfs.serverUrl is unset; set it with `git config dfs.serverUrl <url>` or DFS_SERVER_URL"))?;
        let token = lookup(repo, "DFS_TOKEN", "XET_TOKEN", "dfs.token")?.ok_or_else(|| {
            anyhow!("dfs.token is unset; set it with `git config dfs.token <jwt>` or DFS_TOKEN")
        })?;

        let token_expiration = match lookup(
            repo,
            "DFS_TOKEN_EXPIRATION",
            "XET_TOKEN_EXPIRATION",
            "dfs.tokenExpiration",
        )? {
            Some(s) => s
                .parse::<u64>()
                .context("dfs.tokenExpiration must be a unix timestamp")?,
            None => far_future_epoch(),
        };

        let cache_dir = resolve_cache_dir(repo)?;

        Ok(Self {
            server_url,
            token,
            token_expiration,
            cache_dir,
        })
    }
}

fn lookup(
    repo: Option<&Path>,
    primary_env: &str,
    alias_env: &str,
    git_key: &str,
) -> Result<Option<String>> {
    if let Ok(v) = env::var(primary_env) {
        if !v.is_empty() {
            return Ok(Some(v));
        }
    }
    if let Ok(v) = env::var(alias_env) {
        if !v.is_empty() {
            return Ok(Some(v));
        }
    }
    git_config_get(repo, git_key)
}

fn git_config_get(repo: Option<&Path>, key: &str) -> Result<Option<String>> {
    let mut cmd = Command::new("git");
    if let Some(p) = repo {
        cmd.current_dir(p);
    }
    cmd.arg("config").arg("--get").arg(key);
    let out = cmd
        .output()
        .with_context(|| format!("spawning git config --get {key}"))?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return Ok(if s.is_empty() { None } else { Some(s) });
    }
    // Exit 1 means "key not found" — not an error here.
    if out.status.code() == Some(1) {
        return Ok(None);
    }
    Err(anyhow!(
        "git config --get {key} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

fn resolve_cache_dir(repo: Option<&Path>) -> Result<PathBuf> {
    if let Ok(v) = env::var("DFS_CACHE_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Ok(v) = env::var("XET_CACHE_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Some(s) = git_config_get(repo, "dfs.cacheDir")? {
        return Ok(PathBuf::from(s));
    }
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("dfs").join("chunks"));
        }
    }
    let home = env::var("HOME").context("$HOME is unset; cannot derive default cache dir")?;
    Ok(PathBuf::from(home)
        .join(".cache")
        .join("dfs")
        .join("chunks"))
}

/// 100 years past epoch — used as a token expiration sentinel when the caller
/// hasn't set one and isn't doing token refresh.
fn far_future_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + 100 * 365 * 24 * 60 * 60
}
