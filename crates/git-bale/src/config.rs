//! Runtime configuration: where to send xorbs/shards, what bearer to use, and
//! where to keep the local chunk cache.
//!
//! Sources, in priority order:
//!   1. Environment variables (`BALE_*`).
//!   2. Git config keys under `bale.*` (read via `git config --get`).
//!   3. Built-in defaults (XDG cache dir; no default server URL or token).

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug)]
pub struct BaleConfig {
    pub server_url: String,
    pub token: String,
    pub token_expiration: u64,
    pub cache_dir: PathBuf,
    /// Resolved git directory (the path `.git` points at). `None` outside a
    /// git context (e.g. unit tests); per-repo caches are disabled then.
    pub git_dir: Option<PathBuf>,
}

/// Local-config-only fields. Produced synchronously at startup, then handed
/// to [`crate::resolver::resolve`] to fill in any missing pieces.
#[derive(Clone, Debug)]
pub struct RawConfig {
    pub server_url: Option<String>,
    pub token: Option<String>,
    pub token_expiration: Option<u64>,
    pub cache_dir: PathBuf,
    pub git_dir: Option<PathBuf>,
}

impl RawConfig {
    /// Server URL and token are optional — the resolver auto-discovers them
    /// from `git remote` + a forge auth roundtrip when absent.
    pub fn load(repo: Option<&Path>) -> Result<Self> {
        // One `git config --get-regexp '^bale\\.'` shaves ~3 subprocess spawns
        // off filter-process startup (was: one `--get` per key). Filter-process
        // start cost dominates `git diff` time when the pointer cache hits.
        let bale_cfg = read_bale_config(repo)?;
        let server_url = env_or_cfg("BALE_SERVER_URL", &bale_cfg, "bale.serverurl");
        let token = env_or_cfg("BALE_TOKEN", &bale_cfg, "bale.token");
        let token_expiration =
            match env_or_cfg("BALE_TOKEN_EXPIRATION", &bale_cfg, "bale.tokenexpiration") {
                Some(s) => Some(
                    s.parse::<u64>()
                        .context("bale.tokenExpiration must be a unix timestamp")?,
                ),
                None => None,
            };
        Ok(Self {
            server_url,
            token,
            token_expiration,
            cache_dir: resolve_cache_dir(&bale_cfg)?,
            git_dir: resolve_git_dir(repo),
        })
    }
}

impl BaleConfig {
    /// Strict loader: requires `server_url` + `token` to be locally configured.
    /// Errors (rather than auto-resolving) so callers that want the fast path
    /// can tell "config missing" from "real failure".
    pub fn load(repo: Option<&Path>) -> Result<Self> {
        let raw = RawConfig::load(repo)?;
        let server_url = raw
            .server_url
            .ok_or_else(|| anyhow!("bale.serverUrl is unset; set it with `git config bale.serverUrl <url>` or BALE_SERVER_URL"))?;
        let token = raw.token.ok_or_else(|| {
            anyhow!("bale.token is unset; set it with `git config bale.token <jwt>` or BALE_TOKEN")
        })?;
        Ok(Self {
            server_url,
            token,
            token_expiration: raw.token_expiration.unwrap_or_else(far_future_epoch),
            cache_dir: raw.cache_dir,
            git_dir: raw.git_dir,
        })
    }
}

/// `git rev-parse --git-dir`, made absolute. Subsequent IO shouldn't depend
/// on the filter's process-level cwd.
fn resolve_git_dir(repo: Option<&Path>) -> Option<PathBuf> {
    let mut cmd = Command::new("git");
    if let Some(p) = repo {
        cmd.current_dir(p);
    }
    cmd.arg("rev-parse").arg("--git-dir");
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    let p = PathBuf::from(s);
    if p.is_absolute() {
        Some(p)
    } else {
        let base = repo
            .map(|r| r.to_path_buf())
            .or_else(|| env::current_dir().ok())?;
        Some(base.join(p))
    }
}

/// Fetch every `bale.*` key in one subprocess. Keys come back lower-cased
/// (git's normalisation); callers must use lowercase lookups.
fn read_bale_config(repo: Option<&Path>) -> Result<HashMap<String, String>> {
    let mut cmd = Command::new("git");
    if let Some(p) = repo {
        cmd.current_dir(p);
    }
    cmd.arg("config")
        .arg("--null")
        .arg("--get-regexp")
        .arg("^bale\\.");
    let out = cmd
        .output()
        .with_context(|| "spawning git config --get-regexp '^bale\\.'")?;
    // Exit 1 = no matches; not an error.
    if !out.status.success() {
        if out.status.code() == Some(1) {
            return Ok(HashMap::new());
        }
        return Err(anyhow!(
            "git config --get-regexp '^bale\\.' failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // `--null` separates records with `\0`; within each record the key and
    // value are separated by `\n` (or no separator if value is empty).
    let mut map = HashMap::new();
    for record in out.stdout.split(|&b| b == 0) {
        if record.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(record);
        let (k, v) = match s.split_once('\n') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (s.into_owned(), String::new()),
        };
        map.insert(k, v);
    }
    Ok(map)
}

fn env_or_cfg(env_key: &str, cfg: &HashMap<String, String>, cfg_key: &str) -> Option<String> {
    if let Ok(v) = env::var(env_key) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    cfg.get(cfg_key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_cache_dir(cfg: &HashMap<String, String>) -> Result<PathBuf> {
    if let Ok(v) = env::var("BALE_CACHE_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Some(s) = cfg.get("bale.cachedir") {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(PathBuf::from(s));
        }
    }
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("bale").join("chunks"));
        }
    }
    let home = env::var("HOME").context("$HOME is unset; cannot derive default cache dir")?;
    Ok(PathBuf::from(home)
        .join(".cache")
        .join("bale")
        .join("chunks"))
}

/// Sentinel "never expires" for tokens with no configured refresh path.
fn far_future_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + 100 * 365 * 24 * 60 * 60
}
