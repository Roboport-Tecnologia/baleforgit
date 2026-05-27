//! Runtime configuration: where to send xorbs/shards, what bearer to use, and
//! where to keep the local chunk cache.
//!
//! Sources, in priority order:
//!   1. Environment variables (`BALE_*`).
//!   2. Git config keys under `bale.*` (read via `gix::discover` + merged
//!      config snapshot — no `git` subprocess).
//!   3. Built-in defaults (XDG cache dir; no default server URL or token).

use std::env;
use std::path::{Path, PathBuf};

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
    ///
    /// Uses `gix::discover` to find the repo and load merged config in one
    /// shot — no `git rev-parse` / `git config` subprocesses. This is the
    /// hot path: every `git status` / `git diff` invokes the filter-process,
    /// which calls `load()` once at startup. Fork+exec on macOS is ~5–15 ms
    /// per call and was adding up.
    pub fn load(repo: Option<&Path>) -> Result<Self> {
        let start_dir = repo
            .map(|p| p.to_path_buf())
            .or_else(|| env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let gix_repo = match gix::discover(&start_dir) {
            Ok(r) => Some(r),
            Err(e) => {
                // No git context (e.g. unit tests): per-repo features off.
                tracing::debug!("gix::discover({}) failed: {e}", start_dir.display());
                None
            }
        };
        let git_dir = gix_repo.as_ref().map(|r| r.git_dir().to_path_buf());
        let snapshot = gix_repo.as_ref().map(|r| r.config_snapshot());

        let server_url = env_or_cfg("BALE_SERVER_URL", snapshot.as_ref(), "bale.serverUrl");
        let token = env_or_cfg("BALE_TOKEN", snapshot.as_ref(), "bale.token");
        let token_expiration = match env_or_cfg(
            "BALE_TOKEN_EXPIRATION",
            snapshot.as_ref(),
            "bale.tokenExpiration",
        ) {
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
            cache_dir: resolve_cache_dir(snapshot.as_ref())?,
            git_dir,
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

fn env_or_cfg(
    env_key: &str,
    snapshot: Option<&gix::config::Snapshot<'_>>,
    key: &str,
) -> Option<String> {
    if let Ok(v) = env::var(env_key) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let s = snapshot?.string(key)?;
    let trimmed = s.to_string().trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn resolve_cache_dir(snapshot: Option<&gix::config::Snapshot<'_>>) -> Result<PathBuf> {
    if let Ok(v) = env::var("BALE_CACHE_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Some(snap) = snapshot {
        if let Some(raw) = snap.string("bale.cacheDir") {
            let s = raw.to_string();
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
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
