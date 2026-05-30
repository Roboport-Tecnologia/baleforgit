//! Runtime configuration. Sources in priority order: `BALE_*` env vars, then
//! `bale.*` git config (via `gix::discover` — no subprocess), then defaults
//! (XDG cache dir; no default server URL or token).

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug)]
pub struct BaleConfig {
    pub server_url: String,
    pub token: String,
    pub token_expiration: u64,
    pub cache_dir: PathBuf,
    /// `None` outside a git context; per-repo caches are disabled then.
    pub git_dir: Option<PathBuf>,
}

/// Local-config-only fields, handed to [`crate::resolver::resolve`] to fill in
/// anything missing.
#[derive(Clone, Debug)]
pub struct RawConfig {
    pub server_url: Option<String>,
    pub token: Option<String>,
    pub token_expiration: Option<u64>,
    pub cache_dir: PathBuf,
    pub git_dir: Option<PathBuf>,
}

impl RawConfig {
    /// Server URL and token are optional — the resolver auto-discovers them via
    /// `git remote` + a forge roundtrip. Uses `gix::discover` (not `git`
    /// subprocesses): this runs on every `git status`/`git diff`, and fork+exec
    /// is ~5–15 ms per call on macOS.
    pub fn load(repo: Option<&Path>) -> Result<Self> {
        let start_dir = repo
            .map(|p| p.to_path_buf())
            .or_else(|| env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let gix_repo = match gix::discover(&start_dir) {
            Ok(r) => Some(r),
            Err(e) => {
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
    /// Strict loader: errors (rather than auto-resolving) when `server_url` /
    /// `token` aren't locally configured, so callers can tell "config missing"
    /// from "real failure".
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
    cache_base()
        .map(|b| b.join("bale").join("chunks"))
        .ok_or_else(|| {
            anyhow!("can't derive a default cache dir: set BALE_CACHE_DIR or bale.cacheDir")
        })
}

/// Cache root when neither `BALE_CACHE_DIR`, `bale.cacheDir`, nor
/// `XDG_CACHE_HOME` is set: `~/.cache` on Unix, `%LOCALAPPDATA%` (falling back
/// to `%USERPROFILE%\.cache`) on Windows, where `HOME` is usually absent.
fn cache_base() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(local) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(local));
        }
        if let Some(profile) = env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(profile).join(".cache"));
        }
        None
    }
    #[cfg(not(windows))]
    {
        env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(|h| PathBuf::from(h).join(".cache"))
    }
}

/// "Effectively never expires" sentinel for a literal `bale.token` with no
/// `bale.tokenExpiration` set and no forge to re-mint from. See the fuller note
/// on `resolver::far_future_epoch`; xet needs *some* expiry and would otherwise
/// try to refresh a static token it can't.
fn far_future_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + 100 * 365 * 24 * 60 * 60
}
