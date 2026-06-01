//! Parse an `origin` URL into protocol/host/port/repo-path for discovery and
//! auth. Recognized shapes (`.git` suffix optional, stripped):
//!
//! ```text
//!   https://git.example.com/alice/repo.git
//!   http://localhost:3000/alice/repo.git
//!   git@git.example.com:alice/repo.git             (scp-style SSH)
//!   ssh://git@git.example.com:2222/alice/repo.git
//! ```

use std::path::Path;

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteScheme {
    Http,
    Https,
    Ssh,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteUrl {
    pub scheme: RemoteScheme,
    /// SSH user (defaults to `git` for ssh-style URLs). `None` for http/https.
    pub user: Option<String>,
    pub host: String,
    /// `None` means "use the scheme default" — 22 for ssh, 80 for http, 443 for https.
    pub port: Option<u16>,
    /// "alice/repo", `.git` suffix stripped. May contain extra path segments
    /// if a forge nests repos under additional path prefixes.
    pub repo_path: String,
}

impl RemoteUrl {
    /// "alice/repo" → ("alice", "repo"). Errors if no slash.
    pub fn owner_and_repo(&self) -> Result<(&str, &str)> {
        let (owner, repo) = self
            .repo_path
            .split_once('/')
            .ok_or_else(|| anyhow!("remote repo path has no '/': {}", self.repo_path))?;
        if owner.is_empty() || repo.is_empty() {
            return Err(anyhow!(
                "remote repo path missing owner or name: {}",
                self.repo_path
            ));
        }
        Ok((owner, repo))
    }

    /// Base URL for the forge's Bale endpoints. SSH remotes assume https on the
    /// same host/default port; override via `bale.serverUrl` if HTTP and SSH
    /// live on different hosts.
    pub fn https_base(&self) -> String {
        match self.scheme {
            RemoteScheme::Http => format!("http://{}", self.host_with_port(80)),
            RemoteScheme::Https => format!("https://{}", self.host_with_port(443)),
            RemoteScheme::Ssh => format!("https://{}", self.host),
        }
    }

    fn host_with_port(&self, default: u16) -> String {
        match self.port {
            Some(p) if p != default => format!("{}:{}", self.host, p),
            _ => self.host.clone(),
        }
    }
}

/// Parse one of the four supported remote URL shapes.
pub fn parse_remote(s: &str) -> Result<RemoteUrl> {
    let s = s.trim();

    // scp-style SSH: `[user@]host:path` — distinguishable by the FIRST `:`
    // not being immediately followed by `//`, and no `://` prefix.
    if !s.contains("://") {
        if let Some((before, path)) = s.split_once(':') {
            let (user, host) = match before.split_once('@') {
                Some((u, h)) => (Some(u.to_string()), h.to_string()),
                None => (None, before.to_string()),
            };
            if host.is_empty() {
                return Err(anyhow!("scp-style remote missing host: {s}"));
            }
            return Ok(RemoteUrl {
                scheme: RemoteScheme::Ssh,
                user: Some(user.unwrap_or_else(|| "git".into())),
                host,
                port: None,
                repo_path: strip_dot_git(path).to_string(),
            });
        }
        return Err(anyhow!("unrecognized remote URL: {s}"));
    }

    let (scheme_str, rest) = s
        .split_once("://")
        .ok_or_else(|| anyhow!("unrecognized remote URL: {s}"))?;
    let scheme = match scheme_str {
        "http" => RemoteScheme::Http,
        "https" => RemoteScheme::Https,
        "ssh" => RemoteScheme::Ssh,
        other => return Err(anyhow!("unsupported remote scheme {other:?}")),
    };

    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (user, host_port) = match authority.split_once('@') {
        Some((u, hp)) => (Some(u.to_string()), hp),
        None => (None, authority),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("invalid port {p:?} in remote {s}"))?;
            (h.to_string(), Some(port))
        }
        None => (host_port.to_string(), None),
    };
    if host.is_empty() {
        return Err(anyhow!("remote URL missing host: {s}"));
    }

    let user = match scheme {
        RemoteScheme::Ssh => Some(user.unwrap_or_else(|| "git".into())),
        _ => user,
    };

    Ok(RemoteUrl {
        scheme,
        user,
        host,
        port,
        repo_path: strip_dot_git(path).to_string(),
    })
}

fn strip_dot_git(p: &str) -> &str {
    p.trim_start_matches('/')
        .strip_suffix(".git")
        .unwrap_or(p.trim_start_matches('/'))
}

/// Every configured remote as `(name, parsed url)`, `origin` first, then the
/// rest alphabetically; unparseable remotes are skipped. Used by `push-pending`
/// to source a file's bytes from whichever remote already holds it when staging
/// has been drained.
pub fn parse_all_remotes(repo: Option<&Path>) -> Vec<(String, RemoteUrl)> {
    let start_dir = match repo
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_dir().ok())
    {
        Some(d) => d,
        None => return Vec::new(),
    };
    let gix_repo = match gix::discover(&start_dir) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut names: Vec<String> = gix_repo
        .remote_names()
        .into_iter()
        .map(|n| n.to_string())
        .collect();
    names.sort_by(|a, b| match (a.as_str(), b.as_str()) {
        ("origin", "origin") => std::cmp::Ordering::Equal,
        ("origin", _) => std::cmp::Ordering::Less,
        (_, "origin") => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    });
    let mut out = Vec::new();
    for name in names {
        let Ok(remote) = gix_repo.find_remote(name.as_str()) else {
            continue;
        };
        let Some(url) = remote.url(gix::remote::Direction::Fetch) else {
            continue;
        };
        if let Ok(parsed) = parse_remote(&url.to_bstring().to_string()) {
            out.push((name, parsed));
        }
    }
    out
}

/// Look up and parse `origin`'s fetch URL via gix (no `git remote` subprocess).
pub fn parse_origin(repo: Option<&Path>) -> Result<RemoteUrl> {
    let start_dir = repo
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow!("can't resolve cwd to discover repo"))?;
    let gix_repo =
        gix::discover(&start_dir).with_context(|| format!("opening repo at {start_dir:?}"))?;
    let remote = gix_repo
        .find_remote("origin")
        .map_err(|e| anyhow!("git remote get-url origin: {e}"))?;
    let url = remote
        .url(gix::remote::Direction::Fetch)
        .ok_or_else(|| anyhow!("origin has no fetch URL configured"))?;
    parse_remote(&url.to_bstring().to_string())
}
