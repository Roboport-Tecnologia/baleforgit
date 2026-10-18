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
    /// Defaults to `git` for ssh; `None` for http/https unless the URL names one.
    pub user: Option<String>,
    pub host: String,
    /// `None` = scheme default.
    pub port: Option<u16>,
    /// `owner/repo`, `.git` stripped; may contain extra segments when a forge
    /// nests repos under a prefix.
    pub repo_path: String,
}

impl RemoteUrl {
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
    /// same host, default port.
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

pub fn parse_remote(s: &str) -> Result<RemoteUrl> {
    let s = s.trim();

    // scp-style SSH: `[user@]host:path`, i.e. no `://` anywhere.
    if !s.contains("://") {
        if let Some((before, path)) = s.split_once(':') {
            let (user, host) = match before.split_once('@') {
                Some((u, h)) => (Some(u.to_string()), h.to_string()),
                None => (None, before.to_string()),
            };
            if host.is_empty() {
                return Err(anyhow!("scp-style remote missing host: {s}"));
            }
            let user = user.unwrap_or_else(|| "git".into());
            validate_ssh_target(&user, &host)?;
            return Ok(RemoteUrl {
                scheme: RemoteScheme::Ssh,
                user: Some(user),
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
    validate_ssh_target(user.as_deref().unwrap_or("git"), &host)?;

    Ok(RemoteUrl {
        scheme,
        user,
        host,
        port,
        repo_path: strip_dot_git(path).to_string(),
    })
}

/// Reject a user/host that ssh could parse as an option (`-oProxyCommand=…`)
/// or that smuggles extra argv/shell tokens. Remote URLs come from repo config
/// and can be attacker-influenced (a cloned repo's submodule, a pasted URL).
pub fn validate_ssh_target(user: &str, host: &str) -> Result<()> {
    for (label, v) in [("user", user), ("host", host)] {
        if v.is_empty() || v.starts_with('-') {
            return Err(anyhow!("remote {label} {v:?} is empty or starts with '-'"));
        }
        if v.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(anyhow!(
                "remote {label} {v:?} contains whitespace or control characters"
            ));
        }
    }
    if host.contains('@') {
        return Err(anyhow!("remote host {host:?} contains '@'"));
    }
    Ok(())
}

fn strip_dot_git(p: &str) -> &str {
    p.trim_start_matches('/')
        .strip_suffix(".git")
        .unwrap_or(p.trim_start_matches('/'))
}

/// `origin` first, then alphabetical; unparseable remotes are skipped.
/// push-pending sources already-pushed files from whichever remote holds them.
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
