//! Parse a `git remote get-url origin` value into the parts we need for
//! discovery and auth: protocol, host, optional port, repo path.
//!
//! Recognized shapes (the standard set git-lfs and most forges accept):
//!
//! ```text
//!   https://git.example.com/alice/repo.git
//!   http://localhost:3000/alice/repo.git
//!   git@git.example.com:alice/repo.git             (scp-style SSH)
//!   ssh://git@git.example.com:2222/alice/repo.git
//! ```
//!
//! The `.git` suffix on the path is optional and stripped if present.

use std::path::Path;
use std::process::Command;

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

    /// Reconstruct the base URL the forge's DFS endpoints live under for
    /// this remote, regardless of which scheme the remote actually uses. For
    /// SSH remotes we assume https on the same host on the default port —
    /// the caller can override via `dfs.serverUrl` if the deployment splits
    /// the forge's HTTP and SSH onto different hosts.
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

    let (scheme_str, rest) = s.split_once("://").unwrap();
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

/// Run `git -C <repo> remote get-url origin` and parse the result.
pub fn parse_origin(repo: Option<&Path>) -> Result<RemoteUrl> {
    let mut cmd = Command::new("git");
    if let Some(p) = repo {
        cmd.current_dir(p);
    }
    cmd.args(["remote", "get-url", "origin"]);
    let out = cmd
        .output()
        .with_context(|| "spawning git remote get-url origin")?;
    if !out.status.success() {
        return Err(anyhow!(
            "git remote get-url origin failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    parse_remote(&url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_with_port() {
        let r = parse_remote("http://localhost:3000/alice/repo.git").unwrap();
        assert_eq!(r.scheme, RemoteScheme::Http);
        assert_eq!(r.host, "localhost");
        assert_eq!(r.port, Some(3000));
        assert_eq!(r.repo_path, "alice/repo");
        assert_eq!(r.user, None);
        assert_eq!(r.https_base(), "http://localhost:3000");
        assert_eq!(r.owner_and_repo().unwrap(), ("alice", "repo"));
    }

    #[test]
    fn https_default_port() {
        let r = parse_remote("https://git.example.com/ns/name").unwrap();
        assert_eq!(r.port, None);
        assert_eq!(r.https_base(), "https://git.example.com");
    }

    #[test]
    fn scp_style_ssh() {
        let r = parse_remote("git@git.example.com:alice/repo.git").unwrap();
        assert_eq!(r.scheme, RemoteScheme::Ssh);
        assert_eq!(r.user.as_deref(), Some("git"));
        assert_eq!(r.host, "git.example.com");
        assert_eq!(r.port, None);
        assert_eq!(r.repo_path, "alice/repo");
        // SSH remote should suggest https for the forge's web endpoints.
        assert_eq!(r.https_base(), "https://git.example.com");
    }

    #[test]
    fn ssh_url_with_port() {
        let r = parse_remote("ssh://git@git.example.com:2222/alice/repo.git").unwrap();
        assert_eq!(r.scheme, RemoteScheme::Ssh);
        assert_eq!(r.user.as_deref(), Some("git"));
        assert_eq!(r.host, "git.example.com");
        assert_eq!(r.port, Some(2222));
        assert_eq!(r.repo_path, "alice/repo");
    }

    #[test]
    fn ssh_url_default_user() {
        // ssh:// without `<user>@` still defaults to git for our purposes.
        let r = parse_remote("ssh://git.example.com/alice/repo.git").unwrap();
        assert_eq!(r.user.as_deref(), Some("git"));
    }

    #[test]
    fn dot_git_optional() {
        let r = parse_remote("https://example.com/alice/repo").unwrap();
        assert_eq!(r.repo_path, "alice/repo");
        let r2 = parse_remote("https://example.com/alice/repo.git").unwrap();
        assert_eq!(r2.repo_path, "alice/repo");
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_remote("file:///tmp/foo").is_err());
    }

    #[test]
    fn rejects_bad_repo_path() {
        let r = parse_remote("https://example.com/missing-slash.git").unwrap();
        assert!(r.owner_and_repo().is_err());
    }
}
