//! Auto-resolve the `(server_url, token)` pair that the xet-core client
//! needs, when one or both are absent from local config.
//!
//! The resolution chains together four steps; each is skipped when its
//! output is already known:
//!
//! 1. **Remote parse** — `git remote get-url origin` → HTTPS or SSH URL.
//! 2. **Discover xet-server URL** — HTTPS: `GET <gitea>/<owner>/<repo>.git/info/dfs`.
//!    SSH: piggy-backs on step 3 (the `git-dfs-authenticate` response carries
//!    the URL as `href`).
//! 3. **Obtain a gitea-side bearer**:
//!    - HTTPS: `git credential fill` → user's gitea PAT.
//!    - SSH: `ssh git@host git-dfs-authenticate <repo> <op>` → ephemeral JWT.
//! 4. **Token exchange** — `GET <xet-server>/api/models/<owner>/<repo>/xet-{rw}-token/<rev>`
//!    with `Authorization: Bearer <gitea-bearer>` → final xet token.
//!
//! Steps 3 and 4 are skipped when the caller's local config already holds a
//! literal xet token (the m11 test path). Step 2 is skipped when local
//! config already holds a `dfs.serverUrl`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use reqwest::header;
use serde::Deserialize;

use crate::config::RawConfig;
use crate::remote::{parse_origin, RemoteScheme, RemoteUrl};

/// Token scope, matching xet-server's `Scope` enum (lowercase JSON / URL
/// segment values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Read,
    Write,
}

impl Scope {
    /// The URL segment xet-server's HF endpoint expects.
    fn url_segment(self) -> &'static str {
        match self {
            Scope::Read => "xet-read-token",
            Scope::Write => "xet-write-token",
        }
    }
}

/// Output of a complete resolution. Same shape the existing `DfsConfig`
/// has held; produced from a [`RawDfsConfig`] + [`Scope`].
#[derive(Clone, Debug)]
pub struct ResolvedAuth {
    pub server_url: String,
    pub token: String,
    pub token_expiration: u64,
}

/// Run the full resolution. Network IO and subprocess calls happen here.
pub async fn resolve(raw: &RawConfig, scope: Scope) -> Result<ResolvedAuth> {
    // Fast path: m11 mode (both pieces locally configured).
    if let (Some(url), Some(tok)) = (raw.server_url.as_ref(), raw.token.as_ref()) {
        return Ok(ResolvedAuth {
            server_url: url.clone(),
            token: tok.clone(),
            token_expiration: raw.token_expiration.unwrap_or_else(far_future_epoch),
        });
    }

    // Use the git_dir's parent as the repo cwd for `git remote` invocations.
    // When the filter is running outside a real repo we just rely on cwd.
    let repo_cwd = raw.git_dir.as_deref().and_then(|p| p.parent());
    let remote = parse_origin(repo_cwd)
        .context("auto-resolving DFS auth: failed to read git remote 'origin'")?;
    let (owner, repo_name) = remote.owner_and_repo()?;
    let revision = "main"; // TODO: derive from HEAD when we want branch-scoped tokens.

    let (server_url, gitea_bearer) = match remote.scheme {
        RemoteScheme::Ssh => {
            let auth = ssh_authenticate(&remote, owner, repo_name, scope).await?;
            let bearer = strip_bearer(&auth.authorization)
                .ok_or_else(|| anyhow!("git-dfs-authenticate returned non-Bearer Authorization"))?
                .to_string();
            // If user explicitly set a server URL, prefer it over the SSH-supplied one.
            let url = raw.server_url.clone().unwrap_or(auth.href);
            (url, bearer)
        }
        RemoteScheme::Http | RemoteScheme::Https => {
            let url = if let Some(u) = raw.server_url.clone() {
                u
            } else {
                discover_server_url(&remote, owner, repo_name).await?
            };
            let bearer = git_credential_fill(&remote, repo_cwd)?;
            (url, bearer)
        }
    };

    // Caller already has a final xet token (e.g. m11 partial-config) — skip exchange.
    if let Some(tok) = raw.token.clone() {
        return Ok(ResolvedAuth {
            server_url,
            token: tok,
            token_expiration: raw.token_expiration.unwrap_or_else(far_future_epoch),
        });
    }

    exchange_token(
        &server_url,
        owner,
        repo_name,
        revision,
        scope,
        &gitea_bearer,
    )
    .await
}

#[derive(Deserialize)]
struct DiscoveryResponse {
    server_url: String,
}

async fn discover_server_url(remote: &RemoteUrl, owner: &str, repo: &str) -> Result<String> {
    let url = format!("{}/{}/{}.git/info/dfs", remote.https_base(), owner, repo);
    let client = http_client()?;
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "discovery {url} returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    let body: DiscoveryResponse = resp
        .json()
        .await
        .with_context(|| "decoding /info/dfs body")?;
    if body.server_url.is_empty() {
        return Err(anyhow!("discovery returned empty server_url"));
    }
    Ok(body.server_url.trim_end_matches('/').to_string())
}

#[derive(Deserialize, Debug)]
struct SshAuthenticateResponse {
    href: String,
    #[serde(rename = "Authorization", default)]
    authorization: String,
    // Mirror gitea's shape: `header` is the canonical place; we keep
    // `Authorization` as a fallback for tools that flatten it.
    #[serde(default)]
    header: std::collections::HashMap<String, String>,
}

struct SshAuthOutcome {
    href: String,
    authorization: String,
}

async fn ssh_authenticate(
    remote: &RemoteUrl,
    owner: &str,
    repo: &str,
    scope: Scope,
) -> Result<SshAuthOutcome> {
    let op = match scope {
        Scope::Read => "download",
        Scope::Write => "upload",
    };
    let host = remote.host.as_str();
    let user = remote.user.as_deref().unwrap_or("git");
    let mut args: Vec<String> = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
    ];
    if let Some(port) = remote.port {
        args.push("-p".into());
        args.push(port.to_string());
    }
    args.push(format!("{user}@{host}"));
    args.push(format!("git-dfs-authenticate {owner}/{repo} {op}"));

    // Run blocking, off the async executor.
    let args_clone = args.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("ssh")
            .args(&args_clone)
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
    })
    .await
    .with_context(|| "joining ssh subprocess")?
    .with_context(|| "spawning ssh")?;
    if !out.status.success() {
        return Err(anyhow!(
            "ssh {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let parsed: SshAuthenticateResponse =
        serde_json::from_slice(&out.stdout).with_context(|| {
            format!(
                "decoding git-dfs-authenticate output: {:?}",
                String::from_utf8_lossy(&out.stdout)
            )
        })?;
    let authz = parsed
        .header
        .get("Authorization")
        .cloned()
        .or_else(|| (!parsed.authorization.is_empty()).then(|| parsed.authorization.clone()))
        .ok_or_else(|| anyhow!("git-dfs-authenticate response has no Authorization header"))?;
    Ok(SshAuthOutcome {
        href: parsed.href.trim_end_matches('/').to_string(),
        authorization: authz,
    })
}

/// Run `git credential fill` to pull the user's stored credential for the
/// remote's host. Returns the password field, which for gitea is the PAT.
/// `cwd` is the repo path so the repo's local `credential.helper` setting
/// is honored (otherwise only `--global` / system helpers apply).
fn git_credential_fill(remote: &RemoteUrl, cwd: Option<&Path>) -> Result<String> {
    let protocol = match remote.scheme {
        RemoteScheme::Http => "http",
        RemoteScheme::Https => "https",
        RemoteScheme::Ssh => {
            // Caller should've taken the SSH branch; defensive guard.
            return Err(anyhow!("git_credential_fill called on SSH remote"));
        }
    };
    // The blank line at the end terminates the request.
    let mut stdin_body = format!("protocol={protocol}\nhost={}\n", remote.host);
    if let Some(port) = remote.port {
        stdin_body.push_str(&format!("port={port}\n"));
    }
    stdin_body.push('\n');

    let mut cmd = Command::new("git");
    if let Some(p) = cwd {
        cmd.current_dir(p);
    }
    let mut child = cmd
        .args(["credential", "fill"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "spawning git credential fill")?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(stdin_body.as_bytes())?;
    }
    let out = child
        .wait_with_output()
        .with_context(|| "waiting on git credential fill")?;
    if !out.status.success() {
        return Err(anyhow!(
            "git credential fill failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let mut password = None;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.strip_prefix("password=") {
            password = Some(rest.to_string());
        }
    }
    password.ok_or_else(|| anyhow!("git credential fill returned no password field"))
}

#[derive(Deserialize)]
struct TokenExchangeResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    exp: u64,
    #[serde(rename = "casUrl", default)]
    cas_url: Option<String>,
}

async fn exchange_token(
    server_url: &str,
    owner: &str,
    repo: &str,
    revision: &str,
    scope: Scope,
    gitea_bearer: &str,
) -> Result<ResolvedAuth> {
    let url = format!(
        "{}/api/models/{}/{}/{}/{}",
        server_url.trim_end_matches('/'),
        owner,
        repo,
        scope.url_segment(),
        revision,
    );
    let client = http_client()?;
    let resp = client
        .get(&url)
        .header(header::AUTHORIZATION, format!("Bearer {gitea_bearer}"))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!(
            "token exchange {url} returned HTTP {} ({})",
            status.as_u16(),
            body.trim()
        ));
    }
    let body: TokenExchangeResponse = resp
        .json()
        .await
        .with_context(|| "decoding xet-token response")?;
    let resolved_url = body
        .cas_url
        .as_deref()
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| server_url.trim_end_matches('/').to_string());
    Ok(ResolvedAuth {
        server_url: resolved_url,
        token: body.access_token,
        token_expiration: body.exp,
    })
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("git-dfs/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| anyhow!("building http client: {e}"))
}

fn strip_bearer(authz: &str) -> Option<&str> {
    authz.strip_prefix("Bearer ").map(str::trim)
}

fn far_future_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + 100 * 365 * 24 * 60 * 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_url_segments() {
        assert_eq!(Scope::Read.url_segment(), "xet-read-token");
        assert_eq!(Scope::Write.url_segment(), "xet-write-token");
    }

    #[test]
    fn strip_bearer_works() {
        assert_eq!(strip_bearer("Bearer abc.def.ghi"), Some("abc.def.ghi"));
        assert_eq!(strip_bearer("token foo"), None);
        assert_eq!(strip_bearer("Bearer  spaced  "), Some("spaced"));
    }

    #[test]
    fn passthrough_when_both_set() {
        let raw = RawConfig {
            server_url: Some("http://x:1".into()),
            token: Some("xet-token".into()),
            token_expiration: Some(123),
            cache_dir: std::path::PathBuf::from("/tmp/cache"),
            git_dir: None,
        };
        // Use a small tokio runtime to drive the async fn.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let out = rt.block_on(resolve(&raw, Scope::Read)).unwrap();
        assert_eq!(out.server_url, "http://x:1");
        assert_eq!(out.token, "xet-token");
        assert_eq!(out.token_expiration, 123);
    }
}
