//! Auto-resolve `(server_url, token)` when local config lacks one or both.
//! See `docs/BALE_FORGE_PROTOCOL.md` for the wire shape. Three steps, each
//! skipped once its output is known:
//!
//! 1. Parse `origin` → HTTPS or SSH URL.
//! 2. Obtain a forge-minted JWT (+ baleforgit-server URL, unless overridden by
//!    `bale.serverUrl`):
//!    - HTTPS: `git credential fill`, then POST
//!      `.../info/bale/authenticate?op=<op>` with Basic auth; the forge verifies
//!      locally and returns `{href, header.Authorization=Bearer <jwt>}`.
//!    - SSH: `ssh git@host git-bale-authenticate <repo> <op>` returns the same.
//! 3. Token exchange: `GET .../bale-{rw}-token/<rev>` with the forge JWT →
//!    final bale token. Skipped when local config holds a literal token.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use reqwest::header;
use serde::Deserialize;

use crate::config::RawConfig;
use crate::remote::{parse_origin, RemoteScheme, RemoteUrl};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Read,
    Write,
}

impl Scope {
    fn url_segment(self) -> &'static str {
        match self {
            Scope::Read => "bale-read-token",
            Scope::Write => "bale-write-token",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedAuth {
    pub server_url: String,
    pub token: String,
    pub token_expiration: u64,
}

pub async fn resolve(raw: &RawConfig, scope: Scope) -> Result<ResolvedAuth> {
    // Fast path: both pieces locally configured.
    if let (Some(url), Some(tok)) = (raw.server_url.as_ref(), raw.token.as_ref()) {
        return Ok(ResolvedAuth {
            server_url: url.clone(),
            token: tok.clone(),
            token_expiration: raw.token_expiration.unwrap_or_else(far_future_epoch),
        });
    }

    let repo_cwd = raw.git_dir.as_deref().and_then(|p| p.parent());
    let remote = parse_origin(repo_cwd)
        .context("auto-resolving Bale auth: failed to read git remote 'origin'")?;
    let (owner, repo_name) = remote.owner_and_repo()?;
    // Interpolated into a URL and into the ssh command (re-shell-parsed by the
    // server), so reject anything outside a safe alphabet first.
    validate_segment("owner", owner)?;
    validate_segment("repo", repo_name)?;
    let revision = "main"; // TODO: derive from HEAD for branch-scoped tokens.

    let (server_url, forge_bearer) = match remote.scheme {
        RemoteScheme::Ssh => {
            let auth = ssh_authenticate(&remote, owner, repo_name, scope).await?;
            let bearer = strip_bearer(&auth.authorization)
                .ok_or_else(|| anyhow!("git-bale-authenticate returned non-Bearer Authorization"))?
                .to_string();
            let url = raw.server_url.clone().unwrap_or(auth.href);
            (url, bearer)
        }
        RemoteScheme::Http | RemoteScheme::Https => {
            // The forge verifies the password locally and returns a JWT — the
            // password never reaches baleforgit-server (the point of this hop).
            let (username, password) = git_credential_fill(&remote, repo_cwd)?;
            let auth =
                authenticate_http(&remote, owner, repo_name, scope, &username, &password).await?;
            let bearer = strip_bearer(&auth.authorization).ok_or_else(|| {
                anyhow!("/info/bale/authenticate returned non-Bearer Authorization")
            })?;
            let url = raw.server_url.clone().unwrap_or(auth.href);
            (url, bearer.to_string())
        }
    };

    // Caller already has a final bale token — skip exchange.
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
        &forge_bearer,
    )
    .await
}

#[derive(Deserialize)]
struct AuthenticateHTTPResponse {
    href: String,
    #[serde(default)]
    header: std::collections::HashMap<String, String>,
}

/// POST `.../info/bale/authenticate?op=...` with Basic auth → forge JWT +
/// baleforgit-server URL. See `docs/BALE_FORGE_PROTOCOL.md`.
async fn authenticate_http(
    remote: &RemoteUrl,
    owner: &str,
    repo: &str,
    scope: Scope,
    username: &str,
    password: &str,
) -> Result<SshAuthOutcome> {
    let op = match scope {
        Scope::Read => "download",
        Scope::Write => "upload",
    };
    let url = format!(
        "{}/{}/{}.git/info/bale/authenticate?op={}",
        remote.https_base(),
        owner,
        repo,
        op,
    );
    let client = http_client()?;
    let resp = client
        .post(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!(
            "/info/bale/authenticate {url} returned HTTP {} ({})",
            status.as_u16(),
            body.trim()
        ));
    }
    let parsed: AuthenticateHTTPResponse = resp
        .json()
        .await
        .with_context(|| "decoding /info/bale/authenticate body")?;
    let authz =
        parsed.header.get("Authorization").cloned().ok_or_else(|| {
            anyhow!("/info/bale/authenticate response has no Authorization header")
        })?;
    Ok(SshAuthOutcome {
        href: parsed.href.trim_end_matches('/').to_string(),
        authorization: authz,
    })
}

#[derive(Deserialize, Debug)]
struct SshAuthenticateResponse {
    href: String,
    #[serde(rename = "Authorization", default)]
    authorization: String,
    // `header` is canonical; top-level `Authorization` is a fallback for tools
    // that flatten it.
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
    args.push(format!("git-bale-authenticate {owner}/{repo} {op}"));

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

    // Never log the raw body — it carries the forge-minted bearer token.
    let parsed: SshAuthenticateResponse =
        serde_json::from_slice(&out.stdout).with_context(|| {
            format!(
                "decoding git-bale-authenticate output ({} bytes)",
                out.stdout.len()
            )
        })?;
    let authz = parsed
        .header
        .get("Authorization")
        .cloned()
        .or_else(|| (!parsed.authorization.is_empty()).then(|| parsed.authorization.clone()))
        .ok_or_else(|| anyhow!("git-bale-authenticate response has no Authorization header"))?;
    Ok(SshAuthOutcome {
        href: parsed.href.trim_end_matches('/').to_string(),
        authorization: authz,
    })
}

/// `git credential fill` → `(username, password)` for the remote's host. The
/// password goes only to the forge's authenticate endpoint (never to
/// baleforgit-server). `cwd` is the repo so its local `credential.helper` applies.
fn git_credential_fill(remote: &RemoteUrl, cwd: Option<&Path>) -> Result<(String, String)> {
    let protocol = match remote.scheme {
        RemoteScheme::Http => "http",
        RemoteScheme::Https => "https",
        RemoteScheme::Ssh => {
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

    let mut username = None;
    let mut password = None;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.strip_prefix("username=") {
            username = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("password=") {
            password = Some(rest.to_string());
        }
    }
    let password =
        password.ok_or_else(|| anyhow!("git credential fill returned no password field"))?;
    // Username may be absent if the credential helper only stored a token;
    // forges typically accept "<any>:token" via Basic auth, so default to "git".
    let username = username.unwrap_or_else(|| "git".to_string());
    Ok((username, password))
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
    forge_bearer: &str,
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
        .header(header::AUTHORIZATION, format!("Bearer {forge_bearer}"))
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
        .with_context(|| "decoding bale-token response")?;
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
        .user_agent(concat!("git-bale/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| anyhow!("building http client: {e}"))
}

fn strip_bearer(authz: &str) -> Option<&str> {
    authz.strip_prefix("Bearer ").map(str::trim)
}

/// Accept only `[A-Za-z0-9._-]+`, no leading dot, length 1..=100 — rejects path
/// traversal and shell metacharacters that could survive ssh-argv quoting and be
/// re-parsed server-side.
fn validate_segment(label: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 100 {
        return Err(anyhow!("{label} {s:?} has invalid length"));
    }
    if s.starts_with('.') {
        return Err(anyhow!("{label} {s:?} starts with a dot"));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(anyhow!(
            "{label} {s:?} contains characters outside [A-Za-z0-9._-]"
        ));
    }
    Ok(())
}

fn far_future_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + 100 * 365 * 24 * 60 * 60
}
