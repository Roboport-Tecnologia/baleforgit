//! Resolve `(server_url, token)` for a remote. A literal `bale.serverUrl` +
//! `bale.token` pair short-circuits everything; otherwise (half a pair is
//! ignored with a warning) the forge is asked. See `docs/BALE_FORGE_PROTOCOL.md`.
//!
//! 1. Parse the remote (`origin` unless overridden) → HTTPS or SSH URL.
//! 2. Obtain a forge-minted JWT + baleforgit-server URL:
//!    - HTTPS: POST `.../info/bale/authenticate?op=<op>` (read tries anonymous
//!      first, else Basic auth from `git credential fill`); the forge returns
//!      `{href, header.Authorization=Bearer <jwt>}`.
//!    - SSH: `ssh git@host git-bale-authenticate <repo> <op>` returns the same.
//! 3. Token exchange: `GET .../api/models/<owner>/<repo>/bale-{read,write}-token/<rev>`
//!    with the forge JWT → final bale token.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use reqwest::header;
use serde::Deserialize;
use xet_client::cas_client::auth::{AuthError, TokenInfo, TokenRefresher};

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
    resolve_for_remote(raw, scope, None).await
}

/// Like [`resolve`], but minted against `remote_override` (`None` = `origin`).
/// The pre-push hook passes the actual push target so the token, and thus the
/// server-side repo scope of any upload, matches it rather than `origin`.
pub async fn resolve_for_remote(
    raw: &RawConfig,
    scope: Scope,
    remote_override: Option<RemoteUrl>,
) -> Result<ResolvedAuth> {
    // Half a pair is ignored: a lone token would go to whatever server some
    // remote's forge names; a lone URL would get another setup's token.
    match (raw.server_url.as_ref(), raw.token.as_ref()) {
        (Some(url), Some(tok)) => {
            return Ok(ResolvedAuth {
                server_url: url.clone(),
                token: tok.clone(),
                token_expiration: raw.token_expiration.unwrap_or_else(far_future_epoch),
            });
        }
        (Some(_), None) => tracing::warn!(
            "bale.serverUrl is set without bale.token; ignoring it and using the forge-advertised server"
        ),
        (None, Some(_)) => tracing::warn!(
            "bale.token is set without bale.serverUrl; ignoring it and minting a token via the forge"
        ),
        (None, None) => {}
    }

    // The common git dir itself: discovery and `git credential fill` both work
    // from inside it, even for a bare repo with linked worktrees.
    let repo_cwd = raw.git_dir.as_deref();
    let remote = match remote_override {
        Some(r) => r,
        None => parse_origin(repo_cwd)
            .context("auto-resolving Bale auth: failed to read git remote 'origin'")?,
    };
    let (owner, repo_name) = remote.owner_and_repo()?;
    // Interpolated into a URL and into the ssh command (re-shell-parsed by the
    // server), so reject anything outside a safe alphabet first.
    validate_segment("owner", owner)?;
    validate_segment("repo", repo_name)?;
    let revision = "main"; // TODO: derive from HEAD for branch-scoped tokens.

    let (server_url, forge_bearer) = match remote.scheme {
        RemoteScheme::Ssh => {
            let auth =
                ssh_authenticate(&remote, owner, repo_name, scope, raw.ssh_command.as_deref())
                    .await?;
            let bearer = strip_bearer(&auth.authorization)
                .ok_or_else(|| anyhow!("git-bale-authenticate returned non-Bearer Authorization"))?
                .to_string();
            (auth.href, bearer)
        }
        RemoteScheme::Http | RemoteScheme::Https => {
            let auth =
                authenticate_http_with_fallback(&remote, owner, repo_name, scope, repo_cwd).await?;
            let bearer = strip_bearer(&auth.authorization).ok_or_else(|| {
                anyhow!("/info/bale/authenticate returned non-Bearer Authorization")
            })?;
            (auth.href, bearer.to_string())
        }
    };

    require_tls(&remote, &server_url, "forge-advertised server URL")?;
    let resolved = exchange_token(
        &server_url,
        owner,
        repo_name,
        revision,
        scope,
        &forge_bearer,
    )
    .await?;
    require_tls(&remote, &resolved.server_url, "token-exchange casUrl")?;
    Ok(resolved)
}

/// Refuses cleartext `http://` for a remote reached over https/ssh: the forge JWT
/// and bale token would cross the network unencrypted. Loopback is exempt.
fn require_tls(remote: &RemoteUrl, url: &str, what: &str) -> Result<()> {
    if remote.scheme == RemoteScheme::Http {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Ok(());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if loopback {
        return Ok(());
    }
    Err(anyhow!(
        "refusing {what} {url}: plain http would send credentials in cleartext for a remote \
         reached over {}",
        if remote.scheme == RemoteScheme::Ssh {
            "ssh"
        } else {
            "https"
        }
    ))
}

/// Mirrors xet's private `REFRESH_BUFFER_SEC`: a fresh token whose `exp` is
/// already inside this window is treated as expired and refreshed immediately.
const REFRESH_BUFFER_SEC: u64 = 30;

/// Consecutive already-expired re-mints mean client/server clock skew exceeds
/// the token TTL; surface it instead of storming the forge with doomed re-mints.
const MAX_EXPIRED_REFRESHES: u32 = 3;

/// Re-mints through the forge so xet swaps in a new token ~30s before the
/// short-lived one lapses; lets a single operation outlive one token's TTL.
pub fn forge_refresher(raw: &RawConfig, scope: Scope) -> Arc<dyn TokenRefresher> {
    forge_refresher_for_remote(raw, scope, None)
}

/// [`forge_refresher`] bound to a remote, so re-mints during a push to a
/// non-`origin` remote stay scoped to that remote's repo.
pub fn forge_refresher_for_remote(
    raw: &RawConfig,
    scope: Scope,
    remote: Option<RemoteUrl>,
) -> Arc<dyn TokenRefresher> {
    Arc::new(ForgeTokenRefresher {
        raw: raw.clone(),
        scope,
        remote,
        consecutive_expired: AtomicU32::new(0),
    })
}

struct ForgeTokenRefresher {
    raw: RawConfig,
    scope: Scope,
    remote: Option<RemoteUrl>,
    consecutive_expired: AtomicU32,
}

#[async_trait::async_trait]
impl TokenRefresher for ForgeTokenRefresher {
    async fn refresh(&self) -> std::result::Result<TokenInfo, AuthError> {
        // xet serializes refresh() (`&mut self` on TokenProvider), so this 1s
        // floor throttles skew-driven retries before the cap below trips.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let resolved = resolve_for_remote(&self.raw, self.scope, self.remote.clone())
            .await
            .map_err(|e| AuthError::token_refresh_failure(format!("{e:#}")))?;
        let now = now_utc();
        if resolved.token_expiration <= now.saturating_add(REFRESH_BUFFER_SEC) {
            let n = self.consecutive_expired.fetch_add(1, Ordering::Relaxed) + 1;
            if n > MAX_EXPIRED_REFRESHES {
                return Err(AuthError::token_refresh_failure(format!(
                    "re-minted bale token is already expired (exp {} ≤ now {now}) {n}× in a row; \
                     client and server clocks differ by more than the token TTL — sync clocks (NTP)",
                    resolved.token_expiration,
                )));
            }
        } else {
            self.consecutive_expired.store(0, Ordering::Relaxed);
        }
        Ok((resolved.token, resolved.token_expiration))
    }
}

#[derive(Deserialize)]
struct AuthenticateHTTPResponse {
    href: String,
    #[serde(default)]
    header: std::collections::HashMap<String, String>,
}

/// Read scope probes anonymously first so cloning a public repo never prompts
/// for credentials; only a 401/403 falls back to `git credential fill`. Upload
/// scope always authenticates: anonymous writes are never granted.
async fn authenticate_http_with_fallback(
    remote: &RemoteUrl,
    owner: &str,
    repo: &str,
    scope: Scope,
    repo_cwd: Option<&Path>,
) -> Result<SshAuthOutcome> {
    if scope == Scope::Read {
        match authenticate_http(remote, owner, repo, scope, None).await {
            Ok(outcome) => return Ok(outcome),
            Err(AuthHttpError::NeedsAuth) => {}
            Err(AuthHttpError::Other(e)) => return Err(e),
        }
    }
    // The forge verifies the password locally and returns a JWT — the password
    // never reaches baleforgit-server (the point of this hop).
    let (username, password) = git_credential_fill(remote, repo_cwd)?;
    authenticate_http(
        remote,
        owner,
        repo,
        scope,
        Some((username.as_str(), password.as_str())),
    )
    .await
    .map_err(AuthHttpError::into_anyhow)
}

enum AuthHttpError {
    /// 401/403: private repo, or the forge doesn't grant anonymous read.
    NeedsAuth,
    Other(anyhow::Error),
}

impl AuthHttpError {
    fn into_anyhow(self) -> anyhow::Error {
        match self {
            AuthHttpError::NeedsAuth => anyhow!(
                "/info/bale/authenticate returned HTTP 401/403 after presenting credentials"
            ),
            AuthHttpError::Other(e) => e,
        }
    }
}

/// `creds = None` is the anonymous probe: no `Authorization` header at all.
async fn authenticate_http(
    remote: &RemoteUrl,
    owner: &str,
    repo: &str,
    scope: Scope,
    creds: Option<(&str, &str)>,
) -> std::result::Result<SshAuthOutcome, AuthHttpError> {
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
    let client = http_client().map_err(AuthHttpError::Other)?;
    let mut req = client.post(&url);
    if let Some((username, password)) = creds {
        req = req.basic_auth(username, Some(password));
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("POST {url}"))
        .map_err(AuthHttpError::Other)?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(AuthHttpError::NeedsAuth);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthHttpError::Other(anyhow!(
            "/info/bale/authenticate {url} returned HTTP {} ({})",
            status.as_u16(),
            body.trim()
        )));
    }
    let parsed: AuthenticateHTTPResponse = resp
        .json()
        .await
        .with_context(|| "decoding /info/bale/authenticate body")
        .map_err(AuthHttpError::Other)?;
    let authz = parsed.header.get("Authorization").cloned().ok_or_else(|| {
        AuthHttpError::Other(anyhow!(
            "/info/bale/authenticate response has no Authorization header"
        ))
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
    ssh_command: Option<&str>,
) -> Result<SshAuthOutcome> {
    let op = match scope {
        Scope::Read => "download",
        Scope::Write => "upload",
    };
    let host = remote.host.as_str();
    let user = remote.user.as_deref().unwrap_or("git");
    crate::remote::validate_ssh_target(user, host)?;
    // ssh is first-occurrence-wins per keyword, so a user's GIT_SSH_COMMAND /
    // core.sshCommand options override these safe defaults.
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
    // `--` ends option parsing, so even a destination that slipped past
    // validation can't be read as `-oProxyCommand=…` (also after a user's
    // GIT_SSH_COMMAND options, since these args are appended).
    args.push("--".into());
    args.push(format!("{user}@{host}"));
    args.push(format!("git-bale-authenticate {owner}/{repo} {op}"));

    let ssh_command = ssh_command.map(str::to_owned);
    let args_clone = args.clone();
    let out = tokio::task::spawn_blocking(move || {
        ssh_subprocess(ssh_command.as_deref(), &args_clone)
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

/// Like git, runs a configured `GIT_SSH_COMMAND` / `core.sshCommand` through
/// `/bin/sh` with our args as `"$@"` so its quoting is honored (e.g.
/// `ssh -F "/path with spaces"`). Bare `ssh` when unset, or on non-unix where
/// there's no POSIX shell to assume.
fn ssh_subprocess(ssh_command: Option<&str>, args: &[String]) -> Command {
    #[cfg(unix)]
    if let Some(cmd) = ssh_command.map(str::trim).filter(|c| !c.is_empty()) {
        let mut c = Command::new("/bin/sh");
        // argv[0]-after-`-c` ($0) is cosmetic; "$@" picks up `args`.
        c.arg("-c").arg(format!("{cmd} \"$@\"")).arg(cmd).args(args);
        return c;
    }
    #[cfg(not(unix))]
    let _ = ssh_command;
    let mut c = Command::new("ssh");
    c.args(args);
    c
}

/// `cwd` is the repo so its local `credential.helper` applies.
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
        // Can't fail: stdin is Stdio::piped() above.
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
    // A helper that only stored a token omits username; forges accept any
    // username with a token over Basic auth.
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
    // xet compares `exp` (server clock) to the local clock, so skew larger than
    // the TTL makes a fresh token look already-expired.
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

/// Rejects path traversal and shell metacharacters that could survive ssh-argv
/// quoting and be re-parsed server-side.
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

fn now_utc() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Expiry for a static `bale.token` / `BALE_TOKEN` without `bale.tokenExpiration`:
/// xet requires an expiry and refreshes once it lapses, but there's no forge to
/// re-mint from, so a near-term value would trigger a refresh that can't succeed.
fn far_future_epoch() -> u64 {
    now_utc() + 100 * 365 * 24 * 60 * 60
}
