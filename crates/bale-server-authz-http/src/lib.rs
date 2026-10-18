//! HTTP-backed `RepoAuthz`: delegates `check_repo_access` to an upstream
//! service; Bale token mint/verify stays local.
//!
//! Wire contract:
//!
//! ```text
//! POST {base_url}/check_access
//! Content-Type: application/json
//! { "hub_bearer": "...", "repo": { "repo_type": "model", "repo_id": "ns/name",
//!                                  "revision": "main" }, "scope": "write",
//!   "purpose": "token" | "file-download", "file_id": "<hex>" (downloads only) }
//!
//! 200 OK  { "user_id": "alice", "repo_id": "id/42" (optional, canonical scope key),
//!           "owner": "7" (accounting owner; required with repo_id) }
//! 401 Unauthorized   — unknown hub_bearer
//! 403 Forbidden      — known user, insufficient access
//! ```
//!
//! `hub_bearer` is the forge's short-lived JWT, opaque to baleforgit-server; the
//! user's long-lived credential never reaches it.

use async_trait::async_trait;
use bale_server_core::{
    AccessGrant, AccessPurpose, CoreError, CoreResult, RepoAuthz, RepoRef, Scope, TokenClaims,
    UserId,
};
use bale_server_tokens as tokens;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Short on purpose: clients refresh via the forge before expiry, so a leaked
/// token has a small blast radius.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

/// Caps a hostile upstream that streams gigabytes; the real body is tiny JSON.
const MAX_UPSTREAM_RESPONSE_BYTES: u64 = 64 * 1024;

pub struct HttpAuthz {
    check_access_url: Url,
    client: reqwest::Client,
    jwt_secret: Vec<u8>,
}

// Reject misconfiguration (relative URLs, junk schemes) before any request fires.
fn build_check_access_url(base_url: &str) -> CoreResult<Url> {
    let trimmed = base_url.trim_end_matches('/');
    let mut base = Url::parse(trimmed)
        .map_err(|e| CoreError::Internal(format!("invalid authz base_url: {e}")))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(CoreError::Internal(format!(
            "invalid authz base_url scheme: {}",
            base.scheme()
        )));
    }
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join("check_access")
        .map_err(|e| CoreError::Internal(format!("invalid authz base_url: {e}")))
}

impl HttpAuthz {
    pub fn new(base_url: impl AsRef<str>, jwt_secret: impl Into<Vec<u8>>) -> CoreResult<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // A redirect would re-POST the body (which carries the user's hub
            // bearer) to wherever `Location` points.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| CoreError::Internal(format!("http client init: {e}")))?;
        Ok(Self {
            check_access_url: build_check_access_url(base_url.as_ref())?,
            client,
            jwt_secret: jwt_secret.into(),
        })
    }
}

#[derive(Serialize)]
struct CheckAccessRequest<'a> {
    hub_bearer: &'a str,
    repo: &'a RepoRef,
    scope: Scope,
    purpose: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct CheckAccessResponse {
    user_id: String,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    owner: Option<String>,
}

fn valid_owner(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn valid_repo_id(s: &str) -> bool {
    matches!(s.split_once('/'), Some((o, n)) if !o.is_empty() && !n.is_empty() && !n.contains('/'))
}

#[async_trait]
impl RepoAuthz for HttpAuthz {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims> {
        tokens::verify(&self.jwt_secret, bearer)
    }

    async fn check_repo_access(
        &self,
        hub_bearer: &str,
        repo: &RepoRef,
        scope: Scope,
        purpose: AccessPurpose<'_>,
    ) -> CoreResult<AccessGrant> {
        let (purpose, file_id) = match purpose {
            AccessPurpose::TokenExchange => ("token", None),
            AccessPurpose::FileDownload { file_id } => ("file-download", Some(file_id)),
        };
        let mut resp = self
            .client
            .post(self.check_access_url.clone())
            .json(&CheckAccessRequest {
                hub_bearer,
                repo,
                scope,
                purpose,
                file_id,
            })
            .send()
            .await
            // Without the URL: it may embed credentials (userinfo).
            .map_err(|e| CoreError::Internal(format!("upstream call: {}", e.without_url())))?;
        match resp.status() {
            s if s.is_success() => {
                // Cap before buffering; the post-read check catches an upstream
                // that lies in Content-Length then streams more.
                if let Some(len) = resp.content_length() {
                    if len > MAX_UPSTREAM_RESPONSE_BYTES {
                        return Err(CoreError::Internal("upstream response too large".into()));
                    }
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(|_| CoreError::Internal("upstream body read failed".into()))?
                {
                    if (bytes.len() + chunk.len()) as u64 > MAX_UPSTREAM_RESPONSE_BYTES {
                        return Err(CoreError::Internal("upstream response too large".into()));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                // Generic message: reqwest's decode error can echo a body snippet,
                // which could leak a bearer reflected back by the upstream.
                let parsed: CheckAccessResponse = serde_json::from_slice(&bytes)
                    .map_err(|_| CoreError::Internal("upstream body decode failed".into()))?;
                if let Some(canon) = &parsed.repo_id {
                    if !valid_repo_id(canon) {
                        return Err(CoreError::Internal(
                            "upstream returned a malformed canonical repo_id".into(),
                        ));
                    }
                    // Else the owner falls back to the key's first segment:
                    // every `id/<n>` repo would bill to one owner "id".
                    if parsed.owner.is_none() {
                        return Err(CoreError::Internal(
                            "upstream returned a canonical repo_id without an owner".into(),
                        ));
                    }
                }
                if let Some(owner) = &parsed.owner {
                    if !valid_owner(owner) {
                        return Err(CoreError::Internal(
                            "upstream returned a malformed owner".into(),
                        ));
                    }
                }
                Ok(AccessGrant {
                    user: UserId(parsed.user_id),
                    canonical_repo_id: parsed.repo_id,
                    canonical_owner: parsed.owner,
                })
            }
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(CoreError::Unauthorized),
            s if s == reqwest::StatusCode::FORBIDDEN => Err(CoreError::Forbidden),
            other => Err(CoreError::Internal(format!(
                "upstream status {} for check_access",
                other.as_u16()
            ))),
        }
    }

    async fn mint_xet_token(
        &self,
        user: &UserId,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<(String, u64)> {
        tokens::mint(&self.jwt_secret, user, repo, scope, DEFAULT_TOKEN_TTL_SECS)
    }
}
