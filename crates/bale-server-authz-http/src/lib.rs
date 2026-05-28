//! HTTP-backed `RepoAuthz`: delegates `check_repo_access` to an upstream
//! service; Bale token mint/verify stays local.
//!
//! Wire contract:
//!
//! ```text
//! POST {base_url}/check_access
//! Content-Type: application/json
//! { "hub_bearer": "...", "repo": { "repo_type": "model", "repo_id": "ns/name",
//!                                  "revision": "main" }, "scope": "write" }
//!
//! 200 OK  { "user_id": "alice" }
//! 401 Unauthorized   — unknown hub_bearer
//! 403 Forbidden      — known user, insufficient access
//! ```
//!
//! `hub_bearer` is opaque to baleforgit-server — typically a short-lived JWT minted
//! by the upstream so no long-lived credential reaches baleforgit-server.

use async_trait::async_trait;
use bale_server_core::{CoreError, CoreResult, RepoAuthz, RepoRef, Scope, TokenClaims, UserId};
use bale_server_tokens as tokens;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

/// Cap on the upstream `check_access` response body. The contract returns a
/// tiny JSON like `{"user_id": "alice"}`; anything materially larger is either
/// a misconfigured upstream or a hostile one trying to OOM us.
const MAX_UPSTREAM_RESPONSE_BYTES: u64 = 64 * 1024;

pub struct HttpAuthz {
    check_access_url: Url,
    client: reqwest::Client,
    jwt_secret: Vec<u8>,
}

// Parsing the base URL up front rejects misconfiguration (relative URLs, junk
// schemes) before any request fires, and `Url::join` composes the path safely
// regardless of query/fragment in the base.
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
            .build()
            .map_err(|e| CoreError::Internal(format!("http client init: {e}")))?;
        Ok(Self {
            check_access_url: build_check_access_url(base_url.as_ref())?,
            client,
            jwt_secret: jwt_secret.into(),
        })
    }

    pub fn with_client(
        base_url: impl AsRef<str>,
        jwt_secret: impl Into<Vec<u8>>,
        client: reqwest::Client,
    ) -> CoreResult<Self> {
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
}

#[derive(Deserialize)]
struct CheckAccessResponse {
    user_id: String,
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
    ) -> CoreResult<UserId> {
        let resp = self
            .client
            .post(self.check_access_url.clone())
            .json(&CheckAccessRequest {
                hub_bearer,
                repo,
                scope,
            })
            .send()
            .await
            .map_err(|e| CoreError::Internal(format!("upstream call: {e}")))?;
        match resp.status() {
            s if s.is_success() => {
                // Reject obviously-oversized responses up front via content_length;
                // for a streamed/unknown-length body, the bytes() call below uses
                // reqwest's internal accumulator which is itself bounded by the
                // client's response_body_limit setting if configured. The hard
                // cap here is defense-in-depth against an upstream that lies in
                // Content-Length and then streams gigabytes.
                if let Some(len) = resp.content_length() {
                    if len > MAX_UPSTREAM_RESPONSE_BYTES {
                        return Err(CoreError::Internal("upstream response too large".into()));
                    }
                }
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|_| CoreError::Internal("upstream body read failed".into()))?;
                if bytes.len() as u64 > MAX_UPSTREAM_RESPONSE_BYTES {
                    return Err(CoreError::Internal("upstream response too large".into()));
                }
                // Decode-error message intentionally generic: reqwest's JSON-decode
                // error can echo a body snippet, which is risky if a misbehaving
                // upstream ever reflects the bearer back to us.
                let parsed: CheckAccessResponse = serde_json::from_slice(&bytes)
                    .map_err(|_| CoreError::Internal("upstream body decode failed".into()))?;
                Ok(UserId(parsed.user_id))
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
