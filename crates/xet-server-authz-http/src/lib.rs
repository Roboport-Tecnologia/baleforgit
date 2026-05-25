//! HTTP-backed `RepoAuthz` skeleton.
//!
//! Instead of storing user/repo permissions locally, this impl delegates
//! `check_repo_access` to an external HTTP service — the "upstream repo
//! authority". Xet token mint/verify stays local (same JWT secret as the
//! rest of the server) — only the access decision is moved out of process.
//!
//! Wire contract (kept deliberately minimal so it can be implemented by a
//! thin proxy in front of any upstream that knows about users and repos):
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
//! `hub_bearer` is opaque from xet-server's point of view — the upstream is
//! free to interpret it however it likes, but the recommended shape is a
//! short-lived JWT minted by the upstream when the client authenticates, so
//! that no long-lived credential ever reaches xet-server. The trait seam is
//! exercised by a real HTTP round trip in the integration tests, and any
//! upstream that wants to integrate need only implement the endpoint above.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use xet_server_core::{CoreError, CoreResult, RepoAuthz, RepoRef, Scope, TokenClaims, UserId};
use xet_server_tokens as tokens;

pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

pub struct HttpAuthz {
    base_url: String,
    client: reqwest::Client,
    jwt_secret: Vec<u8>,
}

impl HttpAuthz {
    pub fn new(base_url: impl Into<String>, jwt_secret: impl Into<Vec<u8>>) -> CoreResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| CoreError::Internal(format!("http client init: {e}")))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
            jwt_secret: jwt_secret.into(),
        })
    }

    /// For tests / advanced setups that need to inject a pre-configured client.
    pub fn with_client(
        base_url: impl Into<String>,
        jwt_secret: impl Into<Vec<u8>>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
            jwt_secret: jwt_secret.into(),
        }
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
        let url = format!("{}/check_access", self.base_url);
        let resp = self
            .client
            .post(&url)
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
                let parsed: CheckAccessResponse = resp
                    .json()
                    .await
                    .map_err(|e| CoreError::Internal(format!("upstream body: {e}")))?;
                Ok(UserId(parsed.user_id))
            }
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(CoreError::Unauthorized),
            s if s == reqwest::StatusCode::FORBIDDEN => Err(CoreError::Forbidden),
            other => Err(CoreError::Internal(format!(
                "upstream status {other} for check_access"
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes as AxumBytes;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use std::sync::Arc;
    use xet_server_core::RepoType;

    fn repo(name: &str) -> RepoRef {
        RepoRef {
            repo_type: RepoType::Model,
            repo_id: name.into(),
            revision: "main".into(),
        }
    }

    type Grant = (String, String, String, Scope);

    #[derive(Clone)]
    struct MockState(Arc<Vec<Grant>>);

    #[derive(Deserialize)]
    struct WireReq {
        hub_bearer: String,
        repo: RepoRef,
        scope: Scope,
    }

    async fn handler(
        State(s): State<MockState>,
        body: AxumBytes,
    ) -> Result<(StatusCode, String), StatusCode> {
        let req: WireReq = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut found_user = None;
        for (hub, user, rid, granted) in s.0.iter() {
            if hub == &req.hub_bearer {
                found_user = Some(user.clone());
                if rid == &req.repo.repo_id {
                    if matches!(req.scope, Scope::Write) && matches!(granted, Scope::Read) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    let body = serde_json::json!({ "user_id": user }).to_string();
                    return Ok((StatusCode::OK, body));
                }
            }
        }
        if found_user.is_some() {
            Err(StatusCode::FORBIDDEN)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }

    async fn spawn_mock(grants: Vec<Grant>) -> String {
        let state = MockState(Arc::new(grants));
        let app = Router::new()
            .route("/check_access", post(handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn http_authz_grants_write_when_upstream_allows() {
        let base = spawn_mock(vec![(
            "hub-alice".into(),
            "alice".into(),
            "alice/m".into(),
            Scope::Write,
        )])
        .await;
        let authz = HttpAuthz::new(base, b"k".to_vec()).unwrap();
        let u = authz
            .check_repo_access("hub-alice", &repo("alice/m"), Scope::Write)
            .await
            .unwrap();
        assert_eq!(u.0, "alice");
    }

    #[tokio::test]
    async fn http_authz_forbids_write_when_only_read() {
        let base = spawn_mock(vec![(
            "hub-bob".into(),
            "bob".into(),
            "bob/m".into(),
            Scope::Read,
        )])
        .await;
        let authz = HttpAuthz::new(base, b"k".to_vec()).unwrap();
        let r = authz
            .check_repo_access("hub-bob", &repo("bob/m"), Scope::Write)
            .await;
        assert!(matches!(r, Err(CoreError::Forbidden)));
    }

    #[tokio::test]
    async fn http_authz_unknown_hub_token_is_unauthorized() {
        let base = spawn_mock(vec![]).await;
        let authz = HttpAuthz::new(base, b"k".to_vec()).unwrap();
        let r = authz
            .check_repo_access("nobody", &repo("x/y"), Scope::Read)
            .await;
        assert!(matches!(r, Err(CoreError::Unauthorized)));
    }

    #[tokio::test]
    async fn mint_then_verify_roundtrip() {
        let base = spawn_mock(vec![]).await;
        let authz = HttpAuthz::new(base, b"jwt-secret-32-bytes-padding-xxxx".to_vec()).unwrap();
        let (tok, _exp) = authz
            .mint_xet_token(&UserId("alice".into()), &repo("alice/m"), Scope::Write)
            .await
            .unwrap();
        let claims = authz.verify_xet_token(&tok).await.unwrap();
        assert_eq!(claims.user.0, "alice");
        assert!(matches!(claims.scope, Scope::Write));
    }
}
