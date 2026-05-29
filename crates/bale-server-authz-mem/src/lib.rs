//! In-memory `RepoAuthz` implementations.

use async_trait::async_trait;
use bale_server_core::{CoreError, CoreResult, RepoAuthz, RepoRef, Scope, TokenClaims, UserId};
use bale_server_tokens as tokens;
use std::collections::HashMap;

/// Test-only: accepts any non-empty bearer and grants write scope. Not for production.
#[derive(Clone, Debug, Default)]
pub struct AlwaysAllow;

#[async_trait]
impl RepoAuthz for AlwaysAllow {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims> {
        if bearer.is_empty() {
            return Err(CoreError::Unauthorized);
        }
        Ok(TokenClaims {
            user: UserId("anonymous".into()),
            repo: bale_server_core::RepoRef {
                repo_type: bale_server_core::RepoType::Model,
                repo_id: "anonymous/repo".into(),
                revision: "main".into(),
            },
            scope: Scope::Write,
            expires_at: u64::MAX,
        })
    }

    async fn check_repo_access(
        &self,
        _hub_bearer: &str,
        _repo: &RepoRef,
        _scope: Scope,
    ) -> CoreResult<UserId> {
        Ok(UserId("anonymous".into()))
    }

    async fn mint_xet_token(
        &self,
        _user: &UserId,
        _repo: &RepoRef,
        _scope: Scope,
    ) -> CoreResult<(String, u64)> {
        Err(CoreError::Internal("AlwaysAllow cannot mint tokens".into()))
    }
}

/// Static config: hub tokens → user + per-repo scope. `repo_id` matching is exact.
#[derive(Clone, Debug, Default)]
pub struct ConfigAuthz {
    pub jwt_secret: Vec<u8>,
    pub users: HashMap<String, ConfigUser>,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigUser {
    pub user_id: String,
    pub repos: HashMap<String, Scope>,
}

impl ConfigAuthz {
    pub fn new(jwt_secret: impl Into<Vec<u8>>) -> Self {
        Self {
            jwt_secret: jwt_secret.into(),
            users: HashMap::new(),
        }
    }

    pub fn grant(
        mut self,
        hub_token: impl Into<String>,
        user_id: impl Into<String>,
        repo_id: impl Into<String>,
        scope: Scope,
    ) -> Self {
        let user_id = user_id.into();
        let entry = self
            .users
            .entry(hub_token.into())
            .or_insert_with(|| ConfigUser {
                user_id: user_id.clone(),
                repos: HashMap::new(),
            });
        // Conflicting user_id grants for the same hub token: first wins.
        entry.repos.insert(repo_id.into(), scope);
        self
    }
}

/// 5 minutes (UTC unix seconds, like `tokens::mint`'s `exp`). Short on purpose:
/// the client refreshes via the forge before expiry (`git-bale`'s
/// `ForgeTokenRefresher`), so a leaked token has a small blast radius.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Fold the length diff in so a presented token's length isn't leaked via timing.
    let mut acc: u32 = (a.len() ^ b.len()) as u32;
    for (x_a, x_b) in a.iter().zip(b.iter()) {
        acc |= (x_a ^ x_b) as u32;
    }
    acc == 0
}

#[async_trait]
impl RepoAuthz for ConfigAuthz {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims> {
        tokens::verify(&self.jwt_secret, bearer)
    }

    async fn check_repo_access(
        &self,
        hub_bearer: &str,
        repo: &RepoRef,
        requested: Scope,
    ) -> CoreResult<UserId> {
        // Iterate + ct_eq instead of a HashMap lookup so the hub bearer match doesn't leak via timing.
        let mut found: Option<&ConfigUser> = None;
        for (k, v) in &self.users {
            if ct_eq(k.as_bytes(), hub_bearer.as_bytes()) {
                found = Some(v);
            }
        }
        let u = found.ok_or(CoreError::Unauthorized)?;
        let granted = u
            .repos
            .get(&repo.repo_id)
            .copied()
            .ok_or(CoreError::Forbidden)?;
        if matches!(requested, Scope::Write) && matches!(granted, Scope::Read) {
            return Err(CoreError::Forbidden);
        }
        Ok(UserId(u.user_id.clone()))
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
