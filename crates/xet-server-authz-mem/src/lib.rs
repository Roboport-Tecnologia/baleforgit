//! In-memory `RepoAuthz` implementations.
//!
//! - [`AlwaysAllow`] is a stub used by tests in earlier milestones.
//! - [`ConfigAuthz`] is the real prototype impl: a static map of hub-bearer
//!   tokens to user permissions, plus a JWT secret used to mint/verify Xet
//!   tokens.

use async_trait::async_trait;
use std::collections::HashMap;
use xet_server_core::{CoreError, CoreResult, RepoAuthz, RepoRef, Scope, TokenClaims, UserId};
use xet_server_tokens as tokens;

/// Accepts any non-empty bearer; grants write-scope on a generic placeholder
/// repo. Useful for tests and pre-M5 milestones; not for production.
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
            repo: xet_server_core::RepoRef {
                repo_type: xet_server_core::RepoType::Model,
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

/// A static configuration: hub tokens → user, plus per-user repo permissions.
/// `repo_id` matching is exact ("namespace/name").
#[derive(Clone, Debug, Default)]
pub struct ConfigAuthz {
    pub jwt_secret: Vec<u8>,
    /// hub_token → (user_id, repo_id → max_scope)
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

    /// Convenience for setup: grant `user_id` `scope` on `repo_id` under the
    /// hub bearer token `hub_token`.
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
        // If multiple grants for the same hub token disagree on user_id, the
        // first wins.
        entry.repos.insert(repo_id.into(), scope);
        self
    }
}

/// Default TTL for minted Xet tokens (one hour).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

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
        let u = self.users.get(hub_bearer).ok_or(CoreError::Unauthorized)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use xet_server_core::RepoType;

    fn repo(name: &str) -> RepoRef {
        RepoRef {
            repo_type: RepoType::Model,
            repo_id: name.into(),
            revision: "main".into(),
        }
    }

    #[tokio::test]
    async fn config_authz_grants_write_when_allowed() {
        let authz =
            ConfigAuthz::new(b"k".to_vec()).grant("hub-alice", "alice", "alice/m", Scope::Write);
        let u = authz
            .check_repo_access("hub-alice", &repo("alice/m"), Scope::Write)
            .await
            .unwrap();
        assert_eq!(u.0, "alice");
    }

    #[tokio::test]
    async fn config_authz_forbids_write_when_only_read() {
        let authz = ConfigAuthz::new(b"k".to_vec()).grant("hub-bob", "bob", "bob/m", Scope::Read);
        let r = authz
            .check_repo_access("hub-bob", &repo("bob/m"), Scope::Write)
            .await;
        assert!(matches!(r, Err(CoreError::Forbidden)));
    }

    #[tokio::test]
    async fn config_authz_unknown_hub_token_is_unauthorized() {
        let authz = ConfigAuthz::new(b"k".to_vec());
        let r = authz
            .check_repo_access("nope", &repo("x/y"), Scope::Read)
            .await;
        assert!(matches!(r, Err(CoreError::Unauthorized)));
    }
}
