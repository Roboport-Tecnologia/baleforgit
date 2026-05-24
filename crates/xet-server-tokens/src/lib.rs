//! Xet JWT mint / verify.
//!
//! These are HS256 tokens issued by our mock HF Hub endpoint and accepted by
//! the CAS API. Symmetric secret because the same process mints and verifies;
//! moving to RS256 (issuer ≠ verifier) is a future-proofing step we'll take
//! if/when the GitLab/Gitea `RepoAuthz` impl needs to call us out-of-process.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use xet_server_core::{CoreError, CoreResult, RepoRef, RepoType, Scope, TokenClaims, UserId};

#[derive(Debug, Serialize, Deserialize)]
pub struct XetClaims {
    pub sub: String,       // user id
    pub repo_type: String, // "model" | "dataset" | "space"
    pub repo_id: String,   // "ns/name"
    pub revision: String,  // git revision
    pub scope: String,     // "read" | "write"
    pub exp: u64,          // unix seconds
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn mint(
    secret: &[u8],
    user: &UserId,
    repo: &RepoRef,
    scope: Scope,
    ttl_secs: u64,
) -> CoreResult<(String, u64)> {
    let exp = now_unix() + ttl_secs;
    let claims = XetClaims {
        sub: user.0.clone(),
        repo_type: repo_type_str(repo.repo_type).into(),
        repo_id: repo.repo_id.clone(),
        revision: repo.revision.clone(),
        scope: scope_str(scope).into(),
        exp,
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| CoreError::Internal(format!("jwt encode: {e}")))?;
    Ok((token, exp))
}

pub fn verify(secret: &[u8], token: &str) -> CoreResult<TokenClaims> {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_required_spec_claims(&["exp"]);
    v.leeway = 0;
    let data = decode::<XetClaims>(token, &DecodingKey::from_secret(secret), &v)
        .map_err(|_| CoreError::Unauthorized)?;
    let c = data.claims;
    Ok(TokenClaims {
        user: UserId(c.sub),
        repo: RepoRef {
            repo_type: parse_repo_type(&c.repo_type)?,
            repo_id: c.repo_id,
            revision: c.revision,
        },
        scope: parse_scope(&c.scope)?,
        expires_at: c.exp,
    })
}

fn repo_type_str(t: RepoType) -> &'static str {
    match t {
        RepoType::Model => "model",
        RepoType::Dataset => "dataset",
        RepoType::Space => "space",
    }
}

pub fn parse_repo_type(s: &str) -> CoreResult<RepoType> {
    match s {
        "model" => Ok(RepoType::Model),
        "dataset" => Ok(RepoType::Dataset),
        "space" => Ok(RepoType::Space),
        _ => Err(CoreError::BadRequest(format!("bad repo_type: {s}"))),
    }
}

fn scope_str(s: Scope) -> &'static str {
    match s {
        Scope::Read => "read",
        Scope::Write => "write",
    }
}

fn parse_scope(s: &str) -> CoreResult<Scope> {
    match s {
        "read" => Ok(Scope::Read),
        "write" => Ok(Scope::Write),
        _ => Err(CoreError::BadRequest(format!("bad scope: {s}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> RepoRef {
        RepoRef {
            repo_type: RepoType::Model,
            repo_id: "alice/m".into(),
            revision: "main".into(),
        }
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let (tok, exp) = mint(secret, &UserId("alice".into()), &repo(), Scope::Write, 60).unwrap();
        let c = verify(secret, &tok).unwrap();
        assert_eq!(c.user.0, "alice");
        assert_eq!(c.repo.repo_id, "alice/m");
        assert_eq!(c.repo.repo_type, RepoType::Model);
        assert_eq!(c.scope, Scope::Write);
        assert_eq!(c.expires_at, exp);
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let (tok, _) = mint(b"a", &UserId("u".into()), &repo(), Scope::Read, 60).unwrap();
        assert!(verify(b"b", &tok).is_err());
    }

    #[test]
    fn verify_rejects_expired() {
        let secret = b"k";
        // Mint a token with negative TTL relative to now by wrapping; we use
        // a tiny ttl and assert verify accepts it now and would reject in the
        // future. (Simpler than mucking with sys time.)
        let (tok, _) = mint(secret, &UserId("u".into()), &repo(), Scope::Read, 1).unwrap();
        assert!(verify(secret, &tok).is_ok());
        // Manually mint a token already expired by 1 hour.
        let claims = XetClaims {
            sub: "u".into(),
            repo_type: "model".into(),
            repo_id: "a/b".into(),
            revision: "main".into(),
            scope: "read".into(),
            exp: now_unix().saturating_sub(3600),
        };
        let tok = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(verify(secret, &tok).is_err());
    }
}
