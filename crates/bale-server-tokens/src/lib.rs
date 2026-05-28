use bale_server_core::{CoreError, CoreResult, RepoRef, RepoType, Scope, TokenClaims, UserId};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct XetClaims {
    pub sub: String,
    pub repo_type: String,
    pub repo_id: String,
    pub revision: String,
    pub scope: String,
    pub exp: u64,
}

fn now_unix() -> CoreResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| CoreError::Internal(format!("system clock before unix epoch: {e}")))
}

pub fn mint(
    secret: &[u8],
    user: &UserId,
    repo: &RepoRef,
    scope: Scope,
    ttl_secs: u64,
) -> CoreResult<(String, u64)> {
    let exp = now_unix()?.saturating_add(ttl_secs);
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
