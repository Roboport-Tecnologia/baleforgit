//! HTTP layer for the Xet CAS server.
//!
//! Routes exposed by [`router`]:
//! - `POST /v1/xorbs/default/:hash`           (xorb upload, write scope)
//! - `POST /v1/shards`                         (shard upload + indexing, write scope)
//! - `GET  /v1/reconstructions/:file_id`       (reconstruction metadata, read scope)
//! - `GET  /xorb/default/:hash` (signed)       (byte-range transfer, no bearer auth)
//! - `GET  /api/{type}s/{ns}/{name}/xet-{rw}-token/{rev}`
//!                                              (mock HF Hub token endpoint)

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use xet_server_core::{
    BlobStore, ChunkRow, CoreError, FileHash, FileTerm, MetadataStore, RepoAuthz, RepoRef,
    RepoType, Scope, ShardHash, TokenClaims, XorbHash, XorbInfo, Hash32, HASH_LEN,
};
use xet_server_shard::ParsedShard;
use xet_server_wire::{
    decode_hash, encode_hash, CASReconstructionFetchInfo, CASReconstructionTerm,
    QueryReconstructionResponse, RangeJson, UploadShardResponse, UploadXorbResponse,
    XetTokenResponse,
};

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const SIGNATURE_TTL_SECS: u64 = 600;

type HmacSha256 = Hmac<Sha256>;

// ---- Service & router ------------------------------------------------------

pub struct Service<B, M, A> {
    pub blobs: Arc<B>,
    pub meta: Arc<M>,
    pub authz: Arc<A>,
    pub transfer_secret: [u8; 32],
    pub public_base_url: String,
}

impl<B, M, A> Clone for Service<B, M, A> {
    fn clone(&self) -> Self {
        Self {
            blobs: self.blobs.clone(),
            meta: self.meta.clone(),
            authz: self.authz.clone(),
            transfer_secret: self.transfer_secret,
            public_base_url: self.public_base_url.clone(),
        }
    }
}

pub fn router<B, M, A>(svc: Service<B, M, A>) -> Router
where
    B: BlobStore + 'static,
    M: MetadataStore + 'static,
    A: RepoAuthz + 'static,
{
    let v1 = Router::new()
        .route("/v1/xorbs/default/:hash", post(upload_xorb::<B, M, A>))
        .route("/v1/shards", post(upload_shard::<B, M, A>))
        .route(
            "/v1/reconstructions/:file_id",
            get(get_reconstruction::<B, M, A>),
        )
        .layer(middleware::from_fn_with_state(
            svc.clone(),
            auth_middleware::<B, M, A>,
        ));

    Router::new()
        .merge(v1)
        .route("/xorb/default/:hash", get(get_xorb_transfer::<B, M, A>))
        .route(
            "/api/:type_seg/:ns/:name/:tok_seg/:rev",
            get(issue_xet_token::<B, M, A>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(svc)
}

// ---- Errors ----------------------------------------------------------------

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.1 }));
        (self.0, body).into_response()
    }
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::NotFound => ApiError(StatusCode::NOT_FOUND, "not found".into()),
            CoreError::BadRequest(m) => ApiError(StatusCode::BAD_REQUEST, m),
            CoreError::Conflict(m) => ApiError(StatusCode::CONFLICT, m),
            CoreError::Unauthorized => ApiError(StatusCode::UNAUTHORIZED, "unauthorized".into()),
            CoreError::Forbidden => ApiError(StatusCode::FORBIDDEN, "forbidden".into()),
            CoreError::Internal(m) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, m),
        }
    }
}

fn bad_req(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn unauthorized(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, msg.into())
}

// ---- Auth middleware -------------------------------------------------------

async fn auth_middleware<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    method: Method,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let raw = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized("missing bearer"))?;
    let token = raw
        .strip_prefix("Bearer ")
        .ok_or_else(|| unauthorized("expected 'Bearer <token>'"))?;
    let claims = svc.authz.verify_xet_token(token).await.map_err(ApiError::from)?;

    // POST methods require write scope.
    if method == Method::POST && claims.scope == Scope::Read {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "this endpoint requires a write-scope token".into(),
        ));
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// ---- Signed transfer URLs --------------------------------------------------

struct SignedRange {
    hash_hex: String,
    start: u64,
    end_inclusive: u64,
    exp: u64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign(secret: &[u8; 32], r: &SignedRange) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key length");
    mac.update(r.hash_hex.as_bytes());
    mac.update(b"|");
    mac.update(r.start.to_string().as_bytes());
    mac.update(b"|");
    mac.update(r.end_inclusive.to_string().as_bytes());
    mac.update(b"|");
    mac.update(r.exp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn build_signed_url(
    base: &str,
    secret: &[u8; 32],
    xorb_hex: &str,
    start: u64,
    end_inclusive: u64,
) -> String {
    let exp = now_unix() + SIGNATURE_TTL_SECS;
    let sig = sign(
        secret,
        &SignedRange {
            hash_hex: xorb_hex.to_string(),
            start,
            end_inclusive,
            exp,
        },
    );
    format!("{base}/xorb/default/{xorb_hex}?s={start}&e={end_inclusive}&x={exp}&sig={sig}")
}

// ---- Handlers: upload ------------------------------------------------------

async fn upload_xorb<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Extension(_claims): Extension<TokenClaims>,
    Path(hash_hex): Path<String>,
    body: Bytes,
) -> Result<Json<UploadXorbResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let hash =
        decode_hash(&hash_hex).map_err(|e| bad_req(format!("malformed xorb hash: {e}")))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(bad_req("xorb exceeds 64 MiB limit"));
    }
    // TODO: re-verify xorb content hash against `hash`; see plan §"Tricky bits".
    let was_inserted = svc.blobs.put_xorb(&XorbHash(hash), body).await?;
    Ok(Json(UploadXorbResponse { was_inserted }))
}

async fn upload_shard<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Extension(claims): Extension<TokenClaims>,
    body: Bytes,
) -> Result<Json<UploadShardResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    if body.len() > MAX_BODY_BYTES {
        return Err(bad_req("shard exceeds 64 MiB limit"));
    }
    let parsed: ParsedShard = xet_server_shard::parse(&body)
        .map_err(|e| bad_req(format!("malformed shard: {e}")))?;

    for cb in &parsed.cas_blocks {
        if !svc.blobs.xorb_exists(&cb.xorb).await? {
            return Err(bad_req(format!(
                "shard references missing xorb {:?}",
                cb.xorb.0
            )));
        }
    }
    for f in &parsed.files {
        for e in &f.entries {
            if !svc.blobs.xorb_exists(&e.xorb).await? {
                return Err(bad_req(format!(
                    "shard references missing xorb {:?}",
                    e.xorb.0
                )));
            }
        }
    }

    for cb in &parsed.cas_blocks {
        let info = XorbInfo {
            xorb: cb.xorb,
            num_chunks: cb.chunks.len() as u32,
            num_bytes_in_cas: cb.num_bytes_in_cas,
            num_bytes_on_disk: cb.num_bytes_on_disk,
        };
        let rows: Vec<ChunkRow> = cb
            .chunks
            .iter()
            .enumerate()
            .map(|(idx, c)| ChunkRow {
                chunk_hash: c.chunk_hash,
                chunk_index: idx as u32,
                byte_start: c.byte_start,
                unpacked_segment_bytes: c.unpacked_segment_bytes,
            })
            .collect();
        svc.meta.register_xorb(&info, &rows).await?;
    }

    for f in &parsed.files {
        let has_verification = !f.verifications.is_empty();
        if has_verification && f.verifications.len() != f.entries.len() {
            return Err(bad_req(
                "shard has verification entries but count != term count",
            ));
        }
        let terms: Vec<FileTerm> = f
            .entries
            .iter()
            .enumerate()
            .map(|(idx, e)| FileTerm {
                xorb: e.xorb,
                chunk_idx_start: e.chunk_idx_start,
                chunk_idx_end: e.chunk_idx_end,
                unpacked_segment_bytes: e.unpacked_segment_bytes,
                verification: if has_verification {
                    Some(f.verifications[idx])
                } else {
                    None
                },
            })
            .collect();
        svc.meta
            .register_file(&f.file_hash, &claims.repo, f.sha256.as_ref(), &terms)
            .await?;
    }

    let shard_hash = shard_storage_hash(&body);
    svc.blobs.put_shard(&shard_hash, body).await?;

    Ok(Json(UploadShardResponse { result: 1 }))
}

fn shard_storage_hash(bytes: &[u8]) -> ShardHash {
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(blake3::hash(bytes).as_bytes());
    ShardHash(Hash32(out))
}

// ---- Handlers: download ----------------------------------------------------

async fn get_reconstruction<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Extension(_claims): Extension<TokenClaims>,
    Path(file_hex): Path<String>,
) -> Result<Json<QueryReconstructionResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    // TODO: scope-check the file's owning repo against `_claims.repo`. The
    // prototype is permissive: any read token can fetch any file. In production
    // we'd want a `files.repo_id == claims.repo.repo_id` check (or fall back
    // to a cross-repo dedup policy).
    let file_hash = FileHash(
        decode_hash(&file_hex).map_err(|e| bad_req(format!("malformed file id: {e}")))?,
    );
    let terms = svc
        .meta
        .lookup_file(&file_hash)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "file not found".into()))?;

    let mut offsets_by_xorb: BTreeMap<[u8; HASH_LEN], Vec<xet_server_core::ChunkOffsetRow>> =
        BTreeMap::new();
    for t in &terms {
        offsets_by_xorb.entry(*t.xorb.as_bytes()).or_default();
    }
    for key in offsets_by_xorb.keys().cloned().collect::<Vec<_>>() {
        let rows = svc.meta.xorb_chunk_offsets(&XorbHash(Hash32(key))).await?;
        offsets_by_xorb.insert(key, rows);
    }

    let mut wire_terms = Vec::with_capacity(terms.len());
    let mut fetch_info: BTreeMap<String, Vec<CASReconstructionFetchInfo>> = BTreeMap::new();
    for t in &terms {
        let xorb_hex = encode_hash(&t.xorb.0);
        let offsets = offsets_by_xorb.get(t.xorb.as_bytes()).ok_or_else(|| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "missing offsets for known xorb".into(),
            )
        })?;
        if (t.chunk_idx_end as usize) > offsets.len() {
            return Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "term chunk range exceeds xorb's known chunks".into(),
            ));
        }
        let start_row = &offsets[t.chunk_idx_start as usize];
        let last_row = &offsets[(t.chunk_idx_end - 1) as usize];
        let byte_start = start_row.byte_start as u64;
        let byte_end_inclusive =
            (last_row.byte_start as u64) + (last_row.unpacked_segment_bytes as u64) - 1;

        wire_terms.push(CASReconstructionTerm {
            hash: xorb_hex.clone(),
            unpacked_length: t.unpacked_segment_bytes as u64,
            range: RangeJson {
                start: t.chunk_idx_start as u64,
                end: t.chunk_idx_end as u64,
            },
        });

        let url = build_signed_url(
            &svc.public_base_url,
            &svc.transfer_secret,
            &xorb_hex,
            byte_start,
            byte_end_inclusive,
        );
        fetch_info
            .entry(xorb_hex)
            .or_default()
            .push(CASReconstructionFetchInfo {
                range: RangeJson {
                    start: t.chunk_idx_start as u64,
                    end: t.chunk_idx_end as u64,
                },
                url,
                url_range: RangeJson {
                    start: byte_start,
                    end: byte_end_inclusive,
                },
            });
    }

    Ok(Json(QueryReconstructionResponse {
        offset_into_first_range: 0,
        terms: wire_terms,
        fetch_info,
    }))
}

#[derive(Debug, Deserialize)]
struct TransferQuery {
    s: u64,
    e: u64,
    x: u64,
    sig: String,
}

async fn get_xorb_transfer<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Path(hash_hex): Path<String>,
    Query(q): Query<TransferQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let xorb_hash = XorbHash(
        decode_hash(&hash_hex).map_err(|e| bad_req(format!("malformed xorb hash: {e}")))?,
    );

    let expected = sign(
        &svc.transfer_secret,
        &SignedRange {
            hash_hex: hash_hex.clone(),
            start: q.s,
            end_inclusive: q.e,
            exp: q.x,
        },
    );
    if !ct_eq(expected.as_bytes(), q.sig.as_bytes()) {
        return Err(unauthorized("bad signature"));
    }
    if q.x < now_unix() {
        return Err(unauthorized("signature expired"));
    }

    let range_header = headers
        .get("range")
        .ok_or_else(|| unauthorized("Range header required"))?;
    let (req_start, req_end_inclusive) =
        parse_byte_range_header(range_header).map_err(|m| bad_req(m))?;
    if req_start != q.s || req_end_inclusive != q.e {
        return Err(unauthorized("Range header does not match signed range"));
    }

    let bytes = svc
        .blobs
        .get_xorb_range(&xorb_hash, q.s..(q.e + 1))
        .await?;

    let len = bytes.len();
    let mut resp = (StatusCode::PARTIAL_CONTENT, bytes).into_response();
    resp.headers_mut().insert(
        "content-length",
        HeaderValue::from_str(&len.to_string()).unwrap(),
    );
    resp.headers_mut().insert(
        "content-range",
        HeaderValue::from_str(&format!("bytes {}-{}/*", q.s, q.e)).unwrap(),
    );
    Ok(resp)
}

fn parse_byte_range_header(v: &HeaderValue) -> Result<(u64, u64), String> {
    let s = v.to_str().map_err(|_| "invalid Range header".to_string())?;
    let rest = s
        .strip_prefix("bytes=")
        .ok_or_else(|| "expected 'bytes=' prefix".to_string())?;
    let (a, b) = rest
        .split_once('-')
        .ok_or_else(|| "expected 'bytes=X-Y'".to_string())?;
    let start: u64 = a.trim().parse().map_err(|_| "bad start".to_string())?;
    let end: u64 = b.trim().parse().map_err(|_| "bad end".to_string())?;
    if end < start {
        return Err("inverted range".into());
    }
    Ok((start, end))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for (x_a, x_b) in a.iter().zip(b.iter()) {
        x |= x_a ^ x_b;
    }
    x == 0
}

// ---- Mock HF Hub token endpoint --------------------------------------------

async fn issue_xet_token<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Path((type_seg, ns, name, tok_seg, rev)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<XetTokenResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let repo_type = parse_hf_repo_type(&type_seg)?;
    let scope = parse_hf_token_scope(&tok_seg)?;
    let repo_id = format!("{ns}/{name}");
    let repo = RepoRef {
        repo_type,
        repo_id,
        revision: rev,
    };

    let hub_bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("missing hub bearer token"))?;

    let user = svc
        .authz
        .check_repo_access(hub_bearer, &repo, scope)
        .await?;

    let (token, exp) = svc.authz.mint_xet_token(&user, &repo, scope).await?;

    Ok(Json(XetTokenResponse {
        access_token: token,
        exp,
        cas_url: svc.public_base_url.clone(),
    }))
}

fn parse_hf_repo_type(seg: &str) -> Result<RepoType, ApiError> {
    match seg {
        "models" => Ok(RepoType::Model),
        "datasets" => Ok(RepoType::Dataset),
        "spaces" => Ok(RepoType::Space),
        _ => Err(bad_req(format!("unknown repo type segment: {seg}"))),
    }
}

fn parse_hf_token_scope(seg: &str) -> Result<Scope, ApiError> {
    match seg {
        "xet-read-token" => Ok(Scope::Read),
        "xet-write-token" => Ok(Scope::Write),
        _ => Err(bad_req(format!("unknown token segment: {seg}"))),
    }
}
