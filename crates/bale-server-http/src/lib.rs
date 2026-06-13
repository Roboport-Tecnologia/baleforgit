//! HTTP layer for the Bale CAS server. See `docs/ARCHITECTURE.md` for the route
//! table, wire formats, and "Tricky bits" notes.

mod metrics;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bale_server_core::{
    BlobStore, ChunkHash, ChunkRow, CoreError, FileHash, FileTerm, Hash32, MetadataStore,
    RepoAuthz, RepoRef, RepoType, Scope, ShardHash, TokenClaims, XorbFrameRow, XorbHash, XorbInfo,
    HASH_LEN,
};
use bale_server_shard::{
    decompress_xorb_chunks_into, parse_xorb_frames, serialize as serialize_shard, verify_xorb_body,
    CasChunkEntry, ParsedCasBlock, ParsedShard, ShardFooter, ShardHeader, XorbVerifyError,
    FOOTER_SIZE, MDB_SHARD_FOOTER_VERSION, MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use bale_server_wire::{
    decode_hash, encode_hash, CASReconstructionFetchInfo, CASReconstructionTerm,
    OwnerUsageResponse, QueryReconstructionResponse, RangeJson, RepoUsageResponse,
    SetOwnerQuotaRequest, UploadShardResponse, UploadXorbResponse, XetTokenResponse,
};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use opentelemetry::KeyValue;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer};
use tracing::Level;

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const SIGNATURE_TTL_SECS: u64 = 600;
// 2× the 64 MiB xorb cap: a term's uncompressed span can exceed the compressed
// xorb body, so the headroom avoids rejecting borderline-valid terms.
const MAX_TERM_UNPACKED_BYTES: u64 = 128 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

pub struct Service<B, M, A> {
    pub blobs: Arc<B>,
    pub meta: Arc<M>,
    pub authz: Arc<A>,
    pub transfer_secret: [u8; 32],
    pub public_base_url: String,
    /// Per-owner override beats this; `None` here AND `None` per-owner = unlimited.
    pub default_quota_bytes: Option<u64>,
    /// When set, gates `PUT /v1/quotas/{owner}` via a constant-time bearer check.
    /// `None` disables the admin endpoint entirely (returns 404).
    pub admin_token: Option<[u8; 32]>,
}

impl<B, M, A> Clone for Service<B, M, A> {
    fn clone(&self) -> Self {
        Self {
            blobs: self.blobs.clone(),
            meta: self.meta.clone(),
            authz: self.authz.clone(),
            transfer_secret: self.transfer_secret,
            public_base_url: self.public_base_url.clone(),
            default_quota_bytes: self.default_quota_bytes,
            admin_token: self.admin_token,
        }
    }
}

pub fn router<B, M, A>(svc: Service<B, M, A>) -> Router
where
    B: BlobStore + 'static,
    M: MetadataStore + 'static,
    A: RepoAuthz + 'static,
{
    // `prefix` is parameterized per the protocol but always "default" today.
    let v1 = Router::new()
        .route("/v1/xorbs/{prefix}/{hash}", post(upload_xorb::<B, M, A>))
        .route("/shards", post(upload_shard::<B, M, A>))
        .route(
            "/v1/reconstructions/{file_id}",
            get(get_reconstruction::<B, M, A>),
        )
        .route(
            "/v1/chunks/{prefix}/{hash}",
            get(get_dedup_chunk::<B, M, A>),
        )
        .layer(middleware::from_fn_with_state(
            svc.clone(),
            auth_middleware::<B, M, A>,
        ));

    // Outside the JWT middleware: these handlers also accept the static admin
    // bearer (not a JWT), so operators can read usage / set quotas without
    // minting a Bale token.
    let admin = Router::new()
        .route("/v1/usage/{owner}", get(get_owner_usage::<B, M, A>))
        .route(
            "/v1/usage/repo/{owner}/{repo}",
            get(get_repo_usage::<B, M, A>),
        )
        .route(
            "/v1/quotas/{owner}",
            axum::routing::put(put_owner_quota::<B, M, A>),
        );

    // Access logs at INFO; on_failure fires at WARN on 4xx/5xx.
    let trace = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(DefaultOnFailure::new().level(Level::WARN));

    let traced = Router::new()
        .merge(v1)
        .merge(admin)
        .route("/xorb/default/{hash}", get(get_xorb_transfer::<B, M, A>))
        .route("/v1/files/{file_id}", get(get_file_download::<B, M, A>))
        .route(
            "/api/{type_seg}/{ns}/{name}/{tok_seg}/{rev}",
            get(issue_xet_token::<B, M, A>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(trace)
        // Inside the trace layer so each recorded request has the access-log
        // span on the stack. No-op when no OTel meter provider is installed.
        .layer(middleware::from_fn(metrics::middleware))
        .with_state(svc);

    // Outside auth and the trace layer: frequent probes would drown out real
    // request logs.
    Router::new().route("/healthz", get(healthz)).merge(traced)
}

async fn healthz() -> &'static str {
    "ok"
}

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log the message before it's consumed into the body — clients like
        // git-xet swallow response bodies, so this is often the only trace.
        if self.0.is_server_error() {
            tracing::error!(status = %self.0.as_u16(), error = %self.1, "api 5xx");
        } else {
            tracing::warn!(status = %self.0.as_u16(), error = %self.1, "api 4xx");
        }
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
    let claims = svc
        .authz
        .verify_xet_token(token)
        .await
        .map_err(ApiError::from)?;

    if method == Method::POST && claims.scope == Scope::Read {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "this endpoint requires a write-scope token".into(),
        ));
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

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

// Per-owner override beats the server default; `None` = unlimited.
async fn effective_quota<M: MetadataStore>(
    meta: &M,
    default: Option<u64>,
    owner: &str,
) -> Result<Option<u64>, ApiError> {
    if let Some(n) = meta.get_owner_quota(owner).await? {
        return Ok(Some(n));
    }
    Ok(default)
}

fn quota_exceeded(owner: &str, used: u64, quota: u64, would_add: u64) -> ApiError {
    // 429, not 413: a 413 reads to clients as "this one request's body is too
    // big". Over-quota is an account-state condition, so we return 429 with a
    // message that names it explicitly. (`git-bale` rewrites this into a
    // user-facing hint; see push_pending::explain_quota_exceeded.)
    ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        format!(
            "storage quota exceeded for owner '{owner}': {used} bytes stored + {would_add} new \
             would exceed the {quota}-byte limit"
        ),
    )
}

async fn upload_xorb<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Extension(claims): Extension<TokenClaims>,
    Path((_prefix, hash_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<UploadXorbResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let hash = decode_hash(&hash_hex).map_err(|e| bad_req(format!("malformed xorb hash: {e}")))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(bad_req("xorb exceeds 64 MiB limit"));
    }
    // Skip the quota check on content-addressed re-puts: they add no disk bytes.
    // Charge the upper bound (body.len()); precise attribution lands at /shards.
    let owner = claims.repo.owner().to_string();
    if let Some(quota) = effective_quota(svc.meta.as_ref(), svc.default_quota_bytes, &owner).await?
    {
        let xorb_already_exists = svc.blobs.xorb_exists(&XorbHash(hash)).await?;
        if !xorb_already_exists {
            let used = svc.meta.stored_bytes_for_owner(&owner).await?;
            let add = body.len() as u64;
            if used.saturating_add(add) > quota {
                return Err(quota_exceeded(&owner, used, quota, add));
            }
        }
    }
    // Record on-disk frame ranges: shard CAS Info has only uncompressed offsets,
    // so reconstruction can't compute HTTP byte ranges without this.
    let frames =
        parse_xorb_frames(&body).map_err(|e| bad_req(format!("malformed xorb body: {e}")))?;
    let layout: Vec<XorbFrameRow> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| XorbFrameRow {
            frame_index: i as u32,
            on_disk_start: f.on_disk_start,
            on_disk_len: f.on_disk_len,
            uncompressed_len: f.uncompressed_len,
        })
        .collect();
    let xorb = XorbHash(hash);
    // Recompute the merkle aggregation and compare to the URL hash, so a writer
    // can't corrupt the CAS by uploading bytes that don't match.
    if let Err(e) = verify_xorb_body(&body, &xorb) {
        return Err(match e {
            XorbVerifyError::HashMismatch => bad_req("xorb body does not match URL hash"),
            other => bad_req(format!("xorb body verification failed: {other}")),
        });
    }
    let body_len = body.len() as u64;
    // Register layout BEFORE the blob: a layout row with no blob is harmless
    // (the shard upload's `xorb_exists` gate rejects it), but a blob with no
    // layout permanently wedges reconstruction, which can't compute byte ranges.
    svc.meta.register_xorb_layout(&xorb, &layout).await?;
    let was_inserted = svc.blobs.put_xorb(&xorb, body).await?;
    metrics::XORBS_UPLOADED.add(
        1,
        &[KeyValue::new(
            "deduplicated",
            if was_inserted { "false" } else { "true" },
        )],
    );
    metrics::UPLOAD_BYTES.add(body_len, &[KeyValue::new("kind", "xorb")]);
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
    let parsed: ParsedShard =
        bale_server_shard::parse(&body).map_err(|e| bad_req(format!("malformed shard: {e}")))?;

    for cb in &parsed.cas_blocks {
        if !svc.blobs.xorb_exists(&cb.xorb).await? {
            return Err(bad_req(format!(
                "shard references missing xorb {:?}",
                cb.xorb.0
            )));
        }
    }
    // Reject empty/inverted ranges before any metadata write: chunk_idx_end == 0
    // would underflow `chunk_idx_end - 1` in the reconstruction handler.
    for f in &parsed.files {
        for e in &f.entries {
            if !svc.blobs.xorb_exists(&e.xorb).await? {
                return Err(bad_req(format!(
                    "shard references missing xorb {:?}",
                    e.xorb.0
                )));
            }
            if e.chunk_idx_start >= e.chunk_idx_end {
                return Err(bad_req(format!(
                    "shard file term has empty/inverted chunk range [{}, {})",
                    e.chunk_idx_start, e.chunk_idx_end
                )));
            }
        }
    }

    // Derive `num_bytes_on_disk` from the xorb_frames table rather than the
    // shard's claim: xet-data sets it to 0 unconditionally, which would collapse
    // owner accounting to 0. Fall back to the shard's value when no layout exists.
    let xorb_hashes: Vec<XorbHash> = parsed.cas_blocks.iter().map(|cb| cb.xorb).collect();
    let frame_layouts = svc.meta.xorb_frame_layouts(&xorb_hashes).await?;
    for cb in &parsed.cas_blocks {
        let derived: u32 = frame_layouts
            .get(&cb.xorb)
            .map(|frames| frames.iter().map(|f| f.on_disk_len).sum())
            .unwrap_or(0);
        let info = XorbInfo {
            xorb: cb.xorb,
            num_chunks: cb.chunks.len() as u32,
            num_bytes_in_cas: cb.num_bytes_in_cas,
            num_bytes_on_disk: if derived > 0 {
                derived
            } else {
                cb.num_bytes_on_disk
            },
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

    // Reject over-quota BEFORE register_files so the shard leaves no file rows
    // behind (orphan xorbs already on disk are GC-able). Delta is the on-disk
    // size of referenced xorbs the owner doesn't already reference.
    let owner = claims.repo.owner().to_string();
    if let Some(quota) = effective_quota(svc.meta.as_ref(), svc.default_quota_bytes, &owner).await?
    {
        let mut candidates: Vec<XorbHash> = Vec::new();
        for f in &parsed.files {
            for e in &f.entries {
                candidates.push(e.xorb);
            }
        }
        let used = svc.meta.stored_bytes_for_owner(&owner).await?;
        let delta = svc
            .meta
            .unaccounted_xorb_bytes_for_owner(&owner, &candidates)
            .await?;
        if used.saturating_add(delta) > quota {
            return Err(quota_exceeded(&owner, used, quota, delta));
        }
    }

    // Materialize all terms up front so a verification-count mismatch fails the
    // whole upload before any state changes.
    let mut files_to_register: Vec<(FileHash, Vec<FileTerm>)> =
        Vec::with_capacity(parsed.files.len());
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
        files_to_register.push((f.file_hash, terms));
    }

    // Persist the shard archive before file-registration: an orphan blob is
    // GC-able, but a file row pointing at a missing shard archive is not.
    let shard_hash = shard_storage_hash(&body);
    let body_len = body.len() as u64;
    svc.blobs.put_shard(&shard_hash, body).await?;

    // Single transaction: a fault rolls back the whole shard, preserving the
    // client's "500 = nothing happened" model.
    svc.meta
        .register_files(&claims.repo, &files_to_register)
        .await?;

    metrics::SHARDS_UPLOADED.add(1, &[]);
    metrics::UPLOAD_BYTES.add(body_len, &[KeyValue::new("kind", "shard")]);

    Ok(Json(UploadShardResponse { result: 1 }))
}

fn shard_storage_hash(bytes: &[u8]) -> ShardHash {
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(blake3::hash(bytes).as_bytes());
    ShardHash(Hash32(out))
}

async fn get_reconstruction<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Extension(claims): Extension<TokenClaims>,
    Path(file_hex): Path<String>,
) -> Result<Json<QueryReconstructionResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let file_hash =
        FileHash(decode_hash(&file_hex).map_err(|e| bad_req(format!("malformed file id: {e}")))?);
    // 404 (not 403) on miss to avoid probing for files in other repos.
    if !svc
        .meta
        .file_in_repo(&file_hash, &claims.repo.repo_id)
        .await?
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "file not found".into()));
    }
    let resp = build_reconstruction_response(&svc, &file_hash).await?;
    metrics::RECONSTRUCTIONS_SERVED.add(1, &[]);
    Ok(Json(resp))
}

async fn build_reconstruction_response<B, M, A>(
    svc: &Service<B, M, A>,
    file_hash: &FileHash,
) -> Result<QueryReconstructionResponse, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let terms = svc
        .meta
        .lookup_file(file_hash)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "file not found".into()))?;

    // On-disk frame layout, NOT the chunks table whose offsets are in
    // uncompressed coordinate space.
    let xorbs: Vec<XorbHash> = terms.iter().map(|t| t.xorb).collect();
    let layouts = svc.meta.xorb_frame_layouts(&xorbs).await?;

    let mut wire_terms = Vec::with_capacity(terms.len());
    let mut fetch_info: BTreeMap<String, Vec<CASReconstructionFetchInfo>> = BTreeMap::new();
    for t in &terms {
        let xorb_hex = encode_hash(&t.xorb.0);
        let layout = layouts.get(&t.xorb).ok_or_else(|| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "xorb on-disk layout missing — upload predates layout indexing".into(),
            )
        })?;
        if t.chunk_idx_start >= t.chunk_idx_end || (t.chunk_idx_end as usize) > layout.len() {
            return Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "term chunk range invalid or exceeds xorb's known frames".into(),
            ));
        }
        let start_frame = &layout[t.chunk_idx_start as usize];
        let last_frame = &layout[(t.chunk_idx_end - 1) as usize];
        let byte_start = start_frame.on_disk_start as u64;
        let byte_end_inclusive =
            (last_frame.on_disk_start as u64) + (last_frame.on_disk_len as u64) - 1;

        wire_terms.push(CASReconstructionTerm {
            hash: xorb_hex.clone(),
            unpacked_length: t.unpacked_segment_bytes as u64,
            range: RangeJson {
                start: t.chunk_idx_start as u64,
                end: t.chunk_idx_end as u64,
            },
        });

        // When the BlobStore can offload the GET (e.g. S3 presign), bytes skip
        // us. The presigned URL must be signed over the same byte range the
        // client will request, with a TTL matching the self-signed path.
        let presigned = svc
            .blobs
            .presign_xorb_range(
                &t.xorb,
                byte_start..byte_end_inclusive + 1,
                Duration::from_secs(SIGNATURE_TTL_SECS),
            )
            .await?;
        let url = match presigned {
            Some(u) => u,
            None => build_signed_url(
                &svc.public_base_url,
                &svc.transfer_secret,
                &xorb_hex,
                byte_start,
                byte_end_inclusive,
            ),
        };
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

    Ok(QueryReconstructionResponse {
        offset_into_first_range: 0,
        terms: wire_terms,
        fetch_info,
    })
}

#[derive(Debug, Deserialize)]
struct FileDownloadQuery {
    // Rides the URL because browsers can't attach Authorization on a 302 follow.
    token: String,
    // bale-server doesn't decode the forge JWT, so the caller names the repo and
    // the forge's `check_access` verifies the JWT binds to it.
    repo: String,
    filename: Option<String>,
}

// We do NOT verify the JWT signature here — `check_repo_access` does that on the
// forge, so an attacker can't swap in a different filename hash. Field name
// matches gitea's `Claims.FilenameSHA256`.
#[derive(Debug, Default, Deserialize)]
struct ForgeJwtPayload {
    #[serde(rename = "FilenameSHA256", default)]
    filename_sha256: String,
}

fn extract_filename_sha256(token: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut parts = token.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let parsed: ForgeJwtPayload = serde_json::from_slice(&payload).ok()?;
    if parsed.filename_sha256.is_empty() {
        None
    } else {
        Some(parsed.filename_sha256)
    }
}

fn parse_owner_name(repo: &str) -> Result<RepoRef, ApiError> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| bad_req("repo must be 'owner/name'"))?;
    if owner.is_empty() || name.is_empty() {
        return Err(bad_req("repo must be 'owner/name'"));
    }
    Ok(RepoRef {
        repo_type: RepoType::Model,
        repo_id: repo.to_string(),
        revision: "main".to_string(),
    })
}

// Outside [`auth_middleware`] because a 302 from the forge can't carry an
// Authorization header — the bearer rides in `?token=`. Scope guarantees still
// hold: `check_repo_access` runs on the forge and the M12 per-repo check runs
// locally against `meta.file_in_repo`.
async fn get_file_download<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Path(file_hex): Path<String>,
    Query(q): Query<FileDownloadQuery>,
) -> Result<Response, ApiError>
where
    B: BlobStore + 'static,
    M: MetadataStore + 'static,
    A: RepoAuthz + 'static,
{
    let file_hash =
        FileHash(decode_hash(&file_hex).map_err(|e| bad_req(format!("malformed file id: {e}")))?);
    let repo = parse_owner_name(&q.repo)?;

    // Authoritative auth lives on the forge; we only learn the resolved user.
    let user = svc
        .authz
        .check_repo_access(&q.token, &repo, Scope::Read)
        .await
        .map_err(ApiError::from)?;

    // M12 scope check: 404 (not 403) so cross-repo probes can't enumerate.
    if !svc.meta.file_in_repo(&file_hash, &repo.repo_id).await? {
        return Err(ApiError(StatusCode::NOT_FOUND, "file not found".into()));
    }

    // Honor a caller-supplied `filename` only when its hash matches the forge's
    // JWT claim, so a leaked URL can't rewrite the download name. Missing claim ⇒
    // no Content-Disposition; an explicit mismatch is a tampered URL (400).
    let validated_filename = match (&q.filename, extract_filename_sha256(&q.token)) {
        (Some(name), Some(claim)) => {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(name.as_bytes());
            let got = hex::encode(hasher.finalize());
            if !ct_eq(got.as_bytes(), claim.as_bytes()) {
                return Err(bad_req("filename does not match token binding"));
            }
            Some(name.clone())
        }
        _ => None,
    };

    let terms = svc
        .meta
        .lookup_file(&file_hash)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "file not found".into()))?;

    let total_bytes: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();

    // Stream term by term so a multi-GiB download never lives in the server's
    // address space. An error mid-stream can only surface as a truncated
    // transport error because the headers are already sent.
    let svc_for_stream = svc.clone();
    let file_hex_for_log = file_hex.clone();
    let user_for_log = user.0.clone();
    let stream = async_stream::stream! {
        for term in terms {
            let item: Result<Bytes, std::io::Error> =
                match fetch_and_decompress_term(&svc_for_stream, &term).await {
                    Ok(bytes) => Ok(bytes),
                    Err(e) => {
                        tracing::error!(
                            file = %file_hex_for_log,
                            user = %user_for_log,
                            status = e.0.as_u16(),
                            error = %e.1,
                            "file download: term reconstruction failed; truncating stream",
                        );
                        Err(std::io::Error::other(format!(
                            "term reconstruction failed: {}",
                            e.1
                        )))
                    }
                };
            let is_err = item.is_err();
            yield item;
            if is_err {
                break;
            }
        }
    };

    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    resp.headers_mut()
        .insert("content-length", HeaderValue::from(total_bytes));
    if let Some(name) = validated_filename {
        let value = HeaderValue::try_from(format!(
            "attachment; filename=\"{}\"",
            sanitize_filename(&name)
        ))
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("filename: {e}")))?;
        resp.headers_mut().insert("content-disposition", value);
    }
    Ok(resp)
}

async fn fetch_and_decompress_term<B, M, A>(
    svc: &Service<B, M, A>,
    term: &FileTerm,
) -> Result<Bytes, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let layout = svc.meta.xorb_frame_layout(&term.xorb).await?;
    if layout.is_empty() {
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "xorb on-disk layout missing — upload predates layout indexing".into(),
        ));
    }
    if term.chunk_idx_start >= term.chunk_idx_end || (term.chunk_idx_end as usize) > layout.len() {
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "term chunk range invalid or exceeds xorb's known frames".into(),
        ));
    }
    let start_frame = &layout[term.chunk_idx_start as usize];
    let last_frame = &layout[(term.chunk_idx_end - 1) as usize];
    let byte_start = start_frame.on_disk_start as u64;
    let byte_end = (last_frame.on_disk_start as u64) + (last_frame.on_disk_len as u64);

    // Cap the decompression buffer so a corrupt term claiming gigabytes can't
    // trigger an unbounded Vec::with_capacity below.
    if (term.unpacked_segment_bytes as u64) > MAX_TERM_UNPACKED_BYTES {
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "term unpacked size exceeds per-term cap".into(),
        ));
    }
    let body = svc
        .blobs
        .get_xorb_range(&term.xorb, byte_start..byte_end)
        .await?;
    let mut out = Vec::with_capacity(term.unpacked_segment_bytes as usize);
    decompress_xorb_chunks_into(&body, &mut out).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("decompress term: {e}"),
        )
    })?;
    Ok(Bytes::from(out))
}

// Drop quotes, backslashes, control bytes, and non-ASCII so the value stays a
// well-formed quoted Content-Disposition without escaping. RFC 5987 would
// preserve unicode, but this ASCII fallback is widely accepted.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .filter(|c| !matches!(c, '"' | '\\'))
        .collect()
}

// Max xorbs cited per dedup response: 8 × ~1024-chunk xorbs is ~384 KiB, well
// under the 64 MiB shard limit and round-trip fast.
const DEDUP_NEIGHBORHOOD: usize = 8;

// Matches HF's published value.
const DEDUP_KEY_TTL_SECS: u64 = 24 * 60 * 60;

async fn get_dedup_chunk<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Extension(_claims): Extension<TokenClaims>,
    Path((_prefix, hash_hex)): Path<(String, String)>,
) -> Result<Response, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let chunk_hash = ChunkHash(
        decode_hash(&hash_hex).map_err(|e| bad_req(format!("malformed chunk hash: {e}")))?,
    );

    let candidates = svc
        .meta
        .xorbs_near_chunk(&chunk_hash, DEDUP_NEIGHBORHOOD)
        .await?;

    // Drop xorbs whose blobs are gone (chunks table can outlive the blob store):
    // advertising one makes the client skip re-upload, then /shards rejects the
    // shard with "references missing xorb".
    let mut near = Vec::with_capacity(candidates.len());
    let mut missing = 0usize;
    for x in candidates {
        if svc.blobs.xorb_exists(&x.xorb).await? {
            near.push(x);
        } else {
            missing += 1;
        }
    }
    if missing > 0 {
        tracing::warn!(
            chunk = %hash_hex,
            missing,
            kept = near.len(),
            "dedup: dropped xorbs whose blobs are gone (chunks table is stale vs blob store)"
        );
    }
    if near.is_empty() {
        return Err(ApiError(StatusCode::NOT_FOUND, "chunk not found".into()));
    }

    // Per-response HMAC key in the footer: the client wraps its own candidate
    // chunks with it to match ours without learning the plaintext hashes.
    let hmac_key: [u8; HASH_LEN] = rand::random();

    let mut cas_blocks = Vec::with_capacity(near.len());
    for x in &near {
        let chunks = svc.meta.xorb_chunk_offsets(&x.xorb).await?;
        let entries: Vec<CasChunkEntry> = chunks
            .iter()
            .map(|c| CasChunkEntry {
                chunk_hash: wrap_chunk_hash(&c.chunk_hash, &hmac_key),
                byte_start: c.byte_start,
                unpacked_segment_bytes: c.unpacked_segment_bytes,
            })
            .collect();
        cas_blocks.push(ParsedCasBlock {
            xorb: x.xorb,
            cas_flags: 0,
            num_bytes_in_cas: x.num_bytes_in_cas,
            num_bytes_on_disk: x.num_bytes_on_disk,
            chunks: entries,
        });
    }

    let now = now_unix();
    let shard = ParsedShard {
        header: ShardHeader {
            tag: MDB_SHARD_HEADER_TAG,
            version: MDB_SHARD_HEADER_VERSION,
            footer_size: FOOTER_SIZE as u64,
        },
        files: vec![],
        cas_blocks,
        footer: Some(ShardFooter {
            version: MDB_SHARD_FOOTER_VERSION,
            // The serializer overwrites these offsets with the true byte positions.
            file_info_offset: 0,
            cas_info_offset: 0,
            chunk_hash_hmac_key: Hash32(hmac_key),
            shard_creation_timestamp: now,
            shard_key_expiry: now + DEDUP_KEY_TTL_SECS,
            footer_offset: 0,
        }),
    };
    let bytes = serialize_shard(&shard);
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response())
}

fn wrap_chunk_hash(chunk: &ChunkHash, key: &[u8; HASH_LEN]) -> ChunkHash {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key length");
    mac.update(chunk.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    ChunkHash(Hash32(out))
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
    let xorb_hash =
        XorbHash(decode_hash(&hash_hex).map_err(|e| bad_req(format!("malformed xorb hash: {e}")))?);

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
    let (req_start, req_end_inclusive) = parse_byte_range_header(range_header).map_err(bad_req)?;
    if req_start != q.s || req_end_inclusive != q.e {
        return Err(unauthorized("Range header does not match signed range"));
    }

    let bytes = svc.blobs.get_xorb_range(&xorb_hash, q.s..(q.e + 1)).await?;

    let len = bytes.len();
    let mut resp = (StatusCode::PARTIAL_CONTENT, bytes).into_response();
    resp.headers_mut()
        .insert("content-length", HeaderValue::from(len));
    // u64 Display is ASCII digits; HeaderValue accepts any visible ASCII.
    let content_range = HeaderValue::try_from(format!("bytes {}-{}/*", q.s, q.e)).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("content-range: {e}"),
        )
    })?;
    resp.headers_mut().insert("content-range", content_range);
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
    // Seed with the length difference so a length mismatch doesn't return early
    // (zip truncates to the shorter side) and can't leak length via timing.
    let mut acc: u32 = (a.len() ^ b.len()) as u32;
    for (x_a, x_b) in a.iter().zip(b.iter()) {
        acc |= (x_a ^ x_b) as u32;
    }
    acc == 0
}

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

// Accepts the admin bearer (constant-time compared) or a Bale JWT whose
// `repo.owner()` matches `owner`. The usage endpoints live outside the JWT
// middleware because the admin bearer is not a JWT.
async fn require_admin_or_owner<B, M, A>(
    svc: &Service<B, M, A>,
    headers: &HeaderMap,
    owner: &str,
) -> Result<(), ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("missing bearer"))?;

    let is_admin = svc
        .admin_token
        .zip(hex::decode(bearer.trim()).ok())
        .is_some_and(|(admin, presented)| ct_eq(&presented, &admin));
    if is_admin {
        return Ok(());
    }
    let claims = svc
        .authz
        .verify_xet_token(bearer)
        .await
        .map_err(ApiError::from)?;
    if claims.repo.owner() != owner {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "token not scoped to this owner".into(),
        ));
    }
    Ok(())
}

async fn get_owner_usage<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Path(owner): Path<String>,
    headers: HeaderMap,
) -> Result<Json<OwnerUsageResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    require_admin_or_owner(&svc, &headers, &owner).await?;

    let raw = svc.meta.raw_bytes_for_owner(&owner).await?;
    let stored = svc.meta.stored_bytes_for_owner(&owner).await?;
    let quota = effective_quota(svc.meta.as_ref(), svc.default_quota_bytes, &owner).await?;
    Ok(Json(OwnerUsageResponse {
        owner,
        raw_bytes: raw,
        stored_bytes: stored,
        dedup_savings_bytes: raw.saturating_sub(stored),
        quota_bytes: quota,
    }))
}

async fn get_repo_usage<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<RepoUsageResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    require_admin_or_owner(&svc, &headers, &owner).await?;
    let repo_id = format!("{owner}/{repo}");
    let raw = svc.meta.raw_bytes_for_repo(&repo_id).await?;
    let stored = svc.meta.stored_bytes_for_repo(&repo_id).await?;
    let exclusive = svc.meta.exclusive_stored_bytes_for_repo(&repo_id).await?;
    Ok(Json(RepoUsageResponse {
        repo_id,
        raw_bytes: raw,
        stored_bytes: stored,
        dedup_savings_bytes: raw.saturating_sub(stored),
        exclusive_bytes: exclusive,
    }))
}

async fn put_owner_quota<B, M, A>(
    State(svc): State<Service<B, M, A>>,
    Path(owner): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SetOwnerQuotaRequest>,
) -> Result<StatusCode, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let admin = svc
        .admin_token
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "admin endpoint disabled".into()))?;
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("missing admin bearer"))?;
    let presented = hex::decode(raw.trim()).map_err(|_| unauthorized("admin token not hex"))?;
    if !ct_eq(&presented, &admin) {
        return Err(unauthorized("bad admin token"));
    }
    svc.meta.set_owner_quota(&owner, body.limit_bytes).await?;
    Ok(StatusCode::NO_CONTENT)
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
        "bale-read-token" => Ok(Scope::Read),
        "bale-write-token" => Ok(Scope::Write),
        _ => Err(bad_req(format!("unknown token segment: {seg}"))),
    }
}
