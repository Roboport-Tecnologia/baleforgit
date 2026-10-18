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
    AccessPurpose, BlobStore, ChunkHash, ChunkRow, CoreError, FileHash, FileRegistration, FileTerm,
    Hash32, MetadataStore, RepoAuthz, RepoRef, RepoType, Scope, ShardHash, TokenClaims,
    XorbFrameRow, XorbHash, XorbInfo, HASH_LEN,
};
use bale_server_shard::{
    decompress_xorb_chunks_verified, parse_xorb_frames, serialize as serialize_shard,
    term_verification_hash, verify_xorb_body, xorb_hash_of, CasChunkEntry, FileHasher,
    ParsedCasBlock, ParsedShard, ShardFooter, ShardHeader, XorbVerifyError, FOOTER_SIZE,
    MDB_SHARD_FOOTER_VERSION, MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use bale_server_wire::{
    decode_hash, encode_hash, CASReconstructionFetchInfo, CASReconstructionTerm,
    OwnerUsageResponse, QueryReconstructionResponse, RangeJson, RepoUsageResponse,
    SetOwnerQuotaRequest, UploadShardResponse, UploadXorbResponse, XetTokenResponse,
};
use futures_util::StreamExt;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use opentelemetry::KeyValue;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::trace::{DefaultOnFailure, DefaultOnResponse, TraceLayer};
use tracing::Level;

// xet cuts xorbs at 64 MiB *unpacked*; incompressible chunks are stored raw plus
// an 8-byte header each (≤ 8192 chunks), so a legit serialized xorb can exceed
// 64 MiB. verify_xorb_body enforces the real unpacked/chunk-count caps.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024 + 8 * 8192 + 64 * 1024;
const MAX_SHARD_BYTES: usize = 64 * 1024 * 1024;
const ADMIN_BODY_BYTES: usize = 4 * 1024;
const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SHARD_VERIFY_CHUNKS: u64 = 256 * 1024 * 1024;
const MAX_CONCURRENT_XORB_UPLOADS: usize = 16;
const XORB_UPLOAD_DEADLINE: Duration = Duration::from_secs(110);
const SHARD_UPLOAD_DEADLINE: Duration = Duration::from_secs(300);
// Bounds concurrent CPU-heavy file verifications (memory per file is constant).
static VERIFY_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
const VERIFY_BATCH_CHUNKS: u64 = 64 * 1024;
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
    /// Detached work (xorb commits) that must finish before shutdown.
    pub background: tokio_util::task::TaskTracker,
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
            background: self.background.clone(),
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
        // Each in-flight xorb holds up to ~64 MiB of body plus a stored copy and
        // decode buffers, and one xet client ramps to 64 parallel uploads; queue
        // past this many rather than let a single push OOM the server (the limit
        // wraps body buffering too). The inner deadline keeps a trickling client
        // from pinning a slot: xet gives up on a xorb POST after 120 s anyway, so
        // a slot held longer only starves everyone queued behind it.
        .route(
            "/v1/xorbs/{prefix}/{hash}",
            post(upload_xorb::<B, M, A>)
                .layer::<_, std::convert::Infallible>(
                    tower_http::timeout::TimeoutLayer::with_status_code(
                        StatusCode::REQUEST_TIMEOUT,
                        XORB_UPLOAD_DEADLINE,
                    ),
                )
                .layer::<_, std::convert::Infallible>(tower::limit::ConcurrencyLimitLayer::new(
                    MAX_CONCURRENT_XORB_UPLOADS,
                )),
        )
        // A 64 MiB shard body can otherwise be trickled indefinitely (the 60 s
        // idle timeout resets per frame), pinning its buffer and connection.
        .route(
            "/shards",
            post(upload_shard::<B, M, A>).layer::<_, std::convert::Infallible>(
                tower_http::timeout::TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    SHARD_UPLOAD_DEADLINE,
                ),
            ),
        )
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
        )
        // Inner limit wins over the router-wide 64 MiB one: these bodies are
        // tiny, and the quota body is buffered before the bearer is checked.
        .layer(DefaultBodyLimit::max(ADMIN_BODY_BYTES));

    // Access logs at INFO; on_failure fires at WARN on 4xx/5xx. Path only: query
    // strings carry forge bearers (`/v1/files?token=`) and reusable transfer
    // signatures (`/xorb/...&sig=`), which must never reach logs or OTel spans.
    let trace = TraceLayer::new_for_http()
        .make_span_with(|req: &axum::http::Request<Body>| {
            tracing::info_span!(
                "request",
                method = %req.method(),
                path = %req.uri().path(),
                version = ?req.version(),
            )
        })
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
        // Idle (per-frame) timeout: a client trickling a 64 MiB body can't pin
        // its buffer and a task forever. Slow-but-steady uploads are unaffected.
        .layer(tower_http::timeout::RequestBodyTimeoutLayer::new(
            BODY_IDLE_TIMEOUT,
        ))
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
            e @ CoreError::QuotaExceeded { .. } => {
                ApiError(StatusCode::PAYLOAD_TOO_LARGE, e.to_string())
            }
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

// Never fall back to 0: a zeroed clock would accept every expired transfer signature.
fn now_unix() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("system clock before unix epoch: {e}"),
            )
        })
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
) -> Result<String, ApiError> {
    let exp = now_unix()?.saturating_add(SIGNATURE_TTL_SECS);
    let sig = sign(
        secret,
        &SignedRange {
            hash_hex: xorb_hex.to_string(),
            start,
            end_inclusive,
            exp,
        },
    );
    Ok(format!(
        "{base}/xorb/default/{xorb_hex}?s={start}&e={end_inclusive}&x={exp}&sig={sig}"
    ))
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
    // 413, not 429: xet retries 429 (and 5xx) with a backoff that squares each
    // step, so an over-quota push would hang for hours before failing. 413 is
    // fatal to xet and otherwise unused by legitimate xet traffic, so git-bale
    // can key its user-facing hint on it (push_pending::explain_quota_exceeded).
    ApiError(
        StatusCode::PAYLOAD_TOO_LARGE,
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
    B: BlobStore + 'static,
    M: MetadataStore + 'static,
    A: RepoAuthz + 'static,
{
    let hash = decode_hash(&hash_hex).map_err(|e| bad_req(format!("malformed xorb hash: {e}")))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(bad_req("xorb body exceeds the size limit"));
    }
    let xorb = XorbHash(hash);
    let owner = claims.repo.owner().to_string();
    // Recompute the merkle aggregation and compare to the URL hash, so a writer
    // can't corrupt the CAS by uploading bytes that don't match.
    let layout = verified_layout(body.clone(), xorb)
        .await?
        .map_err(|e| match e {
            XorbVerifyError::HashMismatch => bad_req("xorb body does not match URL hash"),
            other => bad_req(format!("xorb body verification failed: {other}")),
        })?;
    let body_len = body.len() as u64;
    // Charge the upper bound (body size) before writing, atomically with the
    // quota check; content-addressed re-puts add no bytes and skip it.
    let quota = effective_quota(svc.meta.as_ref(), svc.default_quota_bytes, &owner).await?;
    let reserved = if svc.blobs.xorb_exists(&xorb).await? {
        false
    } else {
        svc.meta
            .reserve_xorb_upload(&xorb, &owner, body_len, quota)
            .await?
    };

    // Equal-hash bodies can differ in compression (hence frame offsets) and the
    // blob store keeps only the first writer's, so the layout is always derived
    // from the exact stored body — never registered ahead of the put, where a
    // delayed or cancelled request could pin offsets for bytes that lost the
    // race. A crash between put and register leaves a blob without a layout,
    // which `ensure_layout` derives from the blob on first use.
    // Detached so a deadline or client disconnect can't cancel it midway (an
    // interrupted fs write would leak its tmp file; a later retry re-derives
    // the layout either way).
    let commit = {
        let svc = svc.clone();
        let tracker = svc.background.clone();
        tracker.spawn(async move {
            let was_inserted = match svc.blobs.put_xorb(&xorb, body.clone()).await {
                Ok(inserted) => inserted,
                Err(e) => {
                    if reserved && !svc.blobs.xorb_exists(&xorb).await.unwrap_or(true) {
                        let _ = svc.meta.release_xorb_upload(&xorb, &owner).await;
                    }
                    return Err(e.into());
                }
            };
            let layout = if was_inserted {
                layout
            } else {
                settle_stored_layout(&svc, &xorb, body, layout).await?
            };
            register_verified(&svc, &xorb, &layout).await?;
            if reserved {
                let on_disk: u64 = layout.iter().map(|f| f.on_disk_len as u64).sum();
                svc.meta.settle_xorb_upload(&xorb, &owner, on_disk).await?;
            }
            Ok::<bool, ApiError>(was_inserted)
        })
    };
    let was_inserted = commit.await.map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("xorb commit task: {e}"),
        )
    })??;

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

// Parse + verify off the async workers: decompressing and hashing 64 MiB is
// tens of milliseconds of CPU that would otherwise stall unrelated requests.
async fn verified_layout(
    body: Bytes,
    xorb: XorbHash,
) -> Result<Result<Vec<XorbFrameRow>, XorbVerifyError>, ApiError> {
    tokio::task::spawn_blocking(move || {
        let frames = parse_xorb_frames(&body)?;
        let hashes = verify_xorb_body(&body, &xorb)?;
        Ok(frames
            .iter()
            .zip(hashes)
            .enumerate()
            .map(|(i, (f, h))| XorbFrameRow {
                frame_index: i as u32,
                on_disk_start: f.on_disk_start,
                on_disk_len: f.on_disk_len,
                uncompressed_len: f.uncompressed_len,
                chunk_hash: h,
            })
            .collect())
    })
    .await
    .map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("verify task: {e}"),
        )
    })
}

// The blob store kept another upload's body: describe those exact bytes. If
// they no longer verify (bit rot / tampering), heal the blob with our verified
// body.
async fn settle_stored_layout<B, M, A>(
    svc: &Service<B, M, A>,
    xorb: &XorbHash,
    ours: Bytes,
    our_layout: Vec<XorbFrameRow>,
) -> Result<Vec<XorbFrameRow>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let stored = svc.blobs.get_xorb(xorb).await?;
    if stored == ours {
        return Ok(our_layout);
    }
    if let Ok(layout) = verified_layout(stored, *xorb).await? {
        return Ok(layout);
    }
    tracing::error!(xorb = ?xorb.0, "stored xorb failed re-verification; replacing it with the verified upload");
    svc.blobs.replace_xorb(xorb, ours).await?;
    // Concurrent healers may each replace with their own encoding; only return
    // once the layout we registered still describes the stored body.
    for _ in 0..3 {
        let landed = svc.blobs.get_xorb(xorb).await?;
        let layout = verified_layout(landed.clone(), *xorb).await?.map_err(|e| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("xorb still fails verification after replace: {e}"),
            )
        })?;
        register_verified(svc, xorb, &layout).await?;
        if svc.blobs.get_xorb(xorb).await? == landed {
            return Ok(layout);
        }
    }
    Err(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "xorb is being replaced concurrently; retry".into(),
    ))
}

async fn register_verified<B, M, A>(
    svc: &Service<B, M, A>,
    xorb: &XorbHash,
    layout: &[XorbFrameRow],
) -> Result<(), ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let chunks = layout_chunks(layout).ok_or_else(|| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "verified layout has non-contiguous frames".into(),
        )
    })?;
    svc.meta.register_xorb_layout(xorb, layout).await?;
    // The dedup index is built only from server-verified chunk hashes, never
    // from client-supplied shard CAS blocks.
    let (info, rows) = xorb_registration(xorb, layout, &chunks)?;
    svc.meta.register_xorb(&info, &rows).await?;
    Ok(())
}

/// `recorded`, or — when a crash between put and register left the blob with no
/// layout — the layout derived from the stored blob (persisted, so read once).
/// `None` if the blob is missing or fails verification.
async fn ensure_layout<B, M, A>(
    svc: &Service<B, M, A>,
    xorb: &XorbHash,
    recorded: Vec<XorbFrameRow>,
) -> Result<Option<Vec<XorbFrameRow>>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    if !recorded.is_empty() {
        return Ok(Some(recorded));
    }
    let stored = match svc.blobs.get_xorb(xorb).await {
        Ok(b) => b,
        Err(CoreError::NotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    match verified_layout(stored, *xorb).await? {
        Ok(layout) => {
            register_verified(svc, xorb, &layout).await?;
            Ok(Some(layout))
        }
        Err(e) => {
            tracing::error!(xorb = ?xorb.0, error = %e, "stored xorb fails verification");
            Ok(None)
        }
    }
}

fn layout_chunks(layout: &[XorbFrameRow]) -> Option<Vec<(ChunkHash, u64)>> {
    layout
        .iter()
        .enumerate()
        .map(|(i, f)| {
            (f.frame_index as usize == i).then_some((f.chunk_hash, f.uncompressed_len as u64))
        })
        .collect()
}

fn xorb_registration(
    xorb: &XorbHash,
    layout: &[XorbFrameRow],
    chunks: &[(ChunkHash, u64)],
) -> Result<(XorbInfo, Vec<ChunkRow>), ApiError> {
    let too_big = || {
        ApiError(
            StatusCode::BAD_REQUEST,
            "xorb exceeds u32 size accounting".into(),
        )
    };
    let mut rows = Vec::with_capacity(chunks.len());
    let mut offset: u32 = 0;
    for (idx, (h, len)) in chunks.iter().enumerate() {
        let len = u32::try_from(*len).map_err(|_| too_big())?;
        rows.push(ChunkRow {
            chunk_hash: *h,
            chunk_index: idx as u32,
            byte_start: offset,
            unpacked_segment_bytes: len,
        });
        offset = offset.checked_add(len).ok_or_else(too_big)?;
    }
    let on_disk = layout
        .iter()
        .try_fold(0u32, |acc, f| acc.checked_add(f.on_disk_len))
        .ok_or_else(too_big)?;
    let info = XorbInfo {
        xorb: *xorb,
        num_chunks: rows.len() as u32,
        num_bytes_in_cas: offset,
        num_bytes_on_disk: on_disk,
    };
    Ok((info, rows))
}

/// The xorb's server-verified chunk sequence (re-checked against the xorb hash).
fn verified_chunks(xorb: &XorbHash, layout: &[XorbFrameRow]) -> Option<Vec<(ChunkHash, u64)>> {
    let chunks = layout_chunks(layout)?;
    if xorb_hash_of(&chunks) != *xorb {
        tracing::error!(xorb = ?xorb.0, "stored chunk hashes do not aggregate to the xorb hash");
        return None;
    }
    Some(chunks)
}

// Consecutive term runs spanning at most VERIFY_BATCH_CHUNKS frames (at least
// one term), so one DB fetch never materializes millions of rows.
fn chunk_bounded_batches(terms: &[FileTerm]) -> Vec<&[FileTerm]> {
    let mut out = Vec::new();
    let (mut start, mut chunks) = (0, 0u64);
    for (i, t) in terms.iter().enumerate() {
        let n = t.chunk_idx_end.saturating_sub(t.chunk_idx_start) as u64;
        if i > start && chunks + n > VERIFY_BATCH_CHUNKS {
            out.push(&terms[start..i]);
            start = i;
            chunks = 0;
        }
        chunks += n;
    }
    if start < terms.len() {
        out.push(&terms[start..]);
    }
    out
}

fn file_chunk_count(terms: &[FileTerm]) -> u64 {
    terms
        .iter()
        .map(|t| t.chunk_idx_end.saturating_sub(t.chunk_idx_start) as u64)
        .sum()
}

/// Proof of possession for one file: every term's frames exist, sizes are
/// exact, its verification range hash matches, and the whole-file merkle hash
/// equals `file_hash`. Without it, knowing a file hash (it's in every git
/// pointer) would grant read access, and a first registration could bind any
/// hash to arbitrary bytes for every repo. Terms are checked in batches as
/// their frames arrive (first mismatch rejects; frames are reduced to
/// `(hash, len)` at once) and hashing runs off the async workers.
async fn verify_file<B, M, A>(
    svc: &Service<B, M, A>,
    reg: &FileRegistration,
) -> Result<(), ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let reject = |e: String| bad_req(format!("file {:?}: {e}", reg.file_hash.0));
    let task_err = |e: tokio::task::JoinError| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("verify task: {e}"),
        )
    };
    let mut hasher = FileHasher::default();
    let mut base = 0;
    for batch in chunk_bounded_batches(&reg.terms) {
        let wanted: Vec<(XorbHash, u32, u32)> = batch
            .iter()
            .map(|t| (t.xorb, t.chunk_idx_start, t.chunk_idx_end))
            .collect();
        let mut spans = svc.meta.xorb_frame_spans(&wanted).await?;
        if heal_missing_layouts(svc, batch, &spans).await? {
            spans = svc.meta.xorb_frame_spans(&wanted).await?;
        }
        let terms = batch.to_vec();
        let batch_base = base;
        base += batch.len();
        let (h, checked) = tokio::task::spawn_blocking(move || {
            let checked = verify_terms(&terms, &spans, batch_base, &mut hasher);
            (hasher, checked)
        })
        .await
        .map_err(task_err)?;
        hasher = h;
        checked.map_err(reject)?;
    }
    let computed = tokio::task::spawn_blocking(move || hasher.finish())
        .await
        .map_err(task_err)?;
    if computed != reg.file_hash {
        return Err(reject("file hash does not match its terms".into()));
    }
    Ok(())
}

// A short span is normally a bad range (rejected by verify_terms). Only a xorb
// with no layout at all — a crash between put and layout write — is derived
// from its blob; probing for any frame keeps a hostile shard from forcing
// full-layout loads of existing xorbs.
async fn heal_missing_layouts<B, M, A>(
    svc: &Service<B, M, A>,
    terms: &[FileTerm],
    spans: &[Vec<XorbFrameRow>],
) -> Result<bool, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let mut short: Vec<XorbHash> = terms
        .iter()
        .zip(spans)
        .filter(|(t, span)| {
            span.len() != t.chunk_idx_end.saturating_sub(t.chunk_idx_start) as usize
        })
        .map(|(t, _)| t.xorb)
        .collect();
    short.sort();
    short.dedup();
    if short.is_empty() {
        return Ok(false);
    }
    let probes: Vec<(XorbHash, u32, u32)> = short.iter().map(|x| (*x, 0, 1)).collect();
    let found = svc.meta.xorb_frame_spans(&probes).await?;
    let mut healed = false;
    for (x, probe) in short.iter().zip(found) {
        if probe.is_empty() && ensure_layout(svc, x, Vec::new()).await?.is_some() {
            healed = true;
        }
    }
    Ok(healed)
}

fn verify_terms(
    terms: &[FileTerm],
    spans: &[Vec<XorbFrameRow>],
    base: usize,
    hasher: &mut FileHasher,
) -> Result<(), String> {
    for (k, (t, span)) in terms.iter().zip(spans).enumerate() {
        let i = base + k;
        let (start, end) = (t.chunk_idx_start, t.chunk_idx_end);
        let contiguous = span
            .iter()
            .enumerate()
            .all(|(n, f)| f.frame_index == start + n as u32);
        if start >= end || span.len() != (end - start) as usize || !contiguous {
            return Err(format!(
                "term {i}: chunk range [{start}, {end}) of xorb {:?} doesn't exist",
                t.xorb.0
            ));
        }
        let bytes: u64 = span.iter().map(|f| f.uncompressed_len as u64).sum();
        if bytes != t.unpacked_segment_bytes as u64 {
            return Err(format!(
                "term {i}: declares {} bytes but its chunks hold {bytes}",
                t.unpacked_segment_bytes
            ));
        }
        let hashes: Vec<ChunkHash> = span.iter().map(|f| f.chunk_hash).collect();
        if t.verification != Some(term_verification_hash(&hashes)) {
            return Err(format!("term {i}: verification hash missing or mismatched"));
        }
        for f in span {
            hasher.push(f.chunk_hash, f.uncompressed_len as u64);
        }
    }
    Ok(())
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
    if body.len() > MAX_SHARD_BYTES {
        return Err(bad_req("shard exceeds 64 MiB limit"));
    }
    let parsed: ParsedShard =
        bale_server_shard::parse(&body).map_err(|e| bad_req(format!("malformed shard: {e}")))?;

    let mut files_to_register: Vec<FileRegistration> = Vec::with_capacity(parsed.files.len());
    for f in &parsed.files {
        // Verification range hashes are the proof of possession: they need the
        // plaintext chunk hashes, which the server never serves. Without them,
        // anyone who once saw a reconstruction (xorb + chunk ranges) could
        // re-register the file into their own repo and regain read access.
        if f.verifications.len() != f.entries.len() {
            return Err(bad_req(
                "shard file needs exactly one verification entry per term",
            ));
        }
        if f.entries
            .iter()
            .any(|e| e.chunk_idx_start >= e.chunk_idx_end)
        {
            return Err(bad_req(
                "shard file term has an empty or inverted chunk range",
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
                verification: f.verifications.get(idx).copied(),
            })
            .collect();
        files_to_register.push(FileRegistration {
            file_hash: f.file_hash,
            terms,
        });
    }

    // Verification memory is constant per file (frames stream in term batches
    // into an incremental merkle hasher), so the only bound needed is on work:
    // a hostile shard of ~700K terms each spanning a whole 8192-chunk xorb
    // would otherwise hash ~6 billion chunks. 256 Mi chunks ≈ 16 TiB of file
    // content at xet's 64 KiB average chunk.
    let total_chunks: u64 = files_to_register
        .iter()
        .map(|r| file_chunk_count(&r.terms))
        .sum();
    if total_chunks > MAX_SHARD_VERIFY_CHUNKS {
        return Err(bad_req(format!(
            "shard spans {total_chunks} chunks (limit {MAX_SHARD_VERIFY_CHUNKS}); push fewer files at once"
        )));
    }

    let mut term_xorbs: Vec<XorbHash> = files_to_register
        .iter()
        .flat_map(|r| r.terms.iter().map(|t| t.xorb))
        .collect();
    term_xorbs.sort();
    term_xorbs.dedup();

    // Concurrent: a huge file references thousands of xorbs, and on S3 each
    // probe is a HEAD round-trip.
    let mut probes = futures_util::stream::iter(term_xorbs.clone())
        .map(|x| {
            let blobs = svc.blobs.clone();
            async move { (x, blobs.xorb_exists(&x).await) }
        })
        .buffered(32);
    while let Some((x, present)) = probes.next().await {
        if !present? {
            return Err(bad_req(format!("shard references missing xorb {:?}", x.0)));
        }
    }
    drop(probes);

    // All verification before any state change. Only the frame spans the terms
    // name are loaded, never whole 8192-frame layouts per referenced xorb, and
    // the shard's own CAS Info chunk lists (client claims) are never used.
    for reg in &files_to_register {
        let _slot = VERIFY_SLOTS.acquire().await.map_err(|e| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("verify slot: {e}"),
            )
        })?;
        verify_file(&svc, reg).await?;
    }

    // Every term xorb gets a `xorbs` row derived from its verified layout, so
    // owner accounting can't be dodged by omitting CAS blocks. upload_xorb
    // normally wrote it; a crash between its layout and row writes is repaired
    // here from the blob.
    for x in &svc.meta.missing_xorb_rows(&term_xorbs).await? {
        let recorded = svc.meta.xorb_frame_layout(x).await?;
        let layout = ensure_layout(&svc, x, recorded).await?.ok_or_else(|| {
            bad_req(format!(
                "xorb {:?} blob missing or failing verification",
                x.0
            ))
        })?;
        register_verified(&svc, x, &layout).await?;
    }

    // Reject over-quota BEFORE register_files so the shard leaves no file rows
    // behind. Delta is the on-disk size of referenced xorbs the owner doesn't
    // already reference.
    let owner = claims.repo.owner().to_string();
    if let Some(quota) = effective_quota(svc.meta.as_ref(), svc.default_quota_bytes, &owner).await?
    {
        let used = svc.meta.stored_bytes_for_owner(&owner).await?;
        let delta = svc
            .meta
            .unaccounted_xorb_bytes_for_owner(&owner, &term_xorbs)
            .await?;
        // Only growth is refused, so an idempotent re-push still succeeds
        // after a quota is lowered.
        if delta > 0 && used.saturating_add(delta) > quota {
            return Err(quota_exceeded(&owner, used, quota, delta));
        }
    }

    // Persist the shard archive before file-registration: an orphan blob is
    // harmless, but a file row pointing at a missing shard archive is not.
    let shard_hash = shard_storage_hash(&body);
    let body_len = body.len() as u64;
    svc.blobs.put_shard(&shard_hash, body).await?;

    // Single transaction: a fault rolls back the whole shard, preserving the
    // client's "500 = nothing happened" model.
    let quota = effective_quota(svc.meta.as_ref(), svc.default_quota_bytes, &owner).await?;
    svc.meta
        .register_files(&claims.repo, &files_to_register, quota)
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
    headers: HeaderMap,
) -> Result<Json<QueryReconstructionResponse>, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let file_hash =
        FileHash(decode_hash(&file_hex).map_err(|e| bad_req(format!("malformed file id: {e}")))?);
    let range = headers
        .get("range")
        .map(parse_byte_range_header)
        .transpose()
        .map_err(bad_req)?;
    // 404 (not 403) on miss to avoid probing for files in other repos.
    if !svc
        .meta
        .file_in_repo(&file_hash, &claims.repo.repo_id)
        .await?
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "file not found".into()));
    }
    let resp = build_reconstruction_response(&svc, &file_hash, range).await?;
    metrics::RECONSTRUCTIONS_SERVED.add(1, &[]);
    Ok(Json(resp))
}

async fn build_reconstruction_response<B, M, A>(
    svc: &Service<B, M, A>,
    file_hash: &FileHash,
    range: Option<(u64, u64)>,
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
    let (terms, offset_into_first_range) = select_range(terms, range)?;

    // On-disk frame layout, NOT the chunks table whose offsets are in
    // uncompressed coordinate space.
    let mut xorbs: Vec<XorbHash> = terms.iter().map(|t| t.xorb).collect();
    xorbs.sort();
    xorbs.dedup();
    let mut layouts = svc.meta.xorb_frame_layouts(&xorbs).await?;
    for x in &xorbs {
        let rec = layouts.remove(x).unwrap_or_default();
        if let Some(layout) = ensure_layout(svc, x, rec).await? {
            layouts.insert(*x, layout);
        }
    }

    let mut wire_terms = Vec::with_capacity(terms.len());
    let mut intervals: BTreeMap<XorbHash, Vec<(u32, u32)>> = BTreeMap::new();
    for t in &terms {
        let layout = layouts.get(&t.xorb).ok_or_else(|| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "xorb blob missing or failing verification".into(),
            )
        })?;
        if t.chunk_idx_start >= t.chunk_idx_end || (t.chunk_idx_end as usize) > layout.len() {
            return Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "term chunk range invalid or exceeds xorb's known frames".into(),
            ));
        }
        wire_terms.push(CASReconstructionTerm {
            hash: encode_hash(&t.xorb.0),
            unpacked_length: t.unpacked_segment_bytes as u64,
            range: RangeJson {
                start: t.chunk_idx_start as u64,
                end: t.chunk_idx_end as u64,
            },
        });
        intervals
            .entry(t.xorb)
            .or_default()
            .push((t.chunk_idx_start, t.chunk_idx_end));
    }

    // One fetch entry per *disjoint* chunk range per xorb. The client binds each
    // term to the first entry containing it and dedups blocks by (xorb, range
    // start), so overlapping per-term entries (e.g. terms [0,5) then [0,10))
    // would make it slice a 5-chunk block for a 10-chunk term and panic.
    let mut fetch_info: BTreeMap<String, Vec<CASReconstructionFetchInfo>> = BTreeMap::new();
    for (xorb, mut ranges) in intervals {
        let layout = layouts.get(&xorb).ok_or_else(|| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "xorb blob missing or failing verification".into(),
            )
        })?;
        let xorb_hex = encode_hash(&xorb.0);
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        for (start, end) in merged {
            let first = &layout[start as usize];
            let last = &layout[(end - 1) as usize];
            let byte_start = first.on_disk_start as u64;
            let byte_end_inclusive = (last.on_disk_start as u64) + (last.on_disk_len as u64) - 1;
            // When the BlobStore can offload the GET (e.g. S3 presign), bytes skip
            // us. The presigned URL must be signed over the same byte range the
            // client will request, with a TTL matching the self-signed path.
            let presigned = svc
                .blobs
                .presign_xorb_range(
                    &xorb,
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
                )?,
            };
            fetch_info
                .entry(xorb_hex.clone())
                .or_default()
                .push(CASReconstructionFetchInfo {
                    range: RangeJson {
                        start: start as u64,
                        end: end as u64,
                    },
                    url,
                    url_range: RangeJson {
                        start: byte_start,
                        end: byte_end_inclusive,
                    },
                });
        }
    }

    Ok(QueryReconstructionResponse {
        offset_into_first_range,
        terms: wire_terms,
        fetch_info,
    })
}

// xet fetches files past 2 × its min fetch size (256 MiB) in byte-range blocks,
// so a block request must get only the terms overlapping it, with the first
// term's leading bytes skipped via offset_into_first_range (the client trims
// the last term), and 416 at or past EOF. Answering every block with the whole
// file makes the client lay the file out at the block's offset and underflow
// its last-term trim — no large file could be reconstructed.
fn select_range(
    terms: Vec<FileTerm>,
    range: Option<(u64, u64)>,
) -> Result<(Vec<FileTerm>, u64), ApiError> {
    let Some((start, end_inclusive)) = range else {
        return Ok((terms, 0));
    };
    let total: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();
    if start >= total {
        return Err(ApiError(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "range starts at or past end of file".into(),
        ));
    }
    let end = end_inclusive.saturating_add(1).min(total);
    let mut selected = Vec::new();
    let mut offset = 0;
    let mut term_start = 0u64;
    for t in terms {
        let term_end = term_start + t.unpacked_segment_bytes as u64;
        if term_end > start && term_start < end {
            if selected.is_empty() {
                offset = start - term_start;
            }
            selected.push(t);
        }
        if term_end >= end {
            break;
        }
        term_start = term_end;
    }
    Ok((selected, offset))
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

// The JWT signature is NOT verified here — `check_repo_access` does that on the
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
        owner: None,
    })
}

// Outside `auth_middleware` because a 302 from the forge can't carry an
// Authorization header, so the bearer rides in `?token=`. Scope still holds:
// `check_repo_access` runs on the forge, then `meta.file_in_repo` locally.
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

    let grant = svc
        .authz
        .check_repo_access(
            &q.token,
            &repo,
            Scope::Read,
            AccessPurpose::FileDownload { file_id: &file_hex },
        )
        .await
        .map_err(ApiError::from)?;
    let user = grant.user;
    let repo_id = grant.canonical_repo_id.unwrap_or(repo.repo_id);

    // 404 (not 403) so cross-repo probes can't enumerate files.
    if !svc.meta.file_in_repo(&file_hash, &repo_id).await? {
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
    let recorded = svc.meta.xorb_frame_layout(&term.xorb).await?;
    match decode_term(svc, term, recorded).await {
        Ok(bytes) => Ok(bytes),
        // A recorded layout that disagrees with the stored blob (only reachable
        // via concurrent heals of a corrupt blob) decodes to wrong chunks; re-derive
        // it from the blob once rather than failing every download of the xorb.
        Err(e) => {
            tracing::warn!(xorb = ?term.xorb.0, error = %e.1, "term decode failed; re-deriving layout from blob");
            decode_term(svc, term, Vec::new()).await
        }
    }
}

async fn decode_term<B, M, A>(
    svc: &Service<B, M, A>,
    term: &FileTerm,
    recorded: Vec<XorbFrameRow>,
) -> Result<Bytes, ApiError>
where
    B: BlobStore,
    M: MetadataStore,
    A: RepoAuthz,
{
    let layout = ensure_layout(svc, &term.xorb, recorded)
        .await?
        .ok_or_else(|| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "xorb blob missing or failing verification".into(),
            )
        })?;
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
    let expected: Vec<ChunkHash> = layout
        [term.chunk_idx_start as usize..term.chunk_idx_end as usize]
        .iter()
        .map(|f| f.chunk_hash)
        .collect();
    decompress_xorb_chunks_verified(&body, &expected, &mut out).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("decompress term: {e}"),
        )
    })?;
    if out.len() != term.unpacked_segment_bytes as usize {
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "term decompressed to the wrong length".into(),
        ));
    }
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

    // Advertise only server-verified chunk sequences: a client dedups by chunk
    // *position*, so a wrong or gapped list (e.g. a repeated chunk collapsed by
    // the chunks table's key) makes it reference the wrong bytes.
    let mut cas_blocks = Vec::with_capacity(near.len());
    for x in &near {
        let recorded = svc.meta.xorb_frame_layout(&x.xorb).await?;
        let Some(layout) = ensure_layout(&svc, &x.xorb, recorded).await? else {
            continue;
        };
        let Some(chunks) = verified_chunks(&x.xorb, &layout) else {
            tracing::warn!(xorb = ?x.xorb.0, "dedup: skipping xorb without a verifiable chunk list");
            continue;
        };
        let (info, rows) = xorb_registration(&x.xorb, &layout, &chunks)?;
        cas_blocks.push(ParsedCasBlock {
            xorb: x.xorb,
            cas_flags: 0,
            num_bytes_in_cas: info.num_bytes_in_cas,
            num_bytes_on_disk: info.num_bytes_on_disk,
            chunks: rows
                .iter()
                .map(|c| CasChunkEntry {
                    chunk_hash: wrap_chunk_hash(&c.chunk_hash, &hmac_key),
                    byte_start: c.byte_start,
                    unpacked_segment_bytes: c.unpacked_segment_bytes,
                })
                .collect(),
        });
    }
    if cas_blocks.is_empty() {
        return Err(ApiError(StatusCode::NOT_FOUND, "chunk not found".into()));
    }

    let now = now_unix()?;
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
            shard_key_expiry: now.saturating_add(DEDUP_KEY_TTL_SECS),
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

// Must match xet's `MerkleHash::hmac` (keyed BLAKE3, not HMAC-SHA256), or no
// client's wrapped chunk hash ever matches and global dedup silently never hits.
fn wrap_chunk_hash(chunk: &ChunkHash, key: &[u8; HASH_LEN]) -> ChunkHash {
    ChunkHash(Hash32(
        *blake3::keyed_hash(key, chunk.as_bytes()).as_bytes(),
    ))
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
    // 403, not 401: xet refreshes the reconstruction (new URLs) only on 403,
    // so a 401 here fails any download that outlives the URL TTL.
    if q.x < now_unix()? {
        return Err(ApiError(StatusCode::FORBIDDEN, "signature expired".into()));
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
    let mut repo = RepoRef {
        repo_type,
        repo_id,
        revision: rev,
        owner: None,
    };

    let hub_bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| unauthorized("missing hub bearer token"))?;

    let grant = svc
        .authz
        .check_repo_access(hub_bearer, &repo, scope, AccessPurpose::TokenExchange)
        .await?;
    let user = grant.user;
    if let Some(canonical) = grant.canonical_repo_id {
        repo.repo_id = canonical;
    }
    repo.owner = grant.canonical_owner;

    let (token, exp) = svc.authz.mint_xet_token(&user, &repo, scope).await?;

    Ok(Json(XetTokenResponse {
        access_token: token,
        exp,
        cas_url: svc.public_base_url.clone(),
    }))
}

enum UsageScope<'a> {
    // Owner-wide totals span private repos, so a read-only collaborator on one
    // of them must not see it: write scope required.
    Owner(&'a str),
    Repo(&'a str),
}

// Accepts the admin bearer (constant-time compared) or a Bale JWT for the
// requested scope. The usage endpoints live outside the JWT middleware because
// the admin bearer is not a JWT.
async fn require_usage_access<B, M, A>(
    svc: &Service<B, M, A>,
    headers: &HeaderMap,
    scope: UsageScope<'_>,
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
    let allowed = match scope {
        UsageScope::Owner(owner) => claims.repo.owner() == owner && claims.scope == Scope::Write,
        UsageScope::Repo(repo_id) => claims.repo.repo_id == repo_id,
    };
    if !allowed {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "token not scoped to this owner/repo".into(),
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
    require_usage_access(&svc, &headers, UsageScope::Owner(&owner)).await?;

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
    let repo_id = format!("{owner}/{repo}");
    require_usage_access(&svc, &headers, UsageScope::Repo(&repo_id)).await?;
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
    body: Bytes,
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
    let body: SetOwnerQuotaRequest =
        serde_json::from_slice(&body).map_err(|e| bad_req(format!("quota body: {e}")))?;
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
