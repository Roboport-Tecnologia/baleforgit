//! Core domain types and traits for the Bale CAS server. Wire-format- and
//! storage-agnostic; concrete impls live in sibling crates.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::time::Duration;
use thiserror::Error;

pub const HASH_LEN: usize = 32;

/// 32-byte content-addressed hash; the newtypes below add the semantic.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; HASH_LEN]);

impl Hash32 {
    pub const ZERO: Hash32 = Hash32([0u8; HASH_LEN]);
    pub const ALL_ONES: Hash32 = Hash32([0xFFu8; HASH_LEN]);

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
    pub fn from_bytes(b: [u8; HASH_LEN]) -> Self {
        Self(b)
    }
}

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Plain hex; the spec's reordered encoding lives in `bale-server-wire`.
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

macro_rules! hash_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
        pub struct $name(pub Hash32);

        impl $name {
            pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
                self.0.as_bytes()
            }
            pub fn from_bytes(b: [u8; HASH_LEN]) -> Self {
                Self(Hash32::from_bytes(b))
            }
        }
    };
}

hash_newtype!(ChunkHash, "Hash of a chunk's raw uncompressed bytes.");
hash_newtype!(XorbHash, "Hash of a xorb, computed over its chunks.");
hash_newtype!(
    FileHash,
    "Hash of a file, computed over its reconstruction."
);
hash_newtype!(ShardHash, "Hash of a shard.");

/// `Write` is a superset of `Read` (per spec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Write,
}

/// Mirrors HF Hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoType {
    Model,
    Dataset,
    Space,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRef {
    pub repo_type: RepoType,
    pub repo_id: String,  // "namespace/name"
    pub revision: String, // default "main"
    /// Accounting owner reported by the authority, when its scope key isn't
    /// owner-prefixed (a forge keying scope on a transfer-stable repo id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

impl RepoRef {
    /// The unit of storage accounting and quotas: the authority's explicit
    /// owner, else the namespace before `/` (whole `repo_id` if there's none).
    pub fn owner(&self) -> &str {
        if let Some(owner) = &self.owner {
            return owner;
        }
        match self.repo_id.split_once('/') {
            Some((owner, _)) => owner,
            None => &self.repo_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UserId(pub String);

/// Claims attached to a verified Bale token (the bearer we accept on /v1/*).
#[derive(Clone, Debug)]
pub struct TokenClaims {
    pub user: UserId,
    pub repo: RepoRef,
    pub scope: Scope,
    pub expires_at: u64, // unix seconds
}

/// One term of a file reconstruction: a chunk-index range inside a xorb.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTerm {
    pub xorb: XorbHash,
    pub chunk_idx_start: u32,
    pub chunk_idx_end: u32, // exclusive
    pub unpacked_segment_bytes: u32,
    pub verification: Option<Hash32>, // FileVerificationEntry.range_hash
}

/// One chunk's metadata, as captured from a shard's CAS Info section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkRow {
    pub chunk_hash: ChunkHash,
    pub chunk_index: u32,
    pub byte_start: u32, // offset inside the xorb body
    pub unpacked_segment_bytes: u32,
}

/// One xorb's metadata (one CASChunkSequenceHeader).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XorbInfo {
    pub xorb: XorbHash,
    pub num_chunks: u32,
    pub num_bytes_in_cas: u32,
    pub num_bytes_on_disk: u32,
}

/// `byte_start` / `unpacked_segment_bytes` are *uncompressed* coordinates —
/// NOT on-disk offsets; never build HTTP byte ranges from them. Use [`XorbFrameRow`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkOffsetRow {
    pub chunk_hash: ChunkHash,
    pub chunk_index: u32,
    pub byte_start: u32,
    pub unpacked_segment_bytes: u32,
}

/// `on_disk_start` points at the frame's 8-byte header; `on_disk_len` covers
/// header + compressed payload. One frame is one chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorbFrameRow {
    pub frame_index: u32,
    pub on_disk_start: u32,
    pub on_disk_len: u32,
    pub uncompressed_len: u32,
    /// Server-computed from the verified xorb body.
    pub chunk_hash: ChunkHash,
}

/// A file whose terms the server has verified against its `file_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRegistration {
    pub file_hash: FileHash,
    pub terms: Vec<FileTerm>,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("internal: {0}")]
    Internal(String),
    #[error("storage quota exceeded for owner '{owner}': {used} bytes would exceed the {quota}-byte limit")]
    QuotaExceeded {
        owner: String,
        used: u64,
        quota: u64,
    },
}

pub type CoreResult<T> = Result<T, CoreError>;

/// Raw-blob storage for xorbs (immutable, content-addressed, ≤64 MiB) and
/// shards (also content-addressed; kept for archival / re-indexing).
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// `true` if newly inserted, `false` if it already existed. Must never
    /// replace an existing blob: equal-hash bodies can differ in compression, and
    /// the recorded frame layout is derived from whichever body was kept.
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool>;
    /// Atomically overwrite a stored blob that failed re-verification with a
    /// verified body (heals bit rot / tampering).
    async fn replace_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<()>;
    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool>;
    /// `byte_range` is half-open `[start, end)`.
    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes>;
    async fn get_xorb(&self, hash: &XorbHash) -> CoreResult<Bytes> {
        self.get_xorb_range(hash, 0..u64::MAX).await
    }
    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()>;
    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes>;
    /// Return an offloaded download URL (e.g. S3 presign) if the backend
    /// supports it; otherwise `None` and the caller serves bytes itself.
    async fn presign_xorb_range(
        &self,
        _hash: &XorbHash,
        _byte_range: Range<u64>,
        _ttl: Duration,
    ) -> CoreResult<Option<String>> {
        Ok(None)
    }
}

/// Single source of truth for "where does chunk X live" and "how do I
/// reconstruct file Y".
#[async_trait]
pub trait MetadataStore: Send + Sync {
    async fn register_xorb(&self, xorb: &XorbInfo, chunks: &[ChunkRow]) -> CoreResult<()>;

    /// Register many files in one transaction so a partial fault can't leak an
    /// orphan file row the client thinks didn't upload. With `quota`, the
    /// owner's usage is rechecked inside the transaction (serialized per owner)
    /// and the whole batch fails with `QuotaExceeded` if it pushed usage over —
    /// concurrent shards can't each pass a separate pre-check and overshoot.
    async fn register_files(
        &self,
        repo: &RepoRef,
        files: &[FileRegistration],
        quota: Option<u64>,
    ) -> CoreResult<()>;

    /// Charge a new xorb to the uploading owner (until some file references
    /// it) BEFORE its blob is written, atomically with the quota check and
    /// serialized per owner, so concurrent uploads can't jointly overshoot.
    /// `false` if the xorb was already charged to someone.
    async fn reserve_xorb_upload(
        &self,
        xorb: &XorbHash,
        owner: &str,
        bytes: u64,
        quota: Option<u64>,
    ) -> CoreResult<bool>;
    /// Replace a reservation's upper-bound size with the stored body's.
    async fn settle_xorb_upload(
        &self,
        xorb: &XorbHash,
        owner: &str,
        bytes_on_disk: u64,
    ) -> CoreResult<()>;
    /// Drop a reservation whose blob write failed.
    async fn release_xorb_upload(&self, xorb: &XorbHash, owner: &str) -> CoreResult<()>;

    /// Upsert: rows for the same `(xorb, frame_index)` are overwritten, so the
    /// layout can be re-derived from whichever encoding the blob store kept.
    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()>;
    /// Ordered by `frame_index`; empty if no layout was registered.
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;
    /// Frames `[start, end)` of each `(xorb, start, end)` span, in span order and
    /// `frame_index` order — what shard verification needs, without loading
    /// whole 8192-frame layouts per referenced xorb. A span with missing frames
    /// comes back short.
    async fn xorb_frame_spans(
        &self,
        spans: &[(XorbHash, u32, u32)],
    ) -> CoreResult<Vec<Vec<XorbFrameRow>>>;
    /// Default impl loops over `xorb_frame_layout`; SQL stores should batch.
    /// Returned map omits xorbs with no recorded layout.
    async fn xorb_frame_layouts(
        &self,
        xorbs: &[XorbHash],
    ) -> CoreResult<std::collections::HashMap<XorbHash, Vec<XorbFrameRow>>> {
        let mut out = std::collections::HashMap::new();
        for x in xorbs {
            let rows = self.xorb_frame_layout(x).await?;
            if !rows.is_empty() {
                out.insert(*x, rows);
            }
        }
        Ok(out)
    }

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    /// The subset of `xorbs` that have no `xorbs` row (batched).
    async fn missing_xorb_rows(&self, xorbs: &[XorbHash]) -> CoreResult<Vec<XorbHash>>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    /// Reconstruction-scope check: `true` iff `file_hash` is registered in
    /// `repo_id`. The same hash can be registered in many repos (cross-repo
    /// dedup); each registration independently grants read.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    async fn xorbs_near_chunk(
        &self,
        chunk_hash: &ChunkHash,
        limit: usize,
    ) -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;

    /// Uncompressed bytes the owner's files would occupy without dedup. For the
    /// dedup-savings display, never for quota enforcement.
    async fn raw_bytes_for_owner(&self, owner: &str) -> CoreResult<u64>;

    /// On-disk bytes of the distinct xorbs the owner's files reference, plus the
    /// owner's uploaded xorbs no file references. Accounted per owner — a xorb
    /// shared by two owners counts once each (no cross-owner dedup accounting).
    async fn stored_bytes_for_owner(&self, owner: &str) -> CoreResult<u64>;

    async fn get_owner_quota(&self, owner: &str) -> CoreResult<Option<u64>>;
    /// `None` clears the override and falls back to the server default.
    async fn set_owner_quota(&self, owner: &str, limit_bytes: Option<u64>) -> CoreResult<()>;

    /// `num_bytes_on_disk` of the `candidates` the owner does NOT already
    /// reference — lets the upload quota check project the post-commit total
    /// without committing. Unknown xorbs contribute 0.
    async fn unaccounted_xorb_bytes_for_owner(
        &self,
        owner: &str,
        candidates: &[XorbHash],
    ) -> CoreResult<u64>;

    /// [`Self::raw_bytes_for_owner`] keyed by full `repo_id` (e.g. `"alice/big-model"`).
    async fn raw_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    /// On-disk bytes of the distinct xorbs this repo's files reference; unlike
    /// [`Self::stored_bytes_for_owner`], unreferenced uploads aren't counted.
    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    /// On-disk bytes of the xorbs this repo references that no *sibling* repo
    /// (same owner) references — how much the owner's stored bytes would drop if
    /// this repo were deleted. Cross-owner sharing is ignored, matching the
    /// owner-independent accounting in [`Self::stored_bytes_for_owner`]. Always
    /// `<= stored_bytes_for_repo`; the gap is storage shared with sibling repos.
    async fn exclusive_stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
}

/// Why the upstream credential is being checked, so the authority can refuse a
/// download-scoped credential for token exchange and bind it to one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessPurpose<'a> {
    TokenExchange,
    FileDownload { file_id: &'a str },
}

#[derive(Clone, Debug)]
pub struct AccessGrant {
    pub user: UserId,
    /// The authority's canonical `owner/name` for the repo, when it reports
    /// one. Scope and accounting key on this instead of the client-typed name,
    /// which a case-insensitive forge resolves the same for many spellings.
    pub canonical_repo_id: Option<String>,
    /// The authority's accounting owner for the repo, when it reports one.
    pub canonical_owner: Option<String>,
}

/// Authorization layer. Pluggable so it can proxy to an external repo
/// authority (git forge, identity provider) instead of holding its own
/// user/repo permissions.
#[async_trait]
pub trait RepoAuthz: Send + Sync {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims>;

    /// `hub_bearer` is the upstream credential the client sent.
    async fn check_repo_access(
        &self,
        hub_bearer: &str,
        repo: &RepoRef,
        scope: Scope,
        purpose: AccessPurpose<'_>,
    ) -> CoreResult<AccessGrant>;

    /// Returns `(token, absolute_expiry_unix_seconds)`; tokens minted here must
    /// verify via this impl's [`Self::verify_xet_token`].
    async fn mint_xet_token(
        &self,
        user: &UserId,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<(String, u64)>;
}
