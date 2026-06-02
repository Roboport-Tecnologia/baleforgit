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
}

impl RepoRef {
    /// Namespace before `/` — the unit of storage accounting and quotas.
    /// Falls back to the whole `repo_id` defensively; forge tokens always have one.
    pub fn owner(&self) -> &str {
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
/// header + compressed payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorbFrameRow {
    pub frame_index: u32,
    pub on_disk_start: u32,
    pub on_disk_len: u32,
    pub uncompressed_len: u32,
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
}

pub type CoreResult<T> = Result<T, CoreError>;

/// Raw-blob storage for xorbs (immutable, content-addressed, ≤64 MiB) and
/// shards (also content-addressed; kept for archival / re-indexing).
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// `true` if newly inserted, `false` if it already existed.
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool>;
    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool>;
    /// `byte_range` is half-open `[start, end)`.
    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes>;
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
    async fn register_file(
        &self,
        file_hash: &FileHash,
        repo: &RepoRef,
        terms: &[FileTerm],
    ) -> CoreResult<()>;

    /// Register many files atomically so a partial fault can't leak an orphan
    /// file row the client thinks didn't upload. Default impl is a non-atomic
    /// loop (fine for in-memory stores); SQL stores must override with one txn.
    async fn register_files(
        &self,
        repo: &RepoRef,
        files: &[(FileHash, Vec<FileTerm>)],
    ) -> CoreResult<()> {
        for (file_hash, terms) in files {
            self.register_file(file_hash, repo, terms).await?;
        }
        Ok(())
    }

    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()>;
    /// Ordered by `frame_index`; empty if no layout was registered.
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;
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

    /// On-disk bytes of the distinct xorbs the owner's files reference. Accounted
    /// per owner — a xorb shared by two owners counts once each (no cross-owner
    /// dedup accounting).
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
    /// [`Self::stored_bytes_for_owner`] per-repo. Cross-repo dedup within an
    /// owner can make this smaller than `raw_bytes_for_repo`.
    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
    /// On-disk bytes of the xorbs this repo references that no *sibling* repo
    /// (same owner) references — how much the owner's stored bytes would drop if
    /// this repo were deleted. Cross-owner sharing is ignored, matching the
    /// owner-independent accounting in [`Self::stored_bytes_for_owner`]. Always
    /// `<= stored_bytes_for_repo`; the gap is storage shared with sibling repos.
    async fn exclusive_stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64>;
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
    ) -> CoreResult<UserId>;

    /// Returns `(token, absolute_expiry_unix_seconds)`; tokens minted here must
    /// verify via this impl's [`Self::verify_xet_token`].
    async fn mint_xet_token(
        &self,
        user: &UserId,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<(String, u64)>;
}
