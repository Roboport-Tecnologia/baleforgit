//! Core domain types and traits for the Bale CAS server. Wire-format- and
//! storage-agnostic; concrete impls live in sibling crates.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::time::Duration;
use thiserror::Error;

pub const HASH_LEN: usize = 32;

/// 32-byte content-addressed hash. The newtypes below carry the semantic.
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

// ---- Indexer / metadata domain types --------------------------------------

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkLocation {
    pub xorb: XorbHash,
    pub chunk_index: u32,
    pub byte_start: u32,
    pub unpacked_segment_bytes: u32,
}

/// Per-chunk byte offsets inside one xorb, used to build global-dedup
/// responses. `byte_start` / `unpacked_segment_bytes` live in *uncompressed*
/// coordinate space — they are NOT on-disk offsets and must NOT be used to
/// build HTTP byte ranges. Use [`XorbFrameRow`] for that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkOffsetRow {
    pub chunk_hash: ChunkHash,
    pub chunk_index: u32,
    pub byte_start: u32,
    pub unpacked_segment_bytes: u32,
}

/// One chunk frame's on-disk layout inside a xorb body, recorded at upload
/// time. `on_disk_start` points at the frame's 8-byte header; `on_disk_len`
/// covers header + compressed payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorbFrameRow {
    pub frame_index: u32,
    pub on_disk_start: u32,
    pub on_disk_len: u32,
    pub uncompressed_len: u32,
}

// ---- Errors ---------------------------------------------------------------

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

// ---- Pluggable traits ------------------------------------------------------

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
        sha256: Option<&Hash32>,
        terms: &[FileTerm],
    ) -> CoreResult<()>;

    /// Record a xorb's on-disk frame layout. Required for
    /// [`Self::xorb_frame_layout`] to return anything.
    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()>;
    /// Frame layout ordered by `frame_index`. Empty if no layout was registered
    /// (e.g. test fixture that only populated chunk-level metadata).
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    /// Reconstruction-scope check: `true` iff `file_hash` has been registered
    /// in `repo_id`. Same `file_hash` may be registered in multiple repos
    /// (cross-repo dedup) and each registration independently grants read.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    /// Resolve a file by its LFS-style sha256 OID (the standard 32-byte hash,
    /// not the Xet merkle file hash). `None` if no shard carrying that sha256
    /// has been uploaded yet.
    async fn lookup_file_by_sha256(&self, sha256: &Hash32) -> CoreResult<Option<FileHash>>;
    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>>;
    async fn xorbs_near_chunk(
        &self,
        chunk_hash: &ChunkHash,
        limit: usize,
    ) -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;
}

/// Authorization layer. Pluggable so it can proxy to an external repo
/// authority (git forge, identity provider) instead of holding its own
/// user/repo permissions.
#[async_trait]
pub trait RepoAuthz: Send + Sync {
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims>;

    /// Used by the mock-HF token endpoint to decide whether to issue a token.
    /// `hub_bearer` is the upstream credential the client sent.
    async fn check_repo_access(
        &self,
        hub_bearer: &str,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<UserId>;

    /// Returns `(token, absolute_expiry_unix_seconds)`. Tokens minted here
    /// must be accepted by this impl's [`Self::verify_xet_token`].
    async fn mint_xet_token(
        &self,
        user: &UserId,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<(String, u64)>;
}
