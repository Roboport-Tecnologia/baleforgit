//! Core domain types and traits for the Xet CAS server.
//!
//! Everything in this crate is wire-format-agnostic and storage-agnostic.
//! Concrete implementations live in sibling crates (`xet-server-storage-fs`,
//! `xet-server-meta-sqlite`, `xet-server-authz-mem`).

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::time::Duration;
use thiserror::Error;

pub const HASH_LEN: usize = 32;

/// A 32-byte content-addressed hash. Used as the underlying representation for
/// chunk / xorb / file / shard hashes; the newtypes below carry the semantic.
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
        // Plain hex for debug; spec's reordered encoding is in `xet-server-wire`.
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

hash_newtype!(
    ChunkHash,
    "Hash of a single chunk's raw uncompressed bytes."
);
hash_newtype!(XorbHash, "Hash of a xorb, computed over its chunks.");
hash_newtype!(
    FileHash,
    "Hash of a file, computed over its reconstruction."
);
hash_newtype!(ShardHash, "Hash of a shard (for archival keying).");

/// Token scope. `Write` is a superset of `Read` (per spec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Write,
}

/// Repository type, mirroring HF Hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoType {
    Model,
    Dataset,
    Space,
}

/// Fully-qualified repo reference: type, "namespace/name", revision (branch/tag/commit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRef {
    pub repo_type: RepoType,
    pub repo_id: String,  // "namespace/name"
    pub revision: String, // default "main"
}

#[derive(Clone, Debug)]
pub struct UserId(pub String);

/// Claims attached to a verified Xet token (the bearer we accept on /v1/*).
#[derive(Clone, Debug)]
pub struct TokenClaims {
    pub user: UserId,
    pub repo: RepoRef,
    pub scope: Scope,
    /// Unix-epoch seconds when the token expires.
    pub expires_at: u64,
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

/// One chunk's metadata as captured from a shard's CAS Info section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkRow {
    pub chunk_hash: ChunkHash,
    pub chunk_index: u32,
    pub byte_start: u32, // offset inside the xorb body
    pub unpacked_segment_bytes: u32,
}

/// Metadata for one xorb (one CASChunkSequenceHeader).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XorbInfo {
    pub xorb: XorbHash,
    pub num_chunks: u32,
    pub num_bytes_in_cas: u32,
    pub num_bytes_on_disk: u32,
}

/// Where to find a chunk that already exists in the system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkLocation {
    pub xorb: XorbHash,
    pub chunk_index: u32,
    pub byte_start: u32,
    pub unpacked_segment_bytes: u32,
}

/// Per-chunk byte offsets inside one xorb. Used to enumerate a xorb's chunks
/// (with their hashes) when building global-dedup responses. `byte_start` and
/// `unpacked_segment_bytes` come from the shard's CAS Info and live in
/// *uncompressed* coordinate space — they are NOT on-disk byte offsets and
/// must NOT be used to build HTTP byte ranges. Use [`XorbFrameRow`] for that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkOffsetRow {
    pub chunk_hash: ChunkHash,
    pub chunk_index: u32,
    pub byte_start: u32,
    pub unpacked_segment_bytes: u32,
}

/// One chunk frame's actual on-disk layout inside a xorb body. Recorded at
/// xorb-upload time by walking the chunk frames (`xet_server_shard::xorb`).
/// `on_disk_start` is the byte offset of the frame's 8-byte header within the
/// xorb body; `on_disk_len` covers the header plus the compressed payload.
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

/// Storage of raw blobs: xorbs and shards.
///
/// Xorbs are immutable, content-addressed by their hash, and capped at 64 MiB.
/// Shards are likewise content-addressed; we keep them for archival / re-indexing.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Returns `true` if the xorb was newly inserted; `false` if it already existed.
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool>;
    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool>;
    /// `byte_range` is half-open `[start, end)`.
    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes>;
    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()>;
    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes>;
    /// If the backend can issue an offloaded download URL (e.g. S3 presign), return it;
    /// otherwise return `None` and the caller will serve bytes itself.
    async fn presign_xorb_range(
        &self,
        _hash: &XorbHash,
        _byte_range: Range<u64>,
        _ttl: Duration,
    ) -> CoreResult<Option<String>> {
        Ok(None)
    }
}

/// Metadata index. The single source of truth for "where does chunk X live"
/// and "how do I reconstruct file Y".
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

    /// Record the on-disk frame layout of a xorb. Called after a successful
    /// `BlobStore::put_xorb` and required for [`Self::xorb_frame_layout`] to
    /// return anything.
    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()>;
    /// Return the xorb's on-disk frame layout, ordered by `frame_index`. Empty
    /// if no layout was registered (e.g. legacy data or a test fixture that
    /// only populated chunk-level metadata).
    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>>;

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool>;
    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>>;
    /// Authorization helper for the reconstruction handler: returns `true`
    /// iff `file_hash` has been registered in `repo_id` (via a prior
    /// `register_file` call from a write-scoped session for that repo).
    /// Cross-repo dedup is supported — the same `file_hash` can be
    /// registered in multiple repos, and each registration independently
    /// grants read access.
    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool>;
    /// Resolve a file by its LFS-style sha256 OID. Returns the Xet `FileHash`
    /// the OID was registered under, or `None` if no shard has uploaded a file
    /// carrying that sha256 yet. The sha256 is the standard 32-byte hash —
    /// not the Xet merkle file hash.
    async fn lookup_file_by_sha256(&self, sha256: &Hash32) -> CoreResult<Option<FileHash>>;
    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>>;
    async fn xorbs_near_chunk(
        &self,
        chunk_hash: &ChunkHash,
        limit: usize,
    ) -> CoreResult<Vec<XorbInfo>>;
    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>>;
}

/// Authorization layer. Pluggable so we can later proxy to GitLab/Gitea instead
/// of keeping our own user/repo permissions.
#[async_trait]
pub trait RepoAuthz: Send + Sync {
    /// Verify a Xet bearer token. Returns the claims granted by the token.
    async fn verify_xet_token(&self, bearer: &str) -> CoreResult<TokenClaims>;

    /// Used by the mock-HF token endpoint to decide whether to issue a token.
    /// `hub_bearer` is the upstream credential the client sent.
    async fn check_repo_access(
        &self,
        hub_bearer: &str,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<UserId>;

    /// Mint a Xet token for `user` scoped to `repo` with `scope`. Returns the
    /// token and its absolute expiry (unix seconds). Different `RepoAuthz`
    /// impls can use different signing schemes; the verifier `verify_xet_token`
    /// must accept tokens produced by this impl.
    async fn mint_xet_token(
        &self,
        user: &UserId,
        repo: &RepoRef,
        scope: Scope,
    ) -> CoreResult<(String, u64)>;
}
