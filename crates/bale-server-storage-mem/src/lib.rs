//! In-memory `BlobStore` for tests and the trait seam.

use async_trait::async_trait;
use bale_server_core::{BlobStore, CoreError, CoreResult, ShardHash, XorbHash};
use bytes::Bytes;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

#[derive(Default)]
pub struct MemBlobStore {
    xorbs: RwLock<HashMap<[u8; 32], Bytes>>,
    shards: RwLock<HashMap<[u8; 32], Bytes>>,
    // Counted outside the maps so a put can be rejected before taking the write lock.
    stored_bytes: AtomicU64,
    // None = unbounded.
    max_bytes: Option<u64>,
}

impl MemBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts past this cumulative byte cap return `CoreError::BadRequest`.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    fn reserve(&self, n: u64) -> CoreResult<()> {
        let Some(max) = self.max_bytes else {
            return Ok(());
        };
        // CAS loop: two concurrent puts must not both observe headroom before either commits.
        loop {
            let cur = self.stored_bytes.load(Ordering::Acquire);
            let next = cur
                .checked_add(n)
                .ok_or_else(|| CoreError::BadRequest("mem store byte counter overflow".into()))?;
            if next > max {
                return Err(CoreError::BadRequest("mem store capacity exhausted".into()));
            }
            if self
                .stored_bytes
                .compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

#[async_trait]
impl BlobStore for MemBlobStore {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool> {
        let mut g = self.xorbs.write().await;
        // Idempotent: re-put of an existing hash is a no-op, not an overwrite.
        if g.contains_key(hash.as_bytes()) {
            return Ok(false);
        }
        self.reserve(body.len() as u64)?;
        g.insert(*hash.as_bytes(), body);
        Ok(true)
    }

    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool> {
        Ok(self.xorbs.read().await.contains_key(hash.as_bytes()))
    }

    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes> {
        if byte_range.end < byte_range.start {
            return Err(CoreError::BadRequest("inverted byte range".into()));
        }
        let g = self.xorbs.read().await;
        let body = g.get(hash.as_bytes()).ok_or(CoreError::NotFound)?;
        let len = body.len() as u64;
        if byte_range.start > len {
            return Err(CoreError::BadRequest("range start past end".into()));
        }
        let end = byte_range.end.min(len);
        Ok(body.slice(byte_range.start as usize..end as usize))
    }

    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()> {
        let mut g = self.shards.write().await;
        if !g.contains_key(hash.as_bytes()) {
            self.reserve(body.len() as u64)?;
        }
        g.insert(*hash.as_bytes(), body);
        Ok(())
    }

    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes> {
        self.shards
            .read()
            .await
            .get(hash.as_bytes())
            .cloned()
            .ok_or(CoreError::NotFound)
    }
}
