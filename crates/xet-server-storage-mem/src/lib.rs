//! In-memory `BlobStore`. Exists to validate the trait seam: the full HTTP
//! stack should run against this with zero handler changes.
//!
//! Not intended for production use — no eviction, no persistence.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::ops::Range;
use tokio::sync::RwLock;
use xet_server_core::{BlobStore, CoreError, CoreResult, ShardHash, XorbHash};

#[derive(Default)]
pub struct MemBlobStore {
    xorbs: RwLock<HashMap<[u8; 32], Bytes>>,
    shards: RwLock<HashMap<[u8; 32], Bytes>>,
}

impl MemBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlobStore for MemBlobStore {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool> {
        let mut g = self.xorbs.write().await;
        // Content-addressed: a second put with the same hash is a no-op.
        if g.contains_key(hash.as_bytes()) {
            return Ok(false);
        }
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
        self.shards.write().await.insert(*hash.as_bytes(), body);
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

#[cfg(test)]
mod tests {
    use super::*;
    use xet_server_core::Hash32;

    fn h(seed: u8) -> XorbHash {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_add(i as u8);
        }
        XorbHash(Hash32(b))
    }

    fn sh(seed: u8) -> ShardHash {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_add(i as u8);
        }
        ShardHash(Hash32(b))
    }

    #[tokio::test]
    async fn put_then_exists_then_idempotent() {
        let store = MemBlobStore::new();
        let hash = h(0x42);
        let body = Bytes::from_static(b"hello xorb");
        assert!(store.put_xorb(&hash, body.clone()).await.unwrap());
        assert!(store.xorb_exists(&hash).await.unwrap());
        assert!(!store.put_xorb(&hash, body).await.unwrap());
    }

    #[tokio::test]
    async fn missing_xorb_get_range_returns_not_found() {
        let store = MemBlobStore::new();
        let err = store.get_xorb_range(&h(0x01), 0..10).await.unwrap_err();
        matches!(err, CoreError::NotFound);
    }

    #[tokio::test]
    async fn range_read_returns_slice() {
        let store = MemBlobStore::new();
        let hash = h(0x77);
        let body: Vec<u8> = (0u8..=255).collect();
        store
            .put_xorb(&hash, Bytes::copy_from_slice(&body))
            .await
            .unwrap();
        let slice = store.get_xorb_range(&hash, 100..150).await.unwrap();
        assert_eq!(slice.len(), 50);
        assert_eq!(slice[0], 100);
        assert_eq!(slice[49], 149);
    }

    #[tokio::test]
    async fn range_clamped_to_file_length() {
        let store = MemBlobStore::new();
        let hash = h(0x33);
        store
            .put_xorb(&hash, Bytes::from_static(b"short"))
            .await
            .unwrap();
        let slice = store.get_xorb_range(&hash, 0..1_000).await.unwrap();
        assert_eq!(&*slice, b"short");
    }

    #[tokio::test]
    async fn shard_put_and_get() {
        let store = MemBlobStore::new();
        let hash = sh(0x99);
        let body = Bytes::from_static(b"shard-bytes");
        store.put_shard(&hash, body.clone()).await.unwrap();
        assert_eq!(store.get_shard(&hash).await.unwrap(), body);
    }
}
