//! Filesystem-backed `BlobStore` implementation.
//!
//! Layout under `data_root`:
//! ```text
//! xorbs/<aa>/<bb>/<full-hex>     # immutable xorb blobs
//! shards/<aa>/<bb>/<full-hex>    # immutable shards
//! tmp/<uuid>                     # staging for atomic rename
//! ```
//! `<aa>`/`<bb>` are bytes 0/1 of the hash in lowercase hex. Plain hex is used
//! here — the Xet hex encoding is only relevant on the wire.

use async_trait::async_trait;
use bytes::Bytes;
use std::io::SeekFrom;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;
use xet_server_core::{
    BlobStore, CoreError, CoreResult, Hash32, ShardHash, XorbHash,
};

pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub async fn open(root: impl Into<PathBuf>) -> CoreResult<Self> {
        let root = root.into();
        for sub in ["xorbs", "shards", "tmp"] {
            fs::create_dir_all(root.join(sub))
                .await
                .map_err(|e| CoreError::Internal(format!("mkdir {sub}: {e}")))?;
        }
        Ok(Self { root })
    }

    fn fanout(kind: &str, hash: &Hash32) -> PathBuf {
        let hex = hex::encode(hash.as_bytes());
        let aa = &hex[0..2];
        let bb = &hex[2..4];
        Path::new(kind).join(aa).join(bb).join(&hex)
    }

    fn xorb_path(&self, hash: &XorbHash) -> PathBuf {
        self.root.join(Self::fanout("xorbs", &hash.0))
    }

    fn shard_path(&self, hash: &ShardHash) -> PathBuf {
        self.root.join(Self::fanout("shards", &hash.0))
    }

    fn tmp_path(&self) -> PathBuf {
        self.root.join("tmp").join(Uuid::new_v4().to_string())
    }

    async fn write_atomic(&self, dst: &Path, body: &Bytes) -> CoreResult<bool> {
        if fs::metadata(dst).await.is_ok() {
            return Ok(false);
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| CoreError::Internal(format!("mkdir {}: {e}", parent.display())))?;
        }
        let tmp = self.tmp_path();
        fs::write(&tmp, body.as_ref())
            .await
            .map_err(|e| CoreError::Internal(format!("write tmp: {e}")))?;
        match fs::rename(&tmp, dst).await {
            Ok(()) => Ok(true),
            Err(_) if fs::metadata(dst).await.is_ok() => {
                // A racing writer beat us to it; tmp is garbage, drop it.
                let _ = fs::remove_file(&tmp).await;
                Ok(false)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp).await;
                Err(CoreError::Internal(format!(
                    "rename to {}: {e}",
                    dst.display()
                )))
            }
        }
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool> {
        self.write_atomic(&self.xorb_path(hash), &body).await
    }

    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool> {
        Ok(fs::metadata(self.xorb_path(hash)).await.is_ok())
    }

    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes> {
        if byte_range.end < byte_range.start {
            return Err(CoreError::BadRequest("inverted byte range".into()));
        }
        let path = self.xorb_path(hash);
        let mut f = fs::File::open(&path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CoreError::NotFound,
            _ => CoreError::Internal(format!("open xorb: {e}")),
        })?;
        let len = f
            .metadata()
            .await
            .map_err(|e| CoreError::Internal(format!("stat xorb: {e}")))?
            .len();
        if byte_range.start > len {
            return Err(CoreError::BadRequest("range start past end".into()));
        }
        let end = byte_range.end.min(len);
        let want = (end - byte_range.start) as usize;
        f.seek(SeekFrom::Start(byte_range.start))
            .await
            .map_err(|e| CoreError::Internal(format!("seek xorb: {e}")))?;
        let mut buf = vec![0u8; want];
        f.read_exact(&mut buf)
            .await
            .map_err(|e| CoreError::Internal(format!("read xorb: {e}")))?;
        Ok(Bytes::from(buf))
    }

    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()> {
        self.write_atomic(&self.shard_path(hash), &body).await?;
        Ok(())
    }

    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes> {
        let path = self.shard_path(hash);
        let buf = fs::read(&path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CoreError::NotFound,
            _ => CoreError::Internal(format!("read shard: {e}")),
        })?;
        Ok(Bytes::from(buf))
    }

    async fn presign_xorb_range(
        &self,
        _hash: &XorbHash,
        _byte_range: Range<u64>,
        _ttl: Duration,
    ) -> CoreResult<Option<String>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let tmp = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(tmp.path()).await.unwrap();
        let hash = h(0x42);
        let body = Bytes::from_static(b"hello xorb");
        assert!(store.put_xorb(&hash, body.clone()).await.unwrap());
        assert!(store.xorb_exists(&hash).await.unwrap());
        // Second put is a no-op.
        assert!(!store.put_xorb(&hash, body).await.unwrap());
    }

    #[tokio::test]
    async fn missing_xorb_get_range_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(tmp.path()).await.unwrap();
        let err = store.get_xorb_range(&h(0x01), 0..10).await.unwrap_err();
        matches!(err, CoreError::NotFound);
    }

    #[tokio::test]
    async fn range_read_returns_slice() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(tmp.path()).await.unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(tmp.path()).await.unwrap();
        let hash = h(0x33);
        let body = Bytes::from_static(b"short");
        store.put_xorb(&hash, body).await.unwrap();
        let slice = store.get_xorb_range(&hash, 0..1_000).await.unwrap();
        assert_eq!(&*slice, b"short");
    }

    #[tokio::test]
    async fn shard_put_and_get() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(tmp.path()).await.unwrap();
        let hash = sh(0x99);
        let body = Bytes::from_static(b"shard-bytes");
        store.put_shard(&hash, body.clone()).await.unwrap();
        let got = store.get_shard(&hash).await.unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn presign_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsBlobStore::open(tmp.path()).await.unwrap();
        let r = store
            .presign_xorb_range(&h(0x00), 0..1, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(r.is_none());
    }
}
