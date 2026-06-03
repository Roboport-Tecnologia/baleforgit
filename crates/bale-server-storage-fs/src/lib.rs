//! Filesystem-backed `BlobStore`. Fanout dirs use plain lowercase hex of the
//! hash — the Xet hex encoding is only relevant on the wire, not on disk.

use async_trait::async_trait;
use bale_server_core::{BlobStore, CoreError, CoreResult, Hash32, ShardHash, XorbHash};
use bytes::Bytes;
use std::io::SeekFrom;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

#[cfg(unix)]
async fn open_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await
}

#[cfg(not(unix))]
async fn open_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
}

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
        let parent = dst.parent();
        if let Some(parent) = parent {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| CoreError::Internal(format!("mkdir {}: {e}", parent.display())))?;
        }
        let tmp = self.tmp_path();
        // fsync tmp before rename so a crash can't leave a short blob at the content-addressed path.
        let mut f = open_private(&tmp)
            .await
            .map_err(|e| CoreError::Internal(format!("create tmp: {e}")))?;
        if let Err(e) = async {
            f.write_all(body.as_ref()).await?;
            // Test-only: simulate a write/fsync failure to exercise the tmp-cleanup
            // path below (no e2e-reachable way to force ENOSPC without breaking the
            // same-fs rename). Inert in production — the var is never set there.
            if std::env::var_os("BALE_TEST_FS_WRITE_FAIL").is_some() {
                return Err(std::io::Error::other("BALE_TEST_FS_WRITE_FAIL"));
            }
            f.sync_all().await
        }
        .await
        {
            let _ = fs::remove_file(&tmp).await;
            return Err(CoreError::Internal(format!("write tmp: {e}")));
        }
        drop(f);
        let rename_result = fs::rename(&tmp, dst).await;
        match rename_result {
            Ok(()) => {
                // fsync the parent dir so the rename is durable — else a crash can lose the entry.
                if let Some(parent) = parent {
                    if let Ok(dir) = fs::File::open(parent).await {
                        let _ = dir.sync_all().await;
                    }
                }
                Ok(true)
            }
            Err(_) if fs::metadata(dst).await.is_ok() => {
                // A racing writer beat us to it; content-addressed, so drop our tmp.
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
