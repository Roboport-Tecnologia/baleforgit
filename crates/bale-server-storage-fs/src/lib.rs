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
        // A crash mid-write leaves its tmp file behind; nothing else would ever
        // reclaim it. Age-gated so a concurrently starting instance's in-flight
        // writes are spared.
        if let Ok(mut entries) = fs::read_dir(root.join("tmp")).await {
            while let Ok(Some(e)) = entries.next_entry().await {
                let stale = e
                    .metadata()
                    .await
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(3600));
                if stale {
                    let _ = fs::remove_file(e.path()).await;
                }
            }
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

    async fn write_atomic(&self, dst: &Path, body: &Bytes, mode: WriteMode) -> CoreResult<bool> {
        let parent = dst
            .parent()
            .ok_or_else(|| CoreError::Internal(format!("no parent for {}", dst.display())))?;
        if mode == WriteMode::NoReplace && fs::metadata(dst).await.is_ok() {
            // The entry (and its fanout dirs) may be a racing writer's, not yet
            // durable; make it so before the caller registers metadata on it.
            self.sync_chain(parent).await?;
            return Ok(false);
        }
        fs::create_dir_all(parent)
            .await
            .map_err(|e| CoreError::Internal(format!("mkdir {}: {e}", parent.display())))?;
        let tmp = self.tmp_path();
        // fsync tmp before linking so a crash can't leave a short blob at the content-addressed path.
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
        let inserted = match mode {
            // link(2) fails with EEXIST instead of replacing, so exactly one
            // concurrent writer's bytes are ever visible at `dst`.
            WriteMode::NoReplace => match fs::hard_link(&tmp, dst).await {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(e) => {
                    let _ = fs::remove_file(&tmp).await;
                    return Err(CoreError::Internal(format!(
                        "link to {}: {e}",
                        dst.display()
                    )));
                }
            },
            WriteMode::Replace => {
                if let Err(e) = fs::rename(&tmp, dst).await {
                    let _ = fs::remove_file(&tmp).await;
                    return Err(CoreError::Internal(format!(
                        "rename to {}: {e}",
                        dst.display()
                    )));
                }
                true
            }
        };
        if mode == WriteMode::NoReplace {
            let _ = fs::remove_file(&tmp).await;
        }
        self.sync_chain(parent).await?;
        Ok(inserted)
    }

    // fsync `dir` and every ancestor up to the root. Unconditional: whichever
    // writer created a fanout dir may not have synced it yet, and a crash could
    // then drop the whole subtree while metadata already points into it.
    async fn sync_chain(&self, dir: &Path) -> CoreResult<()> {
        let mut cur = dir;
        loop {
            sync_dir(cur).await?;
            if cur == self.root {
                return Ok(());
            }
            match cur.parent() {
                Some(up) => cur = up,
                None => return Ok(()),
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    NoReplace,
    Replace,
}

#[cfg(unix)]
async fn sync_dir(dir: &Path) -> CoreResult<()> {
    let d = fs::File::open(dir)
        .await
        .map_err(|e| CoreError::Internal(format!("open dir {}: {e}", dir.display())))?;
    d.sync_all()
        .await
        .map_err(|e| CoreError::Internal(format!("fsync dir {}: {e}", dir.display())))
}

// Windows can't open a directory handle via std; NTFS journals metadata.
#[cfg(not(unix))]
async fn sync_dir(_dir: &Path) -> CoreResult<()> {
    Ok(())
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool> {
        self.write_atomic(&self.xorb_path(hash), &body, WriteMode::NoReplace)
            .await
    }

    async fn replace_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<()> {
        self.write_atomic(&self.xorb_path(hash), &body, WriteMode::Replace)
            .await?;
        Ok(())
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
        self.write_atomic(&self.shard_path(hash), &body, WriteMode::NoReplace)
            .await?;
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
