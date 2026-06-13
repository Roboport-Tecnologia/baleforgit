//! Byte-source for virtual files. Plain git blobs come from the ODB (cached
//! whole, capped at 16 MiB — bigger should've been Bale-tracked). Bale pointers
//! reconstruct from the chunk cache (fast) with a `FileDownloadSession` fallback
//! that repopulates it (cold), and are held in a byte-budgeted LRU (default 1 GiB).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use xet_client::cas_client::auth::TokenRefresher;
use xet_client::chunk_cache::{get_cache, CacheConfig, ChunkCache};
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::default_config;
use xet_data::processing::FileDownloadSession;
use xet_runtime::core::XetRuntime;

use crate::config::{BaleConfig, RawConfig};
use crate::local_reconstruct::{try_reconstruct_from_cache, CacheReconstructOutcome};
use crate::manifest_cache;
use crate::pointer;
use crate::remote_manifest::fetch_manifest;
use crate::resolver;

const PLAIN_BLOB_MAX_BYTES: usize = 16 * 1024 * 1024;
const BALE_LRU_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct BlobSource {
    /// Hex OID, 40 (SHA-1) or 64 (SHA-256) chars, validated by gix.
    pub oid: String,
}

/// `Bytes` (Arc-backed) so reads clone without re-allocating.
struct CachedBlob {
    data: Bytes,
}

pub struct Reader {
    /// `None` only in `for_test_only` builds, where any git path errors.
    repo: Option<Arc<gix::ThreadSafeRepository>>,
    raw: Option<RawConfig>,
    rt: Option<Arc<XetRuntime>>,
    chunk_cache: Option<Arc<dyn ChunkCache>>,
    /// Lazily-resolved, read-scope only.
    bale_cfg: Mutex<Option<BaleConfig>>,
    /// `oid → file size`, so `getattr` answers `stat` without decompressing.
    size_cache: Mutex<HashMap<String, u64>>,
    plain_cache: Mutex<HashMap<String, Arc<CachedBlob>>>,
    /// Keyed by xet file id (the pointer's `hash`).
    bale_cache: Mutex<BaleLru>,
    /// Per-open resources keyed by the `fi.fh` libfuse round-trips.
    handles: Mutex<HashMap<u64, Arc<HandleData>>>,
    next_handle: AtomicU64,
}

/// Bytes for cache hits / LRU-sized files; an on-disk tempfile for Bale files
/// too large to cache, so a 128 KiB FUSE read loop doesn't re-reconstruct.
enum HandleData {
    Bytes(Bytes),
    Tempfile {
        /// Owns the path; unlinks on drop.
        _tmp: tempfile::NamedTempFile,
        file: std::fs::File,
        size: u64,
    },
}

struct BaleLru {
    map: HashMap<String, Arc<CachedBlob>>,
    /// Oldest at front. A Vec suffices — VFS sizes are tiny.
    order: Vec<String>,
    bytes_used: u64,
    budget: u64,
}

impl BaleLru {
    fn new(budget: u64) -> Self {
        Self {
            map: HashMap::new(),
            order: Vec::new(),
            bytes_used: 0,
            budget,
        }
    }

    fn get(&mut self, key: &str) -> Option<Arc<CachedBlob>> {
        let v = self.map.get(key).cloned()?;
        // Touch: move to back.
        if let Some(idx) = self.order.iter().position(|k| k == key) {
            let s = self.order.remove(idx);
            self.order.push(s);
        }
        Some(v)
    }

    fn put(&mut self, key: String, blob: Arc<CachedBlob>) {
        let size = blob.data.len() as u64;
        if size > self.budget {
            // One entry busts the budget; serve it but don't cache.
            return;
        }
        while self.bytes_used + size > self.budget {
            let Some(victim) = self.order.first().cloned() else {
                break;
            };
            self.order.remove(0);
            if let Some(old) = self.map.remove(&victim) {
                self.bytes_used = self.bytes_used.saturating_sub(old.data.len() as u64);
            }
        }
        self.bytes_used += size;
        self.order.push(key.clone());
        self.map.insert(key, blob);
    }
}

impl Reader {
    pub fn new(repo: Arc<gix::ThreadSafeRepository>, raw: RawConfig) -> Result<Self> {
        let rt = XetRuntime::new().context("starting xet runtime")?;
        let cache_cfg = CacheConfig {
            cache_directory: raw.cache_dir.clone(),
            cache_size: rt.config().chunk_cache.size_bytes,
        };
        let chunk_cache = get_cache(&cache_cfg)
            .map_err(|e| anyhow!("init chunk cache at {}: {e}", raw.cache_dir.display()))?;
        if let Err(e) = crate::fs_util::restrict_user_cache_dir(&raw.cache_dir) {
            tracing::debug!("tightening perms on {}: {e}", raw.cache_dir.display());
        }

        Ok(Self {
            repo: Some(repo),
            raw: Some(raw),
            rt: Some(rt),
            chunk_cache: Some(chunk_cache),
            bale_cfg: Mutex::new(None),
            size_cache: Mutex::new(HashMap::new()),
            plain_cache: Mutex::new(HashMap::new()),
            bale_cache: Mutex::new(BaleLru::new(BALE_LRU_BUDGET_BYTES)),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(0),
        })
    }

    fn repo_thread_local(&self) -> Result<gix::Repository> {
        let repo = self
            .repo
            .as_ref()
            .ok_or_else(|| anyhow!("reader was constructed without a repo"))?;
        Ok(repo.to_thread_local())
    }

    /// Logical file size without reconstructing: pointer `file_size` from the
    /// JSON, or the plain blob's ODB length.
    pub fn size_of(&self, source: &BlobSource) -> Result<u64> {
        if let Some(&s) = self.size_cache.lock().unwrap().get(&source.oid) {
            return Ok(s);
        }
        let repo = self.repo_thread_local()?;
        let oid = gix::ObjectId::from_hex(source.oid.as_bytes())
            .with_context(|| format!("parsing OID {}", source.oid))?;
        let obj = repo
            .find_object(oid)
            .with_context(|| format!("loading object {}", source.oid))?;
        if obj.kind != gix::object::Kind::Blob {
            return Err(anyhow!(
                "expected blob for OID {}, found {:?}",
                source.oid,
                obj.kind
            ));
        }
        let size = if pointer::looks_like_pointer(&obj.data) {
            match pointer::parse_pointer(&obj.data) {
                Ok(info) => info
                    .file_size()
                    .ok_or_else(|| anyhow!("bale pointer {} missing file_size", source.oid))?,
                // Sentinel matched but parse failed: a plain blob containing the
                // `"hash"` token. Fall back to its byte length.
                Err(_) => obj.data.len() as u64,
            }
        } else {
            obj.data.len() as u64
        };
        self.size_cache
            .lock()
            .unwrap()
            .insert(source.oid.clone(), size);
        Ok(size)
    }

    /// Per-open handle backing the next `pread`s. Over-budget Bale files go to a
    /// tempfile held for the open so a readahead loop doesn't re-run the pipeline.
    pub fn open(&self, source: &BlobSource) -> Result<u64> {
        let data = self.materialize(source)?;
        // 0 is reserved as "uninitialized fh" by the FUSE callbacks.
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed) + 1;
        self.handles.lock().unwrap().insert(id, Arc::new(data));
        Ok(id)
    }

    /// Read from a handle from `open`. Short read only at EOF or unknown handle
    /// (caller maps that to EBADF).
    pub fn pread(&self, fh: u64, offset: u64, len: usize) -> Result<Bytes> {
        let handle = self
            .handles
            .lock()
            .unwrap()
            .get(&fh)
            .cloned()
            .ok_or_else(|| anyhow!("unknown open handle {fh}"))?;
        match &*handle {
            HandleData::Bytes(b) => {
                let total = b.len() as u64;
                if offset >= total {
                    return Ok(Bytes::new());
                }
                let start = offset as usize;
                let end = (start + len).min(b.len());
                Ok(b.slice(start..end))
            }
            HandleData::Tempfile { file, size, .. } => {
                if offset >= *size {
                    return Ok(Bytes::new());
                }
                let max = (*size - offset) as usize;
                let want = len.min(max);
                let mut buf = vec![0u8; want];
                let n = crate::fs_util::pread(file, &mut buf, offset)
                    .with_context(|| format!("pread fh={fh} off={offset} len={want}"))?;
                buf.truncate(n);
                Ok(Bytes::from(buf))
            }
        }
    }

    /// Drop the handle's resources. False if it was already absent.
    pub fn close(&self, fh: u64) -> bool {
        self.handles.lock().unwrap().remove(&fh).is_some()
    }

    fn materialize(&self, source: &BlobSource) -> Result<HandleData> {
        if let Some(c) = self.plain_cache.lock().unwrap().get(&source.oid).cloned() {
            return Ok(HandleData::Bytes(c.data.clone()));
        }

        let repo = self.repo_thread_local()?;
        let oid = gix::ObjectId::from_hex(source.oid.as_bytes())
            .with_context(|| format!("parsing OID {}", source.oid))?;
        let obj = repo
            .find_object(oid)
            .with_context(|| format!("loading object {}", source.oid))?;
        if obj.kind != gix::object::Kind::Blob {
            return Err(anyhow!(
                "expected blob for OID {}, found {:?}",
                source.oid,
                obj.kind
            ));
        }
        let raw = obj.data.clone();

        if pointer::looks_like_pointer(&raw) {
            if let Ok(info) = pointer::parse_pointer(&raw) {
                let file_id_hex = info.hash().to_string();
                if let Some(cached) = self.bale_cache.lock().unwrap().get(&file_id_hex) {
                    return Ok(HandleData::Bytes(cached.data.clone()));
                }
                let file_size = info
                    .file_size()
                    .ok_or_else(|| anyhow!("bale pointer missing file_size"))?;
                let tmp = self.reconstruct_bale_to_tempfile(&info)?;
                if file_size <= BALE_LRU_BUDGET_BYTES {
                    // Fits the LRU: slurp, cache, serve from RAM.
                    let buf = std::fs::read(tmp.path())?;
                    let bytes = Bytes::from(buf);
                    let blob = Arc::new(CachedBlob {
                        data: bytes.clone(),
                    });
                    self.bale_cache.lock().unwrap().put(file_id_hex, blob);
                    return Ok(HandleData::Bytes(bytes));
                }
                // Too large for the LRU: keep the tempfile, pread on demand.
                let file = tmp
                    .reopen()
                    .context("opening reconstruction tempfile for read")?;
                return Ok(HandleData::Tempfile {
                    _tmp: tmp,
                    file,
                    size: file_size,
                });
            }
        }

        if raw.len() > PLAIN_BLOB_MAX_BYTES {
            return Err(anyhow!(
                "plain blob {} is {} bytes (> {}); mount-diff only handles plain blobs up to 16 MiB. Track it via `git-bale track` so it's stored as a Bale pointer.",
                source.oid,
                raw.len(),
                PLAIN_BLOB_MAX_BYTES,
            ));
        }
        let bytes = Bytes::from(raw);
        self.plain_cache.lock().unwrap().insert(
            source.oid.clone(),
            Arc::new(CachedBlob {
                data: bytes.clone(),
            }),
        );
        Ok(HandleData::Bytes(bytes))
    }

    fn reconstruct_bale_to_tempfile(
        &self,
        info: &xet_data::processing::XetFileInfo,
    ) -> Result<tempfile::NamedTempFile> {
        let rt = self
            .rt
            .as_ref()
            .ok_or_else(|| anyhow!("reader was constructed without a xet runtime"))?;
        let chunk_cache = self
            .chunk_cache
            .as_ref()
            .ok_or_else(|| anyhow!("reader was constructed without a chunk cache"))?;
        let raw = self
            .raw
            .as_ref()
            .ok_or_else(|| anyhow!("reader was constructed without a config"))?;
        let file_size = info
            .file_size()
            .ok_or_else(|| anyhow!("bale pointer missing file_size"))?;
        let file_id_hex = info.hash().to_string();
        if !is_safe_file_id(&file_id_hex) {
            return Err(anyhow!(
                "bale pointer hash is not canonical hex (got {} chars)",
                file_id_hex.len()
            ));
        }

        // xet-data's download writer is by-value `'static`, so we go through a
        // tempfile; the caller slurps it or keeps the on-disk handle.
        let tmp = tempfile::NamedTempFile::new()?;

        let cache_hit = if let Some(git_dir) = raw.git_dir.as_deref() {
            match manifest_cache::load(git_dir, &file_id_hex)? {
                Some(manifest) => {
                    let dest_file = tmp.reopen()?;
                    let rt_clone = rt.clone();
                    let cache_clone = chunk_cache.clone();
                    let outcome = rt
                        .bridge_sync(async move {
                            let mut dest = dest_file;
                            try_reconstruct_from_cache(
                                &rt_clone,
                                &cache_clone,
                                &manifest,
                                file_size,
                                &mut dest,
                            )
                            .await
                        })
                        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
                    matches!(outcome, CacheReconstructOutcome::Wrote(_))
                }
                None => false,
            }
        } else {
            false
        };

        if !cache_hit {
            // Discard any partial bytes from a failed hot-path attempt.
            let mut trunc = tmp.reopen()?;
            trunc.set_len(0)?;
            std::io::Seek::seek(&mut trunc, std::io::SeekFrom::Start(0))?;
            drop(trunc);

            let cfg = self.resolved_cfg()?;
            let translator = build_translator_config(
                &cfg,
                resolver::forge_refresher(raw, resolver::Scope::Read),
            )?;
            let info_clone = info.clone();
            let cache_clone = chunk_cache.clone();
            let dest_file = tmp.reopen()?;
            // Same `0..file_size` range cap as the smudge filter — see
            // filter_process.rs for why this is load-bearing — and the same
            // no-progress watchdog, so a misconfigured/unreachable blob store
            // fails the read instead of hanging the mount for hours.
            let label = file_id_hex.clone();
            let stall_secs = crate::filter_process::cold_download_stall_secs();
            rt.bridge_sync(async move {
                let session =
                    FileDownloadSession::new(Arc::new(translator), Some(cache_clone)).await?;
                crate::filter_process::download_cold(
                    &session,
                    &info_clone,
                    file_size,
                    dest_file,
                    &label,
                    stall_secs,
                )
                .await
            })
            .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

            // Backfill the per-repo manifest cache for the next mount.
            if let Some(git_dir) = raw.git_dir.as_deref() {
                if let Ok(merkle) = info.merkle_hash() {
                    let cfg_clone = cfg.clone();
                    let refresher = resolver::forge_refresher(raw, resolver::Scope::Read);
                    let fetched = rt.bridge_sync(async move {
                        fetch_manifest(&cfg_clone, refresher, &merkle).await
                    });
                    if let Ok(Ok(manifest)) = fetched {
                        let _ = manifest_cache::save(git_dir, &file_id_hex, &manifest);
                    }
                }
            }
        }

        Ok(tmp)
    }

    fn resolved_cfg(&self) -> Result<BaleConfig> {
        if let Some(cfg) = self.bale_cfg.lock().unwrap().clone() {
            return Ok(cfg);
        }
        let rt = self
            .rt
            .as_ref()
            .ok_or_else(|| anyhow!("reader was constructed without a xet runtime"))?;
        let raw = self
            .raw
            .as_ref()
            .ok_or_else(|| anyhow!("reader was constructed without a config"))?;
        let raw_clone = raw.clone();
        let resolved = rt
            .bridge_sync(async move { resolver::resolve(&raw_clone, resolver::Scope::Read).await })
            .map_err(|e| anyhow!("xet runtime error during Bale auth resolution: {e:?}"))??;
        let cfg = BaleConfig {
            server_url: resolved.server_url,
            token: resolved.token,
            token_expiration: resolved.token_expiration,
            cache_dir: raw.cache_dir.clone(),
            git_dir: raw.git_dir.clone(),
        };
        *self.bale_cfg.lock().unwrap() = Some(cfg.clone());
        Ok(cfg)
    }
}

fn build_translator_config(
    cfg: &BaleConfig,
    refresher: Arc<dyn TokenRefresher>,
) -> Result<TranslatorConfig> {
    Ok(default_config(
        cfg.server_url.clone(),
        Some((cfg.token.clone(), cfg.token_expiration)),
        Some(refresher),
        None,
    )?)
}

/// 64 lowercase hex chars; same constraint as the smudge filter.
fn is_safe_file_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Process-wide active reader so libfuse C callbacks (no per-call user_data) can
/// reach it. Set once per mount.
static ACTIVE_READER: OnceLock<Arc<Reader>> = OnceLock::new();

pub fn install_active(reader: Arc<Reader>) -> Result<()> {
    ACTIVE_READER
        .set(reader)
        .map_err(|_| anyhow!("active reader already installed; only one mount per process"))
}

pub fn active() -> Option<Arc<Reader>> {
    ACTIVE_READER.get().cloned()
}
