//! `git-bale filter-process` — Git's long-running filter protocol over
//! pkt-line, wired to xet-core's `FileUploadSession` / `FileDownloadSession`.

use std::io::{stdin, stdout, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use xet_client::cas_client::auth::TokenRefresher;
use xet_client::chunk_cache::{get_cache, CacheConfig, ChunkCache};
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::default_config;
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::clean_cache::{self, PathKey};
use crate::config::BaleConfig;
use crate::local_reconstruct::{try_reconstruct_from_cache, CacheReconstructOutcome};
use crate::manifest_cache;
use crate::pktline::{PktReader, PktWriter, MAX_PKT_PAYLOAD};
use crate::pointer;
use crate::remote_manifest::fetch_manifest;
use crate::resolver;
use crate::staging::{file_is_staged, mark_file_staged, staging_root, touch_marker_if_exists};
use crate::store::{self, StoreLock};

// Per-callsite payload caps: defense against a peer forcing unbounded heap or
// disk growth. Well above any real workload, not a protocol limit.
const CLEAN_PAYLOAD_CAP: u64 = 128 * 1024 * 1024 * 1024;
const DRAIN_PAYLOAD_CAP: u64 = 64 * 1024 * 1024;
/// Smudge input above this is spilled to disk: it can't be a pointer, and is
/// passed through unchanged.
const SMUDGE_INLINE: usize = pointer::POINTER_MAX_BYTES + 4096;

const VERSION: &str = "version=2";

/// A failed write to git's stdin pipe. Once any response byte is out the
/// stream can't carry a `status=error` anymore, so this tears the filter down.
#[derive(Debug, thiserror::Error)]
#[error("writing to git over the filter protocol: {0}")]
struct ProtocolWrite(#[source] std::io::Error);

fn w<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| ProtocolWrite(e).into())
}

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = crate::config::RawConfig::load(Some(cwd.as_path()))?;

    let stdin_lock = stdin().lock();
    let stdout_lock = stdout().lock();

    let mut reader = PktReader::new(stdin_lock);
    let mut writer = PktWriter::new(stdout_lock);

    handshake(&mut reader, &mut writer)?;
    negotiate_capabilities(&mut reader, &mut writer)?;

    // XetRuntime startup allocates 8 MiB worker stacks; cache-hit cleans don't
    // need it. Defer construction so pointer-cache hits stay fast.
    let mut rt_slot: Option<Arc<XetRuntime>> = None;

    // Clean is offline (upload is deferred to push-pending); only smudge
    // resolves auth, cached for the process.
    let mut smudge_cfg: Option<BaleConfig> = None;

    loop {
        let headers = match reader.read_text_list() {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if headers.is_empty() {
            return Ok(());
        }
        let map = parse_headers(&headers);
        let command = map
            .iter()
            .find(|(k, _)| k == "command")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let pathname = map
            .iter()
            .find(|(k, _)| k == "pathname")
            .map(|(_, v)| v.as_str())
            .unwrap_or("<unknown>");

        // The payload is always drained to its flush BEFORE any reply, so a
        // per-request failure can go out as `status=error` without desyncing
        // the stream. A failed drain leaves the stream unrecoverable: fatal.
        let outcome = match command {
            "clean" => {
                let (payload, size) =
                    drain_payload_spilling(&mut reader, max_inline_clean(), CLEAN_PAYLOAD_CAP)?;
                do_clean(&mut rt_slot, &raw, payload, size, &mut writer, pathname)
            }
            "smudge" => {
                let (payload, _) =
                    drain_payload_spilling(&mut reader, SMUDGE_INLINE, CLEAN_PAYLOAD_CAP)?;
                handle_smudge(
                    &mut rt_slot,
                    &raw,
                    &mut smudge_cfg,
                    payload,
                    &mut writer,
                    pathname,
                )
            }
            other => {
                let mut sink = std::io::sink();
                reader.read_binary_to(&mut sink, DRAIN_PAYLOAD_CAP)?;
                Err(anyhow!("unknown command \"{other}\""))
            }
        };
        if let Err(e) = outcome {
            if e.downcast_ref::<ProtocolWrite>().is_some() {
                return Err(e);
            }
            report_request_error(&mut writer, command, pathname, &e)?;
        }
    }
}

fn resolve_cached<'a>(
    slot: &'a mut Option<BaleConfig>,
    raw: &crate::config::RawConfig,
    rt: &Arc<XetRuntime>,
    scope: resolver::Scope,
) -> Result<&'a BaleConfig> {
    if slot.is_none() {
        let raw_clone = raw.clone();
        let resolved = rt
            .bridge_sync(async move { resolver::resolve(&raw_clone, scope).await })
            .map_err(|e| anyhow!("xet runtime error during Bale auth resolution: {e:?}"))??;
        *slot = Some(BaleConfig {
            server_url: resolved.server_url,
            token: resolved.token,
            token_expiration: resolved.token_expiration,
            cache_dir: raw.cache_dir.clone(),
            git_dir: raw.git_dir.clone(),
        });
    }
    slot.as_ref()
        .ok_or_else(|| anyhow!("auth slot unexpectedly empty"))
}

fn handshake<R: Read, W: Write>(
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
) -> Result<()> {
    let welcome = reader.read_text()?;
    if welcome != "git-filter-client" {
        return Err(anyhow!(
            "invalid filter-process welcome message: {welcome:?}"
        ));
    }
    let versions = reader.read_text_list()?;
    if !versions.iter().any(|v| v == VERSION) {
        return Err(anyhow!(
            "git does not support {VERSION} (offered: {versions:?})"
        ));
    }
    writer.write_text_list(&["git-filter-server", VERSION])?;
    Ok(())
}

fn negotiate_capabilities<R: Read, W: Write>(
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
) -> Result<()> {
    let supported = reader.read_text_list()?;
    let required = ["capability=clean", "capability=smudge"];
    for req in &required {
        if !supported.iter().any(|s| s == req) {
            return Err(anyhow!("git does not advertise {req} (got: {supported:?})"));
        }
    }
    writer.write_text_list(&required)?;
    Ok(())
}

fn parse_headers(list: &[String]) -> Vec<(String, String)> {
    list.iter()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Error chain is sent verbatim via `{e:#}`; callers must not put secrets
/// (passwords, JWTs, the bale token) in the `anyhow::Error` chain. Only valid
/// before any byte of this request's response was written.
fn report_request_error<W: Write>(
    writer: &mut PktWriter<W>,
    op: &str,
    pathname: &str,
    e: &anyhow::Error,
) -> Result<()> {
    tracing::warn!("{op} failed for {pathname}: {e:#}");
    let mut msg: String = format!("{e:#}")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if msg.len() > 1024 {
        let mut cut = 1024;
        while !msg.is_char_boundary(cut) {
            cut -= 1;
        }
        msg.truncate(cut);
    }
    let err_line = format!("error={op} failed: {msg}");
    w(writer.write_text_list(&["status=error", err_line.as_str()]))
}

fn ensure_runtime(slot: &mut Option<Arc<XetRuntime>>) -> Result<Arc<XetRuntime>> {
    if let Some(rt) = slot {
        return Ok(rt.clone());
    }
    let rt = XetRuntime::new().context("starting xet runtime")?;
    *slot = Some(rt.clone());
    Ok(rt)
}

/// Above this size, spill the pkt-line clean payload to a tmp file instead of
/// holding the whole file in RAM. Bounds peak RSS while keeping realistic files
/// in-memory to avoid the disk round-trip (~250 ms on a 350 MiB file).
const MAX_INLINE_CLEAN: usize = 4 * 1024 * 1024 * 1024;

/// `BALE_MAX_INLINE_CLEAN` overrides the threshold so tests can hit the spilled
/// path without a multi-GiB file.
fn max_inline_clean() -> usize {
    std::env::var("BALE_MAX_INLINE_CLEAN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_INLINE_CLEAN)
}

/// TEST-ONLY: widens the objects-written → marker-written window (gc vs clean race).
fn maybe_test_marker_delay() {
    test_delay("BALE_TEST_CLEAN_MARKER_DELAY_MS");
}

/// TEST-ONLY: widens the cache-hit emit window (cache-hit clean vs gc race).
fn maybe_test_cache_hit_delay() {
    test_delay("BALE_TEST_CLEAN_CACHE_HIT_DELAY_MS");
}

/// TEST-ONLY: widens the gap between loading a clean-cache entry and locking.
fn maybe_test_cache_hit_prelock_delay() {
    test_delay("BALE_TEST_CLEAN_CACHE_PRELOCK_DELAY_MS");
}

/// Store lock for a clean, plus the local-mode ownership bookkeeping: a shared
/// store (re)registers this repo under its current path (a moved or copied repo
/// must never look unreferenced to `prune`); a non-shared store must be ours.
fn lock_for_write(
    raw: &crate::config::RawConfig,
    store: &Path,
    git_dir: &Path,
) -> Result<StoreLock> {
    let lock = StoreLock::acquire_exclusive(store).context("locking object store")?;
    if raw.local_mode {
        if raw.local_shared {
            store::register_repo_locked(store, git_dir, &lock)?;
        } else {
            store::claim_store(store, git_dir, &lock)?;
        }
    }
    Ok(lock)
}

fn test_delay(var: &str) {
    if let Some(ms) = std::env::var(var).ok().and_then(|v| v.parse::<u64>().ok()) {
        if ms > 0 {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
}

enum Payload {
    InMemory(Vec<u8>),
    Spilled(NamedTempFile),
}

/// Read data packets up to the flush, spilling to a temp file past
/// `max_inline`. Always consumes through the flush (or errors fatally).
fn drain_payload_spilling<R: Read>(
    reader: &mut PktReader<R>,
    max_inline: usize,
    cap: u64,
) -> Result<(Payload, u64)> {
    use crate::pktline::Packet;
    let mut buf: Vec<u8> = Vec::new();
    let mut spilled: Option<NamedTempFile> = None;
    let mut total: u64 = 0;
    loop {
        match reader.read_packet()? {
            Packet::Flush => break,
            Packet::Data(bytes) => {
                let n = bytes.len() as u64;
                if total.saturating_add(n) > cap {
                    return Err(anyhow!("pkt-line payload exceeded cap of {cap} bytes"));
                }
                if let Some(f) = spilled.as_mut() {
                    f.write_all(&bytes)?;
                } else if buf.len().saturating_add(bytes.len()) > max_inline {
                    let mut f = NamedTempFile::new()?;
                    f.write_all(&buf)?;
                    f.write_all(&bytes)?;
                    buf = Vec::new();
                    spilled = Some(f);
                } else {
                    buf.extend_from_slice(&bytes);
                }
                total += n;
            }
            other => {
                return Err(anyhow!(
                    "expected pkt-line data or flush in payload, got {other:?}"
                ));
            }
        }
    }
    let payload = if let Some(mut f) = spilled {
        f.flush()?;
        Payload::Spilled(f)
    } else {
        Payload::InMemory(buf)
    };
    Ok((payload, total))
}

fn do_clean<W: Write>(
    rt_slot: &mut Option<Arc<XetRuntime>>,
    raw: &crate::config::RawConfig,
    payload: Payload,
    file_size: u64,
    writer: &mut PktWriter<W>,
    pathname: &str,
) -> Result<()> {
    let git_dir = raw.git_dir.as_deref().ok_or_else(|| {
        anyhow!("clean: cannot stage upload — no git directory resolved from cwd")
    })?;
    // Already a pointer (a worktree checked out without the filter, a
    // renormalize): pass it through like git-lfs, or the commit would record
    // the pointer text itself as the file's content.
    if file_size <= pointer::POINTER_MAX_BYTES as u64 {
        let small = match &payload {
            Payload::InMemory(buf) => buf.clone(),
            Payload::Spilled(tmp) => std::fs::read(tmp.path()).context("reading clean payload")?,
        };
        if pointer::is_canonical_pointer(&small) {
            tracing::debug!("clean: {pathname} is already a bale pointer; passing through");
            w(writer.write_text_list(&["status=success"]))?;
            w(writer.write_all_then_flush(&small))?;
            w(writer.write_text_list(&["status=success"]))?;
            return Ok(());
        }
    }
    let store = store::object_store_root(raw).context("resolving object store root")?;
    let cache_key = clean_cache::path_key(pathname);

    // `git status`/`git diff` re-invoke clean on every command for a modified
    // bale file; short-circuit on size, then verify every chunk.
    match clean_cache::load(git_dir, &cache_key) {
        Ok(Some(entry)) if entry.size == file_size => {
            let verified = match &payload {
                Payload::InMemory(buf) => {
                    Ok(clean_cache::verify_chunks_in_memory(&entry.chunks, buf))
                }
                Payload::Spilled(tmp) => {
                    clean_cache::verify_chunks(&entry.chunks, tmp.path(), file_size)
                }
            };
            match verified {
                Ok(true) => {
                    if emit_cache_hit(raw, git_dir, &store, &cache_key, &entry, writer)? {
                        return Ok(());
                    }
                }
                Ok(false) => {
                    tracing::debug!("clean-cache chunk mismatch for {pathname}; full clean")
                }
                Err(e) => tracing::debug!("clean-cache verify IO error: {e}; full clean"),
            }
        }
        Ok(Some(entry)) => tracing::debug!(
            "clean-cache size diverged for {pathname} (cached {} vs actual {file_size}); full clean",
            entry.size
        ),
        Ok(None) => {}
        Err(e) => tracing::debug!("clean-cache load failed for {pathname}: {e}; full clean"),
    }

    let rt = ensure_runtime(rt_slot)?;
    // Per-file lock across {write objects → write marker} so a concurrent
    // gc/prune/push-pending sweep can't delete a half-written file's only copy.
    // Never held for the filter-process lifetime: a porcelain op (stash/commit)
    // nesting another clean would deadlock. The marker-vs-index gap is closed by
    // gc skipping while an index/ref `*.lock` is held.
    let _store_lock = lock_for_write(raw, &store, git_dir)?;
    match payload {
        Payload::InMemory(buf) => handle_clean_in_memory(
            &rt, git_dir, &store, buf, writer, pathname, &cache_key, file_size,
        ),
        Payload::Spilled(tmp) => handle_clean(
            &rt, git_dir, &store, tmp, writer, pathname, &cache_key, file_size,
        ),
    }
}

/// Answer a verified clean-cache hit with its stored pointer. Returns false
/// (nothing written) when the hit can't be trusted and a full clean must run.
fn emit_cache_hit<W: Write>(
    raw: &crate::config::RawConfig,
    git_dir: &Path,
    store: &Path,
    cache_key: &PathKey,
    entry: &clean_cache::CacheEntry,
    writer: &mut PktWriter<W>,
) -> Result<bool> {
    maybe_test_cache_hit_prelock_delay();
    let lock = lock_for_write(raw, store, git_dir)?;
    // The entry was loaded without the lock; gc forgets entries (under it)
    // before sweeping their bytes. Still present ⇒ still backed.
    let still_cached = matches!(
        clean_cache::load(git_dir, cache_key),
        Ok(Some(e)) if e.pointer == entry.pointer && e.size == entry.size
    );
    if !still_cached {
        tracing::debug!("clean-cache entry changed under us; full clean");
        return Ok(false);
    }
    let current_id = store::store_id(store).unwrap_or_else(|e| {
        tracing::debug!("reading store id: {e:#}");
        Some(String::new())
    });
    if Path::new(&entry.store) != store || entry.store_id != current_id {
        tracing::debug!("clean-cache entry backed by another store; full clean");
        return Ok(false);
    }
    let pointer_str = entry.pointer.as_str();
    // Bump the marker mtime (gc's reclaim grace keys on the latest add) but
    // never create one: in server mode a hit legitimately re-emits pointers
    // for content already drained to the server.
    let marker_present = match pointer::parse_pointer(pointer_str.as_bytes()) {
        Ok(info) => match touch_marker_if_exists(git_dir, info.hash()) {
            Ok(present) => present,
            Err(e) => {
                tracing::debug!("clean-cache hit: touching marker: {e}");
                false
            }
        },
        Err(_) => return Ok(false),
    };
    if raw.local_mode && !marker_present {
        // The store is the only copy and no marker vouches for it: re-stage.
        tracing::debug!("clean-cache hit without a marker in local mode; full clean");
        drop(lock);
        return Ok(false);
    }
    maybe_test_cache_hit_delay();
    w(writer.write_text_list(&["status=success"]))?;
    w(writer.write_all_then_flush(pointer_str.as_bytes()))?;
    w(writer.write_text_list(&["status=success"]))?;
    drop(lock);
    Ok(true)
}

/// In-memory variant of [`handle_clean`]: avoids the tmp-file write plus the
/// re-reads `clean_file`/`compute_chunks` would do, building the chunk index
/// from the buffer already in RAM.
#[allow(clippy::too_many_arguments)]
fn handle_clean_in_memory<W: Write>(
    rt: &Arc<XetRuntime>,
    git_dir: &Path,
    store: &Path,
    bytes: Vec<u8>,
    writer: &mut PktWriter<W>,
    pathname: &str,
    cache_key: &PathKey,
    file_size: u64,
) -> Result<()> {
    // Markers stay per-repo under .git/bale/staging/file-index even when the
    // object store is shared; only xorbs/shards go to `store`.
    crate::fs_util::create_bale_subdir(git_dir, "staging")
        .with_context(|| format!("creating staging dir under {}", git_dir.display()))?;
    std::fs::create_dir_all(store)
        .with_context(|| format!("creating object store {}", store.display()))?;
    let translator =
        TranslatorConfig::local_config(store).context("building local TranslatorConfig")?;
    let snapshot = store::ObjectSnapshot::take(store)?;
    // Build the index before clean_bytes consumes the Vec.
    let chunks = clean_cache::compute_chunks_from_slice(&bytes);
    let (pointer_string, file_hex) = rt
        .bridge_sync(async move {
            let session = FileUploadSession::new(Arc::new(translator)).await?;
            let (info, _metrics) = xet_data::processing::data_client::clean_bytes(
                session.clone(),
                bytes,
                Sha256Policy::Compute,
            )
            .await?;
            session.finalize().await?;
            let file_hex = info.hash().to_string();
            let s = pointer::encode_pointer_string(&info)?;
            Ok::<_, anyhow::Error>((s, file_hex))
        })
        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

    // The objects are the only copy until pushed (server) or forever (local),
    // and xet doesn't fsync them: make them durable before the marker vouches.
    snapshot
        .sync_new(store)
        .context("syncing new objects to disk")?;
    maybe_test_marker_delay();
    // Markers are the inventory gc/prune/push-pending trust: emitting a pointer
    // with no marker would let gc sweep its only copy (local) or push-pending
    // skip uploading it (server).
    mark_file_staged(git_dir, &file_hex, file_size)
        .with_context(|| format!("recording staged marker for {file_hex}"))?;

    w(writer.write_text_list(&["status=success"]))?;
    w(writer.write_all_then_flush(pointer_string.as_bytes()))?;
    w(writer.write_text_list(&["status=success"]))?;

    let entry = clean_cache::CacheEntry {
        v: clean_cache::CURRENT_VERSION,
        size: file_size,
        chunks,
        pointer: pointer_string,
        store: store.to_string_lossy().into_owned(),
        store_id: store::store_id(store).ok().flatten(),
    };
    if let Err(e) = clean_cache::save(git_dir, cache_key, &entry) {
        tracing::warn!("saving clean-cache entry for {pathname}: {e}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_clean<W: Write>(
    rt: &Arc<XetRuntime>,
    git_dir: &Path,
    store: &Path,
    tmp: NamedTempFile,
    writer: &mut PktWriter<W>,
    pathname: &str,
    cache_key: &PathKey,
    file_size: u64,
) -> Result<()> {
    crate::fs_util::create_bale_subdir(git_dir, "staging")
        .with_context(|| format!("creating staging dir under {}", git_dir.display()))?;
    std::fs::create_dir_all(store)
        .with_context(|| format!("creating object store {}", store.display()))?;
    let translator =
        TranslatorConfig::local_config(store).context("building local TranslatorConfig")?;
    let snapshot = store::ObjectSnapshot::take(store)?;
    // Moving `tmp` into the closure would unlink it before compute_chunks below;
    // pass only the path and keep `tmp` owned out here.
    let tmp_path = tmp.path().to_path_buf();
    let tmp_path_for_xet = tmp_path.clone();
    let (pointer_string, file_hex) = rt
        .bridge_sync(async move {
            let session = FileUploadSession::new(Arc::new(translator)).await?;
            let (info, _metrics) = xet_data::processing::data_client::clean_file(
                session.clone(),
                &tmp_path_for_xet,
                Sha256Policy::Compute,
            )
            .await?;
            session.finalize().await?;
            let file_hex = info.hash().to_string();
            let s = pointer::encode_pointer_string(&info)?;
            Ok::<_, anyhow::Error>((s, file_hex))
        })
        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

    // The objects are the only copy until pushed (server) or forever (local),
    // and xet doesn't fsync them: make them durable before the marker vouches.
    snapshot
        .sync_new(store)
        .context("syncing new objects to disk")?;
    maybe_test_marker_delay();
    mark_file_staged(git_dir, &file_hex, file_size)
        .with_context(|| format!("recording staged marker for {file_hex}"))?;

    // Respond before populating the cache so the pointer lands in the index
    // without waiting on best-effort cache work.
    w(writer.write_text_list(&["status=success"]))?;
    w(writer.write_all_then_flush(pointer_string.as_bytes()))?;
    w(writer.write_text_list(&["status=success"]))?;

    match clean_cache::compute_chunks(&tmp_path, file_size) {
        Ok(chunks) => {
            let entry = clean_cache::CacheEntry {
                v: clean_cache::CURRENT_VERSION,
                size: file_size,
                chunks,
                pointer: pointer_string,
                store: store.to_string_lossy().into_owned(),
                store_id: store::store_id(store).ok().flatten(),
            };
            if let Err(e) = clean_cache::save(git_dir, cache_key, &entry) {
                tracing::warn!("saving clean-cache entry for {pathname}: {e}");
            }
        }
        Err(e) => tracing::warn!("computing chunk index for {pathname}: {e}"),
    }

    Ok(())
}

const STALL_POLL: Duration = Duration::from_secs(2);
const DEFAULT_DOWNLOAD_STALL_SECS: u64 = 30;

/// Seconds of zero download progress before the cold path gives up. `0` disables
/// the watchdog (used by the e2e stall phase to verify the hang it replaces).
/// Shared by the smudge filter and `git-bale mount`.
pub(crate) fn cold_download_stall_secs() -> u64 {
    std::env::var("BALE_DOWNLOAD_STALL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DOWNLOAD_STALL_SECS)
}

/// Counts bytes actually written so the watchdog can tell a stalled transfer from
/// a slow-but-progressing one.
struct StallGuardWriter<W> {
    inner: W,
    written: Arc<AtomicU64>,
}

impl<W: Write> Write for StallGuardWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Cold-path reconstruction under a no-progress watchdog. xet-core retries a DNS
/// "host not found" with base-squared backoff (3s, then ~2.5h), so an unreachable
/// blob store would hang `git checkout` for hours; after `stall_secs` with no
/// bytes, dropping the future cancels the request and its backoff sleep.
pub(crate) async fn download_cold<W: Write + Send + 'static>(
    session: &FileDownloadSession,
    info: &XetFileInfo,
    file_size: u64,
    dest: W,
    label: &str,
    stall_secs: u64,
) -> Result<()> {
    let written = Arc::new(AtomicU64::new(0));
    let guard_writer = StallGuardWriter {
        inner: dest,
        written: written.clone(),
    };
    let dl = session.download_to_writer(info, 0..file_size, guard_writer);

    if stall_secs == 0 {
        dl.await?;
        return Ok(());
    }

    tokio::pin!(dl);
    let stall = Duration::from_secs(stall_secs);
    let mut last_seen = 0u64;
    let mut idle = Duration::ZERO;
    loop {
        tokio::select! {
            r = &mut dl => { r?; return Ok(()); }
            _ = tokio::time::sleep(STALL_POLL) => {
                let cur = written.load(Ordering::Relaxed);
                if cur > last_seen {
                    last_seen = cur;
                    idle = Duration::ZERO;
                } else {
                    idle += STALL_POLL;
                    if idle >= stall {
                        return Err(anyhow!(
                            "download of '{label}' stalled: no data received for {stall_secs}s. \
                             The bale storage server is unreachable or misconfigured — check your \
                             network connection, or contact the repository administrator."
                        ));
                    }
                }
            }
        }
    }
}

/// True when `path` has exactly the pointer's size and (if the pointer carries
/// one) sha256. Every smudge path gates on this before git sees a byte: xet
/// reconstructs from xorb chunks without re-hashing them, so a corrupt cache,
/// staging dir, local store or server object would otherwise land silently in
/// the worktree.
pub(crate) fn content_matches(path: &Path, info: &XetFileInfo, file_size: u64) -> Result<bool> {
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("opening reconstructed file {}", path.display()))?;
    if f.metadata()?.len() != file_size {
        return Ok(false);
    }
    // git-bale always writes sha256; without it the bytes can't be verified.
    let Some(expected) = info.sha256() else {
        tracing::warn!(
            "pointer {} has no sha256; refusing unverifiable content",
            info.hash()
        );
        return Ok(false);
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()).eq_ignore_ascii_case(expected.trim()))
}

fn reset_tmp(tmp: &NamedTempFile) -> Result<()> {
    let mut f = tmp.reopen()?;
    f.set_len(0)?;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0))?;
    Ok(())
}

fn handle_smudge<W: Write>(
    rt_slot: &mut Option<Arc<XetRuntime>>,
    raw: &crate::config::RawConfig,
    auth_slot: &mut Option<BaleConfig>,
    payload: Payload,
    writer: &mut PktWriter<W>,
    pathname: &str,
) -> Result<()> {
    // Non-pointer content (a file committed before the path was tracked, or
    // anything too large to be a pointer) passes through unchanged, like
    // git-lfs, rather than failing the checkout.
    let pointer_buf = match payload {
        Payload::Spilled(tmp) => {
            let len = std::fs::metadata(tmp.path())?.len();
            return finish_smudge(writer, tmp.path(), len);
        }
        Payload::InMemory(bytes) => bytes,
    };
    let info = match pointer::parse_pointer(&pointer_buf) {
        Ok(info) => info,
        Err(e) => {
            tracing::debug!("smudge: {pathname} is not a bale pointer ({e}); passing through");
            return passthrough_bytes(writer, &pointer_buf);
        }
    };

    let file_size = info
        .file_size()
        .ok_or_else(|| anyhow!("bale pointer missing file_size"))?;
    // The pointer's `hash` is a free-form String in xet-data; constrain it to
    // lowercase hex before interpolating into the manifest cache path, or a
    // crafted `{"hash":"../../etc/passwd"}` escapes the git dir.
    let file_id_hex = info.hash().to_string();
    if !pointer::is_safe_file_id(&file_id_hex) {
        return Err(anyhow!(
            "bale pointer hash is not lowercase hex (got {} chars)",
            file_id_hex.len()
        ));
    }
    let rt = ensure_runtime(rt_slot)?;

    // From raw config so the hot path stays local — no auth resolution.
    let cache_cfg = CacheConfig {
        cache_directory: raw.cache_dir.clone(),
        cache_size: rt.config().chunk_cache.size_bytes,
    };
    let chunk_cache = get_cache(&cache_cfg)
        .map_err(|e| anyhow!("init chunk cache at {}: {e}", raw.cache_dir.display()))?;
    if let Err(e) = crate::fs_util::restrict_user_cache_dir(&raw.cache_dir) {
        tracing::debug!("tightening perms on {}: {e}", raw.cache_dir.display());
    }

    let tmp = NamedTempFile::new()?;
    let git_dir = raw.git_dir.as_deref();

    // Hot path: cache-only reconstruction. A miss, error or mismatch falls
    // through.
    let mut done = false;
    let mut server_backed = false;
    // Bytes came from this repo's own staging/store (not merely a marker).
    let mut store_backed = false;
    if let Some(gd) = git_dir {
        let hit = match try_smudge_from_cache(&rt, &chunk_cache, gd, &file_id_hex, file_size, &tmp)
        {
            Ok(hit) => hit,
            Err(e) => {
                tracing::debug!("chunk-cache reconstruction of {file_id_hex} failed: {e:#}");
                false
            }
        };
        if hit {
            if content_matches(tmp.path(), &info, file_size)? {
                done = true;
                // Manifests are only saved from a server fetch.
                server_backed = !raw.local_mode;
            } else {
                tracing::warn!(
                    "chunk-cache reconstruction of {file_id_hex} failed verification; refetching"
                );
                if let Err(e) = manifest_cache::remove(gd, &file_id_hex) {
                    tracing::debug!("removing manifest for {file_id_hex}: {e}");
                }
            }
        }
    }

    if !done && !raw.local_mode {
        if let Some(gd) = git_dir {
            if try_smudge_from_staging(&rt, gd, &info, file_size, &tmp)? {
                done = true;
                store_backed = true;
            }
        }
    }

    if !done && raw.local_mode {
        smudge_from_local_store(&rt, raw, &info, file_size, &tmp)?;
        done = true;
        store_backed = true;
    }

    // Cold path: delegate to xet-data. A mismatch through the chunk cache is
    // retried once without it (the cache itself may be what's corrupt).
    if !done {
        let cfg = resolve_cached(auth_slot, raw, &rt, resolver::Scope::Read)?.clone();
        let mut verified = false;
        for cache in [Some(chunk_cache.clone()), None] {
            reset_tmp(&tmp)?;
            download_cold_to(&rt, raw, &cfg, &info, file_size, &tmp, pathname, cache)?;
            if content_matches(tmp.path(), &info, file_size)? {
                verified = true;
                break;
            }
            tracing::warn!("downloaded content for {file_id_hex} failed verification");
        }
        if !verified {
            return Err(anyhow!(
                "downloaded content for {pathname} ({file_id_hex}) does not match the pointer's \
                 sha256; the server's copy is corrupt. Refusing to write it to the worktree."
            ));
        }
        if let Some(gd) = git_dir {
            save_remote_manifest(&rt, raw, &cfg, gd, &info, &file_id_hex);
        }
        server_backed = true;
    }

    // Seed the clean cache so the next `git status` hits without CDC, but only
    // while the bytes are guaranteed retrievable (server, or a marker checked
    // under the store lock): a seed racing gc's `forget_hashes` would let a later
    // add emit a pointer with no backing. Best-effort: never blocks on the lock
    // or fails the smudge. A local-mode hot-path hit isn't seeded: a marker
    // alone doesn't prove the current store holds the bytes.
    if let (Some(gd), true) = (git_dir, server_backed || store_backed) {
        if let Ok(store) = store::object_store_root(raw) {
            if let Some(entry) =
                smudge_cache_entry(pathname, tmp.path(), &pointer_buf, file_size, &store)
            {
                if let Ok(Some(_lock)) = StoreLock::try_exclusive(&store) {
                    if server_backed || file_is_staged(gd, &file_id_hex) {
                        let key = clean_cache::path_key(pathname);
                        if let Err(e) = clean_cache::save(gd, &key, &entry) {
                            tracing::debug!("smudge: saving clean-cache entry for {pathname}: {e}");
                        }
                    }
                }
            }
        }
    }

    finish_smudge(writer, tmp.path(), file_size)
}

/// Cache-only reconstruction from a saved manifest. `Ok(false)` on any miss.
fn try_smudge_from_cache(
    rt: &Arc<XetRuntime>,
    chunk_cache: &Arc<dyn ChunkCache>,
    git_dir: &Path,
    file_id_hex: &str,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<bool> {
    let manifest = match manifest_cache::load(git_dir, file_id_hex) {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(false),
        Err(e) => {
            tracing::warn!("reading cached manifest for {file_id_hex}: {e}; falling back");
            return Ok(false);
        }
    };
    let dest_file = tmp.reopen()?;
    let rt_for_cache = rt.clone();
    let cache = chunk_cache.clone();
    let outcome = rt
        .bridge_sync(async move {
            let mut dest = dest_file;
            try_reconstruct_from_cache(&rt_for_cache, &cache, &manifest, file_size, &mut dest).await
        })
        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
    Ok(matches!(outcome, CacheReconstructOutcome::Wrote(_)))
}

#[allow(clippy::too_many_arguments)]
fn download_cold_to(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    cfg: &BaleConfig,
    info: &XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
    pathname: &str,
    cache: Option<Arc<dyn ChunkCache>>,
) -> Result<()> {
    // `0..file_size` (in `download_cold`), not `FileRange::full()`: xet fetches
    // files past 2 × 256 MiB in Range blocks either way (the server honors
    // Range on /v1/reconstructions), but the cap spares a past-EOF block request.
    let translator =
        build_translator_config(cfg, resolver::forge_refresher(raw, resolver::Scope::Read))?;
    let dest_file = tmp.reopen()?;
    let info_for_dl = info.clone();
    let pathname_owned = pathname.to_string();
    let stall_secs = cold_download_stall_secs();
    rt.bridge_sync(async move {
        let session = FileDownloadSession::new(Arc::new(translator), cache).await?;
        download_cold(
            &session,
            &info_for_dl,
            file_size,
            dest_file,
            &pathname_owned,
            stall_secs,
        )
        .await
    })
    .map_err(|e| anyhow!("xet runtime error: {e:?}"))?
}

/// Best-effort manifest fetch so subsequent checkouts hit the hot path;
/// failure only keeps the cache cold.
fn save_remote_manifest(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    cfg: &BaleConfig,
    git_dir: &Path,
    info: &XetFileInfo,
    file_id_hex: &str,
) {
    let merkle = match info.merkle_hash() {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("can't parse merkle hash from pointer ({file_id_hex}): {e}");
            return;
        }
    };
    let cfg_for_fetch = cfg.clone();
    let refresher = resolver::forge_refresher(raw, resolver::Scope::Read);
    let fetched =
        rt.bridge_sync(async move { fetch_manifest(&cfg_for_fetch, refresher, &merkle).await });
    match fetched {
        Ok(Ok(manifest)) => {
            if let Err(e) = manifest_cache::save(git_dir, file_id_hex, &manifest) {
                tracing::warn!("saving manifest for {file_id_hex}: {e}");
            }
        }
        Ok(Err(e)) => tracing::warn!("fetching manifest for {file_id_hex}: {e:?}"),
        Err(e) => tracing::warn!("xet runtime error fetching manifest: {e:?}"),
    }
}

fn smudge_cache_entry(
    pathname: &str,
    content_path: &Path,
    pointer_bytes: &[u8],
    file_size: u64,
    store: &Path,
) -> Option<clean_cache::CacheEntry> {
    let Ok(pointer) = std::str::from_utf8(pointer_bytes) else {
        tracing::debug!("smudge: refusing to cache non-utf8 pointer for {pathname}");
        return None;
    };
    match clean_cache::compute_chunks(content_path, file_size) {
        Ok(chunks) => Some(clean_cache::CacheEntry {
            v: clean_cache::CURRENT_VERSION,
            size: file_size,
            chunks,
            pointer: pointer.to_string(),
            store: store.to_string_lossy().into_owned(),
            store_id: store::store_id(store).ok().flatten(),
        }),
        Err(e) => {
            tracing::debug!(
                "smudge: compute_chunks failed for {pathname} at {}: {e}",
                content_path.display()
            );
            None
        }
    }
}

/// Lukewarm path (server mode only): bytes staged but not yet pushed, gated on
/// the per-file marker. `Ok(true)` only once the bytes in `tmp` are verified.
pub(crate) fn try_smudge_from_staging(
    rt: &Arc<XetRuntime>,
    git_dir: &Path,
    info: &XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<bool> {
    let file_id_hex = info.hash().to_string();
    if !file_is_staged(git_dir, &file_id_hex) {
        return Ok(false);
    }
    reset_tmp(tmp)?;
    match try_smudge_from_store(rt, &staging_root(git_dir), info, file_size, tmp) {
        Ok(true) if content_matches(tmp.path(), info, file_size)? => Ok(true),
        Ok(true) => {
            tracing::warn!(
                "staged reconstruction of {file_id_hex} failed verification; trying server"
            );
            Ok(false)
        }
        Ok(false) => Ok(false),
        Err(e) => {
            tracing::debug!("staging reconstruction failed for {file_id_hex}: {e:#}");
            Ok(false)
        }
    }
}

/// Local mode: reconstruct only from the durable store into `tmp`, verified.
/// No network, no auth, no silent fallback — a miss or bad bytes is a hard error.
pub(crate) fn smudge_from_local_store(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    info: &XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<()> {
    let file_id_hex = info.hash().to_string();
    let store = store::object_store_root(raw).context("resolving object store root")?;
    reset_tmp(tmp)?;
    let ok = try_smudge_from_store(rt, &store, info, file_size, tmp)
        .with_context(|| format!("reconstructing {file_id_hex} from local store"))?;
    let written = std::fs::metadata(tmp.path()).map(|m| m.len()).unwrap_or(0);
    if !ok || written != file_size {
        return Err(anyhow!(
            "local store at {} cannot reconstruct {} ({} of {} bytes); the object \
             data is missing — was this repo copied without its store, or the store pruned?",
            store.display(),
            file_id_hex,
            written,
            file_size
        ));
    }
    if !content_matches(tmp.path(), info, file_size)? {
        return Err(anyhow!(
            "local store at {} returned corrupt content for {file_id_hex} (sha256 mismatch); \
             refusing to serve it",
            store.display()
        ));
    }
    Ok(())
}

/// Unverified: callers check size + sha256. `Ok(false)` means the store dir
/// doesn't exist; other errors propagate so callers fall through (server mode)
/// or hard-error (local mode).
fn try_smudge_from_store(
    rt: &Arc<XetRuntime>,
    store: &Path,
    info: &XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<bool> {
    if !store.exists() {
        return Ok(false);
    }
    let translator =
        TranslatorConfig::local_config(store).context("building local TranslatorConfig")?;
    let dest_file = tmp.reopen()?;
    let info_for_dl = info.clone();
    rt.bridge_sync(async move {
        let session = FileDownloadSession::new(Arc::new(translator), None).await?;
        let (_id, _n) = session
            .download_to_writer(&info_for_dl, 0..file_size, dest_file)
            .await?;
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
    Ok(true)
}

fn passthrough_bytes<W: Write>(writer: &mut PktWriter<W>, bytes: &[u8]) -> Result<()> {
    w(writer.write_text_list(&["status=success"]))?;
    w(writer.write_all_then_flush(bytes))?;
    w(writer.write_text_list(&["status=success"]))
}

/// Stream `path` to git. Opened and size-checked BEFORE `status=success` so a
/// failure there is still reportable; a read error mid-stream follows the
/// protocol's mid-content error form (flush, then `status=error`) so git
/// discards the partial content instead of taking error text as file bytes.
fn finish_smudge<W: Write>(
    writer: &mut PktWriter<W>,
    path: &Path,
    expected_size: u64,
) -> Result<()> {
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("opening smudge output {}", path.display()))?;
    let len = f.metadata()?.len();
    if len != expected_size {
        return Err(anyhow!(
            "smudge output is {len} bytes, expected {expected_size}"
        ));
    }
    w(writer.write_text_list(&["status=success"]))?;
    let mut buf = vec![0u8; MAX_PKT_PAYLOAD];
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("reading smudge output {}: {e}", path.display());
                w(writer.flush_packet())?;
                return w(writer.write_text_list(&["status=error"]));
            }
        };
        if n == 0 {
            break;
        }
        w(writer.write_binary(&buf[..n]))?;
    }
    w(writer.flush_packet())?;
    w(writer.write_text_list(&["status=success"]))
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
