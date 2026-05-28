//! `git-bale filter-process` — Git's long-running filter protocol over
//! pkt-line, wired to xet-core's `FileUploadSession` / `FileDownloadSession`.

use std::io::{stdin, stdout, Read, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tempfile::NamedTempFile;
use xet_client::chunk_cache::{get_cache, CacheConfig};
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::default_config;
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy};
use xet_runtime::core::XetRuntime;

use crate::clean_cache::{self, PathKey};
use crate::config::BaleConfig;
use crate::local_reconstruct::{try_reconstruct_from_cache, CacheReconstructOutcome};
use crate::manifest_cache;
use crate::pktline::{PktReader, PktWriter, MAX_PKT_PAYLOAD};

// Per-callsite `read_binary_to` caps: defense against a peer forcing unbounded
// heap growth. Well above any real workload, not a protocol limit.
const SMUDGE_PAYLOAD_CAP: u64 = (pointer::POINTER_MAX_BYTES as u64) + 4096;
const CLEAN_PAYLOAD_CAP: u64 = 128 * 1024 * 1024 * 1024;
const DRAIN_PAYLOAD_CAP: u64 = 64 * 1024 * 1024;
use crate::pointer;
use crate::remote_manifest::fetch_manifest;
use crate::resolver;
use crate::staging::{file_is_staged, mark_file_staged, staging_root};

const VERSION: &str = "version=2";

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

    // Clean no longer needs auth — it writes to staging; upload is deferred to
    // `git-bale push-pending`. Only smudge resolves auth, cached for the process.
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

        // Per-request failures go out as `status=error` pktlines; a propagated
        // error would tear down the filter-process and tank the whole git op.
        match command {
            "clean" => {
                if let Err(e) = do_clean(&mut rt_slot, &raw, &mut reader, &mut writer, pathname) {
                    report_request_error(&mut reader, &mut writer, "clean", pathname, &e)?;
                }
            }
            "smudge" => {
                let rt = ensure_runtime(&mut rt_slot)?;
                if let Err(e) = handle_smudge(
                    rt,
                    &raw,
                    &mut smudge_cfg,
                    &mut reader,
                    &mut writer,
                    pathname,
                ) {
                    report_request_error(&mut reader, &mut writer, "smudge", pathname, &e)?;
                }
            }
            other => {
                drain_payload(&mut reader)?;
                let err_line = format!("error=unknown command \"{other}\"");
                writer.write_text_list(&["status=error", err_line.as_str()])?;
                writer.flush_packet()?;
            }
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
    Ok(slot.as_ref().unwrap())
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

fn drain_payload<R: Read>(reader: &mut PktReader<R>) -> Result<()> {
    let mut sink = std::io::sink();
    reader.read_binary_to(&mut sink, DRAIN_PAYLOAD_CAP)?;
    Ok(())
}

/// Error chain is sent verbatim via `{e:#}`; callers must not put secrets
/// (passwords, JWTs, the bale token) in the `anyhow::Error` chain. `_reader`
/// is held only to signal the payload was already consumed — re-draining would
/// block or desync the stream.
fn report_request_error<R: Read, W: Write>(
    _reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    op: &str,
    pathname: &str,
    e: &anyhow::Error,
) -> Result<()> {
    tracing::warn!("{op} failed for {pathname}: {e:#}");
    let err_line = format!("error={op} failed: {e:#}");
    writer.write_text_list(&["status=error", err_line.as_str()])?;
    writer.flush_packet()?;
    Ok(())
}

fn ensure_runtime(slot: &mut Option<Arc<XetRuntime>>) -> Result<&Arc<XetRuntime>> {
    if slot.is_none() {
        *slot = Some(XetRuntime::new().context("starting xet runtime")?);
    }
    Ok(slot.as_ref().unwrap())
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

enum CleanPayload {
    InMemory(Vec<u8>),
    Spilled(NamedTempFile),
}

fn drain_clean_payload<R: Read>(
    reader: &mut PktReader<R>,
    max_inline: usize,
) -> Result<(CleanPayload, u64)> {
    use crate::pktline::Packet;
    let mut buf: Vec<u8> = Vec::new();
    let mut spilled: Option<NamedTempFile> = None;
    let mut total: u64 = 0;
    loop {
        match reader.read_packet()? {
            Packet::Flush => break,
            Packet::Data(bytes) => {
                let n = bytes.len() as u64;
                if total.saturating_add(n) > CLEAN_PAYLOAD_CAP {
                    return Err(anyhow!(
                        "pkt-line payload exceeded cap of {CLEAN_PAYLOAD_CAP} bytes"
                    ));
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
                    "expected pkt-line data or flush in clean payload, got {other:?}"
                ));
            }
        }
    }
    let payload = if let Some(mut f) = spilled {
        f.flush()?;
        CleanPayload::Spilled(f)
    } else {
        CleanPayload::InMemory(buf)
    };
    Ok((payload, total))
}

fn do_clean<R: Read, W: Write>(
    rt_slot: &mut Option<Arc<XetRuntime>>,
    raw: &crate::config::RawConfig,
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    pathname: &str,
) -> Result<()> {
    let (payload, file_size) = drain_clean_payload(reader, max_inline_clean())?;

    let git_dir = raw.git_dir.as_deref().ok_or_else(|| {
        anyhow!("clean: cannot stage upload — no git directory resolved from cwd")
    })?;
    let cache_key = clean_cache::path_key(pathname);

    // `git status`/`git diff` re-invoke clean on every command for a modified
    // bale file; short-circuit on size, then sample-verify chunks.
    match clean_cache::load(git_dir, &cache_key) {
        Ok(Some(entry)) => {
            if entry.size != file_size {
                tracing::debug!(
                    "clean-cache size diverged for {pathname} (cached {} vs actual {file_size}); full clean",
                    entry.size
                );
            } else {
                let verified = match &payload {
                    CleanPayload::InMemory(buf) => {
                        Ok(clean_cache::verify_chunks_in_memory(&entry.chunks, buf))
                    }
                    CleanPayload::Spilled(tmp) => {
                        clean_cache::verify_chunks(&entry.chunks, tmp.path(), file_size)
                    }
                };
                match verified {
                    Ok(true) => {
                        writer.write_text_list(&["status=success"])?;
                        writer.write_all_then_flush(entry.pointer.as_bytes())?;
                        writer.write_text_list(&["status=success"])?;
                        return Ok(());
                    }
                    Ok(false) => {
                        tracing::debug!("clean-cache chunk mismatch for {pathname}; full clean");
                    }
                    Err(e) => tracing::debug!("clean-cache verify IO error: {e}; full clean"),
                }
            }
        }
        Ok(None) => {}
        Err(e) => tracing::debug!("clean-cache load failed for {pathname}: {e}; full clean"),
    }

    let rt = ensure_runtime(rt_slot)?;
    match payload {
        CleanPayload::InMemory(buf) => {
            handle_clean_in_memory(rt, git_dir, buf, writer, pathname, &cache_key, file_size)
        }
        CleanPayload::Spilled(tmp) => {
            handle_clean(rt, git_dir, tmp, writer, pathname, &cache_key, file_size)
        }
    }
}

/// In-memory variant of [`handle_clean`]: avoids the tmp-file write plus the
/// re-reads `clean_file`/`compute_chunks` would do, building the chunk index
/// from the buffer already in RAM.
fn handle_clean_in_memory<W: Write>(
    rt: &Arc<XetRuntime>,
    git_dir: &Path,
    bytes: Vec<u8>,
    writer: &mut PktWriter<W>,
    pathname: &str,
    cache_key: &PathKey,
    file_size: u64,
) -> Result<()> {
    crate::fs_util::create_bale_subdir(git_dir, "staging")
        .with_context(|| format!("creating staging dir under {}", git_dir.display()))?;
    let staging = staging_root(git_dir);
    let translator =
        TranslatorConfig::local_config(&staging).context("building local TranslatorConfig")?;
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

    if let Err(e) = mark_file_staged(git_dir, &file_hex, file_size) {
        tracing::warn!("failed to mark {file_hex} staged: {e}");
    }

    writer.write_text_list(&["status=success"])?;
    writer.write_all_then_flush(pointer_string.as_bytes())?;
    writer.write_text_list(&["status=success"])?;

    let entry = clean_cache::CacheEntry {
        v: clean_cache::CURRENT_VERSION,
        size: file_size,
        chunks,
        pointer: pointer_string,
    };
    if let Err(e) = clean_cache::save(git_dir, cache_key, &entry) {
        tracing::warn!("saving clean-cache entry for {pathname}: {e}");
    }

    Ok(())
}

fn handle_clean<W: Write>(
    rt: &Arc<XetRuntime>,
    git_dir: &Path,
    tmp: NamedTempFile,
    writer: &mut PktWriter<W>,
    pathname: &str,
    cache_key: &PathKey,
    file_size: u64,
) -> Result<()> {
    // Stage chunks/xorbs/shards locally via xet-data's LocalClient instead of
    // uploading; `git-bale push-pending` drains staging at push time.
    crate::fs_util::create_bale_subdir(git_dir, "staging")
        .with_context(|| format!("creating staging dir under {}", git_dir.display()))?;
    let staging = staging_root(git_dir);
    let translator =
        TranslatorConfig::local_config(&staging).context("building local TranslatorConfig")?;
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

    // Marker gates the lukewarm smudge fallback. Without it, a smudge for a
    // not-staged file_hash (e.g. `git stash`'s HEAD-restore) returns zero terms
    // and trips a `debug_assert_eq!` in xet-data's progress tracker. Best-effort:
    // a failed write only costs a cache miss on the next checkout-after-add.
    if let Err(e) = mark_file_staged(git_dir, &file_hex, file_size) {
        tracing::warn!("failed to mark {file_hex} staged: {e}");
    }

    // Respond before populating the cache so the pointer lands in the index
    // without waiting on best-effort cache work.
    writer.write_text_list(&["status=success"])?;
    writer.write_all_then_flush(pointer_string.as_bytes())?;
    writer.write_text_list(&["status=success"])?;

    // Best-effort chunk index for next time; `tmp` is still owned, so the file
    // is still on disk.
    match clean_cache::compute_chunks(&tmp_path, file_size) {
        Ok(chunks) => {
            let entry = clean_cache::CacheEntry {
                v: clean_cache::CURRENT_VERSION,
                size: file_size,
                chunks,
                pointer: pointer_string,
            };
            if let Err(e) = clean_cache::save(git_dir, cache_key, &entry) {
                tracing::warn!("saving clean-cache entry for {pathname}: {e}");
            }
        }
        Err(e) => tracing::warn!("computing chunk index for {pathname}: {e}"),
    }

    Ok(())
}

fn handle_smudge<R: Read, W: Write>(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    auth_slot: &mut Option<BaleConfig>,
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    pathname: &str,
) -> Result<()> {
    let mut pointer_buf = Vec::with_capacity(256);
    reader.read_binary_to(&mut pointer_buf, SMUDGE_PAYLOAD_CAP)?;
    let info =
        pointer::parse_pointer(&pointer_buf).context("smudge: input is not a bale pointer")?;

    let file_size = info
        .file_size()
        .ok_or_else(|| anyhow!("bale pointer missing file_size"))?;
    // The pointer's `hash` is a free-form String in xet-data; constrain it to
    // lowercase hex before interpolating into the manifest cache path, or a
    // crafted `{"hash":"../../etc/passwd"}` escapes the git dir.
    let file_id_hex = info.hash().to_string();
    if !is_safe_file_id(&file_id_hex) {
        return Err(anyhow!(
            "bale pointer hash is not lowercase hex (got {} chars)",
            file_id_hex.len()
        ));
    }

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

    // Hot path: cache-only reconstruction.
    let tmp = NamedTempFile::new()?;
    let cache_hit = if let Some(git_dir) = raw.git_dir.as_deref() {
        match manifest_cache::load(git_dir, &file_id_hex) {
            Ok(Some(manifest)) => {
                // Reopen so the async block owns its own handle and `tmp` stays
                // usable for the byte-streaming below.
                let dest_file = tmp.reopen()?;
                let rt_for_cache = rt.clone();
                let cache_for_cache = chunk_cache.clone();
                let outcome = rt
                    .bridge_sync(async move {
                        let mut dest = dest_file;
                        try_reconstruct_from_cache(
                            &rt_for_cache,
                            &cache_for_cache,
                            &manifest,
                            file_size,
                            &mut dest,
                        )
                        .await
                    })
                    .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
                matches!(outcome, CacheReconstructOutcome::Wrote(_))
            }
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    "reading cached manifest for {file_id_hex}: {e}; falling back to network"
                );
                false
            }
        }
    } else {
        false
    };

    // Lukewarm path: bytes still staged locally, not yet pushed. Gated on the
    // per-file marker — reconstructing without it trips a `debug_assert_eq!` in
    // xet-data on an empty term list (see `staging::mark_file_staged`).
    let staging_hit = if !cache_hit
        && raw
            .git_dir
            .as_deref()
            .is_some_and(|gd| file_is_staged(gd, &file_id_hex))
    {
        match try_smudge_from_staging(rt, raw, &info, file_size, &tmp) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::debug!("staging reconstruction failed for {file_id_hex}: {e:#}");
                false
            }
        }
    } else {
        false
    };

    // Cold path: delegate to xet-data.
    if !cache_hit && !staging_hit {
        // Discard any partial bytes from a failed hot-path attempt.
        let mut trunc = tmp.reopen()?;
        trunc.set_len(0)?;
        std::io::Seek::seek(&mut trunc, std::io::SeekFrom::Start(0))?;
        drop(trunc);

        let cfg = resolve_cached(auth_slot, raw, rt, resolver::Scope::Read)?;

        // The `0..file_size` range cap is load-bearing (do not pass
        // `FileRange::full()`). With full(), `ReconstructionTermManager`
        // prefetches up to 256 MiB past EOF, but baleforgit-server has no Range
        // support on `/v1/reconstructions/*` (see docs/ARCHITECTURE.md), so each
        // prefetch re-receives full-file terms, shifting `cur_file_byte_offset`
        // 256 MiB per round and tripping SequentialWriter's contiguity check.
        // Capping at `file_size` skips the speculative prefetch entirely.
        let translator = build_translator_config(cfg)?;
        let dest_file = tmp.reopen()?;
        let info_for_dl = info.clone();
        let cache_for_dl = chunk_cache.clone();
        rt.bridge_sync(async move {
            let session =
                FileDownloadSession::new(Arc::new(translator), Some(cache_for_dl)).await?;
            let (_id, _n) = session
                .download_to_writer(&info_for_dl, 0..file_size, dest_file)
                .await?;
            Ok::<(), anyhow::Error>(())
        })
        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

        // Best-effort manifest fetch so subsequent checkouts hit the hot path;
        // failure only keeps the cache cold.
        if let Some(git_dir) = raw.git_dir.as_deref() {
            let merkle = match info.merkle_hash() {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!("can't parse merkle hash from pointer ({file_id_hex}): {e}");
                    return finish_smudge(writer, tmp.path());
                }
            };
            let cfg_for_fetch = cfg.clone();
            let fetched =
                rt.bridge_sync(async move { fetch_manifest(&cfg_for_fetch, &merkle).await });
            match fetched {
                Ok(Ok(manifest)) => {
                    if let Err(e) = manifest_cache::save(git_dir, &file_id_hex, &manifest) {
                        tracing::warn!("saving manifest for {file_id_hex}: {e}");
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!("fetching manifest for {file_id_hex}: {e:?}");
                }
                Err(e) => {
                    tracing::warn!("xet runtime error fetching manifest: {e:?}");
                }
            }
        }
    }

    // We hold both sides of the content→pointer mapping (the pointer git gave
    // us, the bytes we reconstructed), so seed the clean cache to make the next
    // `git status`/`git diff` on this path hit without re-running CDC.
    if let Some(git_dir) = raw.git_dir.as_deref() {
        populate_clean_cache_from_smudge(git_dir, pathname, tmp.path(), &pointer_buf, file_size);
    }

    finish_smudge(writer, tmp.path())
}

fn populate_clean_cache_from_smudge(
    git_dir: &Path,
    pathname: &str,
    content_path: &Path,
    pointer_bytes: &[u8],
    file_size: u64,
) {
    let pointer = match std::str::from_utf8(pointer_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::debug!("smudge: refusing to cache non-utf8 pointer for {pathname}");
            return;
        }
    };
    let chunks = match clean_cache::compute_chunks(content_path, file_size) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                "smudge: compute_chunks failed for {pathname} at {}: {e}",
                content_path.display()
            );
            return;
        }
    };
    let entry = clean_cache::CacheEntry {
        v: clean_cache::CURRENT_VERSION,
        size: file_size,
        chunks,
        pointer,
    };
    let key = clean_cache::path_key(pathname);
    if let Err(e) = clean_cache::save(git_dir, &key, &entry) {
        tracing::debug!("smudge: saving clean-cache entry for {pathname}: {e}");
    }
}

/// Reconstruct from staging. `Ok(false)` means no usable staging dir; on-disk
/// errors propagate so the caller falls through to the cold path.
fn try_smudge_from_staging(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    info: &xet_data::processing::XetFileInfo,
    file_size: u64,
    tmp: &NamedTempFile,
) -> Result<bool> {
    let Some(git_dir) = raw.git_dir.as_deref() else {
        return Ok(false);
    };
    let staging = staging_root(git_dir);
    if !staging.exists() {
        return Ok(false);
    }
    let translator =
        TranslatorConfig::local_config(&staging).context("building local TranslatorConfig")?;
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

fn finish_smudge<W: Write>(writer: &mut PktWriter<W>, tmp_path: &Path) -> Result<()> {
    writer.write_text_list(&["status=success"])?;
    let mut f = std::fs::File::open(tmp_path)?;
    let mut buf = vec![0u8; MAX_PKT_PAYLOAD];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_binary(&buf[..n])?;
    }
    writer.flush_packet()?;
    writer.write_text_list(&["status=success"])?;
    Ok(())
}

/// MerkleHash is 32 bytes → 64 hex chars; reject any other length as hostile.
fn is_safe_file_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn build_translator_config(cfg: &BaleConfig) -> Result<TranslatorConfig> {
    Ok(default_config(
        cfg.server_url.clone(),
        Some((cfg.token.clone(), cfg.token_expiration)),
        None,
        None,
    )?)
}
