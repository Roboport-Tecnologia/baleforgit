//! Implementation of `git-dfs filter-process` — Git's long-running filter
//! protocol. Loosely modeled after git-lfs's `commands/command_filter_process.go`
//! and `git/filter_process_scanner.go`, but in Rust over pkt-line and wired to
//! xet-core's `FileUploadSession` / `FileDownloadSession` instead of git-lfs's
//! transfer queue.
//!
//! Per-request wire shape (Git side ↔ filter side):
//!
//! ```text
//! → key=value header packets, flush
//! → payload data packets, flush
//! ← "status=success", flush
//! ← payload data packets, flush
//! ← "status=success" (or "status=error"), flush
//! ```
//!
//! On `command=clean`, payload is file content and we respond with the pointer.
//! On `command=smudge`, payload is the pointer and we respond with the
//! reconstructed file content.

use std::io::{stdin, stdout, Read, Write};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tempfile::NamedTempFile;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::default_config;
use xet_data::processing::{
    get_cache, CacheConfig, FileDownloadSession, FileUploadSession, Sha256Policy,
};
use xet_runtime::core::XetContext;

use crate::config::DfsConfig;
use crate::local_reconstruct::{try_reconstruct_from_cache, CacheReconstructOutcome};
use crate::manifest_cache;
use crate::pktline::{PktReader, PktWriter, MAX_PKT_PAYLOAD};
use crate::pointer;
use crate::remote_manifest::fetch_manifest;

const VERSION: &str = "version=2";

pub fn run() -> Result<()> {
    let cfg = DfsConfig::load(Some(std::env::current_dir()?.as_path()))?;
    let ctx = XetContext::default().context("starting xet runtime")?;

    let stdin_lock = stdin().lock();
    let stdout_lock = stdout().lock();

    let mut reader = PktReader::new(stdin_lock);
    let mut writer = PktWriter::new(stdout_lock);

    handshake(&mut reader, &mut writer)?;
    negotiate_capabilities(&mut reader, &mut writer)?;

    loop {
        let headers = match reader.read_text_list() {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if headers.is_empty() {
            // Git closes its side of the pipe with no more headers — done.
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

        match command {
            "clean" => handle_clean(&ctx, &cfg, &mut reader, &mut writer, pathname)?,
            "smudge" => handle_smudge(&ctx, &cfg, &mut reader, &mut writer, pathname)?,
            other => {
                // Drain payload before responding so the stream stays in sync.
                drain_payload(&mut reader)?;
                let err_line = format!("error=unknown command \"{other}\"");
                writer.write_text_list(&["status=error", err_line.as_str()])?;
                writer.flush_packet()?;
            }
        }
    }
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
    reader.read_binary_to(&mut sink)?;
    Ok(())
}

fn handle_clean<R: Read, W: Write>(
    ctx: &XetContext,
    cfg: &DfsConfig,
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    _pathname: &str,
) -> Result<()> {
    // Spool the incoming bytes to a temp file. We could stream straight into
    // `start_clean` + `add_data`, but spooling lets us reuse the path-based
    // `clean_file` API and keeps the upload session creation off the hot
    // pkt-line loop.
    let mut tmp = NamedTempFile::new()?;
    reader.read_binary_to(&mut tmp)?;
    tmp.flush()?;

    let translator = build_translator_config(ctx, cfg)?;
    let pointer_bytes = ctx
        .runtime
        .bridge_sync(async move {
            let session = FileUploadSession::new(Arc::new(translator)).await?;
            let (info, _metrics) = xet_data::processing::data_client::clean_file(
                session.clone(),
                tmp.path(),
                Sha256Policy::Compute,
            )
            .await?;
            session.finalize().await?;
            pointer::encode_pointer(&info).map_err(anyhow::Error::from)
        })
        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

    writer.write_text_list(&["status=success"])?;
    writer.write_all_then_flush(&pointer_bytes)?;
    writer.write_text_list(&["status=success"])?;
    Ok(())
}

fn handle_smudge<R: Read, W: Write>(
    ctx: &XetContext,
    cfg: &DfsConfig,
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    _pathname: &str,
) -> Result<()> {
    let mut pointer_buf = Vec::with_capacity(256);
    reader.read_binary_to(&mut pointer_buf)?;
    let info =
        pointer::parse_pointer(&pointer_buf).context("smudge: input is not a dfs pointer")?;

    let file_size = info
        .file_size()
        .ok_or_else(|| anyhow!("dfs pointer missing file_size"))?;
    let file_id_hex = info.hash().to_string();

    // Shared chunk cache, used by both the hot (cache-only) path and the
    // fallback path (which lets xet-data populate it).
    let cache_cfg = CacheConfig {
        cache_directory: cfg.cache_dir.clone(),
        cache_size: ctx.config.chunk_cache.size_bytes,
    };
    let chunk_cache = get_cache(&ctx.config, &cache_cfg)
        .map_err(|e| anyhow!("init chunk cache at {}: {e}", cfg.cache_dir.display()))?;

    // ---- Hot path: cache-only reconstruction -----------------------------
    // If we have a cached manifest *and* every chunk it references is in the
    // local chunk cache, assemble the file without touching the network.
    let tmp = NamedTempFile::new()?;
    let cache_hit = if let Some(git_dir) = cfg.git_dir.as_deref() {
        match manifest_cache::load(git_dir, &file_id_hex) {
            Ok(Some(manifest)) => {
                // Reopen via the path so the async block owns its own File
                // handle without moving `tmp` — `tmp` is still used below to
                // stream bytes back to git after we're done.
                let dest_file = tmp.reopen()?;
                let ctx_for_cache = ctx.clone();
                let cache_for_cache = chunk_cache.clone();
                let outcome = ctx
                    .runtime
                    .bridge_sync(async move {
                        let mut dest = dest_file;
                        try_reconstruct_from_cache(
                            &ctx_for_cache,
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

    // ---- Cold / lukewarm path: delegate to xet-data ----------------------
    // Either we had no cached manifest, or a chunk was missing. Reset the
    // temp file (a partial cache-only write may be in it) and let
    // FileDownloadSession do the full thing, populating the chunk cache as
    // a side effect.
    if !cache_hit {
        // Truncate any partial bytes from a failed cache-only attempt. We
        // reopen via the path so we don't have to thread `&mut tmp` around.
        let mut trunc = tmp.reopen()?;
        trunc.set_len(0)?;
        std::io::Seek::seek(&mut trunc, std::io::SeekFrom::Start(0))?;
        drop(trunc);

        // We must pass an explicit `0..file_size` range here. xet-data's
        // `download_file` calls into `FileReconstructor` with
        // `FileRange::full()` (0..u64::MAX), and `ReconstructionTermManager`
        // prefetches up to `min_reconstruction_fetch_size` (default 256 MiB)
        // ahead of EOF. Our xet-server does not implement Range support on
        // `/v1/reconstructions/*` (see docs/ARCHITECTURE.md), so every
        // prefetched block re-receives the full-file terms — and xet-data
        // accumulates them, shifting `cur_file_byte_offset` forward by 256
        // MiB each round and tripping the SequentialWriter's contiguity
        // check. Capping the range by the known file size avoids the
        // speculative prefetch entirely.
        let translator = build_translator_config(ctx, cfg)?;
        let dest_file = tmp.reopen()?;
        let info_for_dl = info.clone();
        let cache_for_dl = chunk_cache.clone();
        ctx.runtime
            .bridge_sync(async move {
                let session =
                    FileDownloadSession::new(Arc::new(translator), Some(cache_for_dl)).await?;
                let (_id, _n) = session
                    .download_to_writer(&info_for_dl, 0..file_size, dest_file)
                    .await?;
                Ok::<(), anyhow::Error>(())
            })
            .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

        // Cold path only: refresh `.git/dfs/manifests/<file_id>.json` so the
        // next checkout can take the hot path. This is one extra small HTTP
        // request per file on first encounter; subsequent checkouts pay
        // nothing. Best-effort — a failure here only means the cache stays
        // cold, not that the smudge fails.
        if let Some(git_dir) = cfg.git_dir.as_deref() {
            let merkle = match info.merkle_hash() {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!("can't parse merkle hash from pointer ({file_id_hex}): {e}");
                    return finish_smudge(writer, tmp.path());
                }
            };
            let ctx_for_fetch = ctx.clone();
            let cfg_for_fetch = cfg.clone();
            let fetched = ctx.runtime.bridge_sync(async move {
                fetch_manifest(&ctx_for_fetch, &cfg_for_fetch, &merkle).await
            });
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

    finish_smudge(writer, tmp.path())
}

/// Streams the temp file's bytes back through pkt-line and writes the
/// terminating `status=success` packets.
fn finish_smudge<W: Write>(writer: &mut PktWriter<W>, tmp_path: &std::path::Path) -> Result<()> {
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

fn build_translator_config(ctx: &XetContext, cfg: &DfsConfig) -> Result<TranslatorConfig> {
    Ok(default_config(
        ctx,
        cfg.server_url.clone(),
        Some((cfg.token.clone(), cfg.token_expiration)),
        None,
        None,
    )?)
}
