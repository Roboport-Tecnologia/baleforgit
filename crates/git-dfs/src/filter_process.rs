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
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy};
use xet_runtime::core::XetContext;

use crate::config::DfsConfig;
use crate::pktline::{PktReader, PktWriter, MAX_PKT_PAYLOAD};
use crate::pointer;

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

    // Reconstruct into a temp file then stream that file's bytes through
    // pkt-line. We must pass an explicit `0..file_size` range here:
    // xet-data's `download_file` calls into `FileReconstructor` with
    // `FileRange::full()` (0..u64::MAX), and `ReconstructionTermManager`
    // prefetches up to `min_reconstruction_fetch_size` (default 256 MiB)
    // ahead of EOF. Our xet-server does not implement Range support on
    // `/v1/reconstructions/*` (see docs/ARCHITECTURE.md), so every prefetched
    // block re-receives the full-file terms — and xet-data accumulates them,
    // shifting `cur_file_byte_offset` forward by 256 MiB each round and
    // tripping the SequentialWriter's contiguity check. Capping the range
    // by the known file size avoids the speculative prefetch entirely.
    let file_size = info
        .file_size()
        .ok_or_else(|| anyhow!("dfs pointer missing file_size"))?;
    let translator = build_translator_config(ctx, cfg)?;
    let tmp = NamedTempFile::new()?;
    let dest_file = tmp.reopen()?;
    ctx.runtime
        .bridge_sync(async move {
            let session = FileDownloadSession::new(Arc::new(translator), None).await?;
            let (_id, _n) = session
                .download_to_writer(&info, 0..file_size, dest_file)
                .await?;
            Ok::<(), anyhow::Error>(())
        })
        .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;

    writer.write_text_list(&["status=success"])?;
    let mut f = std::fs::File::open(tmp.path())?;
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
