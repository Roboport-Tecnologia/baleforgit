//! `git-bale filter-process` — Git's long-running filter protocol over
//! pkt-line, wired to xet-core's `FileUploadSession` / `FileDownloadSession`.
//!
//! On `command=clean`, the payload is file content and we respond with the
//! pointer. On `command=smudge`, the payload is the pointer and we respond
//! with the reconstructed file content.

use std::io::{stdin, stdout, Read, Write};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tempfile::NamedTempFile;
use xet_client::chunk_cache::{get_cache, CacheConfig};
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::default_config;
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy};
use xet_runtime::core::XetRuntime;

use crate::config::BaleConfig;
use crate::local_reconstruct::{try_reconstruct_from_cache, CacheReconstructOutcome};
use crate::manifest_cache;
use crate::pktline::{PktReader, PktWriter, MAX_PKT_PAYLOAD};
use crate::pointer;
use crate::remote_manifest::fetch_manifest;
use crate::resolver;

const VERSION: &str = "version=2";

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = crate::config::RawConfig::load(Some(cwd.as_path()))?;
    let rt = XetRuntime::new().context("starting xet runtime")?;

    let stdin_lock = stdin().lock();
    let stdout_lock = stdout().lock();

    let mut reader = PktReader::new(stdin_lock);
    let mut writer = PktWriter::new(stdout_lock);

    handshake(&mut reader, &mut writer)?;
    negotiate_capabilities(&mut reader, &mut writer)?;

    // Auth is cached per scope. A single filter-process invocation typically
    // does only push or only fetch/checkout, so usually only one fills in.
    let mut clean_cfg: Option<BaleConfig> = None;
    let mut smudge_cfg: Option<BaleConfig> = None;

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

        // A panic or `?`-propagated error here would tank the whole git
        // operation. Report per-request failures as `status=error` pktlines so
        // Git can surface them and continue with the next entry.
        match command {
            "clean" => {
                if let Err(e) = do_clean(
                    &rt,
                    &raw,
                    &mut clean_cfg,
                    &mut reader,
                    &mut writer,
                    pathname,
                ) {
                    report_request_error(&mut reader, &mut writer, "clean", pathname, &e)?;
                }
            }
            "smudge" => {
                if let Err(e) = handle_smudge(
                    &rt,
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
    reader.read_binary_to(&mut sink)?;
    Ok(())
}

/// Report a per-request failure as a trailing `status=error` so Git rejects
/// this entry without us tearing down the whole filter-process. The error
/// chain is sent verbatim via `{e:#}`; callers must not put secrets in the
/// `anyhow::Error` chain (passwords, JWTs, the bale token).
///
/// `_reader` is held to make it clear at the call sites that the input
/// payload has already been consumed by the failing handler — re-draining
/// here would either block (input already at flush) or desync the stream.
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

fn do_clean<R: Read, W: Write>(
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    auth_slot: &mut Option<BaleConfig>,
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    pathname: &str,
) -> Result<()> {
    // Read the payload first so a later auth failure doesn't leave the
    // pkt-line stream desynced.
    let mut tmp = NamedTempFile::new()?;
    reader.read_binary_to(&mut tmp)?;
    tmp.flush()?;
    let cfg = resolve_cached(auth_slot, raw, rt, resolver::Scope::Write)?;
    handle_clean(rt, cfg, tmp, writer, pathname)
}

fn handle_clean<W: Write>(
    rt: &Arc<XetRuntime>,
    cfg: &BaleConfig,
    tmp: NamedTempFile,
    writer: &mut PktWriter<W>,
    _pathname: &str,
) -> Result<()> {
    // Spooling to a temp file lets us reuse the path-based `clean_file` API
    // and keeps `FileUploadSession::new` off the hot pkt-line loop.
    let translator = build_translator_config(cfg)?;
    let pointer_bytes = rt
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
    rt: &Arc<XetRuntime>,
    raw: &crate::config::RawConfig,
    auth_slot: &mut Option<BaleConfig>,
    reader: &mut PktReader<R>,
    writer: &mut PktWriter<W>,
    _pathname: &str,
) -> Result<()> {
    let mut pointer_buf = Vec::with_capacity(256);
    reader.read_binary_to(&mut pointer_buf)?;
    let info =
        pointer::parse_pointer(&pointer_buf).context("smudge: input is not a bale pointer")?;

    let file_size = info
        .file_size()
        .ok_or_else(|| anyhow!("bale pointer missing file_size"))?;
    // The pointer's `hash` field is a free-form String in xet-data with no
    // deserialization-time validation. Constraining it to lowercase hex here
    // keeps it safe to interpolate into the manifest cache path
    // (`<git-dir>/bale/manifests/<file_id_hex>.json`) — otherwise a crafted
    // pointer like `{"hash":"../../etc/passwd"}` would read/write outside the
    // git dir.
    let file_id_hex = info.hash().to_string();
    if !is_safe_file_id(&file_id_hex) {
        return Err(anyhow!(
            "bale pointer hash is not lowercase hex (got {} chars)",
            file_id_hex.len()
        ));
    }

    // Built from raw config so cache initialization never triggers auth
    // resolution (the hot path stays purely local).
    let cache_cfg = CacheConfig {
        cache_directory: raw.cache_dir.clone(),
        cache_size: rt.config().chunk_cache.size_bytes,
    };
    let chunk_cache = get_cache(&cache_cfg)
        .map_err(|e| anyhow!("init chunk cache at {}: {e}", raw.cache_dir.display()))?;

    // ---- Hot path: cache-only reconstruction ----------------------------
    let tmp = NamedTempFile::new()?;
    let cache_hit = if let Some(git_dir) = raw.git_dir.as_deref() {
        match manifest_cache::load(git_dir, &file_id_hex) {
            Ok(Some(manifest)) => {
                // Reopen by path so the async block owns its own File handle
                // and `tmp` stays usable for the byte-streaming below.
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

    // ---- Cold / lukewarm path: delegate to xet-data ---------------------
    if !cache_hit {
        // Discard any partial bytes from a failed hot-path attempt.
        let mut trunc = tmp.reopen()?;
        trunc.set_len(0)?;
        std::io::Seek::seek(&mut trunc, std::io::SeekFrom::Start(0))?;
        drop(trunc);

        let cfg = resolve_cached(auth_slot, raw, rt, resolver::Scope::Read)?;

        // The `0..file_size` range cap is load-bearing. xet-data's
        // `download_file` passes `FileRange::full()` (0..u64::MAX) into
        // `FileReconstructor`, and `ReconstructionTermManager` prefetches
        // up to `min_reconstruction_fetch_size` (default 256 MiB) past EOF.
        // baleforgit-server has no Range support on `/v1/reconstructions/*` (see
        // docs/ARCHITECTURE.md), so every prefetched block re-receives the
        // full-file terms — xet-data accumulates them, shifting
        // `cur_file_byte_offset` forward by 256 MiB each round and tripping
        // the SequentialWriter's contiguity check. Capping the range at
        // `file_size` skips the speculative prefetch entirely.
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

        // One extra small request per cold-path file; subsequent checkouts
        // hit the hot path. Best-effort — failure here only keeps the cache
        // cold, it doesn't fail the smudge.
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

    finish_smudge(writer, tmp.path())
}

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

/// MerkleHash is 32 bytes → 64 hex chars. We accept the canonical length only;
/// anything else is treated as a malformed/hostile pointer.
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

#[cfg(test)]
mod tests {
    use super::is_safe_file_id;

    #[test]
    fn is_safe_file_id_accepts_canonical_hex() {
        assert!(is_safe_file_id(&"0".repeat(64)));
        assert!(is_safe_file_id(&"f".repeat(64)));
        assert!(is_safe_file_id(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn is_safe_file_id_rejects_traversal() {
        assert!(!is_safe_file_id("../../etc/passwd"));
        assert!(!is_safe_file_id("/etc/passwd"));
        assert!(!is_safe_file_id("..\\..\\windows"));
    }

    #[test]
    fn is_safe_file_id_rejects_wrong_length() {
        assert!(!is_safe_file_id(""));
        assert!(!is_safe_file_id(&"a".repeat(63)));
        assert!(!is_safe_file_id(&"a".repeat(65)));
    }

    #[test]
    fn is_safe_file_id_rejects_uppercase_and_separators() {
        assert!(!is_safe_file_id(&"A".repeat(64)));
        let mut with_dot = "a".repeat(63);
        with_dot.push('.');
        assert!(!is_safe_file_id(&with_dot));
    }
}
