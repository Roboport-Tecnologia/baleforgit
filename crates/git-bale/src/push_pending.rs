//! `git-bale push-pending` — drains the per-repo staging area to the bale
//! server.
//!
//! Instead of POSTing the locally-staged xorbs/shards verbatim (which would
//! miss xet-data's global-dedup query path entirely — the whole staging dir
//! was produced by `TranslatorConfig::local_config`, which uses a
//! filesystem-backed dedup table that knows nothing about the server), we
//! reconstruct each staged file from local staging via a download session,
//! then **re-translate** it through an online `FileUploadSession`. The
//! online session does the proper dedup dance:
//!
//!   - for chunks already known to the server (via the eligibility-gated
//!     `GET /v1/chunks/{prefix}/{hash}` query), reuse the existing xorb
//!     terms — no new bytes uploaded;
//!   - for chunks the server doesn't know, pack them into new xorbs and
//!     `POST /v1/xorbs/default/{hash}` them;
//!   - shards built from the resulting per-file terms get `POST`ed to
//!     `/shards`.
//!
//! That keeps the "defer-uploads" contract intact (clean is still offline)
//! while preventing the bug where editing 8 bytes in a 35 MiB file uploads
//! ~35 MiB of duplicate xorbs every push.
//!
//! Re-translation is safe because xet's CDC is deterministic: the merkle
//! file hash that comes out of the online session must equal the file_hex
//! the clean filter recorded in the marker. We assert that and bail
//! loudly on mismatch — a divergence would indicate either xet-data version
//! skew between clean and push-pending or staging-side corruption.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tempfile::NamedTempFile;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::{clean_file, default_config};
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::resolver;
use crate::staging::{clear_file_markers, list_staged_files, staging_root};

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = RawConfig::load(Some(cwd.as_path()))?;
    let git_dir = raw
        .git_dir
        .clone()
        .ok_or_else(|| anyhow!("not inside a git repository"))?;
    let staging = staging_root(&git_dir);
    if !staging.exists() {
        return Ok(());
    }

    let staged_files = list_staged_files(&git_dir)
        .with_context(|| format!("listing staged files in {}", staging.display()))?;
    if staged_files.is_empty() {
        // No marker files → either nothing was cleaned, or a previous run
        // already drained the markers but left behind orphan objects. Clean
        // the empty tree as best-effort and exit.
        let _ = remove_empty_dirs(&staging);
        return Ok(());
    }

    let rt = XetRuntime::new().context("starting xet runtime")?;
    let raw_for_auth = raw.clone();
    let auth = rt
        .bridge_sync(async move { resolver::resolve(&raw_for_auth, resolver::Scope::Write).await })
        .map_err(|e| anyhow!("xet runtime error during Bale auth resolution: {e:?}"))??;

    // Online config drives the upload session (real RemoteClient — global
    // dedup query path + POSTs to /v1/xorbs and /shards). Local config
    // drives the download session (reads from staging/).
    let online_cfg = default_config(
        auth.server_url.trim_end_matches('/').to_string(),
        Some((auth.token.clone(), auth.token_expiration)),
        None,
        None,
    )
    .context("building online TranslatorConfig for push-pending")?;
    let local_cfg = TranslatorConfig::local_config(&staging)
        .context("building local TranslatorConfig for staging reconstruction")?;

    let staged_files_for_async = staged_files.clone();
    rt.bridge_sync(async move {
        let upload_session = FileUploadSession::new(Arc::new(online_cfg)).await?;
        let download_session = FileDownloadSession::new(Arc::new(local_cfg), None).await?;

        for (file_hex, file_size_opt) in &staged_files_for_async {
            let file_size = file_size_opt.ok_or_else(|| {
                anyhow!(
                    "staged marker for {file_hex} has no size — was it written by an \
                     older client? Run `git add` again to re-stage with a size."
                )
            })?;
            re_translate_one(
                &download_session,
                upload_session.clone(),
                file_hex,
                file_size,
            )
            .await
            .with_context(|| format!("re-translating staged file {file_hex}"))?;
        }
        upload_session.finalize().await?;
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error during push-pending: {e:?}"))??;

    // Past this point the server holds (at minimum) the file's
    // reconstruction info. Safe to drop staging.
    if let Err(e) = clear_file_markers(&git_dir) {
        tracing::warn!("clearing file markers in {}: {e}", staging.display());
    }
    if let Err(e) = remove_all_staged_objects(&staging) {
        tracing::warn!("removing staged objects under {}: {e}", staging.display());
    }
    let _ = remove_empty_dirs(&staging);

    Ok(())
}

async fn re_translate_one(
    download_session: &Arc<FileDownloadSession>,
    upload_session: Arc<FileUploadSession>,
    file_hex: &str,
    file_size: u64,
) -> Result<()> {
    // Reconstruct from the local staging into a temp file, then feed the
    // temp file to the online upload session. We can't stream straight from
    // download to upload because `clean_file` takes a path (it reads the
    // file twice — once for hashing, once for chunking — and needs random
    // access). For typical bale workloads (large opaque binaries) the
    // tempfile round-trip is cheap relative to the actual chunking.
    let tmp = NamedTempFile::new().context("creating temp file for re-translation")?;
    let info_for_dl = XetFileInfo::new(file_hex.to_string(), file_size);
    let writer = tmp
        .reopen()
        .context("reopening temp file for download write")?;
    let (_id, _n) = download_session
        .download_to_writer(&info_for_dl, 0..file_size, writer)
        .await
        .with_context(|| format!("local reconstruct of {file_hex} failed"))?;

    let (new_info, _metrics) = clean_file(upload_session, tmp.path(), Sha256Policy::Compute)
        .await
        .with_context(|| format!("re-cleaning {file_hex} through online session"))?;

    // Deterministic CDC means the hash must round-trip. A mismatch points
    // at a real corruption (or xet-data version skew between clean and
    // push-pending) — abort before uploading a shard that disagrees with
    // the pointer Git already committed.
    if new_info.hash() != file_hex {
        bail!(
            "re-translation produced file_hash {} but staged pointer said {} \
             — aborting push to keep the server's view consistent with Git's",
            new_info.hash(),
            file_hex,
        );
    }
    Ok(())
}

/// Recursively removes any `default.<hex>` (xorb) and `<hex>.mdb` (shard)
/// leaves under `staging`. Anything else (the `file-index/` dir, an empty
/// `xet/` tree) is left alone — `remove_empty_dirs` handles the cleanup.
fn remove_all_staged_objects(staging: &Path) -> std::io::Result<()> {
    let rd = match std::fs::read_dir(staging) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            remove_all_staged_objects(&path)?;
        } else if ft.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if is_xorb_filename(name) || is_shard_filename(name) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
    Ok(())
}

fn is_xorb_filename(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("default.") else {
        return false;
    };
    is_64_lower_hex(rest)
}

fn is_shard_filename(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".mdb") else {
        return false;
    };
    is_64_lower_hex(stem)
}

fn is_64_lower_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn remove_empty_dirs(root: &Path) -> std::io::Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let _ = remove_empty_dirs(&entry.path());
        }
    }
    // rmdir succeeds only when the directory is empty — exactly what we want.
    let _ = std::fs::remove_dir(root);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xorb_filename_recognition() {
        let h = "a".repeat(64);
        assert!(is_xorb_filename(&format!("default.{h}")));
        assert!(!is_xorb_filename(&format!("foo.{h}")));
        assert!(!is_xorb_filename(&format!("default.{}", "a".repeat(63))));
        assert!(!is_xorb_filename(&format!("default.{}.bak", h)));
    }

    #[test]
    fn shard_filename_recognition() {
        let h = "0".repeat(64);
        assert!(is_shard_filename(&format!("{h}.mdb")));
        assert!(!is_shard_filename("not-a-shard.txt"));
        assert!(!is_shard_filename(&format!("{}.mdb", "X".repeat(64))));
    }

    #[test]
    fn hex64_check_rejects_uppercase() {
        assert!(!is_64_lower_hex(&"A".repeat(64)));
        assert!(is_64_lower_hex(&"0".repeat(64)));
        assert!(!is_64_lower_hex(""));
    }
}
