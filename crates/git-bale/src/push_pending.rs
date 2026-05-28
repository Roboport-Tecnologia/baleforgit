//! `git-bale push-pending` — drains the per-repo staging area to the bale
//! server.
//!
//! POSTing staged xorbs/shards verbatim would bypass the server's global dedup
//! (staging's dedup table is filesystem-local and knows nothing about the
//! server), re-uploading ~35 MiB of dupes for an 8-byte edit. Instead we
//! reconstruct each staged file from staging and re-translate it through an
//! online `FileUploadSession`, which queries server-known chunks and only POSTs
//! genuinely new xorbs/shards. Clean stays offline; the contract holds.
//!
//! Safe because xet's CDC is deterministic: the merkle hash out of the online
//! session must equal the marker's `file_hex`. We assert that and bail on
//! mismatch (version skew between clean and push-pending, or staging corruption).

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tempfile::NamedTempFile;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::{clean_file, default_config};
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::resolver;
use crate::staging::{
    clear_file_markers, list_staged_files, remove_all_staged_objects, remove_empty_dirs,
    staging_root,
};

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
        // No markers → nothing cleaned, or a prior run drained but left orphans.
        let _ = remove_empty_dirs(&staging);
        return Ok(());
    }

    let rt = XetRuntime::new().context("starting xet runtime")?;
    let raw_for_auth = raw.clone();
    let auth = rt
        .bridge_sync(async move { resolver::resolve(&raw_for_auth, resolver::Scope::Write).await })
        .map_err(|e| anyhow!("xet runtime error during Bale auth resolution: {e:?}"))??;

    // Online config = upload session (server dedup + POSTs); local config =
    // download session reading from staging/.
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
    let server_url = auth.server_url.clone();
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
    .map_err(|e| anyhow!("xet runtime error during push-pending: {e:?}"))?
    .map_err(|e| explain_dedup_cache_mismatch(e, &server_url))?;

    // Server now holds the reconstruction info; safe to drop staging.
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
    // Via a temp file because `clean_file` takes a path (it reads twice —
    // hashing then chunking — and needs random access), so we can't stream
    // download straight into upload.
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

    // Deterministic CDC means the hash must round-trip; a mismatch (corruption
    // or version skew) means aborting before uploading a shard that disagrees
    // with the committed pointer.
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

// Turn the opaque "400 Bad Request on /shards" that xet surfaces into an
// actionable diagnosis. The server rejects a shard whose CAS blocks name a xorb
// it doesn't hold; in push-pending that happens when our local xet dedup cache
// recorded a xorb as already uploaded and so skipped re-sending it, but the
// server no longer has it (its storage was reset or gc'd). xet erases the
// response body and hands us only status + URL, so we key on those — a /shards
// 400 here is overwhelmingly this case (a freshly round-tripped shard can't be
// malformed or oversized).
fn explain_dedup_cache_mismatch(err: anyhow::Error, server_url: &str) -> anyhow::Error {
    let chain = format!("{err:#}");
    let is_shards_400 =
        chain.contains("shards") && (chain.contains("400") || chain.contains("Bad Request"));
    if !is_shards_400 {
        return err;
    }
    // main()'s set_default_xet_cache_root() pins HF_XET_CACHE before any work,
    // so this is the directory xet actually used for this session's dedup.
    let current_cache_dir =
        std::env::var("HF_XET_CACHE").unwrap_or_else(|_| "~/.cache/bale/xet".to_string());
    err.context(format!(
        "push to {server_url} was rejected: the server is missing content this \
         push depends on. This almost always means your local cache is incompatible \
         with the server. Either clear the cache to continue or set a new cache directory. \
         Active cache directory: {current_cache_dir}. Set env var \"$BALE_XET_CACHE\" to override."
    ))
}
