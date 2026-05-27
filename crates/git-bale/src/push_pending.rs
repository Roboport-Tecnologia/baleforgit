//! `git-bale push-pending` — uploads any xorbs/shards staged under
//! `<git_dir>/bale/staging/` to the configured bale server.
//!
//! The clean filter writes to local staging instead of uploading directly, so
//! the actual network traffic only happens here. Invoked by the pre-push hook
//! that `git-bale install` writes.
//!
//! Both endpoints are content-addressed and idempotent: a partial run can be
//! re-run safely. We delete each local file only after the server returns 2xx.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use xet_core_structures::metadata_shard::MDBShardFile;
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::resolver::{self, ResolvedAuth};
use crate::staging::{clear_file_markers, staging_root};

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

    let xorb_files = find_files_matching(&staging, is_xorb_filename)?;
    let shard_files = find_files_matching(&staging, is_shard_filename)?;

    if xorb_files.is_empty() && shard_files.is_empty() {
        return Ok(());
    }

    let rt = XetRuntime::new().context("starting xet runtime")?;
    let raw_for_auth = raw.clone();
    let auth = rt
        .bridge_sync(async move { resolver::resolve(&raw_for_auth, resolver::Scope::Write).await })
        .map_err(|e| anyhow!("xet runtime error during Bale auth resolution: {e:?}"))??;
    let server_url = auth.server_url.trim_end_matches('/').to_string();

    let http = build_http_client()?;

    // Xorbs first — `/shards` rejects shards that reference unknown xorbs.
    for path in &xorb_files {
        upload_one_xorb(&rt, &http, &server_url, &auth, path)
            .with_context(|| format!("uploading xorb {}", path.display()))?;
    }
    for path in &shard_files {
        upload_one_shard(&rt, &http, &server_url, &auth, path)
            .with_context(|| format!("uploading shard {}", path.display()))?;
    }

    // Markers advertise "this file_hash is reconstructable from staging".
    // After a successful drain the bytes are gone, so drop the markers too.
    if let Err(e) = clear_file_markers(&git_dir) {
        tracing::warn!("clearing file markers in {}: {e}", staging.display());
    }

    // Best-effort: drop now-empty directories so subsequent runs see a clean
    // tree. Don't fail if a sibling process raced us.
    let _ = remove_empty_dirs(&staging);

    Ok(())
}

fn upload_one_xorb(
    rt: &Arc<XetRuntime>,
    http: &reqwest::Client,
    server_url: &str,
    auth: &ResolvedAuth,
    path: &Path,
) -> Result<()> {
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("non-utf8 xorb filename"))?;
    let hash_hex = filename
        .strip_prefix("default.")
        .ok_or_else(|| anyhow!("xorb filename does not start with `default.`: {filename}"))?
        .to_string();
    if !is_64_lower_hex(&hash_hex) {
        bail!("xorb filename hash component is not 64 lowercase hex chars: {filename}");
    }
    let body = std::fs::read(path)?;
    let url = format!("{server_url}/v1/xorbs/default/{hash_hex}");
    let token = auth.token.clone();
    let http = http.clone();
    rt.bridge_sync(async move {
        let resp = http
            .post(&url)
            .bearer_auth(&token)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            bail!("POST {url} returned {status}: {txt}");
        }
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
    std::fs::remove_file(path)
        .with_context(|| format!("removing staged xorb {}", path.display()))?;
    Ok(())
}

fn upload_one_shard(
    rt: &Arc<XetRuntime>,
    http: &reqwest::Client,
    server_url: &str,
    auth: &ResolvedAuth,
    path: &Path,
) -> Result<()> {
    let body = read_shard_without_footer(path)
        .with_context(|| format!("reading shard {}", path.display()))?;
    let url = format!("{server_url}/shards");
    let token = auth.token.clone();
    let http = http.clone();
    rt.bridge_sync(async move {
        let resp = http
            .post(&url)
            .bearer_auth(&token)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            bail!("POST {url} returned {status}: {txt}");
        }
        Ok::<(), anyhow::Error>(())
    })
    .map_err(|e| anyhow!("xet runtime error: {e:?}"))??;
    std::fs::remove_file(path)
        .with_context(|| format!("removing staged shard {}", path.display()))?;
    Ok(())
}

/// Strip the lookup tables + footer from an on-disk MDB shard so the bale
/// server's parser only sees `header | file_info | cas_info`. Mirrors
/// xet-data's private `read_shard_to_bytes_remove_footer`.
fn read_shard_without_footer(path: &Path) -> Result<Vec<u8>> {
    let shard = MDBShardFile::load_from_file(path)
        .map_err(|e| anyhow!("loading shard {}: {e}", path.display()))?;
    let split_at = shard.shard.metadata.file_lookup_offset as usize;
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; split_at];
    file.read_exact(&mut buf)?;

    // Rewrite `footer_size` (8 bytes at offset 40 = tag(32) + version(8)) to 0
    // so the receiver knows there is no footer to parse.
    if buf.len() < 48 {
        bail!("shard {} truncated below header size", path.display());
    }
    buf[40..48].copy_from_slice(&0u64.to_le_bytes());

    Ok(buf)
}

fn find_files_matching(
    root: &Path,
    predicate: impl Fn(&str) -> bool + Copy,
) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(root, &mut out, &predicate)?;
    out.sort();
    Ok(out)
}

fn walk(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    predicate: &(impl Fn(&str) -> bool + Copy),
) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("read_dir {}: {e}", dir.display())),
    };
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(&path, out, predicate)?;
        } else if ft.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if predicate(name) {
                    out.push(path);
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

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("git-bale/", env!("CARGO_PKG_VERSION")))
        // Shard POSTs can be slow on the server side for shards with many file
        // entries; xet-data uses a no-read-timeout client for the same reason.
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| anyhow!("building http client: {e}"))
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
