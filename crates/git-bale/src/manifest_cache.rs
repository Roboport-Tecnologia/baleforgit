//! Per-repo cache of reconstruction *terms* under
//! `<git-dir>/bale/manifests/<file_id_hex>.json`.
//!
//! Only `terms` are stored: they're immutable per `file_id`, while the
//! `fetch_info` URLs expire after the server's `SIGNATURE_TTL_SECS` (10 min).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// `bale_server_wire::CASReconstructionTerm` with `start`/`end` inlined.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedTerm {
    pub xorb_hash: String,
    pub chunk_start: u32,
    pub chunk_end: u32,
    pub unpacked_length: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedManifest {
    pub v: u32,
    pub terms: Vec<CachedTerm>,
}

pub const CURRENT_VERSION: u32 = 1;

pub fn manifest_dir(git_dir: &Path) -> PathBuf {
    git_dir.join("bale").join("manifests")
}

pub fn manifest_path(git_dir: &Path, file_id_hex: &str) -> PathBuf {
    manifest_dir(git_dir).join(format!("{file_id_hex}.json"))
}

/// `Ok(None)` for missing, malformed, or unknown-version manifests: all mean
/// cold path and overwrite.
pub fn load(git_dir: &Path, file_id_hex: &str) -> io::Result<Option<CachedManifest>> {
    let path = manifest_path(git_dir, file_id_hex);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let manifest: CachedManifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if manifest.v != CURRENT_VERSION {
        return Ok(None);
    }
    Ok(Some(manifest))
}

/// Temp lives in the target dir so the rename is atomic (same fs).
pub fn save(git_dir: &Path, file_id_hex: &str, manifest: &CachedManifest) -> io::Result<()> {
    crate::fs_util::create_bale_subdir(git_dir, "manifests")?;
    let dir = manifest_dir(git_dir);
    let final_path = manifest_path(git_dir, file_id_hex);

    let tmp = dir.join(format!("{file_id_hex}.json.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        let body = serde_json::to_vec_pretty(manifest)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        f.write_all(&body)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &final_path)?;
    crate::fs_util::fsync_dir(&dir)
}

/// For a manifest whose reconstruction failed verification: the next smudge
/// refetches terms from the server.
pub fn remove(git_dir: &Path, file_id_hex: &str) -> io::Result<()> {
    match fs::remove_file(manifest_path(git_dir, file_id_hex)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
