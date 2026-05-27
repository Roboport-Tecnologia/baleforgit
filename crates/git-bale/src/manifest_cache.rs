//! Per-repo cache of reconstruction *terms* under
//! `<git-dir>/bale/manifests/<file_id_hex>.json`.
//!
//! Stores only `terms` (xorb hash + chunk-index-range), not the full
//! reconstruction response. The `fetch_info` URLs have a 10-minute TTL
//! (`SIGNATURE_TTL_SECS` in bale-server-http) and aren't safe to persist; the
//! terms list is content-addressed by `file_id` and immutable, so it stays
//! valid forever. Cache misses fall back to the server, which re-issues
//! fresh URLs.
//!
//! Writes are atomic (temp + rename) so a partial write never poisons the
//! cache for the next checkout.

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

/// `v` is the on-disk schema version; clients ignore manifests they don't
/// understand and overwrite them on the next cold path.
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

/// `Ok(None)` covers missing, malformed, *and* unknown-version manifests —
/// the caller treats them all as cold-path-and-overwrite.
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

/// Atomic write via temp + rename. The hand-rolled `<final>.tmp.<pid>` (over
/// `tempfile::NamedTempFile`) keeps the temp file in the target directory,
/// which is required for `rename` to be atomic on the same fs.
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
    fs::rename(&tmp, &final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample() -> CachedManifest {
        CachedManifest {
            v: CURRENT_VERSION,
            terms: vec![CachedTerm {
                xorb_hash: "abcd".into(),
                chunk_start: 0,
                chunk_end: 4,
                unpacked_length: 1024,
            }],
        }
    }

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        save(dir.path(), "ffee", &sample()).unwrap();
        let loaded = load(dir.path(), "ffee").unwrap().unwrap();
        assert_eq!(loaded.terms, sample().terms);
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempdir().unwrap();
        assert!(load(dir.path(), "ffee").unwrap().is_none());
    }

    #[test]
    fn malformed_returns_none() {
        let dir = tempdir().unwrap();
        let path = manifest_path(dir.path(), "ffee");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json").unwrap();
        assert!(load(dir.path(), "ffee").unwrap().is_none());
    }

    #[test]
    fn unknown_version_returns_none() {
        let dir = tempdir().unwrap();
        let path = manifest_path(dir.path(), "ffee");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, br#"{"v":999,"terms":[]}"#).unwrap();
        assert!(load(dir.path(), "ffee").unwrap().is_none());
    }
}
