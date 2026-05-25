//! Per-repo cache of reconstruction *terms* (xorb hash + chunk-index-range),
//! living under `<git-dir>/dfs/manifests/<file_id_hex>.json`.
//!
//! Why we cache only the terms and not the full reconstruction response:
//! the response also contains presigned URLs in `fetch_info`, but those have
//! a 10-minute TTL (see `SIGNATURE_TTL_SECS` in `xet-server-http`). The
//! `terms` list, in contrast, is fully content-addressed by `file_id`
//! (the file's merkle hash from the pointer) and is immutable forever —
//! same file_id yields the same terms on every server. So persisting just
//! the terms is safe across days/months, and we re-derive the URLs only
//! when a chunk-cache miss forces us to call the server anyway.
//!
//! File layout under `.git/`:
//!
//! ```text
//!   .git/dfs/manifests/<file_id_hex>.json
//! ```
//!
//! Files are written atomically (temp + rename) so a partial write never
//! poisons the cache for the next checkout.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One reconstruction term, distilled to the content-addressed parts only.
/// Mirrors `xet_server_wire::CASReconstructionTerm` but with `start`/`end`
/// inlined (the wire type wraps a `RangeJson`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedTerm {
    /// Xorb hash in Xet hex encoding (what comes back from the wire).
    pub xorb_hash: String,
    /// Chunk index range start (inclusive).
    pub chunk_start: u32,
    /// Chunk index range end (exclusive).
    pub chunk_end: u32,
    /// Total uncompressed bytes covered by this term. Used as the expected
    /// length when reading from the chunk cache.
    pub unpacked_length: u64,
}

/// Persistent shape of a cached manifest. Versioned (`v`) so we can evolve
/// the layout without re-fetching every term — older clients can ignore
/// manifests with newer versions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedManifest {
    pub v: u32,
    pub terms: Vec<CachedTerm>,
}

pub const CURRENT_VERSION: u32 = 1;

/// `<git_dir>/dfs/manifests/`.
pub fn manifest_dir(git_dir: &Path) -> PathBuf {
    git_dir.join("dfs").join("manifests")
}

/// `<git_dir>/dfs/manifests/<file_id_hex>.json`.
pub fn manifest_path(git_dir: &Path, file_id_hex: &str) -> PathBuf {
    manifest_dir(git_dir).join(format!("{file_id_hex}.json"))
}

/// Returns `Ok(None)` if the manifest is missing, malformed, or written by a
/// newer version we don't understand — the caller treats those identically
/// (cold-path fetch and overwrite).
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

/// Writes the manifest atomically. Errors (permission, disk full, ...) are
/// surfaced to the caller, which should log and continue — a missing cache
/// just means the next checkout re-fetches.
pub fn save(git_dir: &Path, file_id_hex: &str, manifest: &CachedManifest) -> io::Result<()> {
    let dir = manifest_dir(git_dir);
    fs::create_dir_all(&dir)?;
    let final_path = manifest_path(git_dir, file_id_hex);

    // tempfile crate is already a dep; using it here would mean naming the
    // file in the right dir to keep the rename atomic on the same fs. A
    // hand-rolled `<final>.tmp.<pid>` keeps the dependency surface flat.
    let tmp = dir.join(format!("{file_id_hex}.json.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        let body = serde_json::to_vec_pretty(manifest)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        f.write_all(&body)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    // rename is atomic on the same filesystem; if it fails we leave the .tmp
    // behind rather than corrupting whatever was already there.
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
