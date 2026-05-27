//! Pointer-result cache for the `clean` filter.
//!
//! Git's status/diff machinery re-invokes the clean filter on every command
//! whenever the worktree file's stat differs from the index. For our
//! pipeline that's CDC + xorb + shard work per invocation — ~1-2 s for a
//! 30 MiB file. Since the pointer JSON is a pure function of the input
//! bytes, content-addressed caching turns the second-and-onward calls into
//! a blake3 pass + a file read, dropping `git status` back to the ms range.
//!
//! Layout: `<git_dir>/bale/clean-cache/<blake3_hex>` containing the raw
//! pointer bytes. Atomic temp+rename writes. No eviction — entries are
//! ~150 bytes; even 100k of them is ~15 MiB. `rm -rf .git/bale/clean-cache/`
//! is a safe manual reset.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub type ContentKey = blake3::Hash;

fn cache_dir(git_dir: &Path) -> PathBuf {
    git_dir.join("bale").join("clean-cache")
}

fn cache_path(git_dir: &Path, key: &ContentKey) -> PathBuf {
    cache_dir(git_dir).join(key.to_hex().as_str())
}

/// `Ok(None)` for missing entries; other IO errors propagate so the caller
/// can log and continue (a cache miss is always safe to fall back to).
pub fn load(git_dir: &Path, key: &ContentKey) -> io::Result<Option<Vec<u8>>> {
    let path = cache_path(git_dir, key);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomic write so a partial flush never poisons subsequent lookups.
pub fn save(git_dir: &Path, key: &ContentKey, pointer_bytes: &[u8]) -> io::Result<()> {
    let dir = cache_dir(git_dir);
    fs::create_dir_all(&dir)?;
    let hex = key.to_hex();
    let final_path = dir.join(hex.as_str());
    let tmp = dir.join(format!("{hex}.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(pointer_bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &final_path)
}

/// Forwards writes to both an inner writer and a blake3 hasher so reading
/// the pkt-line payload into a temp file also yields a content key for the
/// cache lookup — no extra disk pass.
pub struct TeeHasher<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> TeeHasher<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    pub fn finalize(self) -> (W, ContentKey) {
        (self.inner, self.hasher.finalize())
    }
}

impl<W: Write> Write for TeeHasher<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        let key = blake3::hash(b"hello");
        assert!(load(dir.path(), &key).unwrap().is_none());
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempdir().unwrap();
        let key = blake3::hash(b"some content");
        let pointer = b"{\"hash\":\"...\",\"file_size\":1024}";
        save(dir.path(), &key, pointer).unwrap();
        let got = load(dir.path(), &key).unwrap().unwrap();
        assert_eq!(got, pointer);
    }

    #[test]
    fn different_keys_independent() {
        let dir = tempdir().unwrap();
        let k1 = blake3::hash(b"a");
        let k2 = blake3::hash(b"b");
        save(dir.path(), &k1, b"p1").unwrap();
        save(dir.path(), &k2, b"p2").unwrap();
        assert_eq!(load(dir.path(), &k1).unwrap().unwrap(), b"p1");
        assert_eq!(load(dir.path(), &k2).unwrap().unwrap(), b"p2");
    }

    #[test]
    fn tee_hasher_matches_plain_hash() {
        let mut buf = Vec::new();
        let mut tee = TeeHasher::new(&mut buf);
        tee.write_all(b"hello ").unwrap();
        tee.write_all(b"world").unwrap();
        let (_, key) = tee.finalize();
        assert_eq!(key, blake3::hash(b"hello world"));
        assert_eq!(buf, b"hello world");
    }
}
