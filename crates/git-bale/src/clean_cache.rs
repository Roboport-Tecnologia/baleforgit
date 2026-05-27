//! Per-clean cache. Keyed by `blake3(pathname)` and verified by
//! `(size, chunked_hashes)` rather than a single full-file blake3.
//!
//! ### Why chunked?
//!
//! `git status` and `git diff` invoke the clean filter on every command for
//! any modified bale-filtered file. Hashing the entire file up front meant
//! we always paid `O(file_size)` time even when the file had been changed
//! and the cache was about to miss anyway. With chunked verification:
//!
//! 1. **Size check first.** Different size → guaranteed miss; we skip
//!    reading the rest entirely and go straight to a full clean.
//! 2. **Priority chunk order.** First chunk + last chunk + a random sample
//!    of middle chunks are checked before the rest. Edits cluster at file
//!    head/tail (headers, appends) in practice, so this catches the
//!    majority of mismatches in a few hundred microseconds.
//! 3. **Concurrent verification.** A small thread pool hashes chunks in
//!    parallel, sharing an `AtomicBool` so the first mismatch shorts every
//!    other worker.
//!
//! Net effect: cache *misses* on large modified files now bail out in
//! ~milliseconds instead of `O(file_size)`; cache *hits* still hash every
//! chunk for correctness (you can't trust a sample-only positive) but the
//! parallelism roughly matches blake3's own internal SIMD throughput.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Chunk size for the index. 1 MiB chosen so an 1 GiB file still indexes
/// in ~1024 chunks (~64 KiB serialized) while leaving plenty of room for
/// early-exit on small files.
const CHUNK_SIZE: u64 = 1 << 20;
pub const CURRENT_VERSION: u32 = 2;
/// How many random middle-chunks to check *before* the rest. 3 is enough
/// to catch most middle edits before the linear sweep.
const MIDDLE_SAMPLES: usize = 3;
/// Worker count for parallel chunk hashing. blake3 already uses internal
/// SIMD parallelism per hash, so this is roughly the sweet spot for
/// 1 MiB chunks on a 4-8 core box.
const VERIFY_PARALLELISM: usize = 3;

pub type PathKey = blake3::Hash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CacheEntry {
    /// Schema version. Older entries are treated as a cache miss.
    pub v: u32,
    /// Size of the source file when the entry was written.
    pub size: u64,
    /// Ordered, contiguous chunks covering `[0, size)`.
    pub chunks: Vec<Chunk>,
    /// Pointer JSON to return on a cache hit. Stored verbatim including
    /// the trailing newline so we can stream it back to git without
    /// re-encoding.
    pub pointer: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Chunk {
    pub start: u64,
    pub end: u64,
    /// blake3 of `[start..end]`, hex-encoded so the cache file stays
    /// hand-readable for debugging.
    pub hash: String,
}

/// Hash the file pathname (as Git sends it) into the cache directory's
/// filename so we don't have to deal with path-character escaping.
pub fn path_key(pathname: &str) -> PathKey {
    blake3::hash(pathname.as_bytes())
}

fn cache_dir(git_dir: &Path) -> PathBuf {
    git_dir.join("bale").join("clean-cache")
}

fn cache_path(git_dir: &Path, key: &PathKey) -> PathBuf {
    cache_dir(git_dir).join(key.to_hex().as_str())
}

/// `Ok(None)` covers missing, malformed, or unknown-version entries.
pub fn load(git_dir: &Path, key: &PathKey) -> io::Result<Option<CacheEntry>> {
    let path = cache_path(git_dir, key);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let entry: CacheEntry = match serde_json::from_slice(&bytes) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    if entry.v != CURRENT_VERSION {
        return Ok(None);
    }
    Ok(Some(entry))
}

/// Atomic write via temp + rename so a partial flush never poisons lookups.
pub fn save(git_dir: &Path, key: &PathKey, entry: &CacheEntry) -> io::Result<()> {
    let dir = cache_dir(git_dir);
    fs::create_dir_all(&dir)?;
    let hex = key.to_hex();
    let final_path = dir.join(hex.as_str());
    let tmp = dir.join(format!("{hex}.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        let body =
            serde_json::to_vec(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &final_path)
}

/// Build the chunk index by hashing `path` in 1 MiB blocks. Returns one
/// zero-length chunk for empty files so verify always has at least one
/// fingerprint to compare against.
pub fn compute_chunks(path: &Path, size: u64) -> io::Result<Vec<Chunk>> {
    let mut file = fs::File::open(path)?;
    let chunk_count = size.div_ceil(CHUNK_SIZE).max(1) as usize;
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    let mut pos = 0u64;
    while pos < size {
        let remaining = size - pos;
        let to_read = remaining.min(CHUNK_SIZE) as usize;
        file.read_exact(&mut buf[..to_read])?;
        let hash = blake3::hash(&buf[..to_read]);
        chunks.push(Chunk {
            start: pos,
            end: pos + to_read as u64,
            hash: hash.to_hex().to_string(),
        });
        pos += to_read as u64;
    }
    if chunks.is_empty() {
        chunks.push(Chunk {
            start: 0,
            end: 0,
            hash: blake3::hash(b"").to_hex().to_string(),
        });
    }
    Ok(chunks)
}

/// Verify the contents of `path` match every fingerprint in `cached`.
/// Workers race on a shared `AtomicBool` and bail at the first mismatch.
pub fn verify_chunks(cached: &[Chunk], path: &Path, file_size: u64) -> io::Result<bool> {
    if cached.is_empty() {
        return Ok(false);
    }
    // Reject entries whose chunks don't fully cover the file: defensive against
    // a partial cache write or a truncated source.
    let covered: u64 = cached.iter().map(|c| c.end - c.start).sum();
    if covered != file_size {
        return Ok(false);
    }

    let order = priority_order(cached.len());
    let mismatch = AtomicBool::new(false);
    let stripe_size = order.len().div_ceil(VERIFY_PARALLELISM).max(1);

    std::thread::scope(|scope| {
        for stripe in order.chunks(stripe_size) {
            let stripe = stripe.to_vec();
            let mismatch_ref = &mismatch;
            scope.spawn(move || {
                if let Err(e) = verify_stripe(path, cached, &stripe, mismatch_ref) {
                    tracing::debug!("chunk verify IO error on {}: {e}", path.display());
                    mismatch_ref.store(true, Ordering::Relaxed);
                }
            });
        }
    });

    Ok(!mismatch.load(Ordering::Relaxed))
}

fn verify_stripe(
    path: &Path,
    cached: &[Chunk],
    indices: &[usize],
    mismatch: &AtomicBool,
) -> io::Result<()> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::with_capacity(CHUNK_SIZE as usize);
    for &idx in indices {
        if mismatch.load(Ordering::Relaxed) {
            return Ok(());
        }
        let c = &cached[idx];
        let len = (c.end - c.start) as usize;
        if buf.len() < len {
            buf.resize(len, 0);
        }
        file.seek(SeekFrom::Start(c.start))?;
        file.read_exact(&mut buf[..len])?;
        let actual = blake3::hash(&buf[..len]);
        if actual.to_hex().as_str() != c.hash {
            mismatch.store(true, Ordering::Relaxed);
            return Ok(());
        }
    }
    Ok(())
}

/// Index ordering for verification: first, last, then a small random middle
/// sample, then the rest. The bail-out heuristic is that edits near the
/// head/tail of a file (headers, appended log lines) are far more common
/// than uniform random edits.
fn priority_order(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    if n <= 2 {
        return (0..n).collect();
    }
    let first = 0usize;
    let last = n - 1;
    let mut middle: Vec<usize> = (1..n - 1).collect();

    // Cheap xorshift; we just need *some* permutation per call. Seeded
    // from system nanoseconds and pid so two filter-process invocations
    // for the same file aren't lockstep.
    let mut state: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        .wrapping_add(std::process::id() as u64);
    if state == 0 {
        state = 1;
    }
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for i in (1..middle.len()).rev() {
        let j = (next() as usize) % (i + 1);
        middle.swap(i, j);
    }

    let mut order = Vec::with_capacity(n);
    order.push(first);
    order.push(last);
    let sample_take = middle.len().min(MIDDLE_SAMPLES);
    order.extend(middle.iter().take(sample_take).copied());
    order.extend(middle.iter().skip(sample_take).copied());
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_entry(size: u64, chunks: Vec<Chunk>, pointer: &str) -> CacheEntry {
        CacheEntry {
            v: CURRENT_VERSION,
            size,
            chunks,
            pointer: pointer.to_string(),
        }
    }

    #[test]
    fn missing_load_is_none() {
        let dir = tempdir().unwrap();
        let key = path_key("some/file");
        assert!(load(dir.path(), &key).unwrap().is_none());
    }

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        let key = path_key("foo.bin");
        let entry = dummy_entry(
            12,
            vec![Chunk {
                start: 0,
                end: 12,
                hash: blake3::hash(b"hello world!").to_hex().to_string(),
            }],
            "{\"hash\":\"abc\",\"file_size\":12}\n",
        );
        save(dir.path(), &key, &entry).unwrap();
        let got = load(dir.path(), &key).unwrap().unwrap();
        assert_eq!(got.size, 12);
        assert_eq!(got.pointer, entry.pointer);
        assert_eq!(got.chunks.len(), 1);
    }

    #[test]
    fn older_version_is_invisible() {
        let dir = tempdir().unwrap();
        let key = path_key("foo.bin");
        let dir_path = cache_dir(dir.path());
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(cache_path(dir.path(), &key), br#"{"v":1,"size":0}"#).unwrap();
        assert!(load(dir.path(), &key).unwrap().is_none());
    }

    #[test]
    fn compute_then_verify_round_trips() {
        let dir = tempdir().unwrap();
        // ~3.5 MiB so we get 4 chunks (3 full + 1 partial).
        let body: Vec<u8> = (0..3_500_000u32).map(|i| (i & 0xff) as u8).collect();
        let path = dir.path().join("data.bin");
        fs::write(&path, &body).unwrap();
        let chunks = compute_chunks(&path, body.len() as u64).unwrap();
        assert_eq!(chunks.len(), 4);
        assert!(verify_chunks(&chunks, &path, body.len() as u64).unwrap());
    }

    #[test]
    fn verify_detects_first_chunk_mismatch() {
        let dir = tempdir().unwrap();
        let body: Vec<u8> = vec![0u8; 2_500_000];
        let path = dir.path().join("data.bin");
        fs::write(&path, &body).unwrap();
        let mut chunks = compute_chunks(&path, body.len() as u64).unwrap();
        // Corrupt chunk 0's hash.
        chunks[0].hash = blake3::hash(b"bogus").to_hex().to_string();
        assert!(!verify_chunks(&chunks, &path, body.len() as u64).unwrap());
    }

    #[test]
    fn verify_detects_last_chunk_mismatch() {
        let dir = tempdir().unwrap();
        let body: Vec<u8> = vec![1u8; 2_500_000];
        let path = dir.path().join("data.bin");
        fs::write(&path, &body).unwrap();
        let mut chunks = compute_chunks(&path, body.len() as u64).unwrap();
        let last = chunks.len() - 1;
        chunks[last].hash = blake3::hash(b"bogus").to_hex().to_string();
        assert!(!verify_chunks(&chunks, &path, body.len() as u64).unwrap());
    }

    #[test]
    fn verify_rejects_size_mismatch() {
        let dir = tempdir().unwrap();
        let body: Vec<u8> = vec![2u8; 1_500_000];
        let path = dir.path().join("data.bin");
        fs::write(&path, &body).unwrap();
        let chunks = compute_chunks(&path, body.len() as u64).unwrap();
        // Lie about the size — total covered bytes won't match.
        assert!(!verify_chunks(&chunks, &path, body.len() as u64 + 1).unwrap());
    }

    #[test]
    fn priority_order_first_two_are_endpoints() {
        let order = priority_order(10);
        assert_eq!(order[0], 0);
        assert_eq!(order[1], 9);
        assert_eq!(order.len(), 10);
        // Every index appears exactly once.
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(sorted, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn priority_order_handles_small_n() {
        assert_eq!(priority_order(0), Vec::<usize>::new());
        assert_eq!(priority_order(1), vec![0]);
        assert_eq!(priority_order(2), vec![0, 1]);
    }

    #[test]
    fn empty_file_yields_one_zero_chunk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        let chunks = compute_chunks(&path, 0).unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(verify_chunks(&chunks, &path, 0).unwrap());
    }

    #[test]
    fn path_key_is_stable() {
        let k1 = path_key("foo/bar.bin");
        let k2 = path_key("foo/bar.bin");
        let k3 = path_key("foo/baz.bin");
        assert_eq!(k1.to_hex().as_str(), k2.to_hex().as_str());
        assert_ne!(k1.to_hex().as_str(), k3.to_hex().as_str());
    }
}
