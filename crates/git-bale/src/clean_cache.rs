//! Per-clean cache. Keyed by `blake3(pathname)` and verified by
//! `(size, chunked_hashes)` rather than a single full-file hash.
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
//! chunk for correctness (you can't trust a sample-only positive).
//!
//! Chunk fingerprints use xxh3-64 — change detection, not adversarial
//! integrity, so the speed (~10× blake3 on modern x86) wins.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use twox_hash::XxHash3_64;

/// Chunk size for the index. 1 MiB chosen so an 1 GiB file still indexes
/// in ~1024 chunks (~64 KiB serialized) while leaving plenty of room for
/// early-exit on small files.
const CHUNK_SIZE: u64 = 1 << 20;
/// Bump when the on-disk schema or the chunk-hash algorithm changes —
/// old entries become invisible and rebuild on the next clean.
/// v3: chunk hashes are xxh3-64 hex (was blake3 hex in v2).
pub const CURRENT_VERSION: u32 = 3;
/// How many random middle-chunks to check *before* the rest. 3 is enough
/// to catch most middle edits before the linear sweep.
const MIDDLE_SAMPLES: usize = 3;
/// Worker count for parallel chunk hashing.
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
    /// xxh3-64 of `[start..end]`, 16-char lowercase hex (big-endian) so the
    /// cache file stays hand-readable for debugging.
    pub hash: String,
}

fn chunk_hash(bytes: &[u8]) -> u64 {
    XxHash3_64::oneshot(bytes)
}

fn chunk_hash_hex(bytes: &[u8]) -> String {
    format!("{:016x}", chunk_hash(bytes))
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
    crate::fs_util::create_bale_subdir(git_dir, "clean-cache")?;
    let dir = cache_dir(git_dir);
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

/// Like [`compute_chunks`] but for a byte slice already in memory — saves the
/// disk round-trip when the clean filter receives the payload via pkt-line and
/// holds it in RAM instead of spilling to a tmp file.
pub fn compute_chunks_from_slice(bytes: &[u8]) -> Vec<Chunk> {
    let size = bytes.len() as u64;
    let mut chunks = Vec::with_capacity((size.div_ceil(CHUNK_SIZE).max(1)) as usize);
    let mut pos = 0u64;
    while pos < size {
        let end = (pos + CHUNK_SIZE).min(size);
        chunks.push(Chunk {
            start: pos,
            end,
            hash: chunk_hash_hex(&bytes[pos as usize..end as usize]),
        });
        pos = end;
    }
    if chunks.is_empty() {
        chunks.push(Chunk {
            start: 0,
            end: 0,
            hash: chunk_hash_hex(b""),
        });
    }
    chunks
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
        chunks.push(Chunk {
            start: pos,
            end: pos + to_read as u64,
            hash: chunk_hash_hex(&buf[..to_read]),
        });
        pos += to_read as u64;
    }
    if chunks.is_empty() {
        chunks.push(Chunk {
            start: 0,
            end: 0,
            hash: chunk_hash_hex(b""),
        });
    }
    Ok(chunks)
}

/// In-memory counterpart of [`verify_chunks`]. No threading: the slice is
/// already in RAM so memcpy + xxh3 dominate; one pass per chunk on the calling
/// thread beats fan-out overhead. Bail on the first mismatch.
pub fn verify_chunks_in_memory(cached: &[Chunk], bytes: &[u8]) -> bool {
    if cached.is_empty() {
        return false;
    }
    let file_size = bytes.len() as u64;
    let covered: u64 = cached.iter().map(|c| c.end - c.start).sum();
    if covered != file_size {
        return false;
    }
    for c in cached {
        let Ok(expected) = u64::from_str_radix(&c.hash, 16) else {
            return false;
        };
        if c.hash.len() != 16 {
            return false;
        }
        if c.end > file_size {
            return false;
        }
        if chunk_hash(&bytes[c.start as usize..c.end as usize]) != expected {
            return false;
        }
    }
    true
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
    // Parse the on-disk hex hashes into u64 once, so the hot loop can
    // compare integers instead of paying hex on every chunk. Any malformed
    // hex is treated as a verification failure (the entry is bogus; we'll
    // rebuild it).
    let mut decoded: Vec<u64> = Vec::with_capacity(cached.len());
    for c in cached {
        match u64::from_str_radix(&c.hash, 16) {
            Ok(h) if c.hash.len() == 16 => decoded.push(h),
            _ => return Ok(false),
        }
    }

    // Share a single File across the worker stripes — verify_chunks runs on
    // every `git status` / `git diff`, so dropping N opens to 1 is the cheap
    // win. read_at / seek_read are stateless so concurrent workers don't
    // contend on a shared seek cursor.
    let file = Arc::new(fs::File::open(path)?);

    let order = priority_order(cached.len());
    let mismatch = AtomicBool::new(false);
    let stripe_size = order.len().div_ceil(VERIFY_PARALLELISM).max(1);

    std::thread::scope(|scope| {
        for stripe in order.chunks(stripe_size) {
            let stripe = stripe.to_vec();
            let mismatch_ref = &mismatch;
            let file = file.clone();
            let decoded = decoded.as_slice();
            scope.spawn(move || {
                if let Err(e) = verify_stripe(&file, cached, decoded, &stripe, mismatch_ref) {
                    tracing::debug!("chunk verify IO error on {}: {e}", path.display());
                    mismatch_ref.store(true, Ordering::Relaxed);
                }
            });
        }
    });

    Ok(!mismatch.load(Ordering::Relaxed))
}

fn verify_stripe(
    file: &fs::File,
    cached: &[Chunk],
    decoded: &[u64],
    indices: &[usize],
    mismatch: &AtomicBool,
) -> io::Result<()> {
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
        read_exact_at(file, &mut buf[..len], c.start)?;
        if chunk_hash(&buf[..len]) != decoded[idx] {
            mismatch.store(true, Ordering::Relaxed);
            return Ok(());
        }
    }
    Ok(())
}

/// Positional read that doesn't move the file's seek cursor, so multiple
/// workers can share one `File` handle without locking. Loops to retry
/// short reads (rare on regular files but well-defined to handle).
fn read_exact_at(file: &fs::File, buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    let mut remaining = buf;
    while !remaining.is_empty() {
        let n = pread(file, remaining, offset)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short read during chunk verify",
            ));
        }
        offset += n as u64;
        remaining = &mut remaining[n..];
    }
    Ok(())
}

#[cfg(unix)]
fn pread(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

#[cfg(windows)]
fn pread(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

#[cfg(not(any(unix, windows)))]
fn pread(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    // Fallback for exotic targets: emulate via clone + seek. Less efficient
    // (extra file descriptor + serialized seek), but correct.
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = file.try_clone()?;
    handle.seek(SeekFrom::Start(offset))?;
    handle.read(buf)
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
                hash: chunk_hash_hex(b"hello world!"),
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
        chunks[0].hash = chunk_hash_hex(b"bogus");
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
        chunks[last].hash = chunk_hash_hex(b"bogus");
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
    fn in_memory_round_trips_and_matches_file_path_variant() {
        // ~3.5 MiB so we get 4 chunks (3 full + 1 partial), same as the file
        // variant — guard against the two implementations drifting apart.
        let body: Vec<u8> = (0..3_500_000u32).map(|i| (i & 0xff) as u8).collect();
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.bin");
        fs::write(&path, &body).unwrap();
        let file_chunks = compute_chunks(&path, body.len() as u64).unwrap();
        let mem_chunks = compute_chunks_from_slice(&body);
        assert_eq!(file_chunks.len(), mem_chunks.len());
        for (a, b) in file_chunks.iter().zip(&mem_chunks) {
            assert_eq!((a.start, a.end, &a.hash), (b.start, b.end, &b.hash));
        }
        assert!(verify_chunks_in_memory(&mem_chunks, &body));
    }

    #[test]
    fn in_memory_verify_detects_mid_chunk_edit() {
        let mut body: Vec<u8> = (0..2_500_000u32).map(|i| (i & 0xff) as u8).collect();
        let chunks = compute_chunks_from_slice(&body);
        body[1_234_567] ^= 0xff;
        assert!(!verify_chunks_in_memory(&chunks, &body));
    }

    #[test]
    fn in_memory_verify_rejects_size_mismatch() {
        let body = vec![3u8; 1_500_000];
        let chunks = compute_chunks_from_slice(&body);
        // Truncate by one byte — the chunk's covered span no longer matches.
        assert!(!verify_chunks_in_memory(&chunks, &body[..body.len() - 1]));
    }

    #[test]
    fn in_memory_empty_file_yields_one_zero_chunk() {
        let chunks = compute_chunks_from_slice(b"");
        assert_eq!(chunks.len(), 1);
        assert_eq!((chunks[0].start, chunks[0].end), (0, 0));
        assert!(verify_chunks_in_memory(&chunks, b""));
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
