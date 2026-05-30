//! Per-clean cache. Keyed by `blake3(pathname)`, verified by
//! `(size, chunked_hashes)` so a modified large file misses in ~ms (size check,
//! then priority/parallel chunk hashing that bails on first mismatch) instead
//! of paying `O(file_size)` on every `git status`/`git diff`. Hits still hash
//! every chunk — a sample-only positive can't be trusted.
//!
//! Chunk fingerprints use xxh3-64 (change detection, not integrity; ~10× blake3).

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use twox_hash::XxHash3_64;

const CHUNK_SIZE: u64 = 1 << 20;
/// Bump on any on-disk schema or chunk-hash change — old entries go invisible
/// and rebuild. v3: chunk hashes are xxh3-64 hex (was blake3 hex in v2).
pub const CURRENT_VERSION: u32 = 3;
/// Random middle-chunks checked before the linear sweep.
const MIDDLE_SAMPLES: usize = 3;
const VERIFY_PARALLELISM: usize = 3;

pub type PathKey = blake3::Hash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CacheEntry {
    pub v: u32,
    pub size: u64,
    pub chunks: Vec<Chunk>,
    /// Pointer JSON returned verbatim (incl. trailing newline) on a hit, so we
    /// stream it back to git without re-encoding.
    pub pointer: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Chunk {
    pub start: u64,
    pub end: u64,
    /// xxh3-64 of `[start..end]` as 16-char lowercase hex.
    pub hash: String,
}

fn chunk_hash(bytes: &[u8]) -> u64 {
    XxHash3_64::oneshot(bytes)
}

fn chunk_hash_hex(bytes: &[u8]) -> String {
    format!("{:016x}", chunk_hash(bytes))
}

/// Hash the pathname into the cache filename to sidestep path-char escaping.
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

/// Drop clean-cache entries whose pointer references one of `hashes` (file-level
/// merkle). `git-bale gc` calls this when it orphans staged content: otherwise a
/// later `git add` of the same bytes hits the cache and hands git a pointer
/// whose xorbs/shards gc already swept and that was never pushed — smudge can
/// then reconstruct from neither staging nor server. Returns entries removed.
pub fn forget_hashes(git_dir: &Path, hashes: &BTreeSet<String>) -> io::Result<usize> {
    if hashes.is_empty() {
        return Ok(0);
    }
    let dir = cache_dir(git_dir);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0usize;
    for ent in entries {
        let path = ent?.path();
        if !path.is_file() {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else { continue };
        let Ok(entry) = serde_json::from_slice::<CacheEntry>(&bytes) else {
            continue;
        };
        if pointer_hash(&entry.pointer).is_some_and(|h| hashes.contains(&h)) {
            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(removed)
}

fn pointer_hash(pointer: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(pointer).ok()?;
    v.get("hash")?.as_str().map(str::to_string)
}

/// In-memory variant of [`compute_chunks`] for a payload still in RAM.
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

/// Chunk index of `path`; empty files get one zero-length chunk so verify
/// always has a fingerprint to compare.
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

/// In-memory counterpart of [`verify_chunks`]. Single-threaded — for a slice in
/// RAM, fan-out overhead exceeds the xxh3 cost. Bails on first mismatch.
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

/// Verify `path` against every fingerprint in `cached`; workers share an
/// `AtomicBool` and bail at the first mismatch.
pub fn verify_chunks(cached: &[Chunk], path: &Path, file_size: u64) -> io::Result<bool> {
    if cached.is_empty() {
        return Ok(false);
    }
    // Reject entries that don't fully cover the file (partial write / truncation).
    let covered: u64 = cached.iter().map(|c| c.end - c.start).sum();
    if covered != file_size {
        return Ok(false);
    }
    // Decode hex once so the hot loop compares u64s; malformed hex fails verify.
    let mut decoded: Vec<u64> = Vec::with_capacity(cached.len());
    for c in cached {
        match u64::from_str_radix(&c.hash, 16) {
            Ok(h) if c.hash.len() == 16 => decoded.push(h),
            _ => return Ok(false),
        }
    }

    // One File shared across stripes; stateless read_at/seek_read avoid cursor
    // contention. Runs on every `git status`/`git diff`, so N opens → 1.
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

/// Positional read (no seek cursor) so workers share one handle; loops over
/// short reads.
fn read_exact_at(file: &fs::File, buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    let mut remaining = buf;
    while !remaining.is_empty() {
        let n = crate::fs_util::pread(file, remaining, offset)?;
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

/// Verification order: first, last, random middle sample, then the rest —
/// edits cluster at head/tail (headers, appends), so this bails sooner.
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

    // Cheap xorshift; seeded from nanos + pid so two invocations aren't lockstep.
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
