//! Cache-only reconstruction: given a [`CachedManifest`] and a populated
//! local chunk cache, write the file's bytes to `out` *without touching the
//! network*. Returns `Ok(false)` (with the writer left in an arbitrary state
//! — caller throws it away) if any chunk is missing; the caller then falls
//! back to `FileDownloadSession`, which fetches the missing pieces and is
//! also free to repopulate the cache.

use std::io::Write;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use xet_client::cas_types::{ChunkRange, Key};
use xet_client::chunk_cache::ChunkCache;
use xet_core_structures::merklehash::MerkleHash;
use xet_runtime::core::XetContext;

use crate::manifest_cache::CachedManifest;

/// Outcome of `try_reconstruct_from_cache`. Distinguishing "miss" from "error"
/// lets the caller fall back on misses while propagating real failures.
pub enum CacheReconstructOutcome {
    /// All chunks were available; `expected_size` bytes were written to `out`.
    Wrote(u64),
    /// At least one chunk was missing. Caller should fall back to a network
    /// download. `out` may have been partially written to and should be reset.
    Miss,
}

pub async fn try_reconstruct_from_cache<W: Write>(
    ctx: &XetContext,
    chunk_cache: &Arc<dyn ChunkCache>,
    manifest: &CachedManifest,
    expected_size: u64,
    out: &mut W,
) -> Result<CacheReconstructOutcome> {
    // Match xet-data's key construction in
    // xet_data::file_reconstruction::reconstruction_terms::xorb_block.rs:113.
    let prefix = ctx.config.data.default_prefix.clone();

    let mut written: u64 = 0;
    for term in &manifest.terms {
        let hash = MerkleHash::from_hex(&term.xorb_hash)
            .map_err(|e| anyhow!("malformed xorb hash {}: {e}", term.xorb_hash))?;
        let key = Key {
            prefix: prefix.clone(),
            hash,
        };
        let range = ChunkRange::new(term.chunk_start, term.chunk_end);

        let cache_range = match chunk_cache.get(&key, &range).await {
            Ok(Some(r)) => r,
            // Cache miss (None) or recoverable error → caller falls back.
            Ok(None) => return Ok(CacheReconstructOutcome::Miss),
            Err(e) => {
                tracing::warn!(
                    "chunk cache read failed for {}/{}..{}: {e}",
                    term.xorb_hash,
                    term.chunk_start,
                    term.chunk_end
                );
                return Ok(CacheReconstructOutcome::Miss);
            }
        };

        // The cache hands us the exact uncompressed bytes for the chunk range,
        // already assembled in order. By spec `data.len() == sum of chunk
        // sizes` for the range; defensively check the term's declared length
        // matches before writing, so a stale manifest can't corrupt the
        // worktree.
        if cache_range.data.len() as u64 != term.unpacked_length {
            tracing::warn!(
                "manifest/cache length mismatch for {}/{}..{}: manifest {}, cache {}",
                term.xorb_hash,
                term.chunk_start,
                term.chunk_end,
                term.unpacked_length,
                cache_range.data.len()
            );
            return Ok(CacheReconstructOutcome::Miss);
        }

        out.write_all(&cache_range.data)?;
        written += cache_range.data.len() as u64;
    }

    if written != expected_size {
        // Same defensive bail: caller falls back, and we'll overwrite the
        // stale manifest after the fallback succeeds.
        tracing::warn!("cache-only reconstruct produced {written} bytes, expected {expected_size}");
        return Ok(CacheReconstructOutcome::Miss);
    }

    Ok(CacheReconstructOutcome::Wrote(written))
}
