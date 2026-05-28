//! Cache-only reconstruction from a [`CachedManifest`] + local chunk cache, no
//! network. Any missing chunk → `Miss`; the caller falls back to
//! `FileDownloadSession` (which repopulates the cache).

use std::io::Write;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use xet_client::cas_types::{ChunkRange, Key};
use xet_client::chunk_cache::ChunkCache;
use xet_core_structures::merklehash::MerkleHash;
use xet_runtime::core::XetRuntime;

use crate::manifest_cache::CachedManifest;

/// Miss is distinct from error so the caller falls back on misses but still
/// propagates real failures.
pub enum CacheReconstructOutcome {
    Wrote(u64),
    /// A chunk was missing; `out` may be partially written, reset before retry.
    Miss,
}

pub async fn try_reconstruct_from_cache<W: Write>(
    rt: &Arc<XetRuntime>,
    chunk_cache: &Arc<dyn ChunkCache>,
    manifest: &CachedManifest,
    expected_size: u64,
    out: &mut W,
) -> Result<CacheReconstructOutcome> {
    // Must match xet-data's `XorbBlock::retrieve_data` key construction.
    let prefix = rt.config().data.default_prefix.clone();

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

        // Length check guards against a stale manifest corrupting the worktree.
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
        tracing::warn!("cache-only reconstruct produced {written} bytes, expected {expected_size}");
        return Ok(CacheReconstructOutcome::Miss);
    }

    Ok(CacheReconstructOutcome::Wrote(written))
}
