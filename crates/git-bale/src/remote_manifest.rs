//! Fetch a reconstruction manifest and convert it to [`CachedManifest`].
//! Called on the cold path only — once cached, the hot path skips the network.
//!
//! Calls `get_reconstruction_v1` directly. The `Client` trait would probe
//! `/v2/...` first and fall back on 404, and baleforgit-server only speaks v1.

use anyhow::{anyhow, Context, Result};
use xet_client::cas_client::auth::AuthConfig;
use xet_client::cas_client::RemoteClient;
use xet_core_structures::merklehash::MerkleHash;

use crate::config::BaleConfig;
use crate::manifest_cache::{CachedManifest, CachedTerm, CURRENT_VERSION};

/// Returns the content-addressed parts only. `fetch_info` is discarded —
/// signed URLs expire (`SIGNATURE_TTL_SECS` = 600s) and aren't safe to persist.
pub async fn fetch_manifest(cfg: &BaleConfig, file_id: &MerkleHash) -> Result<CachedManifest> {
    let auth = AuthConfig::maybe_new(Some(cfg.token.clone()), Some(cfg.token_expiration), None);
    let client = RemoteClient::new(&cfg.server_url, &auth, "git-bale", false, None);

    let response = client
        .get_reconstruction_v1(file_id, None)
        .await
        .with_context(|| format!("fetching reconstruction manifest for {}", file_id.hex()))?
        .ok_or_else(|| anyhow!("server returned no reconstruction for {}", file_id.hex()))?;

    // Normalize to plain hex `String` + `u64`: xet-client uses a `HexMerkleHash`
    // newtype and a `u32` `unpacked_length`, both of which would tie our
    // persisted shape to xet-client's internal types.
    let terms = response
        .terms
        .into_iter()
        .map(|t| CachedTerm {
            xorb_hash: MerkleHash::from(&t.hash).hex(),
            chunk_start: t.range.start,
            chunk_end: t.range.end,
            unpacked_length: t.unpacked_length as u64,
        })
        .collect();

    Ok(CachedManifest {
        v: CURRENT_VERSION,
        terms,
    })
}
