//! Fetches a fresh reconstruction manifest from the CAS server and converts
//! it to our cache shape ([`CachedManifest`]). Used only on the cold path —
//! once cached under `.git/dfs/manifests/`, the hot path skips the network.
//!
//! We deliberately call `RemoteClient::get_reconstruction_v1` directly rather
//! than going through the `Client` trait, which would probe `/v2/...` first
//! and fall back on 404. xet-server only speaks v1, so the probe is wasted.

use anyhow::{anyhow, Context, Result};
use xet_client::cas_client::auth::AuthConfig;
use xet_client::cas_client::RemoteClient;
use xet_core_structures::merklehash::MerkleHash;
use xet_runtime::core::XetContext;

use crate::config::DfsConfig;
use crate::manifest_cache::{CachedManifest, CachedTerm, CURRENT_VERSION};

/// Hits `GET /v1/reconstructions/<file_id>` and returns just the
/// content-addressed parts. Signed URLs in the response (`fetch_info`) are
/// thrown away since they expire and aren't safe to persist.
pub async fn fetch_manifest(
    ctx: &XetContext,
    cfg: &DfsConfig,
    file_id: &MerkleHash,
) -> Result<CachedManifest> {
    let auth = AuthConfig::maybe_new(Some(cfg.token.clone()), Some(cfg.token_expiration), None);
    let client = RemoteClient::new(ctx.clone(), &cfg.server_url, &auth, "git-dfs", false, None);

    let response = client
        .get_reconstruction_v1(file_id, None)
        .await
        .with_context(|| format!("fetching reconstruction manifest for {}", file_id.hex()))?
        .ok_or_else(|| anyhow!("server returned no reconstruction for {}", file_id.hex()))?;

    // xet-client deserializes `terms[].hash` as a `HexMerkleHash` newtype and
    // `unpacked_length` as `u32` (whereas the wire crate uses `u64`). We
    // normalize to a plain hex `String` + `u64` here so the persisted shape
    // doesn't depend on xet-client's internal types.
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
