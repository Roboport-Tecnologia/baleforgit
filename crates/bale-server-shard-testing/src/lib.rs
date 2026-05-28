//! Test-only helpers for synthesizing valid xorb bodies and their hashes
//! without pulling in a real LZ4 encoder. Used by `bale-server-shard`'s own
//! unit tests and by the integration tests in `bale-server-tests`.

use bale_server_core::XorbHash;
use xet_core_structures::merklehash::{compute_data_hash, xorb_hash as compute_xorb_merkle_hash};

/// `file_flags` bit indicating each `FileTermEntry` is followed by a 32-byte
/// verification hash. Mirrors the private value `bale-server-shard` uses in its
/// parse/serialize paths; tests use this constant when authoring shards.
pub const FLAG_WITH_VERIFICATION: u32 = 1 << 31;

/// Compute the xorb merkle hash for the same chunks `build_uncompressed_xorb_body`
/// would serialize. Tests that hand-roll xorb uploads use this to produce a URL
/// hash that passes `verify_xorb_body`.
pub fn xorb_hash_for_uncompressed_chunks(chunks: &[&[u8]]) -> XorbHash {
    let entries: Vec<(xet_core_structures::merklehash::MerkleHash, u64)> = chunks
        .iter()
        .map(|c| (compute_data_hash(c), c.len() as u64))
        .collect();
    let merkle = compute_xorb_merkle_hash(&entries);
    let bytes: [u8; 32] = merkle.into();
    XorbHash::from_bytes(bytes)
}

/// Build a minimal valid xorb body whose chunks are stored uncompressed
/// (compression scheme 0).
pub fn build_uncompressed_xorb_body(chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in chunks {
        let clen = c.len() as u32;
        out.push(0); // version
        out.extend_from_slice(&clen.to_le_bytes()[0..3]); // compressed_length
        out.push(0); // compression_scheme = None
        out.extend_from_slice(&clen.to_le_bytes()[0..3]); // uncompressed_length
        out.extend_from_slice(c);
    }
    out
}
