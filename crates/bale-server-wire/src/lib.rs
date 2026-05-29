//! Wire types. Hashes in paths/JSON are NOT plain hex: each 8-byte group is a
//! little-endian u64 rendered as 16-char lowercase hex, i.e. reverse byte order
//! within each group then hex (spec §"Converting Hashes to Strings").

use bale_server_core::{Hash32, HASH_LEN};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HexError {
    #[error("hash hex string must be 64 lowercase chars")]
    BadLength,
    #[error("hash hex string contains non-hex characters")]
    BadHex,
}

pub fn encode_hash(h: &Hash32) -> String {
    let mut out = String::with_capacity(HASH_LEN * 2);
    for group in 0..4 {
        let start = group * 8;
        for i in (0..8).rev() {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", h.0[start + i]); // infallible into String
        }
    }
    out
}

pub fn decode_hash(s: &str) -> Result<Hash32, HexError> {
    if s.len() != HASH_LEN * 2 {
        return Err(HexError::BadLength);
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; HASH_LEN];
    for group in 0..4 {
        let str_off = group * 16;
        let byte_off = group * 8;
        for i in 0..8 {
            let hi = hex_nibble(bytes[str_off + i * 2])?;
            let lo = hex_nibble(bytes[str_off + i * 2 + 1])?;
            // Reverse within group: i-th hex pair maps to byte (7 - i).
            out[byte_off + (7 - i)] = (hi << 4) | lo;
        }
    }
    Ok(Hash32(out))
}

fn hex_nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // Uppercase rejected: spec mandates lowercase.
        _ => Err(HexError::BadHex),
    }
}

/// Half-open `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeJson {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CASReconstructionTerm {
    pub hash: String,
    pub unpacked_length: u64,
    /// Chunk indices, end-exclusive.
    pub range: RangeJson,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CASReconstructionFetchInfo {
    /// Chunk indices this URL covers, end-exclusive.
    pub range: RangeJson,
    pub url: String,
    /// Byte range, end-INCLUSIVE per spec; signed URL enforces a matching
    /// Range header on GET.
    pub url_range: RangeJson,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryReconstructionResponse {
    pub offset_into_first_range: u64,
    pub terms: Vec<CASReconstructionTerm>,
    pub fetch_info: BTreeMap<String, Vec<CASReconstructionFetchInfo>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadXorbResponse {
    pub was_inserted: bool,
}

/// `result`: `0` = shard already existed, `1` = `SyncPerformed`; not meaningful
/// beyond "200 means success" per spec.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadShardResponse {
    pub result: u32,
}

/// Mock HF Hub token endpoint response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XetTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    pub exp: u64,
    #[serde(rename = "casUrl")]
    pub cas_url: String,
}

/// `quota_bytes` is null when no quota is configured for the owner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerUsageResponse {
    pub owner: String,
    pub raw_bytes: u64,
    pub stored_bytes: u64,
    pub dedup_savings_bytes: u64,
    pub quota_bytes: Option<u64>,
}

/// Null `limit_bytes` clears the override. `deny_unknown_fields` so a typo'd key
/// on the admin endpoint fails loudly instead of being silently ignored.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetOwnerQuotaRequest {
    pub limit_bytes: Option<u64>,
}

/// No quota field — quotas are owner-scoped. `raw_bytes` is the user-facing repo
/// size (sum of file totals, ignoring cross-repo dedup); `stored_bytes` is the
/// on-disk cost of every xorb the repo references (siblings may share some);
/// `exclusive_bytes` is the subset no *sibling* repo (same owner) references —
/// how much the owner's stored bytes would drop if the repo were deleted
/// (`exclusive_bytes <= stored_bytes`; cross-owner sharing is ignored).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoUsageResponse {
    pub repo_id: String,
    pub raw_bytes: u64,
    pub stored_bytes: u64,
    pub dedup_savings_bytes: u64,
    pub exclusive_bytes: u64,
}
