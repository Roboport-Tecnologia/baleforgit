//! Wire-format types and the Xet hash hex encoding.
//!
//! ## Hash hex encoding (per spec §"Converting Hashes to Strings")
//!
//! Hashes appearing in API paths and JSON fields are NOT plain hex of the 32
//! bytes. Each 8-byte group is treated as a little-endian u64; the resulting
//! four numbers are concatenated as 16-char lowercase hex strings in order.
//! Equivalently: reverse the byte order within each 8-byte group, then hex.

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
            // write! into String is infallible.
            let _ = write!(out, "{:02x}", h.0[start + i]);
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
            // Reverse within the group: the i-th hex pair (left to right) maps to byte (7 - i).
            out[byte_off + (7 - i)] = (hi << 4) | lo;
        }
    }
    Ok(Hash32(out))
}

fn hex_nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // Uppercase rejected intentionally; spec says lowercase.
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
    /// Byte range; end-INCLUSIVE per spec, and the signed URL enforces a
    /// matching Range header on GET.
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

/// `0` = shard already existed, `1` = `SyncPerformed`. Per spec the value is
/// not meaningful beyond "200 means success".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadShardResponse {
    pub result: u32,
}

/// Mock HF Hub token endpoint response shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XetTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    pub exp: u64,
    #[serde(rename = "casUrl")]
    pub cas_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec test vector. The published example string is missing the byte "10";
    /// the algorithm gives 64 hex chars, so we reinstate it here.
    #[test]
    fn hash_hex_spec_vector() {
        let input = Hash32([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let expected = "0706050403020100\
                        0f0e0d0c0b0a0908\
                        17161514131211 10\
                        1f1e1d1c1b1a1918"
            .replace(' ', "");
        assert_eq!(encode_hash(&input), expected);
        let roundtrip = decode_hash(&expected).expect("decode");
        assert_eq!(roundtrip, input);
    }

    #[test]
    fn hash_hex_zero() {
        let z = Hash32([0u8; 32]);
        let s = encode_hash(&z);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c == '0'));
        assert_eq!(decode_hash(&s).unwrap(), z);
    }

    #[test]
    fn hash_hex_all_ones() {
        let o = Hash32([0xFFu8; 32]);
        let s = encode_hash(&o);
        assert!(s.chars().all(|c| c == 'f'));
        assert_eq!(decode_hash(&s).unwrap(), o);
    }

    #[test]
    fn hash_hex_rejects_uppercase() {
        let s = "0706050403020100\
                 0f0e0d0c0b0a0908\
                 17161514131211 10\
                 1f1e1d1c1b1a1918"
            .replace(' ', "")
            .to_uppercase();
        assert!(decode_hash(&s).is_err());
    }

    #[test]
    fn hash_hex_rejects_bad_length() {
        assert!(decode_hash("deadbeef").is_err());
    }

    #[test]
    fn json_roundtrip_reconstruction() {
        let mut fi = BTreeMap::new();
        fi.insert(
            "0706050403020100\
             0f0e0d0c0b0a0908\
             1716151413121110\
             1f1e1d1c1b1a1918"
                .into(),
            vec![CASReconstructionFetchInfo {
                range: RangeJson { start: 0, end: 4 },
                url: "https://x.example/xorb/abc?sig=1".into(),
                url_range: RangeJson {
                    start: 0,
                    end: 131_071,
                },
            }],
        );
        let r = QueryReconstructionResponse {
            offset_into_first_range: 0,
            terms: vec![CASReconstructionTerm {
                hash: "0706050403020100\
                       0f0e0d0c0b0a0908\
                       1716151413121110\
                       1f1e1d1c1b1a1918"
                    .into(),
                unpacked_length: 263_873,
                range: RangeJson { start: 0, end: 4 },
            }],
            fetch_info: fi,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: QueryReconstructionResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.terms.len(), 1);
        assert_eq!(back.fetch_info.len(), 1);
    }
}
