//! Xorb body parser.
//!
//! A xorb is a sequence of chunk frames concatenated with no separator:
//!
//! ```text
//! frame_0 | frame_1 | ... | frame_N | optional footer
//! frame = 8-byte XorbChunkHeader | compressed_length bytes of payload
//! ```
//!
//! XorbChunkHeader (8 bytes, little-endian, no padding):
//! ```text
//! offset 0 : version            (u8, currently 0)
//! offset 1 : compressed_length  (u24, payload bytes after the header)
//! offset 4 : compression_scheme (u8: 0=none, 1=LZ4 frame, 2=BG4-LZ4)
//! offset 5 : uncompressed_length(u24)
//! ```
//!
//! We don't decompress here — this only walks the on-disk frame boundaries so
//! the server can compute correct HTTP byte ranges for downstream reconstruction.
//! Compression scheme `99` (Auto) is sentinel-only and must never appear on the
//! wire; we reject it. Any header whose `version` byte is non-zero is treated
//! as the start of the footer (xet-core's footer magic strings all begin with
//! ASCII bytes well outside the version-0 range, e.g. `XETBLOB`).

use bale_server_core::XorbHash;
use thiserror::Error;
use xet_core_structures::merklehash::{compute_data_hash, xorb_hash as compute_xorb_merkle_hash};
use xet_core_structures::xorb_object::CompressionScheme;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorbChunkFrame {
    pub on_disk_start: u32,
    /// 8-byte header + compressed_length payload.
    pub on_disk_len: u32,
    pub uncompressed_len: u32,
    pub compression_scheme: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum XorbParseError {
    #[error("xorb contained no chunk frames")]
    Empty,
    #[error("frame {frame_index} truncated: declared {need} bytes, only {have} remain")]
    Truncated {
        frame_index: usize,
        need: usize,
        have: usize,
    },
    #[error("frame {frame_index} has invalid compression scheme {scheme}")]
    BadCompressionScheme { frame_index: usize, scheme: u8 },
    #[error("xorb body exceeds {max} bytes ({actual} given)")]
    TooLarge { actual: usize, max: usize },
}

#[derive(Debug, Error)]
pub enum XorbVerifyError {
    #[error(transparent)]
    Parse(#[from] XorbParseError),
    #[error("frame {frame_index} failed to decompress: {message}")]
    DecompressFailed { frame_index: usize, message: String },
    #[error(
        "frame {frame_index} length mismatch: header declared {declared}, decompressed {actual}"
    )]
    LengthMismatch {
        frame_index: usize,
        declared: usize,
        actual: usize,
    },
    #[error("xorb content hash does not match URL hash")]
    HashMismatch,
}

const HEADER_LEN: usize = 8;

fn u24_le(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

/// Walk every chunk frame in `body`. Stops at the first header whose version
/// byte is non-zero (treated as the footer marker) or at EOF, whichever comes
/// first. Returns at least one frame or an error.
///
/// `XorbChunkFrame` stores offsets as u32, so bodies larger than u32::MAX are
/// rejected up front. Production xorbs are capped at 64 MiB by the upload
/// handler, so this is a defense-in-depth check.
pub fn parse_xorb_frames(body: &[u8]) -> Result<Vec<XorbChunkFrame>, XorbParseError> {
    if body.len() > u32::MAX as usize {
        return Err(XorbParseError::TooLarge {
            actual: body.len(),
            max: u32::MAX as usize,
        });
    }
    let mut frames = Vec::new();
    let mut pos: usize = 0;
    while pos + HEADER_LEN <= body.len() {
        let header = &body[pos..pos + HEADER_LEN];
        let version = header[0];
        if version != 0 {
            break; // footer or unknown trailer
        }
        let compressed_length = u24_le(&header[1..4]);
        let compression_scheme = header[4];
        let uncompressed_length = u24_le(&header[5..8]);

        if !matches!(compression_scheme, 0..=2) {
            return Err(XorbParseError::BadCompressionScheme {
                frame_index: frames.len(),
                scheme: compression_scheme,
            });
        }

        let frame_len = HEADER_LEN.checked_add(compressed_length as usize).ok_or(
            XorbParseError::Truncated {
                frame_index: frames.len(),
                need: usize::MAX,
                have: body.len() - pos,
            },
        )?;
        if pos + frame_len > body.len() {
            return Err(XorbParseError::Truncated {
                frame_index: frames.len(),
                need: frame_len,
                have: body.len() - pos,
            });
        }

        frames.push(XorbChunkFrame {
            on_disk_start: pos as u32,
            on_disk_len: frame_len as u32,
            uncompressed_len: uncompressed_length,
            compression_scheme,
        });
        pos += frame_len;
    }
    if frames.is_empty() {
        return Err(XorbParseError::Empty);
    }
    Ok(frames)
}

/// Recompute the xorb content hash from `body` and compare it to `expected`.
///
/// Walks every chunk frame, decompresses it via xet-core's `CompressionScheme`
/// (so BG4-LZ4 / LZ4-frame / None all match the client byte-for-byte),
/// computes each chunk's `compute_data_hash`, then aggregates with xet-core's
/// `xorb_hash`. The expected hash arrives in natural-byte order (as decoded
/// from the URL by `bale_server_wire::decode_hash`), which is exactly the
/// layout `DataHash::from([u8; 32])` consumes.
///
/// Returns `Ok(())` on match; any decompression, length, or hash mismatch is
/// surfaced so callers can reject the upload before persisting.
pub fn verify_xorb_body(body: &[u8], expected: &XorbHash) -> Result<(), XorbVerifyError> {
    let frames = parse_xorb_frames(body)?;
    let mut entries: Vec<(xet_core_structures::merklehash::MerkleHash, u64)> =
        Vec::with_capacity(frames.len());
    for (i, f) in frames.iter().enumerate() {
        let payload_start = f.on_disk_start as usize + HEADER_LEN;
        let payload_end = f.on_disk_start as usize + f.on_disk_len as usize;
        let payload = &body[payload_start..payload_end];

        let scheme = match f.compression_scheme {
            0 => CompressionScheme::None,
            1 => CompressionScheme::LZ4,
            2 => CompressionScheme::ByteGrouping4LZ4,
            // parse_xorb_frames already rejects anything outside 0..=2.
            other => {
                return Err(XorbVerifyError::Parse(
                    XorbParseError::BadCompressionScheme {
                        frame_index: i,
                        scheme: other,
                    },
                ));
            }
        };

        let decompressed = scheme.decompress_from_slice(payload).map_err(|e| {
            XorbVerifyError::DecompressFailed {
                frame_index: i,
                message: e.to_string(),
            }
        })?;
        if decompressed.len() != f.uncompressed_len as usize {
            return Err(XorbVerifyError::LengthMismatch {
                frame_index: i,
                declared: f.uncompressed_len as usize,
                actual: decompressed.len(),
            });
        }

        let chunk_hash = compute_data_hash(&decompressed);
        entries.push((chunk_hash, decompressed.len() as u64));
    }

    let computed = compute_xorb_merkle_hash(&entries);
    let expected_mh: xet_core_structures::merklehash::MerkleHash = (*expected.as_bytes()).into();
    if computed != expected_mh {
        return Err(XorbVerifyError::HashMismatch);
    }
    Ok(())
}

/// Decompress every chunk frame in `body` (which holds the bytes for one
/// reconstruction term, i.e. the on-disk range covering one or more contiguous
/// chunks of a single xorb) and append the result to `out` in order. Mirrors
/// the per-frame loop in [`verify_xorb_body`] but without the hash check —
/// callers (e.g. the file-download streamer) already know the xorb is intact.
pub fn decompress_xorb_chunks_into(body: &[u8], out: &mut Vec<u8>) -> Result<(), XorbVerifyError> {
    let frames = parse_xorb_frames(body)?;
    for (i, f) in frames.iter().enumerate() {
        let payload_start = f.on_disk_start as usize + HEADER_LEN;
        let payload_end = f.on_disk_start as usize + f.on_disk_len as usize;
        let payload = &body[payload_start..payload_end];

        let scheme = match f.compression_scheme {
            0 => CompressionScheme::None,
            1 => CompressionScheme::LZ4,
            2 => CompressionScheme::ByteGrouping4LZ4,
            other => {
                return Err(XorbVerifyError::Parse(
                    XorbParseError::BadCompressionScheme {
                        frame_index: i,
                        scheme: other,
                    },
                ));
            }
        };
        let decompressed = scheme.decompress_from_slice(payload).map_err(|e| {
            XorbVerifyError::DecompressFailed {
                frame_index: i,
                message: e.to_string(),
            }
        })?;
        if decompressed.len() != f.uncompressed_len as usize {
            return Err(XorbVerifyError::LengthMismatch {
                frame_index: i,
                declared: f.uncompressed_len as usize,
                actual: decompressed.len(),
            });
        }
        out.extend_from_slice(&decompressed);
    }
    Ok(())
}

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
/// (compression scheme 0). Useful for tests that need bytes the production
/// xorb parser will accept without pulling in a real LZ4 encoder.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(scheme: u8, payload: &[u8], uncompressed_len: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push(0); // version
        let clen = payload.len() as u32;
        out.extend_from_slice(&clen.to_le_bytes()[0..3]);
        out.push(scheme);
        out.extend_from_slice(&uncompressed_len.to_le_bytes()[0..3]);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn empty_body_errors() {
        assert_eq!(parse_xorb_frames(&[]).unwrap_err(), XorbParseError::Empty);
    }

    #[test]
    fn single_uncompressed_frame() {
        let body = make_frame(0, b"hello world!", 12);
        let frames = parse_xorb_frames(&body).unwrap();
        assert_eq!(frames.len(), 1);
        let f = frames[0];
        assert_eq!(f.on_disk_start, 0);
        assert_eq!(f.on_disk_len as usize, HEADER_LEN + 12);
        assert_eq!(f.uncompressed_len, 12);
        assert_eq!(f.compression_scheme, 0);
    }

    #[test]
    fn multiple_frames_have_contiguous_offsets() {
        let mut body = make_frame(1, &[0xAA; 100], 200);
        body.extend(make_frame(2, &[0xBB; 50], 80));
        body.extend(make_frame(0, &[0xCC; 16], 16));
        let frames = parse_xorb_frames(&body).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].on_disk_start, 0);
        assert_eq!(frames[0].on_disk_len, (HEADER_LEN + 100) as u32);
        assert_eq!(frames[1].on_disk_start, frames[0].on_disk_len);
        assert_eq!(frames[1].on_disk_len, (HEADER_LEN + 50) as u32);
        assert_eq!(
            frames[2].on_disk_start,
            frames[1].on_disk_start + frames[1].on_disk_len
        );
        assert_eq!(frames[2].uncompressed_len, 16);
    }

    #[test]
    fn footer_marker_stops_iteration() {
        let mut body = make_frame(0, b"abc", 3);
        body.extend_from_slice(b"XETBLOB\0\0\0\0\0\0\0\0\0extra"); // footer-ish bytes
        let frames = parse_xorb_frames(&body).unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn rejects_bad_compression_scheme() {
        let body = make_frame(99, b"data", 4); // Auto = sentinel only
        let err = parse_xorb_frames(&body).unwrap_err();
        assert!(matches!(err, XorbParseError::BadCompressionScheme { .. }));
    }

    #[test]
    fn detects_truncated_payload() {
        let mut body = make_frame(0, b"hello", 5);
        body.truncate(body.len() - 2);
        let err = parse_xorb_frames(&body).unwrap_err();
        assert!(matches!(err, XorbParseError::Truncated { .. }));
    }

    #[test]
    fn verify_accepts_correct_hash() {
        let c0: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let c1: Vec<u8> = (0..128u32).map(|i| (i as u8).wrapping_add(7)).collect();
        let body = build_uncompressed_xorb_body(&[&c0, &c1]);
        let expected = xorb_hash_for_uncompressed_chunks(&[&c0, &c1]);
        verify_xorb_body(&body, &expected).expect("hash should match");
    }

    #[test]
    fn verify_rejects_mismatched_hash() {
        let payload: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        let body = build_uncompressed_xorb_body(&[&payload]);
        let wrong = XorbHash::from_bytes([0xAB; 32]);
        let err = verify_xorb_body(&body, &wrong).unwrap_err();
        assert!(matches!(err, XorbVerifyError::HashMismatch));
    }

    #[test]
    fn verify_rejects_body_whose_chunks_were_swapped() {
        // Hash is computed over c0 then c1, but the body has c1 then c0.
        let c0: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let c1: Vec<u8> = (0..200u32).map(|i| (i as u8).wrapping_add(0x33)).collect();
        let expected = xorb_hash_for_uncompressed_chunks(&[&c0, &c1]);
        let swapped_body = build_uncompressed_xorb_body(&[&c1, &c0]);
        let err = verify_xorb_body(&swapped_body, &expected).unwrap_err();
        assert!(matches!(err, XorbVerifyError::HashMismatch));
    }

    #[test]
    fn verify_rejects_empty_body() {
        let expected = XorbHash::from_bytes([0; 32]);
        let err = verify_xorb_body(&[], &expected).unwrap_err();
        assert!(matches!(err, XorbVerifyError::Parse(XorbParseError::Empty)));
    }

    #[test]
    fn verify_rejects_corrupted_chunk_bytes() {
        let payload: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let expected = xorb_hash_for_uncompressed_chunks(&[&payload]);
        let mut body = build_uncompressed_xorb_body(&[&payload]);
        // Flip a payload byte after the 8-byte header.
        body[HEADER_LEN + 5] ^= 0xFF;
        let err = verify_xorb_body(&body, &expected).unwrap_err();
        assert!(matches!(err, XorbVerifyError::HashMismatch));
    }
}
