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
