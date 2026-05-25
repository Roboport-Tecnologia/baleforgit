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

use thiserror::Error;

/// One chunk frame's on-disk layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorbChunkFrame {
    /// Byte offset of this frame's header within the xorb body.
    pub on_disk_start: u32,
    /// Total on-disk frame size: 8 (header) + compressed_length.
    pub on_disk_len: u32,
    /// Payload size after decompression.
    pub uncompressed_len: u32,
    /// Raw compression-scheme byte (0=none, 1=LZ4 frame, 2=BG4-LZ4).
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
}

const HEADER_LEN: usize = 8;

fn u24_le(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

/// Walk every chunk frame in `body`. Stops at the first header whose version
/// byte is non-zero (treated as the footer marker) or at EOF, whichever comes
/// first. Returns at least one frame or an error.
pub fn parse_xorb_frames(body: &[u8]) -> Result<Vec<XorbChunkFrame>, XorbParseError> {
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
}
