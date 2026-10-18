//! Xorb body parser. Chunk frames concatenated with no separator:
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
//! Frame boundaries only, no decompression — the server needs them to compute
//! HTTP byte ranges for reconstruction. A non-zero `version` byte marks the
//! footer start (xet-core footer magics like `XETBLOB` are ASCII, outside the
//! version-0 range). Scheme `99` (Auto) is sentinel-only and rejected.

use bale_server_core::{ChunkHash, FileHash, Hash32, XorbHash};
use std::io::Read;
use thiserror::Error;
use xet_core_structures::merklehash::{
    compute_data_hash, xorb_hash as compute_xorb_merkle_hash, MerkleHash,
};
use xet_core_structures::xorb_object::byte_grouping::bg4::bg4_regroup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorbChunkFrame {
    pub on_disk_start: u32,
    /// 8-byte header + compressed payload.
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
    #[error("{0} trailing bytes after the last chunk frame")]
    TrailingBytes(usize),
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
// xet-core-structures' MAX_XORB_CHUNKS / MAX_XORB_BYTES.
const MAX_XORB_CHUNKS: usize = 8 * 1024;
const MAX_XORB_UNPACKED_BYTES: u64 = 64 * 1024 * 1024;

fn u24_le(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

/// Stops at the first non-zero version byte (footer marker) or EOF. Bodies over
/// u32::MAX are rejected since `XorbChunkFrame` offsets are u32 (defense in
/// depth — the upload handler already caps xorbs at 64 MiB).
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

/// Recompute the xorb content hash and compare to `expected` so a bad upload is
/// rejected before persisting. `expected` is natural-byte order (from
/// `bale_server_wire::decode_hash`), which is what `DataHash::from([u8; 32])`
/// consumes. Returns the per-frame chunk hashes: they are the only trusted
/// source for the dedup index and for verifying shard file terms.
pub fn verify_xorb_body(
    body: &[u8],
    expected: &XorbHash,
) -> Result<Vec<ChunkHash>, XorbVerifyError> {
    let frames = parse_xorb_frames(body)?;
    // xet uploads xorbs without a footer; unverified trailing bytes would be
    // stored (and unaccounted) forever.
    let consumed = frames
        .last()
        .map(|f| f.on_disk_start as usize + f.on_disk_len as usize)
        .unwrap_or(0);
    if consumed != body.len() {
        return Err(XorbVerifyError::Parse(XorbParseError::TrailingBytes(
            body.len() - consumed,
        )));
    }
    // xet never builds past these; checked before decompressing so a body of
    // ~1000 max-size frames can't cost ~16 GiB of decode + hashing per request.
    let unpacked: u64 = frames.iter().map(|f| f.uncompressed_len as u64).sum();
    if frames.len() > MAX_XORB_CHUNKS || unpacked > MAX_XORB_UNPACKED_BYTES {
        return Err(XorbVerifyError::Parse(XorbParseError::TooLarge {
            actual: unpacked as usize,
            max: MAX_XORB_UNPACKED_BYTES as usize,
        }));
    }
    let mut entries: Vec<(MerkleHash, u64)> = Vec::with_capacity(frames.len());
    let mut buf = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        buf.clear();
        decompress_frame(body, f, i, &mut buf)?;
        entries.push((compute_data_hash(&buf), buf.len() as u64));
    }

    if compute_xorb_merkle_hash(&entries) != MerkleHash::from(expected.as_bytes()) {
        return Err(XorbVerifyError::HashMismatch);
    }
    Ok(entries
        .iter()
        .map(|(h, _)| ChunkHash::from_bytes((*h).into()))
        .collect())
}

/// Decompress `body` (the on-disk range for one reconstruction term) into `out`,
/// in order. Like [`verify_xorb_body`] without the hash check — callers (e.g. the
/// download streamer) already know the xorb is intact.
pub fn decompress_xorb_chunks_into(body: &[u8], out: &mut Vec<u8>) -> Result<(), XorbVerifyError> {
    let frames = parse_xorb_frames(body)?;
    for (i, f) in frames.iter().enumerate() {
        decompress_frame(body, f, i, out)?;
    }
    Ok(())
}

/// [`decompress_xorb_chunks_into`] that also checks each chunk against the
/// expected hash (one per frame, in order), so bit rot or tampering in the blob
/// store is never served.
pub fn decompress_xorb_chunks_verified(
    body: &[u8],
    expected: &[ChunkHash],
    out: &mut Vec<u8>,
) -> Result<(), XorbVerifyError> {
    let frames = parse_xorb_frames(body)?;
    if frames.len() != expected.len() {
        return Err(XorbVerifyError::HashMismatch);
    }
    for (i, (f, want)) in frames.iter().zip(expected).enumerate() {
        let start = out.len();
        decompress_frame(body, f, i, out)?;
        if compute_data_hash(&out[start..]) != MerkleHash::from(want.as_bytes()) {
            return Err(XorbVerifyError::HashMismatch);
        }
    }
    Ok(())
}

// Appends exactly `f.uncompressed_len` bytes to `out`. Output is capped at the
// declared length (+1 to detect overrun) while decoding: LZ4 expands ~255x, so
// an unbounded decode of a 16 MiB frame is a multi-GiB allocation (OOM kill).
fn decompress_frame(
    body: &[u8],
    f: &XorbChunkFrame,
    frame_index: usize,
    out: &mut Vec<u8>,
) -> Result<(), XorbVerifyError> {
    let payload_start = f.on_disk_start as usize + HEADER_LEN;
    let payload_end = f.on_disk_start as usize + f.on_disk_len as usize;
    let payload = &body[payload_start..payload_end];
    let declared = f.uncompressed_len as usize;
    let fail = |message: String| XorbVerifyError::DecompressFailed {
        frame_index,
        message,
    };

    let base = out.len();
    match f.compression_scheme {
        0 => out.extend_from_slice(payload),
        1 | 2 => {
            let mut dec = lz4_flex::frame::FrameDecoder::new(payload).take(declared as u64 + 1);
            if f.compression_scheme == 1 {
                dec.read_to_end(out).map_err(|e| fail(e.to_string()))?;
            } else {
                let mut grouped = Vec::with_capacity(declared);
                dec.read_to_end(&mut grouped)
                    .map_err(|e| fail(e.to_string()))?;
                out.extend_from_slice(&bg4_regroup(&grouped));
            }
        }
        // parse_xorb_frames already rejects schemes outside 0..=2.
        other => {
            return Err(XorbVerifyError::Parse(
                XorbParseError::BadCompressionScheme {
                    frame_index,
                    scheme: other,
                },
            ))
        }
    }
    let actual = out.len() - base;
    if actual != declared {
        return Err(XorbVerifyError::LengthMismatch {
            frame_index,
            declared,
            actual,
        });
    }
    Ok(())
}

fn merkle_entries(chunks: &[(ChunkHash, u64)]) -> Vec<(MerkleHash, u64)> {
    chunks
        .iter()
        .map(|(h, len)| (MerkleHash::from(h.as_bytes()), *len))
        .collect()
}

pub fn xorb_hash_of(chunks: &[(ChunkHash, u64)]) -> XorbHash {
    XorbHash::from_bytes(compute_xorb_merkle_hash(&merkle_entries(chunks)).into())
}

/// xet's file hash over the file's full chunk sequence.
pub fn file_hash_of(chunks: &[(ChunkHash, u64)]) -> FileHash {
    FileHash::from_bytes(xet_core_structures::merklehash::file_hash(&merkle_entries(chunks)).into())
}

/// xet's `FileVerificationEntry.range_hash` for one term's chunks.
pub fn term_verification_hash(chunks: &[ChunkHash]) -> Hash32 {
    let hashes: Vec<MerkleHash> = chunks
        .iter()
        .map(|h| MerkleHash::from(h.as_bytes()))
        .collect();
    Hash32(
        xet_core_structures::metadata_shard::chunk_verification::range_hash_from_chunks(&hashes)
            .into(),
    )
}

/// xet's file hash computed incrementally in O(levels) memory, so verifying a
/// huge file doesn't hold every chunk hash. Equivalent to `file_hash_of` over
/// the pushed sequence: xet's tree groups each level greedily left to right,
/// and with ≥ `MAX_GROUP` entries buffered a group's cut depends only on those
/// entries, so groups can be emitted as soon as they are decidable.
#[derive(Default)]
pub struct FileHasher {
    levels: Vec<Vec<(MerkleHash, u64)>>,
    pushed: Vec<u64>,
}

// xet aggregated_hashes: groups of 2..=2·4+1 entries, cut after an entry whose
// hash % 4 == 0 (from the 3rd entry on).
const MERGE_BRANCHING: u64 = 4;
const MAX_GROUP: usize = 2 * MERGE_BRANCHING as usize + 1;

impl FileHasher {
    pub fn push(&mut self, chunk: ChunkHash, len: u64) {
        self.push_at(0, (MerkleHash::from(chunk.as_bytes()), len));
    }

    pub fn finish(mut self) -> FileHash {
        if self.pushed.first().copied().unwrap_or(0) == 0 {
            return FileHash::from_bytes(MerkleHash::default().into());
        }
        let mut lvl = 0;
        loop {
            let higher_empty = self.pushed.get(lvl + 1).copied().unwrap_or(0) == 0;
            if self.pushed[lvl] == 1 && higher_empty {
                let root = self.levels[lvl][0].0;
                return FileHash::from_bytes(root.hmac([0u8; 32].into()).into());
            }
            let rest = std::mem::take(&mut self.levels[lvl]);
            let mut i = 0;
            while i < rest.len() {
                let cut = tail_cut(&rest[i..]);
                let merged = merged_hash(&rest[i..i + cut]);
                self.push_at(lvl + 1, merged);
                i += cut;
            }
            lvl += 1;
        }
    }

    fn push_at(&mut self, lvl: usize, entry: (MerkleHash, u64)) {
        if self.levels.len() <= lvl {
            self.levels.resize_with(lvl + 1, Vec::new);
            self.pushed.resize(lvl + 1, 0);
        }
        self.levels[lvl].push(entry);
        self.pushed[lvl] += 1;
        while self.levels[lvl].len() >= MAX_GROUP {
            let cut = tail_cut(&self.levels[lvl][..MAX_GROUP]);
            let group: Vec<(MerkleHash, u64)> = self.levels[lvl].drain(..cut).collect();
            let merged = merged_hash(&group);
            self.push_at(lvl + 1, merged);
        }
    }
}

// xet's next_merge_cut over the remaining entries.
fn tail_cut(entries: &[(MerkleHash, u64)]) -> usize {
    if entries.len() <= 2 {
        return entries.len();
    }
    let end = MAX_GROUP.min(entries.len());
    (2..end)
        .find(|&i| entries[i].0 % MERGE_BRANCHING == 0)
        .map_or(end, |i| i + 1)
}

// xet's merged_hash_of_sequence: "{hash words as 16-hex each} : {size}\n" per
// entry, hashed as an internal node.
fn merged_hash(entries: &[(MerkleHash, u64)]) -> (MerkleHash, u64) {
    use std::fmt::Write;
    let mut buf = String::with_capacity(entries.len() * 88);
    let mut total = 0u64;
    for (h, size) in entries {
        for word in h.iter() {
            let _ = write!(buf, "{:016x}", word.to_le());
        }
        let _ = writeln!(buf, " : {size}");
        total += size;
    }
    (
        xet_core_structures::merklehash::compute_internal_node_hash(buf.as_bytes()),
        total,
    )
}
