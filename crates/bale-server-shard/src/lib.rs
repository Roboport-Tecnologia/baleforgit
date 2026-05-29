//! MDB shard binary format parser and serializer. Layout (per Xet spec):
//! ```text
//! Header (48 B) | FileInfo... | FileInfo bookend (48 B)
//!               | CasInfo...  | CasInfo bookend  (48 B)
//!               | Footer (200 B, optional)
//! ```

use bale_server_core::{ChunkHash, FileHash, Hash32, XorbHash, HASH_LEN};
use thiserror::Error;

pub mod xorb;
pub use xorb::{
    decompress_xorb_chunks_into, parse_xorb_frames, verify_xorb_body, XorbChunkFrame,
    XorbParseError, XorbVerifyError,
};

const ENTRY_SIZE: usize = 48;
const HEADER_SIZE: usize = 48;
pub const FOOTER_SIZE: usize = 200;

pub const MDB_SHARD_HEADER_VERSION: u64 = 2;
pub const MDB_SHARD_FOOTER_VERSION: u64 = 1;

const FLAG_WITH_VERIFICATION: u32 = 1 << 31; // 0x8000_0000
const FLAG_WITH_METADATA_EXT: u32 = 1 << 30; // 0x4000_0000

/// Canonical 32-byte shard magic, verbatim from xet-core's
/// `mdb_shard::shard_format::MDB_SHARD_HEADER_TAG` (git-xet-v0.2.1). Parse only
/// checks length so older shards round-trip; serialize emits this so xet-core's
/// strict check accepts ours.
pub const MDB_SHARD_HEADER_TAG: [u8; HASH_LEN] = [
    b'H', b'F', b'R', b'e', b'p', b'o', b'M', b'e', b't', b'a', b'D', b'a', b't', b'a', 0, 85, 105,
    103, 69, 106, 123, 129, 87, 131, 165, 189, 217, 92, 205, 209, 74, 169,
];

#[derive(Debug, Error)]
pub enum ShardError {
    #[error("shard truncated: needed {needed} more bytes at offset {offset}")]
    Truncated { offset: usize, needed: usize },
    #[error("unsupported header version {0}")]
    BadHeaderVersion(u64),
    #[error("unsupported footer version {0}")]
    BadFooterVersion(u64),
    #[error("declared footer offset {declared} exceeds shard length {len}")]
    BadFooterOffset { declared: u64, len: usize },
    #[error("shard too large ({0} bytes, max 64 MiB)")]
    TooLarge(usize),
}

pub type ShardResult<T> = Result<T, ShardError>;

const MAX_SHARD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardHeader {
    pub tag: [u8; HASH_LEN],
    pub version: u64,
    pub footer_size: u64, // 0 if footer omitted
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTermEntry {
    pub xorb: XorbHash,
    pub cas_flags: u32,
    pub unpacked_segment_bytes: u32,
    pub chunk_idx_start: u32,
    pub chunk_idx_end: u32, // exclusive
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedFile {
    pub file_hash: FileHash,
    pub file_flags: u32,
    pub entries: Vec<FileTermEntry>,
    /// One per entry, present iff `FLAG_WITH_VERIFICATION`.
    pub verifications: Vec<Hash32>,
    /// File SHA-256, present iff `FLAG_WITH_METADATA_EXT`.
    pub sha256: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasChunkEntry {
    pub chunk_hash: ChunkHash,
    pub byte_start: u32,
    pub unpacked_segment_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCasBlock {
    pub xorb: XorbHash,
    pub cas_flags: u32,
    pub num_bytes_in_cas: u32,
    pub num_bytes_on_disk: u32,
    pub chunks: Vec<CasChunkEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardFooter {
    pub version: u64,
    pub file_info_offset: u64,
    pub cas_info_offset: u64,
    pub chunk_hash_hmac_key: Hash32,
    pub shard_creation_timestamp: u64,
    pub shard_key_expiry: u64,
    pub footer_offset: u64,
}

#[derive(Clone, Debug)]
pub struct ParsedShard {
    pub header: ShardHeader,
    pub files: Vec<ParsedFile>,
    pub cas_blocks: Vec<ParsedCasBlock>,
    pub footer: Option<ShardFooter>,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn need(&self, n: usize) -> ShardResult<()> {
        if self.buf.len().saturating_sub(self.pos) < n {
            Err(ShardError::Truncated {
                offset: self.pos,
                needed: n - (self.buf.len() - self.pos),
            })
        } else {
            Ok(())
        }
    }
    fn take(&mut self, n: usize) -> ShardResult<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> ShardResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> ShardResult<u64> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
    fn hash(&mut self) -> ShardResult<Hash32> {
        let s = self.take(HASH_LEN)?;
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(s);
        Ok(Hash32(out))
    }
    fn skip(&mut self, n: usize) -> ShardResult<()> {
        self.take(n).map(|_| ())
    }
}

/// Reverse byte order within each of the four 8-byte groups (its own inverse).
/// xet-core stores a `MerkleHash` (`[u64; 4]`) as 4 little-endian u64s, and
/// reuses that layout for `FileMetadataExt.sha256`; this maps it to/from
/// standard sha256 byte order.
fn swap_u64_groups(input: [u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    for group in 0..4 {
        for i in 0..8 {
            out[group * 8 + i] = input[group * 8 + (7 - i)];
        }
    }
    out
}

fn is_bookend_hash(h: &Hash32) -> bool {
    h.0.iter().all(|b| *b == 0xFF)
}

pub fn parse(bytes: &[u8]) -> ShardResult<ParsedShard> {
    if bytes.len() > MAX_SHARD_BYTES {
        return Err(ShardError::TooLarge(bytes.len()));
    }

    let mut c = Cursor::new(bytes);

    let tag_slice = c.take(HASH_LEN)?;
    let mut tag = [0u8; HASH_LEN];
    tag.copy_from_slice(tag_slice);
    let version = c.u64()?;
    if version != MDB_SHARD_HEADER_VERSION {
        return Err(ShardError::BadHeaderVersion(version));
    }
    let footer_size = c.u64()?;
    let header = ShardHeader {
        tag,
        version,
        footer_size,
    };

    let mut files = Vec::new();
    loop {
        let file_hash = c.hash()?;
        let file_flags = c.u32()?;
        let num_entries = c.u32()?;
        c.skip(8)?; // _unused

        if is_bookend_hash(&file_hash) {
            // Bookend is a full 48-byte entry; flags/num_entries/_unused are its trailing zeros.
            break;
        }

        // Cap preallocation at remaining/ENTRY_SIZE so a hostile num_entries=u32::MAX
        // can't trigger a ~200 GiB Vec; an honest count fails later anyway.
        let max_entries = (c.remaining() / ENTRY_SIZE) as u32;
        if num_entries > max_entries {
            return Err(ShardError::Truncated {
                offset: c.pos,
                needed: (num_entries as usize).saturating_mul(ENTRY_SIZE) - c.remaining(),
            });
        }
        let mut entries = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            let cas_hash = c.hash()?;
            let cas_flags = c.u32()?;
            let unpacked_segment_bytes = c.u32()?;
            let chunk_idx_start = c.u32()?;
            let chunk_idx_end = c.u32()?;
            entries.push(FileTermEntry {
                xorb: XorbHash(cas_hash),
                cas_flags,
                unpacked_segment_bytes,
                chunk_idx_start,
                chunk_idx_end,
            });
        }

        let mut verifications = Vec::new();
        if file_flags & FLAG_WITH_VERIFICATION != 0 {
            // Verification section needs another ENTRY_SIZE per entry beyond the file terms.
            if num_entries as usize > c.remaining() / ENTRY_SIZE {
                return Err(ShardError::Truncated {
                    offset: c.pos,
                    needed: (num_entries as usize).saturating_mul(ENTRY_SIZE) - c.remaining(),
                });
            }
            verifications.reserve(num_entries as usize);
            for _ in 0..num_entries {
                let range_hash = c.hash()?;
                c.skip(16)?; // _unused
                verifications.push(range_hash);
            }
        }

        let sha256 = if file_flags & FLAG_WITH_METADATA_EXT != 0 {
            // On disk the sha256 is in xet's u64-group order, not plain sha256 order;
            // normalize to standard byte order (serialize applies the inverse).
            let h = c.hash()?;
            c.skip(16)?;
            Some(Hash32(swap_u64_groups(h.0)))
        } else {
            None
        };

        files.push(ParsedFile {
            file_hash: FileHash(file_hash),
            file_flags,
            entries,
            verifications,
            sha256,
        });
    }

    let mut cas_blocks = Vec::new();
    loop {
        let cas_hash = c.hash()?;
        let cas_flags = c.u32()?;
        let num_entries = c.u32()?;
        let num_bytes_in_cas = c.u32()?;
        let num_bytes_on_disk = c.u32()?;

        if is_bookend_hash(&cas_hash) {
            break;
        }

        // Same allocation guard as the file-info section.
        if num_entries as usize > c.remaining() / ENTRY_SIZE {
            return Err(ShardError::Truncated {
                offset: c.pos,
                needed: (num_entries as usize).saturating_mul(ENTRY_SIZE) - c.remaining(),
            });
        }
        let mut chunks = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            let chunk_hash = c.hash()?;
            let byte_start = c.u32()?;
            let unpacked_segment_bytes = c.u32()?;
            c.skip(8)?; // _unused
            chunks.push(CasChunkEntry {
                chunk_hash: ChunkHash(chunk_hash),
                byte_start,
                unpacked_segment_bytes,
            });
        }
        cas_blocks.push(ParsedCasBlock {
            xorb: XorbHash(cas_hash),
            cas_flags,
            num_bytes_in_cas,
            num_bytes_on_disk,
            chunks,
        });
    }

    let footer = if footer_size == FOOTER_SIZE as u64 {
        let fv = c.u64()?;
        if fv != MDB_SHARD_FOOTER_VERSION {
            return Err(ShardError::BadFooterVersion(fv));
        }
        let file_info_offset = c.u64()?;
        let cas_info_offset = c.u64()?;
        c.skip(48)?; // _buffer
        let hmac_key = c.hash()?;
        let shard_creation_timestamp = c.u64()?;
        let shard_key_expiry = c.u64()?;
        c.skip(72)?; // _buffer2
        let footer_offset = c.u64()?;
        if footer_offset > bytes.len() as u64 {
            return Err(ShardError::BadFooterOffset {
                declared: footer_offset,
                len: bytes.len(),
            });
        }
        Some(ShardFooter {
            version: fv,
            file_info_offset,
            cas_info_offset,
            chunk_hash_hmac_key: hmac_key,
            shard_creation_timestamp,
            shard_key_expiry,
            footer_offset,
        })
    } else {
        None
    };

    Ok(ParsedShard {
        header,
        files,
        cas_blocks,
        footer,
    })
}

pub fn serialize(s: &ParsedShard) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + ENTRY_SIZE * 16);
    out.extend_from_slice(&s.header.tag);
    out.extend_from_slice(&s.header.version.to_le_bytes());
    out.extend_from_slice(&s.header.footer_size.to_le_bytes());

    let file_info_offset = out.len() as u64;

    for f in &s.files {
        out.extend_from_slice(&f.file_hash.as_bytes()[..]);
        out.extend_from_slice(&f.file_flags.to_le_bytes());
        out.extend_from_slice(&(f.entries.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 8]); // _unused

        for e in &f.entries {
            out.extend_from_slice(&e.xorb.as_bytes()[..]);
            out.extend_from_slice(&e.cas_flags.to_le_bytes());
            out.extend_from_slice(&e.unpacked_segment_bytes.to_le_bytes());
            out.extend_from_slice(&e.chunk_idx_start.to_le_bytes());
            out.extend_from_slice(&e.chunk_idx_end.to_le_bytes());
        }
        if f.file_flags & FLAG_WITH_VERIFICATION != 0 {
            for v in &f.verifications {
                out.extend_from_slice(&v.0);
                out.extend_from_slice(&[0u8; 16]);
            }
        }
        if f.file_flags & FLAG_WITH_METADATA_EXT != 0 {
            // Flag implies Some(sha256); fall back to zeros to keep layout valid, not panic.
            let sha = f.sha256.unwrap_or(Hash32([0u8; HASH_LEN]));
            out.extend_from_slice(&swap_u64_groups(sha.0));
            out.extend_from_slice(&[0u8; 16]);
        }
    }
    // File-info bookend: 0xFF*32 + 0x00*16.
    out.extend_from_slice(&[0xFFu8; HASH_LEN]);
    out.extend_from_slice(&[0u8; 16]);

    let cas_info_offset = out.len() as u64;

    for cb in &s.cas_blocks {
        out.extend_from_slice(&cb.xorb.as_bytes()[..]);
        out.extend_from_slice(&cb.cas_flags.to_le_bytes());
        out.extend_from_slice(&(cb.chunks.len() as u32).to_le_bytes());
        out.extend_from_slice(&cb.num_bytes_in_cas.to_le_bytes());
        out.extend_from_slice(&cb.num_bytes_on_disk.to_le_bytes());
        for ce in &cb.chunks {
            out.extend_from_slice(&ce.chunk_hash.as_bytes()[..]);
            out.extend_from_slice(&ce.byte_start.to_le_bytes());
            out.extend_from_slice(&ce.unpacked_segment_bytes.to_le_bytes());
            out.extend_from_slice(&[0u8; 8]);
        }
    }
    // CAS info bookend
    out.extend_from_slice(&[0xFFu8; HASH_LEN]);
    out.extend_from_slice(&[0u8; 16]);

    let footer_offset = out.len() as u64;

    if let Some(ref ft) = s.footer {
        out.extend_from_slice(&ft.version.to_le_bytes());
        out.extend_from_slice(&file_info_offset.to_le_bytes());
        out.extend_from_slice(&cas_info_offset.to_le_bytes());
        // file/xorb/chunk lookup tables are omitted (counts = 0), but each
        // offset must still point at the section end, not 0: xet's
        // read_all_truncated_hashes takes file_lookup_offset as the *end* of the
        // xorb-info range, so a zero here makes (end - xorb_info_offset)
        // underflow — debug panic, release OOM — when the client ingests the
        // dedup shard. Mirror xet's own serializer, which sets the offset even
        // when the table is absent.
        for offset_or_count in [footer_offset, 0, footer_offset, 0, footer_offset, 0] {
            out.extend_from_slice(&offset_or_count.to_le_bytes());
        }
        out.extend_from_slice(&ft.chunk_hash_hmac_key.0);
        out.extend_from_slice(&ft.shard_creation_timestamp.to_le_bytes());
        out.extend_from_slice(&ft.shard_key_expiry.to_le_bytes());
        out.extend_from_slice(&[0u8; 72]);
        out.extend_from_slice(&footer_offset.to_le_bytes());
    }

    out
}
