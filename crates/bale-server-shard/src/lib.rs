//! MDB shard binary format parser and serializer.
//!
//! Layout (per Xet spec):
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

// Mirrored as a pub const in `bale-server-shard-testing` so test code that
// authors shards can name it; production paths only read it internally.
const FLAG_WITH_VERIFICATION: u32 = 1 << 31; // 0x8000_0000
const FLAG_WITH_METADATA_EXT: u32 = 1 << 30; // 0x4000_0000

/// The canonical 32-byte magic that prefixes every MDB shard. Lifted verbatim
/// from xet-core's `mdb_shard::shard_format::MDB_SHARD_HEADER_TAG` (see
/// xet-core@git-xet-v0.2.1). Our parser only checks length, not identity, so
/// shards written by older toolchains still round-trip; serialization uses
/// this value so shards we produce are accepted by xet-core's strict check.
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
    /// One verification hash per entry, present iff `FLAG_WITH_VERIFICATION`.
    pub verifications: Vec<Hash32>,
    /// Present iff `FLAG_WITH_METADATA_EXT`. The 32-byte SHA-256 of the file.
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

/// Reverse the byte order within each 8-byte group of a 32-byte buffer.
/// This is its own inverse. xet-core serializes a `MerkleHash` (internally
/// `[u64; 4]`) as 32 little-endian bytes per u64; the same shape is reused
/// for `FileMetadataExt.sha256`, so to round-trip a sha256 between the
/// standard byte order and the on-disk layout we apply this swap.
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

    // Header
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

    // File info section
    let mut files = Vec::new();
    loop {
        let file_hash = c.hash()?;
        let file_flags = c.u32()?;
        let num_entries = c.u32()?;
        c.skip(8)?; // _unused

        if is_bookend_hash(&file_hash) {
            // The remaining 16 bytes after the hash are required by layout
            // (the bookend is a full 48-byte entry) — file_flags/num_entries
            // and _unused all become part of the 16 trailing zero bytes.
            break;
        }

        // Bound the preallocation against the remaining buffer: each entry is
        // ENTRY_SIZE bytes, so num_entries items cannot exceed remaining/ENTRY_SIZE
        // without the parse failing later anyway. Guards against a malicious
        // num_entries=u32::MAX from triggering a ~200 GiB Vec preallocation.
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
            // num_entries is already bounded against remaining above, but the
            // verification section needs another ENTRY_SIZE bytes per entry on
            // top of the file-term bytes we just consumed.
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
            // git-xet serializes the sha256 in the same little-endian-u64-group
            // order as every other Xet hash on disk, NOT in plain sha256 byte
            // order. Normalize here so `ParsedFile.sha256` matches the standard
            // byte order (the inverse swap happens on serialize). See
            // `swap_u64_groups` for the byte mapping.
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

    // CAS info section
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

    // Footer (optional)
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
    // Header
    out.extend_from_slice(&s.header.tag);
    out.extend_from_slice(&s.header.version.to_le_bytes());
    out.extend_from_slice(&s.header.footer_size.to_le_bytes());

    let file_info_offset = out.len() as u64;

    // File info section
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
            // Caller invariant: flag implies Some(sha256). Defensive fallback to
            // zeros keeps the layout valid rather than panicking server-wide.
            let sha = f.sha256.unwrap_or(Hash32([0u8; HASH_LEN]));
            out.extend_from_slice(&swap_u64_groups(sha.0));
            out.extend_from_slice(&[0u8; 16]);
        }
    }
    // File info bookend: 0xFF*32 + 0x00*16
    out.extend_from_slice(&[0xFFu8; HASH_LEN]);
    out.extend_from_slice(&[0u8; 16]);

    let cas_info_offset = out.len() as u64;

    // CAS info section
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
        // 200-byte footer
        out.extend_from_slice(&ft.version.to_le_bytes());
        out.extend_from_slice(&file_info_offset.to_le_bytes());
        out.extend_from_slice(&cas_info_offset.to_le_bytes());
        out.extend_from_slice(&[0u8; 48]);
        out.extend_from_slice(&ft.chunk_hash_hmac_key.0);
        out.extend_from_slice(&ft.shard_creation_timestamp.to_le_bytes());
        out.extend_from_slice(&ft.shard_key_expiry.to_le_bytes());
        out.extend_from_slice(&[0u8; 72]);
        out.extend_from_slice(&footer_offset.to_le_bytes());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_hash(seed: u8) -> Hash32 {
        let mut h = [0u8; HASH_LEN];
        for (i, b) in h.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        Hash32(h)
    }

    fn sample_shard(
        with_verification: bool,
        with_metadata: bool,
        with_footer: bool,
    ) -> ParsedShard {
        let xorb1 = XorbHash(mk_hash(0x11));
        let xorb2 = XorbHash(mk_hash(0x22));

        let mut flags: u32 = 0;
        if with_verification {
            flags |= FLAG_WITH_VERIFICATION;
        }
        if with_metadata {
            flags |= FLAG_WITH_METADATA_EXT;
        }

        let entries = vec![
            FileTermEntry {
                xorb: xorb1,
                cas_flags: 0,
                unpacked_segment_bytes: 1024,
                chunk_idx_start: 0,
                chunk_idx_end: 3,
            },
            FileTermEntry {
                xorb: xorb2,
                cas_flags: 0,
                unpacked_segment_bytes: 2048,
                chunk_idx_start: 0,
                chunk_idx_end: 2,
            },
        ];
        let verifications = if with_verification {
            vec![mk_hash(0xA1), mk_hash(0xA2)]
        } else {
            vec![]
        };
        let sha256 = if with_metadata {
            Some(mk_hash(0xCC))
        } else {
            None
        };

        let files = vec![ParsedFile {
            file_hash: FileHash(mk_hash(0xF0)),
            file_flags: flags,
            entries,
            verifications,
            sha256,
        }];

        let cas_blocks = vec![
            ParsedCasBlock {
                xorb: xorb1,
                cas_flags: 0,
                num_bytes_in_cas: 1024,
                num_bytes_on_disk: 900,
                chunks: vec![
                    CasChunkEntry {
                        chunk_hash: ChunkHash(mk_hash(0x01)),
                        byte_start: 0,
                        unpacked_segment_bytes: 300,
                    },
                    CasChunkEntry {
                        chunk_hash: ChunkHash(mk_hash(0x02)),
                        byte_start: 300,
                        unpacked_segment_bytes: 350,
                    },
                    CasChunkEntry {
                        chunk_hash: ChunkHash(mk_hash(0x03)),
                        byte_start: 650,
                        unpacked_segment_bytes: 374,
                    },
                ],
            },
            ParsedCasBlock {
                xorb: xorb2,
                cas_flags: 0,
                num_bytes_in_cas: 2048,
                num_bytes_on_disk: 1800,
                chunks: vec![
                    CasChunkEntry {
                        chunk_hash: ChunkHash(mk_hash(0x10)),
                        byte_start: 0,
                        unpacked_segment_bytes: 1000,
                    },
                    CasChunkEntry {
                        chunk_hash: ChunkHash(mk_hash(0x11)),
                        byte_start: 1000,
                        unpacked_segment_bytes: 1048,
                    },
                ],
            },
        ];

        let footer = if with_footer {
            Some(ShardFooter {
                version: MDB_SHARD_FOOTER_VERSION,
                // Offsets are recomputed by the serializer; the values here are ignored.
                file_info_offset: 0,
                cas_info_offset: 0,
                chunk_hash_hmac_key: mk_hash(0xEE),
                shard_creation_timestamp: 1_700_000_000,
                shard_key_expiry: 1_700_604_800,
                footer_offset: 0,
            })
        } else {
            None
        };

        ParsedShard {
            header: ShardHeader {
                tag: MDB_SHARD_HEADER_TAG,
                version: MDB_SHARD_HEADER_VERSION,
                footer_size: if with_footer { FOOTER_SIZE as u64 } else { 0 },
            },
            files,
            cas_blocks,
            footer,
        }
    }

    fn assert_roundtrip(shard: &ParsedShard) {
        let bytes = serialize(shard);
        let parsed = parse(&bytes).expect("parse");
        assert_eq!(parsed.header, shard.header, "header roundtrip");
        assert_eq!(parsed.files, shard.files, "files roundtrip");
        assert_eq!(parsed.cas_blocks, shard.cas_blocks, "cas_blocks roundtrip");
        // Footer offsets are recomputed by the serializer; compare logical fields only.
        match (&parsed.footer, &shard.footer) {
            (Some(p), Some(s)) => {
                assert_eq!(p.version, s.version);
                assert_eq!(p.chunk_hash_hmac_key, s.chunk_hash_hmac_key);
                assert_eq!(p.shard_creation_timestamp, s.shard_creation_timestamp);
                assert_eq!(p.shard_key_expiry, s.shard_key_expiry);
                // The serializer writes the true offsets — sanity check they
                // point at the right sections by reparsing.
                assert!(p.file_info_offset >= HEADER_SIZE as u64);
                assert!(p.cas_info_offset > p.file_info_offset);
                assert!(p.footer_offset > p.cas_info_offset);
            }
            (None, None) => {}
            _ => panic!("footer presence mismatch"),
        }
    }

    #[test]
    fn roundtrip_no_optionals_no_footer() {
        assert_roundtrip(&sample_shard(false, false, false));
    }

    #[test]
    fn roundtrip_with_verification_no_footer() {
        assert_roundtrip(&sample_shard(true, false, false));
    }

    #[test]
    fn roundtrip_with_verification_and_metadata_no_footer() {
        assert_roundtrip(&sample_shard(true, true, false));
    }

    #[test]
    fn roundtrip_with_footer() {
        assert_roundtrip(&sample_shard(true, true, true));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let err = parse(&[0u8; 10]).unwrap_err();
        matches!(err, ShardError::Truncated { .. });
    }

    #[test]
    fn parse_rejects_oversized_num_entries() {
        // Build a header + a file-info entry that claims num_entries = u32::MAX.
        // Without the bound check this would `Vec::with_capacity(u32::MAX as usize)`
        // and OOM. With the check, it must error as truncated.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MDB_SHARD_HEADER_TAG);
        bytes.extend_from_slice(&MDB_SHARD_HEADER_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes()); // footer_size
        bytes.extend_from_slice(&mk_hash(0x01).0); // file_hash (not bookend)
        bytes.extend_from_slice(&0u32.to_le_bytes()); // file_flags
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // num_entries
        bytes.extend_from_slice(&[0u8; 8]); // _unused
                                            // Body intentionally too small to fit u32::MAX entries.
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(err, ShardError::Truncated { .. }));
    }

    #[test]
    fn parse_rejects_bad_version() {
        let mut bytes = serialize(&sample_shard(false, false, false));
        // Header version is at offset 32 (after the 32-byte tag).
        bytes[32..40].copy_from_slice(&99u64.to_le_bytes());
        let err = parse(&bytes).unwrap_err();
        matches!(err, ShardError::BadHeaderVersion(99));
    }

    #[test]
    fn empty_file_section_still_has_bookend() {
        // A shard with zero file info entries (e.g. a global-dedup response).
        let shard = ParsedShard {
            header: ShardHeader {
                tag: MDB_SHARD_HEADER_TAG,
                version: MDB_SHARD_HEADER_VERSION,
                footer_size: 0,
            },
            files: vec![],
            cas_blocks: vec![ParsedCasBlock {
                xorb: XorbHash(mk_hash(0x55)),
                cas_flags: 0,
                num_bytes_in_cas: 64,
                num_bytes_on_disk: 60,
                chunks: vec![CasChunkEntry {
                    chunk_hash: ChunkHash(mk_hash(0x56)),
                    byte_start: 0,
                    unpacked_segment_bytes: 64,
                }],
            }],
            footer: None,
        };
        assert_roundtrip(&shard);
    }
}
