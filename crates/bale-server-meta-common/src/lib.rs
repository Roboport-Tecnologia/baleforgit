//! Dialect-free pieces shared by the SQLite and Postgres `MetadataStore` impls:
//! the value conversions, the i64-overflow guard, and the row→struct decoders.
//! The decoders are generic over `sqlx::Row` via the [`DecodeRow`] blanket impl,
//! so a fix to a decoder (e.g. the `verification` mapping) can't drift between
//! the two backends. Everything dialect-specific stays in the backend crates:
//! DDL types, `?`/`$n` placeholders, upsert syntax, the `::BIGINT` SUM cast, and
//! — load-bearing for the no-corruption guarantee — the per-backend concurrency
//! control (Postgres' `pg_advisory_xact_lock` vs SQLite's tx serialization).

use bale_server_core::{
    ChunkHash, ChunkOffsetRow, CoreError, CoreResult, FileTerm, Hash32, XorbFrameRow, XorbHash,
    XorbInfo, HASH_LEN,
};
use sqlx::{ColumnIndex, Decode, Row, Type};
use std::time::{SystemTime, UNIX_EPOCH};

// SQLite caps bound params at ~32k and Postgres at 65535; the widest row binds 7,
// so 500 rows stays far under either ceiling.
pub const CHUNK_INSERT_BATCH: usize = 500;

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn hash_to_blob(h: &Hash32) -> Vec<u8> {
    h.as_bytes().to_vec()
}

pub fn blob_to_hash(b: &[u8]) -> CoreResult<Hash32> {
    if b.len() != HASH_LEN {
        return Err(CoreError::Internal(format!(
            "bad hash blob length {} (want {})",
            b.len(),
            HASH_LEN
        )));
    }
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(b);
    Ok(Hash32(out))
}

// A negative SUM means i64 overflow; `.max(0)` would mask it to 0 and quietly
// vanish the quota limit, so error instead.
pub fn nonneg_i64_to_u64(n: i64, label: &'static str) -> CoreResult<u64> {
    if n < 0 {
        return Err(CoreError::Internal(format!(
            "{label}: aggregate overflowed i64 (got {n}); database is corrupt or owner exceeds 8 EiB"
        )));
    }
    Ok(n as u64)
}

pub fn internal<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Internal(format!("row decode: {e}"))
}

// Sort + dedup by raw bytes so an `IN (...)` clause stays compact and stable.
pub fn dedup_sorted_xorbs(xorbs: &[XorbHash]) -> Vec<XorbHash> {
    let mut uniq = xorbs.to_vec();
    uniq.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    uniq.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
    uniq
}

/// Column reads shared by both backends. The verbose sqlx trait bounds live here
/// once; `SqliteRow`/`PgRow` satisfy them, so the decoders below take a bare
/// `R: DecodeRow`. Columns are addressed by name, matching every store query.
pub trait DecodeRow: Row {
    fn get_i64(&self, col: &str) -> CoreResult<i64>;
    fn get_u32(&self, col: &str) -> CoreResult<u32>;
    fn get_blob(&self, col: &str) -> CoreResult<Vec<u8>>;
    fn get_opt_blob(&self, col: &str) -> CoreResult<Option<Vec<u8>>>;
    fn get_hash(&self, col: &str) -> CoreResult<Hash32>;
}

impl<R> DecodeRow for R
where
    R: Row,
    for<'r> i64: Decode<'r, R::Database> + Type<R::Database>,
    for<'r> Vec<u8>: Decode<'r, R::Database> + Type<R::Database>,
    for<'r> Option<Vec<u8>>: Decode<'r, R::Database> + Type<R::Database>,
    for<'r> &'r str: ColumnIndex<R>,
{
    fn get_i64(&self, col: &str) -> CoreResult<i64> {
        self.try_get(col).map_err(internal)
    }
    fn get_u32(&self, col: &str) -> CoreResult<u32> {
        Ok(self.get_i64(col)? as u32)
    }
    fn get_blob(&self, col: &str) -> CoreResult<Vec<u8>> {
        self.try_get(col).map_err(internal)
    }
    fn get_opt_blob(&self, col: &str) -> CoreResult<Option<Vec<u8>>> {
        self.try_get(col).map_err(internal)
    }
    fn get_hash(&self, col: &str) -> CoreResult<Hash32> {
        blob_to_hash(&self.get_blob(col)?)
    }
}

pub fn row_to_file_term<R: DecodeRow>(r: &R) -> CoreResult<FileTerm> {
    Ok(FileTerm {
        xorb: XorbHash(r.get_hash("xorb_hash")?),
        chunk_idx_start: r.get_u32("chunk_idx_start")?,
        chunk_idx_end: r.get_u32("chunk_idx_end")?,
        unpacked_segment_bytes: r.get_u32("unpacked_bytes")?,
        verification: r
            .get_opt_blob("verification")?
            .as_deref()
            .map(blob_to_hash)
            .transpose()?,
    })
}

pub fn row_to_frame<R: DecodeRow>(r: &R) -> CoreResult<XorbFrameRow> {
    Ok(XorbFrameRow {
        frame_index: r.get_u32("frame_index")?,
        on_disk_start: r.get_u32("on_disk_start")?,
        on_disk_len: r.get_u32("on_disk_len")?,
        uncompressed_len: r.get_u32("uncompressed_len")?,
    })
}

pub fn row_to_chunk_offset<R: DecodeRow>(r: &R) -> CoreResult<ChunkOffsetRow> {
    Ok(ChunkOffsetRow {
        chunk_hash: ChunkHash(r.get_hash("chunk_hash")?),
        chunk_index: r.get_u32("chunk_index")?,
        byte_start: r.get_u32("byte_start")?,
        unpacked_segment_bytes: r.get_u32("unpacked_bytes")?,
    })
}

pub fn row_to_xorb_info<R: DecodeRow>(r: &R, xorb: XorbHash) -> CoreResult<XorbInfo> {
    Ok(XorbInfo {
        xorb,
        num_chunks: r.get_u32("num_chunks")?,
        num_bytes_in_cas: r.get_u32("num_bytes_in_cas")?,
        num_bytes_on_disk: r.get_u32("num_bytes_on_disk")?,
    })
}
