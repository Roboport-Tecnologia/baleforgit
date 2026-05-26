//! SQLite-backed `MetadataStore` implementation.

use async_trait::async_trait;
use bale_server_core::{
    ChunkHash, ChunkLocation, ChunkOffsetRow, ChunkRow, CoreError, CoreResult, FileHash, FileTerm,
    Hash32, MetadataStore, RepoRef, XorbFrameRow, XorbHash, XorbInfo, HASH_LEN,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Row, Sqlite};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS xorbs (
    hash             BLOB    PRIMARY KEY,
    num_chunks       INTEGER NOT NULL,
    num_bytes_in_cas INTEGER NOT NULL,
    num_bytes_on_disk INTEGER NOT NULL,
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
    chunk_hash       BLOB    NOT NULL,
    xorb_hash        BLOB    NOT NULL,
    chunk_index      INTEGER NOT NULL,
    byte_start       INTEGER NOT NULL,
    unpacked_bytes   INTEGER NOT NULL,
    PRIMARY KEY (chunk_hash, xorb_hash)
);
CREATE INDEX IF NOT EXISTS chunks_by_xorb ON chunks(xorb_hash, chunk_index);

CREATE TABLE IF NOT EXISTS xorb_frames (
    xorb_hash        BLOB    NOT NULL,
    frame_index      INTEGER NOT NULL,
    on_disk_start    INTEGER NOT NULL,
    on_disk_len      INTEGER NOT NULL,
    uncompressed_len INTEGER NOT NULL,
    PRIMARY KEY (xorb_hash, frame_index)
);

CREATE TABLE IF NOT EXISTS files (
    file_hash    BLOB    NOT NULL,
    repo_type    TEXT    NOT NULL,
    repo_id      TEXT    NOT NULL,
    revision     TEXT    NOT NULL,
    total_bytes  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    -- Composite PK: same file_hash can live in multiple repos (cross-repo
    -- dedup), and the reconstruction handler authorizes reads by requiring a
    -- (file_hash, repo_id=token.repo) row to exist.
    PRIMARY KEY (file_hash, repo_id)
);
CREATE INDEX IF NOT EXISTS files_by_repo ON files(repo_id);

CREATE TABLE IF NOT EXISTS file_terms (
    file_hash       BLOB    NOT NULL,
    term_index      INTEGER NOT NULL,
    xorb_hash       BLOB    NOT NULL,
    chunk_idx_start INTEGER NOT NULL,
    chunk_idx_end   INTEGER NOT NULL,
    unpacked_bytes  INTEGER NOT NULL,
    verification    BLOB,
    PRIMARY KEY (file_hash, term_index)
);
"#;

pub struct SqliteMetadataStore {
    pool: Pool<Sqlite>,
}

impl SqliteMetadataStore {
    /// Test/diagnostics helper — kept off the trait since no request path needs it.
    pub async fn count_xorbs(&self) -> CoreResult<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM xorbs")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("count xorbs: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        Ok(n as u64)
    }

    pub async fn count_files(&self) -> CoreResult<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM files")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("count files: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        Ok(n as u64)
    }

    /// Pass `":memory:"` for an in-memory test database — pool size is then
    /// forced to 1 so the schema survives between calls.
    pub async fn open_path(path: impl AsRef<Path>) -> CoreResult<Self> {
        let p = path.as_ref().to_string_lossy().to_string();
        let url = if p == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite://{p}")
        };
        Self::open_url(&url).await
    }

    pub async fn open_url(url: &str) -> CoreResult<Self> {
        let opts = SqliteConnectOptions::from_str(url)
            .map_err(|e| CoreError::Internal(format!("sqlite url: {e}")))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let in_memory = url.contains(":memory:");
        let pool = SqlitePoolOptions::new()
            .max_connections(if in_memory { 1 } else { 16 })
            .connect_with(opts)
            .await
            .map_err(|e| CoreError::Internal(format!("sqlite connect: {e}")))?;

        for stmt in SCHEMA_SQL.split(';') {
            let s = stmt.trim();
            if s.is_empty() {
                continue;
            }
            sqlx::query(s)
                .execute(&pool)
                .await
                .map_err(|e| CoreError::Internal(format!("migrate: {e}")))?;
        }
        Ok(Self { pool })
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hash_to_blob(h: &Hash32) -> Vec<u8> {
    h.as_bytes().to_vec()
}

fn blob_to_hash(b: &[u8]) -> CoreResult<Hash32> {
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

#[async_trait]
impl MetadataStore for SqliteMetadataStore {
    async fn register_xorb(&self, xorb: &XorbInfo, chunks: &[ChunkRow]) -> CoreResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;

        sqlx::query(
            "INSERT OR IGNORE INTO xorbs (hash, num_chunks, num_bytes_in_cas, num_bytes_on_disk, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(hash_to_blob(&xorb.xorb.0))
        .bind(xorb.num_chunks as i64)
        .bind(xorb.num_bytes_in_cas as i64)
        .bind(xorb.num_bytes_on_disk as i64)
        .bind(now_unix())
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("insert xorb: {e}")))?;

        for c in chunks {
            sqlx::query(
                "INSERT OR IGNORE INTO chunks
                 (chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(hash_to_blob(&c.chunk_hash.0))
            .bind(hash_to_blob(&xorb.xorb.0))
            .bind(c.chunk_index as i64)
            .bind(c.byte_start as i64)
            .bind(c.unpacked_segment_bytes as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("insert chunk: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(())
    }

    async fn register_file(
        &self,
        file_hash: &FileHash,
        repo: &RepoRef,
        terms: &[FileTerm],
    ) -> CoreResult<()> {
        let total_bytes: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;

        sqlx::query(
            "INSERT OR REPLACE INTO files (file_hash, repo_type, repo_id, revision, total_bytes, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(hash_to_blob(&file_hash.0))
        .bind(format!("{:?}", repo.repo_type).to_lowercase())
        .bind(&repo.repo_id)
        .bind(&repo.revision)
        .bind(total_bytes as i64)
        .bind(now_unix())
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("insert file: {e}")))?;

        // Rewrite the term list so a re-register with fewer terms can't leave stragglers.
        sqlx::query("DELETE FROM file_terms WHERE file_hash = ?")
            .bind(hash_to_blob(&file_hash.0))
            .execute(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("clear terms: {e}")))?;

        for (idx, t) in terms.iter().enumerate() {
            sqlx::query(
                "INSERT INTO file_terms
                 (file_hash, term_index, xorb_hash, chunk_idx_start, chunk_idx_end, unpacked_bytes, verification)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(hash_to_blob(&file_hash.0))
            .bind(idx as i64)
            .bind(hash_to_blob(&t.xorb.0))
            .bind(t.chunk_idx_start as i64)
            .bind(t.chunk_idx_end as i64)
            .bind(t.unpacked_segment_bytes as i64)
            .bind(t.verification.as_ref().map(hash_to_blob))
            .execute(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("insert term: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(())
    }

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool> {
        let row = sqlx::query("SELECT 1 FROM xorbs WHERE hash = ? LIMIT 1")
            .bind(hash_to_blob(&xorb.0))
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("select xorb: {e}")))?;
        Ok(row.is_some())
    }

    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool> {
        let row = sqlx::query("SELECT 1 FROM files WHERE file_hash = ? AND repo_id = ? LIMIT 1")
            .bind(hash_to_blob(&file_hash.0))
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("select file_in_repo: {e}")))?;
        Ok(row.is_some())
    }

    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>> {
        let rows = sqlx::query(
            "SELECT xorb_hash, chunk_idx_start, chunk_idx_end, unpacked_bytes, verification
             FROM file_terms WHERE file_hash = ? ORDER BY term_index ASC",
        )
        .bind(hash_to_blob(&file_hash.0))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("select terms: {e}")))?;

        if rows.is_empty() {
            return Ok(None);
        }
        let mut terms = Vec::with_capacity(rows.len());
        for r in rows {
            let xorb_blob: Vec<u8> = r.try_get("xorb_hash").map_err(internal)?;
            let cs: i64 = r.try_get("chunk_idx_start").map_err(internal)?;
            let ce: i64 = r.try_get("chunk_idx_end").map_err(internal)?;
            let unp: i64 = r.try_get("unpacked_bytes").map_err(internal)?;
            let ver: Option<Vec<u8>> = r.try_get("verification").map_err(internal)?;
            terms.push(FileTerm {
                xorb: XorbHash(blob_to_hash(&xorb_blob)?),
                chunk_idx_start: cs as u32,
                chunk_idx_end: ce as u32,
                unpacked_segment_bytes: unp as u32,
                verification: ver.as_deref().map(blob_to_hash).transpose()?,
            });
        }
        Ok(Some(terms))
    }

    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;
        for f in frames {
            sqlx::query(
                "INSERT OR IGNORE INTO xorb_frames
                 (xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(hash_to_blob(&xorb.0))
            .bind(f.frame_index as i64)
            .bind(f.on_disk_start as i64)
            .bind(f.on_disk_len as i64)
            .bind(f.uncompressed_len as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("insert frame: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit frames: {e}")))?;
        Ok(())
    }

    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>> {
        let rows = sqlx::query(
            "SELECT frame_index, on_disk_start, on_disk_len, uncompressed_len
             FROM xorb_frames WHERE xorb_hash = ? ORDER BY frame_index ASC",
        )
        .bind(hash_to_blob(&xorb.0))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("select frames: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let fi: i64 = r.try_get("frame_index").map_err(internal)?;
            let s: i64 = r.try_get("on_disk_start").map_err(internal)?;
            let l: i64 = r.try_get("on_disk_len").map_err(internal)?;
            let u: i64 = r.try_get("uncompressed_len").map_err(internal)?;
            out.push(XorbFrameRow {
                frame_index: fi as u32,
                on_disk_start: s as u32,
                on_disk_len: l as u32,
                uncompressed_len: u as u32,
            });
        }
        Ok(out)
    }

    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>> {
        let row = sqlx::query(
            "SELECT xorb_hash, chunk_index, byte_start, unpacked_bytes
             FROM chunks WHERE chunk_hash = ? LIMIT 1",
        )
        .bind(hash_to_blob(&chunk_hash.0))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("select chunk: {e}")))?;

        let Some(r) = row else {
            return Ok(None);
        };
        let xorb_blob: Vec<u8> = r.try_get("xorb_hash").map_err(internal)?;
        let ci: i64 = r.try_get("chunk_index").map_err(internal)?;
        let bs: i64 = r.try_get("byte_start").map_err(internal)?;
        let unp: i64 = r.try_get("unpacked_bytes").map_err(internal)?;
        Ok(Some(ChunkLocation {
            xorb: XorbHash(blob_to_hash(&xorb_blob)?),
            chunk_index: ci as u32,
            byte_start: bs as u32,
            unpacked_segment_bytes: unp as u32,
        }))
    }

    async fn xorbs_near_chunk(
        &self,
        chunk_hash: &ChunkHash,
        limit: usize,
    ) -> CoreResult<Vec<XorbInfo>> {
        // Prototype: just the containing xorb. Real neighborhood expansion (e.g.
        // xorbs sharing chunks with this one's xorb) is future work.
        let row = sqlx::query("SELECT xorb_hash FROM chunks WHERE chunk_hash = ? LIMIT 1")
            .bind(hash_to_blob(&chunk_hash.0))
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("near: {e}")))?;
        let Some(r) = row else {
            return Ok(vec![]);
        };
        let xorb_blob: Vec<u8> = r.try_get("xorb_hash").map_err(internal)?;
        let xorb = XorbHash(blob_to_hash(&xorb_blob)?);

        let row = sqlx::query(
            "SELECT num_chunks, num_bytes_in_cas, num_bytes_on_disk FROM xorbs WHERE hash = ?",
        )
        .bind(hash_to_blob(&xorb.0))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("xorb meta: {e}")))?;
        let nc: i64 = row.try_get("num_chunks").map_err(internal)?;
        let nb_cas: i64 = row.try_get("num_bytes_in_cas").map_err(internal)?;
        let nb_disk: i64 = row.try_get("num_bytes_on_disk").map_err(internal)?;

        let mut out = vec![XorbInfo {
            xorb,
            num_chunks: nc as u32,
            num_bytes_in_cas: nb_cas as u32,
            num_bytes_on_disk: nb_disk as u32,
        }];
        out.truncate(limit);
        Ok(out)
    }

    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>> {
        let rows = sqlx::query(
            "SELECT chunk_hash, chunk_index, byte_start, unpacked_bytes
             FROM chunks WHERE xorb_hash = ? ORDER BY chunk_index ASC",
        )
        .bind(hash_to_blob(&xorb.0))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("xorb offsets: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let chunk_blob: Vec<u8> = r.try_get("chunk_hash").map_err(internal)?;
            let ci: i64 = r.try_get("chunk_index").map_err(internal)?;
            let bs: i64 = r.try_get("byte_start").map_err(internal)?;
            let unp: i64 = r.try_get("unpacked_bytes").map_err(internal)?;
            out.push(ChunkOffsetRow {
                chunk_hash: ChunkHash(blob_to_hash(&chunk_blob)?),
                chunk_index: ci as u32,
                byte_start: bs as u32,
                unpacked_segment_bytes: unp as u32,
            });
        }
        Ok(out)
    }
}

fn internal<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Internal(format!("row decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bale_server_core::{Hash32, RepoType};

    fn h(seed: u8) -> Hash32 {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_add(i as u8);
        }
        Hash32(b)
    }

    async fn store() -> SqliteMetadataStore {
        SqliteMetadataStore::open_path(":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn xorb_register_and_lookup_chunk() {
        let s = store().await;
        let xorb = XorbHash(h(0x11));
        let info = XorbInfo {
            xorb,
            num_chunks: 2,
            num_bytes_in_cas: 1024,
            num_bytes_on_disk: 900,
        };
        let chunks = vec![
            ChunkRow {
                chunk_hash: ChunkHash(h(0xA1)),
                chunk_index: 0,
                byte_start: 0,
                unpacked_segment_bytes: 500,
            },
            ChunkRow {
                chunk_hash: ChunkHash(h(0xA2)),
                chunk_index: 1,
                byte_start: 500,
                unpacked_segment_bytes: 524,
            },
        ];
        s.register_xorb(&info, &chunks).await.unwrap();
        assert!(s.xorb_exists(&xorb).await.unwrap());

        let loc = s.lookup_chunk(&ChunkHash(h(0xA2))).await.unwrap().unwrap();
        assert_eq!(loc.xorb, xorb);
        assert_eq!(loc.chunk_index, 1);
        assert_eq!(loc.byte_start, 500);
        assert_eq!(loc.unpacked_segment_bytes, 524);

        let offsets = s.xorb_chunk_offsets(&xorb).await.unwrap();
        assert_eq!(offsets.len(), 2);
        assert_eq!(offsets[0].chunk_index, 0);
        assert_eq!(offsets[1].chunk_index, 1);
        assert_eq!(offsets[1].byte_start, 500);
    }

    #[tokio::test]
    async fn xorb_register_is_idempotent() {
        let s = store().await;
        let xorb = XorbHash(h(0x55));
        let info = XorbInfo {
            xorb,
            num_chunks: 1,
            num_bytes_in_cas: 64,
            num_bytes_on_disk: 60,
        };
        let chunks = vec![ChunkRow {
            chunk_hash: ChunkHash(h(0x66)),
            chunk_index: 0,
            byte_start: 0,
            unpacked_segment_bytes: 64,
        }];
        s.register_xorb(&info, &chunks).await.unwrap();
        s.register_xorb(&info, &chunks).await.unwrap();
        assert!(s.xorb_exists(&xorb).await.unwrap());
    }

    #[tokio::test]
    async fn missing_chunk_returns_none() {
        let s = store().await;
        assert!(s.lookup_chunk(&ChunkHash(h(0))).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_register_and_lookup_preserves_order() {
        let s = store().await;
        let file = FileHash(h(0xF0));
        let xorb_a = XorbHash(h(0x10));
        let xorb_b = XorbHash(h(0x20));
        let repo = RepoRef {
            repo_type: RepoType::Model,
            repo_id: "alice/big-model".into(),
            revision: "main".into(),
        };
        let terms = vec![
            FileTerm {
                xorb: xorb_a,
                chunk_idx_start: 0,
                chunk_idx_end: 3,
                unpacked_segment_bytes: 1000,
                verification: Some(h(0xE1)),
            },
            FileTerm {
                xorb: xorb_b,
                chunk_idx_start: 0,
                chunk_idx_end: 2,
                unpacked_segment_bytes: 500,
                verification: Some(h(0xE2)),
            },
        ];
        s.register_file(&file, &repo, &terms).await.unwrap();

        let back = s.lookup_file(&file).await.unwrap().unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].xorb, xorb_a);
        assert_eq!(back[0].chunk_idx_end, 3);
        assert_eq!(back[1].xorb, xorb_b);
        assert_eq!(back[1].unpacked_segment_bytes, 500);
        assert!(back[0].verification.is_some());
    }

    #[tokio::test]
    async fn file_in_repo_supports_cross_repo_dedup() {
        let s = store().await;
        let file = FileHash(h(0xCC));
        let alice = RepoRef {
            repo_type: RepoType::Model,
            repo_id: "alice/m".into(),
            revision: "main".into(),
        };
        let bob = RepoRef {
            repo_type: RepoType::Model,
            repo_id: "bob/m".into(),
            revision: "main".into(),
        };
        let terms = vec![FileTerm {
            xorb: XorbHash(h(0x33)),
            chunk_idx_start: 0,
            chunk_idx_end: 1,
            unpacked_segment_bytes: 16,
            verification: None,
        }];

        assert!(!s.file_in_repo(&file, "alice/m").await.unwrap());
        assert!(!s.file_in_repo(&file, "bob/m").await.unwrap());

        s.register_file(&file, &alice, &terms).await.unwrap();
        assert!(s.file_in_repo(&file, "alice/m").await.unwrap());
        assert!(!s.file_in_repo(&file, "bob/m").await.unwrap());

        // Same file_hash in a second repo must NOT displace Alice's row (composite PK).
        s.register_file(&file, &bob, &terms).await.unwrap();
        assert!(s.file_in_repo(&file, "alice/m").await.unwrap());
        assert!(s.file_in_repo(&file, "bob/m").await.unwrap());

        assert!(!s.file_in_repo(&file, "carol/m").await.unwrap());
    }

    #[tokio::test]
    async fn xorbs_near_chunk_returns_containing_xorb() {
        let s = store().await;
        let xorb = XorbHash(h(0x77));
        let info = XorbInfo {
            xorb,
            num_chunks: 1,
            num_bytes_in_cas: 100,
            num_bytes_on_disk: 90,
        };
        let chunks = vec![ChunkRow {
            chunk_hash: ChunkHash(h(0x78)),
            chunk_index: 0,
            byte_start: 0,
            unpacked_segment_bytes: 100,
        }];
        s.register_xorb(&info, &chunks).await.unwrap();

        let near = s.xorbs_near_chunk(&ChunkHash(h(0x78)), 10).await.unwrap();
        assert_eq!(near.len(), 1);
        assert_eq!(near[0].xorb, xorb);
        assert_eq!(near[0].num_chunks, 1);
    }

    #[tokio::test]
    async fn persistence_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.db");
        {
            let s = SqliteMetadataStore::open_path(&path).await.unwrap();
            let xorb = XorbHash(h(0x33));
            s.register_xorb(
                &XorbInfo {
                    xorb,
                    num_chunks: 1,
                    num_bytes_in_cas: 1,
                    num_bytes_on_disk: 1,
                },
                &[ChunkRow {
                    chunk_hash: ChunkHash(h(0x34)),
                    chunk_index: 0,
                    byte_start: 0,
                    unpacked_segment_bytes: 1,
                }],
            )
            .await
            .unwrap();
        }
        let s = SqliteMetadataStore::open_path(&path).await.unwrap();
        assert!(s.xorb_exists(&XorbHash(h(0x33))).await.unwrap());
    }
}
