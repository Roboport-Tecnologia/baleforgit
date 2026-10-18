//! SQLite-backed `MetadataStore` implementation.
//!
//! Dialect-free helpers and row decoders live in `bale-server-meta-common`; this
//! crate holds the SQLite SQL (`?` placeholders, `INSERT OR IGNORE`/`OR REPLACE`,
//! `BLOB`/`INTEGER` DDL) and its concurrency model (write-once term registration
//! serialized by the enclosing transaction).

use async_trait::async_trait;
use bale_server_core::{
    ChunkHash, ChunkOffsetRow, ChunkRow, CoreError, CoreResult, FileHash, FileRegistration,
    FileTerm, MetadataStore, RepoRef, XorbFrameRow, XorbHash, XorbInfo,
};
use bale_server_meta_common::{
    blob_to_hash, dedup_sorted_xorbs, hash_to_blob, internal, nonneg_i64_to_u64, now_unix,
    row_to_chunk_offset, row_to_file_term, row_to_frame, row_to_xorb_info, CHUNK_INSERT_BATCH,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, QueryBuilder, Row, Sqlite};
use std::path::Path;
use std::str::FromStr;

const SPAN_QUERY_BATCH: usize = 300;

// A reservation whose blob never landed (crash between reserve and put) stops
// counting after this long; in-flight ones count from the start.
const RESERVATION_GRACE_SECS: i64 = 3600;

// Referenced xorbs plus the owner's unreferenced uploads; binds owner twice.
const STORED_BYTES_SQL: &str = "SELECT
    COALESCE((SELECT SUM(num_bytes_on_disk) FROM xorbs WHERE hash IN (
        SELECT DISTINCT ft.xorb_hash FROM file_terms ft
        JOIN files f ON f.file_hash = ft.file_hash WHERE f.owner = ?)), 0)
  + COALESCE((SELECT SUM(u.num_bytes_on_disk) FROM xorb_uploads u WHERE u.owner = ?
        AND NOT EXISTS (SELECT 1 FROM file_terms ft WHERE ft.xorb_hash = u.xorb_hash)
        AND (u.created_at >= ? OR EXISTS (SELECT 1 FROM xorbs x WHERE x.hash = u.xorb_hash))), 0)
    AS n";
const CAST_IDX: &str = "";

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
    chunk_hash       BLOB    NOT NULL,
    PRIMARY KEY (xorb_hash, frame_index)
);

CREATE TABLE IF NOT EXISTS files (
    file_hash    BLOB    NOT NULL,
    repo_type    TEXT    NOT NULL,
    repo_id      TEXT    NOT NULL,
    revision     TEXT    NOT NULL,
    total_bytes  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    -- Denormalized namespace before `/` in repo_id so quota aggregation is an
    -- indexed scan, not a LIKE prefix match.
    owner        TEXT    NOT NULL,
    -- Composite PK: same file_hash lives in multiple repos (cross-repo dedup),
    -- and reconstruction authorizes reads by requiring a (file_hash, token.repo) row.
    PRIMARY KEY (file_hash, repo_id)
);
CREATE INDEX IF NOT EXISTS files_by_repo ON files(repo_id);
CREATE INDEX IF NOT EXISTS files_by_owner ON files(owner);

-- Uploaded xorbs charged to their uploader until a file references them.
CREATE TABLE IF NOT EXISTS xorb_uploads (
    xorb_hash         BLOB    PRIMARY KEY,
    owner             TEXT    NOT NULL,
    num_bytes_on_disk INTEGER NOT NULL,
    created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS xorb_uploads_by_owner ON xorb_uploads(owner);

CREATE TABLE IF NOT EXISTS owner_quotas (
    owner       TEXT    PRIMARY KEY,
    limit_bytes INTEGER NOT NULL
);

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
-- Quota checks join file_terms by xorb_hash, so without this index each is a full scan.
-- Do not put a statement separator inside a comment here: open_url splits
-- SCHEMA_SQL on that character, so one in a comment truncates the next statement.
CREATE INDEX IF NOT EXISTS file_terms_by_xorb ON file_terms(xorb_hash);
"#;

pub struct SqliteMetadataStore {
    pool: Pool<Sqlite>,
}

impl SqliteMetadataStore {
    // `":memory:"` forces pool size to 1 so the schema survives between calls.
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
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            // Quota'd uploads serialize on BEGIN IMMEDIATE; sqlx's 5s default
            // turns a burst of concurrent xorb uploads into 500s.
            .busy_timeout(std::time::Duration::from_secs(30));

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
        // CREATE TABLE IF NOT EXISTS leaves an older table as is; fail at
        // startup rather than 500 on every upload and reconstruction.
        let has_chunk_hash =
            sqlx::query("SELECT 1 FROM pragma_table_info('xorb_frames') WHERE name = 'chunk_hash'")
                .fetch_optional(&pool)
                .await
                .map_err(|e| CoreError::Internal(format!("schema check: {e}")))?
                .is_some();
        if !has_chunk_hash {
            return Err(CoreError::Internal(
                "metadata database predates xorb_frames.chunk_hash; it was created by an \
                 incompatible baleforgit-server version and must be recreated"
                    .into(),
            ));
        }
        Ok(Self { pool })
    }
}

async fn stored_bytes_in_tx(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    owner: &str,
) -> CoreResult<u64> {
    let row = sqlx::query(STORED_BYTES_SQL)
        .bind(owner)
        .bind(owner)
        .bind(now_unix() - RESERVATION_GRACE_SECS)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| CoreError::Internal(format!("stored_bytes_for_owner: {e}")))?;
    let n: i64 = row.try_get("n").map_err(internal)?;
    nonneg_i64_to_u64(n, "stored_bytes_for_owner")
}

// On-disk bytes of `candidates` this owner neither references through its
// files nor already pays for as its own unreferenced uploads — i.e. what
// registering them would add to the owner's usage. Batched so a huge shard
// stays under the bind-parameter limit (deduped batches sum exactly).
async fn unaccounted_bytes(
    conn: &mut sqlx::SqliteConnection,
    owner: &str,
    candidates: &[XorbHash],
) -> CoreResult<u64> {
    let uniq = dedup_sorted_xorbs(candidates);
    let mut total: u64 = 0;
    for batch in uniq.chunks(CHUNK_INSERT_BATCH) {
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0) AS n FROM xorbs WHERE hash IN (",
        );
        let mut sep = qb.separated(", ");
        for x in batch {
            sep.push_bind(hash_to_blob(&x.0));
        }
        qb.push(
            ") AND hash NOT IN (
                SELECT ft.xorb_hash FROM file_terms ft
                JOIN files f ON f.file_hash = ft.file_hash
                WHERE f.owner = ",
        );
        qb.push_bind(owner.to_string());
        // Mirrors STORED_BYTES_SQL: an upload row stops counting once any
        // file (any owner's) references the xorb.
        qb.push(") AND hash NOT IN (SELECT u.xorb_hash FROM xorb_uploads u WHERE u.owner = ");
        qb.push_bind(owner.to_string());
        qb.push(" AND NOT EXISTS (SELECT 1 FROM file_terms ft WHERE ft.xorb_hash = u.xorb_hash))");
        let row = qb
            .build()
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| CoreError::Internal(format!("unaccounted_xorb_bytes: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        total += nonneg_i64_to_u64(n, "unaccounted_xorb_bytes_for_owner")?;
    }
    Ok(total)
}

// Refuses (whole batch) only a registration that would *grow* the owner's
// usage past `quota`, so an idempotent re-push still succeeds after a quota is
// lowered. Runs serialized per owner inside the registering transaction.
async fn check_quota_in_tx(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    owner: &str,
    files: &[FileRegistration],
    quota: u64,
) -> CoreResult<()> {
    // Terms are write-once: a file already registered keeps its stored
    // terms, whatever this registration claims. Batched: this runs under the
    // owner's write lock, so per-file queries would stall every writer.
    let mut file_hashes: Vec<Vec<u8>> =
        files.iter().map(|f| hash_to_blob(&f.file_hash.0)).collect();
    file_hashes.sort();
    file_hashes.dedup();
    let mut registered: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut xorbs: Vec<XorbHash> = Vec::new();
    for batch in file_hashes.chunks(CHUNK_INSERT_BATCH) {
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT DISTINCT file_hash, xorb_hash FROM file_terms WHERE file_hash IN (",
        );
        let mut sep = qb.separated(", ");
        for h in batch {
            sep.push_bind(h.clone());
        }
        qb.push(")");
        let rows = qb
            .build()
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| CoreError::Internal(format!("probe stored terms: {e}")))?;
        for r in rows {
            let f: Vec<u8> = r.try_get("file_hash").map_err(internal)?;
            let x: Vec<u8> = r.try_get("xorb_hash").map_err(internal)?;
            registered.insert(f);
            xorbs.push(XorbHash(blob_to_hash(&x)?));
        }
    }
    for f in files {
        if !registered.contains(&hash_to_blob(&f.file_hash.0)) {
            xorbs.extend(f.terms.iter().map(|t| t.xorb));
        }
    }
    let delta = unaccounted_bytes(tx, owner, &xorbs).await?;
    if delta == 0 {
        return Ok(());
    }
    let used = stored_bytes_in_tx(tx, owner).await?;
    if used.saturating_add(delta) > quota {
        return Err(CoreError::QuotaExceeded {
            owner: owner.to_string(),
            used: used.saturating_add(delta),
            quota,
        });
    }
    Ok(())
}

async fn write_file_in_tx(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    repo: &RepoRef,
    reg: &FileRegistration,
) -> CoreResult<()> {
    let file_hash = &reg.file_hash;
    let terms = &reg.terms;
    let total_bytes: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();

    sqlx::query(
        "INSERT OR REPLACE INTO files (file_hash, repo_type, repo_id, revision, total_bytes, created_at, owner)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(hash_to_blob(&file_hash.0))
    .bind(format!("{:?}", repo.repo_type).to_lowercase())
    .bind(&repo.repo_id)
    .bind(&repo.revision)
    .bind(total_bytes as i64)
    .bind(now_unix())
    .bind(repo.owner())
    .execute(&mut **tx)
    .await
    .map_err(|e| CoreError::Internal(format!("insert file: {e}")))?;

    // The term list for a file_hash is NOT canonical: global dedup segments the
    // same content into a different *number* of xorb-referencing terms depending
    // on which pre-existing xorbs it matches. file_terms is global (keyed by
    // file_hash, not repo), so a per-term INSERT OR IGNORE would *merge* two
    // differently-segmented registrations — keeping the old terms where indices
    // collide and appending the longer list's tail — yielding Σunpacked > file_size
    // and corrupting every reconstruction of this hash (xet's last-term trim then
    // underflows). Register write-once: the first complete list fully describes the
    // content, so if any terms already exist we leave them untouched. The
    // enclosing write transaction serializes this against concurrent registers.
    let terms_exist = sqlx::query("SELECT 1 FROM file_terms WHERE file_hash = ? LIMIT 1")
        .bind(hash_to_blob(&file_hash.0))
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| CoreError::Internal(format!("probe existing terms: {e}")))?
        .is_some();
    if terms_exist {
        return Ok(());
    }

    let indexed: Vec<(usize, &FileTerm)> = terms.iter().enumerate().collect();
    for batch in indexed.chunks(CHUNK_INSERT_BATCH) {
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
            "INSERT OR IGNORE INTO file_terms
             (file_hash, term_index, xorb_hash, chunk_idx_start, chunk_idx_end, unpacked_bytes, verification) ",
        );
        qb.push_values(batch, |mut b, (idx, t)| {
            b.push_bind(hash_to_blob(&file_hash.0))
                .push_bind(*idx as i64)
                .push_bind(hash_to_blob(&t.xorb.0))
                .push_bind(t.chunk_idx_start as i64)
                .push_bind(t.chunk_idx_end as i64)
                .push_bind(t.unpacked_segment_bytes as i64)
                .push_bind(t.verification.as_ref().map(hash_to_blob));
        });
        qb.build()
            .execute(&mut **tx)
            .await
            .map_err(|e| CoreError::Internal(format!("insert terms: {e}")))?;
    }
    Ok(())
}

impl SqliteMetadataStore {
    async fn stored_file_terms(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>> {
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
        for r in &rows {
            terms.push(row_to_file_term(r)?);
        }
        Ok(Some(terms))
    }
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
            "INSERT INTO xorbs (hash, num_chunks, num_bytes_in_cas, num_bytes_on_disk, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT (hash) DO UPDATE SET
                 num_chunks = excluded.num_chunks,
                 num_bytes_in_cas = excluded.num_bytes_in_cas,
                 num_bytes_on_disk = excluded.num_bytes_on_disk",
        )
        .bind(hash_to_blob(&xorb.xorb.0))
        .bind(xorb.num_chunks as i64)
        .bind(xorb.num_bytes_in_cas as i64)
        .bind(xorb.num_bytes_on_disk as i64)
        .bind(now_unix())
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("insert xorb: {e}")))?;

        for batch in chunks.chunks(CHUNK_INSERT_BATCH) {
            let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
                "INSERT OR IGNORE INTO chunks
                 (chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes) ",
            );
            qb.push_values(batch, |mut b, c| {
                b.push_bind(hash_to_blob(&c.chunk_hash.0))
                    .push_bind(hash_to_blob(&xorb.xorb.0))
                    .push_bind(c.chunk_index as i64)
                    .push_bind(c.byte_start as i64)
                    .push_bind(c.unpacked_segment_bytes as i64);
            });
            qb.build()
                .execute(&mut *tx)
                .await
                .map_err(|e| CoreError::Internal(format!("insert chunks: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(())
    }

    async fn register_files(
        &self,
        repo: &RepoRef,
        files: &[FileRegistration],
        quota: Option<u64>,
    ) -> CoreResult<()> {
        if files.is_empty() {
            return Ok(());
        }
        // IMMEDIATE takes the write lock up front, so the usage read and the
        // inserts are one serialized unit (a deferred BEGIN could also fail the
        // read→write upgrade with SQLITE_BUSY_SNAPSHOT).
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;
        if let Some(q) = quota {
            check_quota_in_tx(&mut tx, repo.owner(), files, q).await?;
        }
        for reg in files {
            write_file_in_tx(&mut tx, repo, reg).await?;
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
        let Some(terms) = self.stored_file_terms(file_hash).await? else {
            return Ok(None);
        };
        // Defense in depth: the terms must sum to the file's recorded size. A
        // mismatch means the term list is internally inconsistent (e.g. legacy data
        // from before terms were registered write-once, where two differently-
        // segmented registrations got merged into an over-describing list). Serving
        // it would underflow xet's last-term trim and panic the client, so error.
        // Any matching row suffices: one repo's bad row must not 500 every repo.
        let term_sum: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();
        let row = sqlx::query(
            "SELECT COUNT(*) AS n, SUM(CASE WHEN total_bytes = ? THEN 1 ELSE 0 END) AS matching
             FROM files WHERE file_hash = ?",
        )
        .bind(term_sum as i64)
        .bind(hash_to_blob(&file_hash.0))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("select file size: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        let matching: Option<i64> = row.try_get("matching").map_err(internal)?;
        if n > 0 && matching.unwrap_or(0) == 0 {
            return Err(CoreError::Internal(format!(
                "file term list sums to {term_sum} but no registration records that size; \
                 refusing to serve an inconsistent reconstruction (re-register this file)"
            )));
        }
        Ok(Some(terms))
    }

    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()> {
        if frames.is_empty() {
            return Ok(());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;
        for batch in frames.chunks(CHUNK_INSERT_BATCH) {
            let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
                "INSERT INTO xorb_frames
                 (xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len, chunk_hash) ",
            );
            qb.push_values(batch, |mut b, f| {
                b.push_bind(hash_to_blob(&xorb.0))
                    .push_bind(f.frame_index as i64)
                    .push_bind(f.on_disk_start as i64)
                    .push_bind(f.on_disk_len as i64)
                    .push_bind(f.uncompressed_len as i64)
                    .push_bind(hash_to_blob(&f.chunk_hash.0));
            });
            qb.push(
                " ON CONFLICT (xorb_hash, frame_index) DO UPDATE SET
                 on_disk_start = excluded.on_disk_start,
                 on_disk_len = excluded.on_disk_len,
                 uncompressed_len = excluded.uncompressed_len,
                 chunk_hash = excluded.chunk_hash",
            );
            qb.build()
                .execute(&mut *tx)
                .await
                .map_err(|e| CoreError::Internal(format!("insert frames: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit frames: {e}")))?;
        Ok(())
    }

    async fn xorb_frame_layouts(
        &self,
        xorbs: &[XorbHash],
    ) -> CoreResult<std::collections::HashMap<XorbHash, Vec<XorbFrameRow>>> {
        if xorbs.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // Batched IN queries: one per CHUNK_INSERT_BATCH xorbs keeps a huge
        // shard under the bind-parameter limit.
        let uniq = dedup_sorted_xorbs(xorbs);
        let mut out: std::collections::HashMap<XorbHash, Vec<XorbFrameRow>> =
            std::collections::HashMap::new();
        for batch in uniq.chunks(CHUNK_INSERT_BATCH) {
            let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
                "SELECT xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len, chunk_hash
                 FROM xorb_frames WHERE xorb_hash IN (",
            );
            let mut sep = qb.separated(", ");
            for x in batch {
                sep.push_bind(hash_to_blob(&x.0));
            }
            qb.push(") ORDER BY xorb_hash, frame_index ASC");

            let rows = qb
                .build()
                .fetch_all(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("select frame layouts: {e}")))?;

            for r in &rows {
                let xorb_blob: Vec<u8> = r.try_get("xorb_hash").map_err(internal)?;
                let xorb = XorbHash(blob_to_hash(&xorb_blob)?);
                out.entry(xorb).or_default().push(row_to_frame(r)?);
            }
        }
        Ok(out)
    }

    async fn missing_xorb_rows(&self, xorbs: &[XorbHash]) -> CoreResult<Vec<XorbHash>> {
        let uniq = dedup_sorted_xorbs(xorbs);
        let mut present = std::collections::HashSet::new();
        for batch in uniq.chunks(CHUNK_INSERT_BATCH) {
            let mut qb: QueryBuilder<Sqlite> =
                QueryBuilder::new("SELECT hash FROM xorbs WHERE hash IN (");
            let mut sep = qb.separated(", ");
            for x in batch {
                sep.push_bind(hash_to_blob(&x.0));
            }
            qb.push(")");
            let rows = qb
                .build()
                .fetch_all(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("select xorb rows: {e}")))?;
            for r in &rows {
                let blob: Vec<u8> = r.try_get("hash").map_err(internal)?;
                present.insert(XorbHash(blob_to_hash(&blob)?));
            }
        }
        Ok(uniq.into_iter().filter(|x| !present.contains(x)).collect())
    }

    async fn xorb_frame_spans(
        &self,
        spans: &[(XorbHash, u32, u32)],
    ) -> CoreResult<Vec<Vec<XorbFrameRow>>> {
        let mut out: Vec<Vec<XorbFrameRow>> = vec![Vec::new(); spans.len()];
        // 4 binds per span: stays far under both backends' bind limits.
        for (batch_no, batch) in spans.chunks(SPAN_QUERY_BATCH).enumerate() {
            let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
                "SELECT s.idx AS idx, f.frame_index, f.on_disk_start, f.on_disk_len, \
                 f.uncompressed_len, f.chunk_hash FROM (",
            );
            for (i, (xorb, start, end)) in batch.iter().enumerate() {
                if i > 0 {
                    qb.push(" UNION ALL ");
                }
                qb.push("SELECT ");
                qb.push_bind((batch_no * SPAN_QUERY_BATCH + i) as i64);
                qb.push(CAST_IDX);
                qb.push(" AS idx, ");
                qb.push_bind(hash_to_blob(&xorb.0));
                qb.push(" AS xh, ");
                qb.push_bind(*start as i64);
                qb.push(CAST_IDX);
                qb.push(" AS lo, ");
                qb.push_bind(*end as i64);
                qb.push(CAST_IDX);
                qb.push(" AS hi");
            }
            qb.push(
                ") s JOIN xorb_frames f ON f.xorb_hash = s.xh \
                 AND f.frame_index >= s.lo AND f.frame_index < s.hi \
                 ORDER BY s.idx, f.frame_index",
            );
            let rows = qb
                .build()
                .fetch_all(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("select frame spans: {e}")))?;
            for r in &rows {
                let idx: i64 = r.try_get("idx").map_err(internal)?;
                let slot = out
                    .get_mut(idx as usize)
                    .ok_or_else(|| CoreError::Internal("frame span index out of range".into()))?;
                slot.push(row_to_frame(r)?);
            }
        }
        Ok(out)
    }

    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>> {
        let rows = sqlx::query(
            "SELECT frame_index, on_disk_start, on_disk_len, uncompressed_len, chunk_hash
             FROM xorb_frames WHERE xorb_hash = ? ORDER BY frame_index ASC",
        )
        .bind(hash_to_blob(&xorb.0))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("select frames: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(row_to_frame(r)?);
        }
        Ok(out)
    }

    async fn xorbs_near_chunk(
        &self,
        chunk_hash: &ChunkHash,
        limit: usize,
    ) -> CoreResult<Vec<XorbInfo>> {
        // Prototype: only the containing xorb; neighborhood expansion is future work.
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

        let mut out = vec![row_to_xorb_info(&row, xorb)?];
        out.truncate(limit);
        Ok(out)
    }

    async fn raw_bytes_for_owner(&self, owner: &str) -> CoreResult<u64> {
        let row =
            sqlx::query("SELECT COALESCE(SUM(total_bytes), 0) AS n FROM files WHERE owner = ?")
                .bind(owner)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("raw_bytes_for_owner: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "raw_bytes_for_owner")
    }

    async fn stored_bytes_for_owner(&self, owner: &str) -> CoreResult<u64> {
        let row = sqlx::query(STORED_BYTES_SQL)
            .bind(owner)
            .bind(owner)
            .bind(now_unix() - RESERVATION_GRACE_SECS)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("stored_bytes_for_owner: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "stored_bytes_for_owner")
    }

    async fn reserve_xorb_upload(
        &self,
        xorb: &XorbHash,
        owner: &str,
        bytes: u64,
        quota: Option<u64>,
    ) -> CoreResult<bool> {
        // Serialized per owner with other reservations and shard registrations.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;
        // A reservation past the grace whose blob never landed is a crashed
        // upload: drop it, or it reads as "already charged" forever.
        sqlx::query(
            "DELETE FROM xorb_uploads WHERE xorb_hash = ? AND created_at < ?
             AND NOT EXISTS (SELECT 1 FROM xorbs WHERE hash = ?)",
        )
        .bind(hash_to_blob(&xorb.0))
        .bind(now_unix() - RESERVATION_GRACE_SECS)
        .bind(hash_to_blob(&xorb.0))
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("drop stale reservation: {e}")))?;
        let charged = sqlx::query("SELECT 1 FROM xorb_uploads WHERE xorb_hash = ?")
            .bind(hash_to_blob(&xorb.0))
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("probe reservation: {e}")))?
            .is_some();
        if charged {
            return Ok(false);
        }
        if let Some(q) = quota {
            let used = stored_bytes_in_tx(&mut tx, owner).await?;
            if used.saturating_add(bytes) > q {
                return Err(CoreError::QuotaExceeded {
                    owner: owner.to_string(),
                    used: used.saturating_add(bytes),
                    quota: q,
                });
            }
        }
        sqlx::query(
            "INSERT INTO xorb_uploads (xorb_hash, owner, num_bytes_on_disk, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(hash_to_blob(&xorb.0))
        .bind(owner)
        .bind(bytes as i64)
        .bind(now_unix())
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("reserve_xorb_upload: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(true)
    }

    async fn settle_xorb_upload(
        &self,
        xorb: &XorbHash,
        owner: &str,
        bytes_on_disk: u64,
    ) -> CoreResult<()> {
        sqlx::query(
            "UPDATE xorb_uploads SET num_bytes_on_disk = ? WHERE xorb_hash = ? AND owner = ?",
        )
        .bind(bytes_on_disk as i64)
        .bind(hash_to_blob(&xorb.0))
        .bind(owner)
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("settle_xorb_upload: {e}")))?;
        Ok(())
    }

    async fn release_xorb_upload(&self, xorb: &XorbHash, owner: &str) -> CoreResult<()> {
        sqlx::query("DELETE FROM xorb_uploads WHERE xorb_hash = ? AND owner = ?")
            .bind(hash_to_blob(&xorb.0))
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("release_xorb_upload: {e}")))?;
        Ok(())
    }

    async fn get_owner_quota(&self, owner: &str) -> CoreResult<Option<u64>> {
        let row = sqlx::query("SELECT limit_bytes FROM owner_quotas WHERE owner = ?")
            .bind(owner)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("get_owner_quota: {e}")))?;
        let Some(r) = row else { return Ok(None) };
        let n: i64 = r.try_get("limit_bytes").map_err(internal)?;
        Ok(Some(nonneg_i64_to_u64(n, "get_owner_quota")?))
    }

    async fn set_owner_quota(&self, owner: &str, limit_bytes: Option<u64>) -> CoreResult<()> {
        match limit_bytes {
            Some(n) => {
                sqlx::query(
                    "INSERT INTO owner_quotas (owner, limit_bytes) VALUES (?, ?)
                     ON CONFLICT(owner) DO UPDATE SET limit_bytes = excluded.limit_bytes",
                )
                .bind(owner)
                .bind(n as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("set_owner_quota: {e}")))?;
            }
            None => {
                sqlx::query("DELETE FROM owner_quotas WHERE owner = ?")
                    .bind(owner)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| CoreError::Internal(format!("clear_owner_quota: {e}")))?;
            }
        }
        Ok(())
    }

    async fn raw_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        let row =
            sqlx::query("SELECT COALESCE(SUM(total_bytes), 0) AS n FROM files WHERE repo_id = ?")
                .bind(repo_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("raw_bytes_for_repo: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "raw_bytes_for_repo")
    }

    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0) AS n
             FROM xorbs
             WHERE hash IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.repo_id = ?
             )",
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("stored_bytes_for_repo: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "stored_bytes_for_repo")
    }

    async fn exclusive_stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        // Xorbs this repo references, minus any also referenced by a *sibling*
        // repo of the same owner (from the files' recorded owner: a canonical
        // key like `id/42` names none) — the amount the owner's stored_bytes would drop if
        // this repo were deleted. Cross-owner sharing is ignored, matching the
        // owner-independent accounting in stored_bytes_for_owner.
        let row = sqlx::query(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0) AS n
             FROM xorbs
             WHERE hash IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.repo_id = ?
             )
             AND hash NOT IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.owner IN (SELECT DISTINCT owner FROM files WHERE repo_id = ?)
                   AND f.repo_id <> ?
             )",
        )
        .bind(repo_id)
        .bind(repo_id)
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("exclusive_stored_bytes_for_repo: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "exclusive_stored_bytes_for_repo")
    }

    async fn unaccounted_xorb_bytes_for_owner(
        &self,
        owner: &str,
        candidates: &[XorbHash],
    ) -> CoreResult<u64> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| CoreError::Internal(format!("acquire: {e}")))?;
        unaccounted_bytes(&mut conn, owner, candidates).await
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
        for r in &rows {
            out.push(row_to_chunk_offset(r)?);
        }
        Ok(out)
    }
}
