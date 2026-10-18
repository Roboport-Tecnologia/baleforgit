//! Postgres `MetadataStore`: a near-mirror of `bale-server-meta-sqlite` (shared
//! helpers in `bale-server-meta-common`). Non-obvious dialect differences: every
//! `SUM(...)` is cast `::BIGINT` (Postgres widens it to `numeric`, which
//! `try_get::<i64>` can't decode), and READ COMMITTED can't serialize two
//! concurrent *first* registrations of a file_hash the way SQLite's transaction
//! does, so `pg_advisory_xact_lock` guards the write-once term check.

use async_trait::async_trait;
use bale_server_core::{
    ChunkHash, ChunkOffsetRow, ChunkRow, CoreError, CoreResult, FileHash, FileRegistration,
    FileTerm, MetadataStore, RepoRef, XorbFrameRow, XorbHash, XorbInfo,
};
use bale_server_meta_common::{
    blob_to_hash, dedup_sorted_xorbs, hash_to_blob, internal, nonneg_i64_to_u64, now_unix,
    row_to_chunk_offset, row_to_file_term, row_to_frame, row_to_xorb_info, CHUNK_INSERT_BATCH,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, QueryBuilder, Row};

const SPAN_QUERY_BATCH: usize = 300;

// A reservation whose blob never landed (crash between reserve and put) stops
// counting after this long; in-flight ones count from the start.
const RESERVATION_GRACE_SECS: i64 = 3600;

// Referenced xorbs plus the owner's unreferenced uploads.
const STORED_BYTES_SQL: &str = "SELECT (
    COALESCE((SELECT SUM(num_bytes_on_disk) FROM xorbs WHERE hash IN (
        SELECT DISTINCT ft.xorb_hash FROM file_terms ft
        JOIN files f ON f.file_hash = ft.file_hash WHERE f.owner = $1)), 0)
  + COALESCE((SELECT SUM(u.num_bytes_on_disk) FROM xorb_uploads u WHERE u.owner = $1
        AND NOT EXISTS (SELECT 1 FROM file_terms ft WHERE ft.xorb_hash = u.xorb_hash)
        AND (u.created_at >= $2 OR EXISTS (SELECT 1 FROM xorbs x WHERE x.hash = u.xorb_hash))), 0)
    )::BIGINT AS n";
const CAST_IDX: &str = "::BIGINT";

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS xorbs (
    hash              BYTEA   PRIMARY KEY,
    num_chunks        BIGINT  NOT NULL,
    num_bytes_in_cas  BIGINT  NOT NULL,
    num_bytes_on_disk BIGINT  NOT NULL,
    created_at        BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
    chunk_hash       BYTEA   NOT NULL,
    xorb_hash        BYTEA   NOT NULL,
    chunk_index      BIGINT  NOT NULL,
    byte_start       BIGINT  NOT NULL,
    unpacked_bytes   BIGINT  NOT NULL,
    PRIMARY KEY (chunk_hash, xorb_hash)
);
CREATE INDEX IF NOT EXISTS chunks_by_xorb ON chunks(xorb_hash, chunk_index);

CREATE TABLE IF NOT EXISTS xorb_frames (
    xorb_hash        BYTEA   NOT NULL,
    frame_index      BIGINT  NOT NULL,
    on_disk_start    BIGINT  NOT NULL,
    on_disk_len      BIGINT  NOT NULL,
    uncompressed_len BIGINT  NOT NULL,
    chunk_hash       BYTEA   NOT NULL,
    PRIMARY KEY (xorb_hash, frame_index)
);

CREATE TABLE IF NOT EXISTS files (
    file_hash    BYTEA   NOT NULL,
    repo_type    TEXT    NOT NULL,
    repo_id      TEXT    NOT NULL,
    revision     TEXT    NOT NULL,
    total_bytes  BIGINT  NOT NULL,
    created_at   BIGINT  NOT NULL,
    owner        TEXT    NOT NULL,
    PRIMARY KEY (file_hash, repo_id)
);
CREATE INDEX IF NOT EXISTS files_by_repo ON files(repo_id);
CREATE INDEX IF NOT EXISTS files_by_owner ON files(owner);

CREATE TABLE IF NOT EXISTS xorb_uploads (
    xorb_hash         BYTEA   PRIMARY KEY,
    owner             TEXT    NOT NULL,
    num_bytes_on_disk BIGINT  NOT NULL,
    created_at        BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS xorb_uploads_by_owner ON xorb_uploads(owner);

CREATE TABLE IF NOT EXISTS owner_quotas (
    owner       TEXT   PRIMARY KEY,
    limit_bytes BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_terms (
    file_hash       BYTEA   NOT NULL,
    term_index      BIGINT  NOT NULL,
    xorb_hash       BYTEA   NOT NULL,
    chunk_idx_start BIGINT  NOT NULL,
    chunk_idx_end   BIGINT  NOT NULL,
    unpacked_bytes  BIGINT  NOT NULL,
    verification    BYTEA,
    PRIMARY KEY (file_hash, term_index)
);
CREATE INDEX IF NOT EXISTS file_terms_by_xorb ON file_terms(xorb_hash);
"#;

// Serializes concurrent startups' DDL: racing `CREATE ... IF NOT EXISTS` can
// still collide in pg_catalog.
const MIGRATION_LOCK_KEY: i64 = 0x42_41_4c_45_5f_4d_44_42; // "BALE_MDB"

pub struct PostgresMetadataStore {
    pool: Pool<Postgres>,
}

impl PostgresMetadataStore {
    /// `url` is a libpq connection string (`postgres://user:pass@host/db`).
    pub async fn open_url(url: &str) -> CoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await
            .map_err(|e| CoreError::Internal(format!("postgres connect: {e}")))?;

        let mut tx = pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin migrate: {e}")))?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("migrate lock: {e}")))?;
        for stmt in SCHEMA_SQL.split(';') {
            let s = stmt.trim();
            if s.is_empty() {
                continue;
            }
            sqlx::query(s)
                .execute(&mut *tx)
                .await
                .map_err(|e| CoreError::Internal(format!("migrate: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit migrate: {e}")))?;
        // CREATE TABLE IF NOT EXISTS leaves an older table as is; fail at
        // startup rather than 500 on every upload and reconstruction.
        let has_chunk_hash = sqlx::query(
            "SELECT 1 FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = 'xorb_frames'
               AND column_name = 'chunk_hash'",
        )
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
    tx: &mut sqlx::Transaction<'_, Postgres>,
    owner: &str,
) -> CoreResult<u64> {
    let row = sqlx::query(STORED_BYTES_SQL)
        .bind(owner)
        .bind(now_unix()? - RESERVATION_GRACE_SECS)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| CoreError::Internal(format!("stored_bytes_for_owner: {e}")))?;
    let n: i64 = row.try_get("n").map_err(internal)?;
    nonneg_i64_to_u64(n, "stored_bytes_for_owner")
}

// What registering `candidates` would add to the owner's usage: bytes it neither
// references through its files nor pays for as unreferenced uploads. Batched
// under the bind-parameter limit (deduped, so batches sum exactly).
async fn unaccounted_bytes(
    conn: &mut sqlx::PgConnection,
    owner: &str,
    candidates: &[XorbHash],
) -> CoreResult<u64> {
    let uniq = dedup_sorted_xorbs(candidates);
    let mut total: u64 = 0;
    for batch in uniq.chunks(CHUNK_INSERT_BATCH) {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0)::BIGINT AS n FROM xorbs WHERE hash IN (",
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
    tx: &mut sqlx::Transaction<'_, Postgres>,
    owner: &str,
    files: &[FileRegistration],
    quota: u64,
) -> CoreResult<()> {
    // Terms are write-once, so an already-registered file is charged by its
    // stored terms, not the claimed ones. Batched: per-file queries under the
    // owner lock would stall every writer.
    let mut file_hashes: Vec<Vec<u8>> =
        files.iter().map(|f| hash_to_blob(&f.file_hash.0)).collect();
    file_hashes.sort();
    file_hashes.dedup();
    let mut registered: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut xorbs: Vec<XorbHash> = Vec::new();
    for batch in file_hashes.chunks(CHUNK_INSERT_BATCH) {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
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
    tx: &mut sqlx::Transaction<'_, Postgres>,
    repo: &RepoRef,
    reg: &FileRegistration,
) -> CoreResult<()> {
    let file_hash = &reg.file_hash;
    let terms = &reg.terms;
    let total_bytes: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();

    // Taken before any row lock, in `register_files`' hash order, so two shards
    // registering overlapping files can't deadlock.
    let lock_key = hash_to_blob(&file_hash.0)
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .map(i64::from_le_bytes)
        .unwrap_or(0);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut **tx)
        .await
        .map_err(|e| CoreError::Internal(format!("advisory lock: {e}")))?;

    sqlx::query(
        "INSERT INTO files (file_hash, repo_type, repo_id, revision, total_bytes, created_at, owner)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (file_hash, repo_id) DO UPDATE SET
             repo_type = excluded.repo_type,
             revision = excluded.revision,
             total_bytes = excluded.total_bytes,
             created_at = excluded.created_at,
             owner = excluded.owner",
    )
    .bind(hash_to_blob(&file_hash.0))
    .bind(format!("{:?}", repo.repo_type).to_lowercase())
    .bind(&repo.repo_id)
    .bind(&repo.revision)
    .bind(total_bytes as i64)
    .bind(now_unix()?)
    .bind(repo.owner())
    .execute(&mut **tx)
    .await
    .map_err(|e| CoreError::Internal(format!("insert file: {e}")))?;

    // Term lists aren't canonical (dedup segments the same content differently
    // depending on which xorbs exist) and file_terms is global, so a per-term
    // ON CONFLICT DO NOTHING would merge two segmentations into Σunpacked >
    // file_size and corrupt every reconstruction. Write-once: the first complete
    // list wins. The advisory lock above makes this check see a concurrent first
    // registration under READ COMMITTED.
    let terms_exist = sqlx::query("SELECT 1 FROM file_terms WHERE file_hash = $1 LIMIT 1")
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
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            "INSERT INTO file_terms
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
        qb.push(" ON CONFLICT DO NOTHING");
        qb.build()
            .execute(&mut **tx)
            .await
            .map_err(|e| CoreError::Internal(format!("insert terms: {e}")))?;
    }
    Ok(())
}

impl PostgresMetadataStore {
    async fn stored_file_terms(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>> {
        let rows = sqlx::query(
            "SELECT xorb_hash, chunk_idx_start, chunk_idx_end, unpacked_bytes, verification
             FROM file_terms WHERE file_hash = $1 ORDER BY term_index ASC",
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
impl MetadataStore for PostgresMetadataStore {
    async fn register_xorb(&self, xorb: &XorbInfo, chunks: &[ChunkRow]) -> CoreResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;

        sqlx::query(
            "INSERT INTO xorbs (hash, num_chunks, num_bytes_in_cas, num_bytes_on_disk, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (hash) DO UPDATE SET
                 num_chunks = excluded.num_chunks,
                 num_bytes_in_cas = excluded.num_bytes_in_cas,
                 num_bytes_on_disk = excluded.num_bytes_on_disk",
        )
        .bind(hash_to_blob(&xorb.xorb.0))
        .bind(xorb.num_chunks as i64)
        .bind(xorb.num_bytes_in_cas as i64)
        .bind(xorb.num_bytes_on_disk as i64)
        .bind(now_unix()?)
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("insert xorb: {e}")))?;

        for batch in chunks.chunks(CHUNK_INSERT_BATCH) {
            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
                "INSERT INTO chunks
                 (chunk_hash, xorb_hash, chunk_index, byte_start, unpacked_bytes) ",
            );
            qb.push_values(batch, |mut b, c| {
                b.push_bind(hash_to_blob(&c.chunk_hash.0))
                    .push_bind(hash_to_blob(&xorb.xorb.0))
                    .push_bind(c.chunk_index as i64)
                    .push_bind(c.byte_start as i64)
                    .push_bind(c.unpacked_segment_bytes as i64);
            });
            qb.push(" ON CONFLICT DO NOTHING");
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
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;
        if let Some(q) = quota {
            // Serializes same-owner quota checks so two shards can't each pass and
            // jointly overshoot. Taken before any per-file lock (consistent lock
            // order); the two-int4 key space is disjoint from the file-hash locks.
            sqlx::query("SELECT pg_advisory_xact_lock(1, hashtext($1))")
                .bind(repo.owner())
                .execute(&mut *tx)
                .await
                .map_err(|e| CoreError::Internal(format!("owner lock: {e}")))?;
            check_quota_in_tx(&mut tx, repo.owner(), files, q).await?;
        }
        let mut ordered: Vec<&FileRegistration> = files.iter().collect();
        ordered.sort_by_key(|a| a.file_hash);
        for reg in ordered {
            write_file_in_tx(&mut tx, repo, reg).await?;
        }
        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(())
    }

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool> {
        let row = sqlx::query("SELECT 1 FROM xorbs WHERE hash = $1 LIMIT 1")
            .bind(hash_to_blob(&xorb.0))
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("select xorb: {e}")))?;
        Ok(row.is_some())
    }

    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool> {
        let row = sqlx::query("SELECT 1 FROM files WHERE file_hash = $1 AND repo_id = $2 LIMIT 1")
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
        // Defense in depth against pre-write-once merged term lists: serving terms
        // that don't sum to the recorded size panics xet's last-term trim. Any
        // matching row suffices: one repo's bad row must not 500 every repo.
        let term_sum: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();
        let row = sqlx::query(
            "SELECT COUNT(*)::BIGINT AS n,
                    COALESCE(SUM(CASE WHEN total_bytes = $1 THEN 1 ELSE 0 END), 0)::BIGINT AS matching
             FROM files WHERE file_hash = $2",
        )
        .bind(term_sum as i64)
        .bind(hash_to_blob(&file_hash.0))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("select file size: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        let matching: i64 = row.try_get("matching").map_err(internal)?;
        if n > 0 && matching == 0 {
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
            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
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
        // Batched to keep a huge shard under the bind-parameter limit.
        let uniq = dedup_sorted_xorbs(xorbs);
        let mut out: std::collections::HashMap<XorbHash, Vec<XorbFrameRow>> =
            std::collections::HashMap::new();
        for batch in uniq.chunks(CHUNK_INSERT_BATCH) {
            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
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
            let mut qb: QueryBuilder<Postgres> =
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
        // 4 binds per span: far under Postgres's 65535 bind limit.
        for (batch_no, batch) in spans.chunks(SPAN_QUERY_BATCH).enumerate() {
            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
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
             FROM xorb_frames WHERE xorb_hash = $1 ORDER BY frame_index ASC",
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
        let row = sqlx::query("SELECT xorb_hash FROM chunks WHERE chunk_hash = $1 LIMIT 1")
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
            "SELECT num_chunks, num_bytes_in_cas, num_bytes_on_disk FROM xorbs WHERE hash = $1",
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
        let row = sqlx::query(
            "SELECT COALESCE(SUM(total_bytes), 0)::BIGINT AS n FROM files WHERE owner = $1",
        )
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
            .bind(now_unix()? - RESERVATION_GRACE_SECS)
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
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;
        sqlx::query("SELECT pg_advisory_xact_lock(1, hashtext($1))")
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(|e| CoreError::Internal(format!("owner lock: {e}")))?;
        // A reservation past the grace whose blob never landed is a crashed
        // upload: drop it, or it reads as "already charged" forever.
        sqlx::query(
            "DELETE FROM xorb_uploads WHERE xorb_hash = $1 AND created_at < $2
             AND NOT EXISTS (SELECT 1 FROM xorbs WHERE hash = $1)",
        )
        .bind(hash_to_blob(&xorb.0))
        .bind(now_unix()? - RESERVATION_GRACE_SECS)
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("drop stale reservation: {e}")))?;
        let charged = sqlx::query("SELECT 1 FROM xorb_uploads WHERE xorb_hash = $1")
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
        // The owner lock doesn't serialize two owners reserving one xorb.
        let inserted = sqlx::query(
            "INSERT INTO xorb_uploads (xorb_hash, owner, num_bytes_on_disk, created_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT (xorb_hash) DO NOTHING",
        )
        .bind(hash_to_blob(&xorb.0))
        .bind(owner)
        .bind(bytes as i64)
        .bind(now_unix()?)
        .execute(&mut *tx)
        .await
        .map_err(|e| CoreError::Internal(format!("reserve_xorb_upload: {e}")))?
        .rows_affected()
            == 1;
        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(inserted)
    }

    async fn settle_xorb_upload(
        &self,
        xorb: &XorbHash,
        owner: &str,
        bytes_on_disk: u64,
    ) -> CoreResult<()> {
        sqlx::query(
            "UPDATE xorb_uploads SET num_bytes_on_disk = $1 WHERE xorb_hash = $2 AND owner = $3",
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
        sqlx::query("DELETE FROM xorb_uploads WHERE xorb_hash = $1 AND owner = $2")
            .bind(hash_to_blob(&xorb.0))
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("release_xorb_upload: {e}")))?;
        Ok(())
    }

    async fn get_owner_quota(&self, owner: &str) -> CoreResult<Option<u64>> {
        let row = sqlx::query("SELECT limit_bytes FROM owner_quotas WHERE owner = $1")
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
                    "INSERT INTO owner_quotas (owner, limit_bytes) VALUES ($1, $2)
                     ON CONFLICT (owner) DO UPDATE SET limit_bytes = excluded.limit_bytes",
                )
                .bind(owner)
                .bind(n as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("set_owner_quota: {e}")))?;
            }
            None => {
                sqlx::query("DELETE FROM owner_quotas WHERE owner = $1")
                    .bind(owner)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| CoreError::Internal(format!("clear_owner_quota: {e}")))?;
            }
        }
        Ok(())
    }

    async fn raw_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(total_bytes), 0)::BIGINT AS n FROM files WHERE repo_id = $1",
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("raw_bytes_for_repo: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "raw_bytes_for_repo")
    }

    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0)::BIGINT AS n
             FROM xorbs
             WHERE hash IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.repo_id = $1
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
        // What the owner's stored_bytes would drop if this repo were deleted:
        // its xorbs minus those a same-owner sibling also references. Owner comes
        // from the files' recorded owner (a canonical key like `id/42` names
        // none); cross-owner sharing is ignored, as in stored_bytes_for_owner.
        let row = sqlx::query(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0)::BIGINT AS n
             FROM xorbs
             WHERE hash IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.repo_id = $1
             )
             AND hash NOT IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.owner IN (SELECT DISTINCT owner FROM files WHERE repo_id = $2)
                   AND f.repo_id <> $3
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
             FROM chunks WHERE xorb_hash = $1 ORDER BY chunk_index ASC",
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
