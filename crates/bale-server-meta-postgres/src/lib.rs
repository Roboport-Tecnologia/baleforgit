//! Postgres-backed `MetadataStore` implementation.
//!
//! Dialect-free helpers and row decoders live in `bale-server-meta-common`. This
//! crate is a near-mirror of `bale-server-meta-sqlite` with the dialect
//! differences that matter: `$n` placeholders instead of `?`, `ON CONFLICT`
//! instead of `INSERT OR IGNORE`/`INSERT OR REPLACE`, `BYTEA`/`BIGINT` column
//! types, a `::BIGINT` cast on every `SUM(...)` (Postgres widens `SUM` over
//! `bigint` to `numeric`, which `try_get::<i64>` can't decode), and — because
//! READ COMMITTED can't serialize two concurrent *first* registrations of a
//! file_hash the way SQLite's transaction does — an explicit
//! `pg_advisory_xact_lock` around the write-once term check.

use async_trait::async_trait;
use bale_server_core::{
    ChunkHash, ChunkOffsetRow, ChunkRow, CoreError, CoreResult, FileHash, FileTerm, MetadataStore,
    RepoRef, XorbFrameRow, XorbHash, XorbInfo,
};
use bale_server_meta_common::{
    blob_to_hash, dedup_sorted_xorbs, hash_to_blob, internal, nonneg_i64_to_u64, now_unix,
    row_to_chunk_offset, row_to_file_term, row_to_frame, row_to_xorb_info, CHUNK_INSERT_BATCH,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, QueryBuilder, Row};

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

// Arbitrary fixed key so concurrent server startups serialize their DDL — two
// instances racing `CREATE TABLE/INDEX IF NOT EXISTS` can otherwise collide in
// pg_catalog. Held only for the migration transaction.
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
        Ok(Self { pool })
    }
}

// Shared per-file writes for register_file (one tx per file) and register_files
// (one tx per shard) — same writes, different transaction scopes.
async fn write_file_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    file_hash: &FileHash,
    repo: &RepoRef,
    terms: &[FileTerm],
) -> CoreResult<()> {
    let total_bytes: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();

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
    .bind(now_unix())
    .bind(repo.owner())
    .execute(&mut **tx)
    .await
    .map_err(|e| CoreError::Internal(format!("insert file: {e}")))?;

    // The term list for a file_hash is NOT canonical: global dedup segments the
    // same content into a different *number* of xorb-referencing terms depending on
    // which pre-existing xorbs it matches. file_terms is global (keyed by file_hash,
    // not repo), so a per-term ON CONFLICT DO NOTHING would *merge* two
    // differently-segmented registrations — keeping the old terms where indices
    // collide and appending the longer list's tail — yielding Σunpacked > file_size
    // and corrupting every reconstruction of this hash (xet's last-term trim then
    // underflows). Register write-once: the first complete list fully describes the
    // content, so skip insertion if any terms already exist. Under READ COMMITTED two
    // concurrent *first* registrations wouldn't see each other's uncommitted rows, so
    // serialize same-hash registers with a tx-scoped advisory lock (auto-released at
    // commit/rollback); cross-hash key collisions only cost a little extra blocking.
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
             ON CONFLICT (hash) DO NOTHING",
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

    async fn register_file(
        &self,
        file_hash: &FileHash,
        repo: &RepoRef,
        terms: &[FileTerm],
    ) -> CoreResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;

        write_file_in_tx(&mut tx, file_hash, repo, terms).await?;

        tx.commit()
            .await
            .map_err(|e| CoreError::Internal(format!("commit: {e}")))?;
        Ok(())
    }

    async fn register_files(
        &self,
        repo: &RepoRef,
        files: &[(FileHash, Vec<FileTerm>)],
    ) -> CoreResult<()> {
        if files.is_empty() {
            return Ok(());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| CoreError::Internal(format!("begin: {e}")))?;

        for (file_hash, terms) in files {
            write_file_in_tx(&mut tx, file_hash, repo, terms).await?;
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

        // Defense in depth: the terms must sum to the file's recorded size. A
        // mismatch means the term list is internally inconsistent (e.g. legacy data
        // from before terms were registered write-once, where two differently-
        // segmented registrations got merged into an over-describing list). Serving
        // it would underflow xet's last-term trim and panic the client, so error.
        let term_sum: u64 = terms.iter().map(|t| t.unpacked_segment_bytes as u64).sum();
        let recorded: Option<i64> =
            sqlx::query("SELECT total_bytes FROM files WHERE file_hash = $1 LIMIT 1")
                .bind(hash_to_blob(&file_hash.0))
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| CoreError::Internal(format!("select file size: {e}")))?
                .map(|r| r.try_get("total_bytes"))
                .transpose()
                .map_err(internal)?;
        if let Some(total) = recorded {
            let total = nonneg_i64_to_u64(total, "files.total_bytes")?;
            if term_sum != total {
                return Err(CoreError::Internal(format!(
                    "file term list sums to {term_sum} but recorded size is {total}; \
                     refusing to serve an inconsistent reconstruction (re-register this file)"
                )));
            }
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
                 (xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len) ",
            );
            qb.push_values(batch, |mut b, f| {
                b.push_bind(hash_to_blob(&xorb.0))
                    .push_bind(f.frame_index as i64)
                    .push_bind(f.on_disk_start as i64)
                    .push_bind(f.on_disk_len as i64)
                    .push_bind(f.uncompressed_len as i64);
            });
            qb.push(" ON CONFLICT DO NOTHING");
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
        // One IN query instead of N round-trips.
        let uniq = dedup_sorted_xorbs(xorbs);

        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT xorb_hash, frame_index, on_disk_start, on_disk_len, uncompressed_len
             FROM xorb_frames WHERE xorb_hash IN (",
        );
        let mut sep = qb.separated(", ");
        for x in &uniq {
            sep.push_bind(hash_to_blob(&x.0));
        }
        qb.push(") ORDER BY xorb_hash, frame_index ASC");

        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("select frame layouts: {e}")))?;

        let mut out: std::collections::HashMap<XorbHash, Vec<XorbFrameRow>> =
            std::collections::HashMap::new();
        for r in &rows {
            let xorb_blob: Vec<u8> = r.try_get("xorb_hash").map_err(internal)?;
            let xorb = XorbHash(blob_to_hash(&xorb_blob)?);
            out.entry(xorb).or_default().push(row_to_frame(r)?);
        }
        Ok(out)
    }

    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>> {
        let rows = sqlx::query(
            "SELECT frame_index, on_disk_start, on_disk_len, uncompressed_len
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
        // Owners are accounted independently: a xorb also referenced by another
        // owner still counts in full for this one.
        let row = sqlx::query(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0)::BIGINT AS n
             FROM xorbs
             WHERE hash IN (
                 SELECT DISTINCT ft.xorb_hash
                 FROM file_terms ft
                 JOIN files f ON f.file_hash = ft.file_hash
                 WHERE f.owner = $1
             )",
        )
        .bind(owner)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CoreError::Internal(format!("stored_bytes_for_owner: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "stored_bytes_for_owner")
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
        // Xorbs this repo references, minus any also referenced by a *sibling*
        // repo (same owner) — the amount the owner's stored_bytes would drop if
        // this repo were deleted. Cross-owner sharing is ignored, matching the
        // owner-independent accounting in stored_bytes_for_owner.
        let owner = repo_id.split_once('/').map_or(repo_id, |(o, _)| o);
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
                 WHERE f.owner = $2 AND f.repo_id <> $3
             )",
        )
        .bind(repo_id)
        .bind(owner)
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
        if candidates.is_empty() {
            return Ok(0);
        }
        let uniq = dedup_sorted_xorbs(candidates);

        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT COALESCE(SUM(num_bytes_on_disk), 0)::BIGINT AS n FROM xorbs WHERE hash IN (",
        );
        let mut sep = qb.separated(", ");
        for x in &uniq {
            sep.push_bind(hash_to_blob(&x.0));
        }
        qb.push(
            ") AND hash NOT IN (
                SELECT DISTINCT ft.xorb_hash
                FROM file_terms ft
                JOIN files f ON f.file_hash = ft.file_hash
                WHERE f.owner = ",
        );
        qb.push_bind(owner.to_string());
        qb.push(")");

        let row = qb
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|e| CoreError::Internal(format!("unaccounted_xorb_bytes: {e}")))?;
        let n: i64 = row.try_get("n").map_err(internal)?;
        nonneg_i64_to_u64(n, "unaccounted_xorb_bytes_for_owner")
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
