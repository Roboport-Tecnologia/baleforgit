//! Shared helpers for the data-loss / corruption exploit tests.
//!
//! `FaultMeta<M>` wraps a real `MetadataStore` and lets a test fault-inject
//! specific calls (e.g. fail the Nth `register_file`, or fail
//! `register_xorb_layout` once) without affecting other operations.

#![allow(dead_code)]

use async_trait::async_trait;
use bale_server_core::{
    ChunkHash, ChunkLocation, ChunkOffsetRow, CoreError, CoreResult, FileHash, FileTerm, Hash32,
    MetadataStore, RepoRef, XorbFrameRow, XorbHash, XorbInfo,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

pub struct FaultMeta<M> {
    pub inner: Arc<M>,
    pub fail_register_xorb_layout: AtomicBool,
    /// When >0, `register_file` will succeed N-1 times then fail.
    pub fail_register_file_after: AtomicU32,
    pub register_file_calls: AtomicU32,
    /// Fail the atomic batch entirely — proves nothing leaks even though the
    /// handler intends to commit multiple files at once.
    pub fail_register_files: AtomicBool,
    pub register_files_calls: AtomicU32,
}

impl<M> FaultMeta<M> {
    pub fn new(inner: Arc<M>) -> Self {
        Self {
            inner,
            fail_register_xorb_layout: AtomicBool::new(false),
            fail_register_file_after: AtomicU32::new(0),
            register_file_calls: AtomicU32::new(0),
            fail_register_files: AtomicBool::new(false),
            register_files_calls: AtomicU32::new(0),
        }
    }
}

fn h(seed: u8) -> Hash32 {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    Hash32(b)
}

pub fn hh(seed: u8) -> Hash32 {
    h(seed)
}

#[async_trait]
impl<M: MetadataStore> MetadataStore for FaultMeta<M> {
    async fn register_xorb(
        &self,
        xorb: &XorbInfo,
        chunks: &[bale_server_core::ChunkRow],
    ) -> CoreResult<()> {
        self.inner.register_xorb(xorb, chunks).await
    }

    async fn register_file(
        &self,
        file_hash: &FileHash,
        repo: &RepoRef,
        terms: &[FileTerm],
    ) -> CoreResult<()> {
        let n = self.register_file_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let threshold = self.fail_register_file_after.load(Ordering::SeqCst);
        if threshold > 0 && n >= threshold {
            return Err(CoreError::Internal(format!(
                "fault-injected: register_file call #{n} (threshold {threshold})"
            )));
        }
        self.inner.register_file(file_hash, repo, terms).await
    }

    async fn register_files(
        &self,
        repo: &RepoRef,
        files: &[(FileHash, Vec<FileTerm>)],
    ) -> CoreResult<()> {
        self.register_files_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_register_files.load(Ordering::SeqCst) {
            // Fault BEFORE delegating so the inner's transaction never opens —
            // proves the handler treats the batch call as the commit boundary
            // and doesn't write per-file outside of it.
            return Err(CoreError::Internal(
                "fault-injected: register_files (batch commit)".into(),
            ));
        }
        // Forward to inner so SQLite's atomic-transaction override actually runs.
        self.inner.register_files(repo, files).await
    }

    async fn register_xorb_layout(
        &self,
        xorb: &XorbHash,
        frames: &[XorbFrameRow],
    ) -> CoreResult<()> {
        if self.fail_register_xorb_layout.load(Ordering::SeqCst) {
            return Err(CoreError::Internal(
                "fault-injected: register_xorb_layout".into(),
            ));
        }
        self.inner.register_xorb_layout(xorb, frames).await
    }

    async fn xorb_frame_layout(&self, xorb: &XorbHash) -> CoreResult<Vec<XorbFrameRow>> {
        self.inner.xorb_frame_layout(xorb).await
    }

    async fn xorb_frame_layouts(
        &self,
        xorbs: &[XorbHash],
    ) -> CoreResult<HashMap<XorbHash, Vec<XorbFrameRow>>> {
        self.inner.xorb_frame_layouts(xorbs).await
    }

    async fn xorb_exists(&self, xorb: &XorbHash) -> CoreResult<bool> {
        self.inner.xorb_exists(xorb).await
    }

    async fn lookup_file(&self, file_hash: &FileHash) -> CoreResult<Option<Vec<FileTerm>>> {
        self.inner.lookup_file(file_hash).await
    }

    async fn file_in_repo(&self, file_hash: &FileHash, repo_id: &str) -> CoreResult<bool> {
        self.inner.file_in_repo(file_hash, repo_id).await
    }

    async fn lookup_chunk(&self, chunk_hash: &ChunkHash) -> CoreResult<Option<ChunkLocation>> {
        self.inner.lookup_chunk(chunk_hash).await
    }

    async fn xorbs_near_chunk(
        &self,
        chunk_hash: &ChunkHash,
        limit: usize,
    ) -> CoreResult<Vec<XorbInfo>> {
        self.inner.xorbs_near_chunk(chunk_hash, limit).await
    }

    async fn xorb_chunk_offsets(&self, xorb: &XorbHash) -> CoreResult<Vec<ChunkOffsetRow>> {
        self.inner.xorb_chunk_offsets(xorb).await
    }

    async fn raw_bytes_for_owner(&self, owner: &str) -> CoreResult<u64> {
        self.inner.raw_bytes_for_owner(owner).await
    }

    async fn stored_bytes_for_owner(&self, owner: &str) -> CoreResult<u64> {
        self.inner.stored_bytes_for_owner(owner).await
    }

    async fn get_owner_quota(&self, owner: &str) -> CoreResult<Option<u64>> {
        self.inner.get_owner_quota(owner).await
    }

    async fn set_owner_quota(&self, owner: &str, limit_bytes: Option<u64>) -> CoreResult<()> {
        self.inner.set_owner_quota(owner, limit_bytes).await
    }

    async fn unaccounted_xorb_bytes_for_owner(
        &self,
        owner: &str,
        candidates: &[XorbHash],
    ) -> CoreResult<u64> {
        self.inner
            .unaccounted_xorb_bytes_for_owner(owner, candidates)
            .await
    }

    async fn raw_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        self.inner.raw_bytes_for_repo(repo_id).await
    }

    async fn stored_bytes_for_repo(&self, repo_id: &str) -> CoreResult<u64> {
        self.inner.stored_bytes_for_repo(repo_id).await
    }
}
