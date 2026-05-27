//! Per-repo scope on the reconstruction handler. A read token for repo A must
//! 404 (not 403, to avoid leaking existence) on a file_id registered only in
//! repo B, and re-registering under B must coexist with A's row (composite PK
//! on (file_hash, repo_id)).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bale_server_authz_mem::ConfigAuthz;
use bale_server_core::{ChunkHash, FileHash, Hash32, Scope, XorbHash};
use bale_server_http::{router, Service};
use bale_server_meta_sqlite::SqliteMetadataStore;
use bale_server_shard::{
    build_uncompressed_xorb_body, serialize, xorb_hash_for_uncompressed_chunks, CasChunkEntry,
    FileTermEntry, ParsedCasBlock, ParsedFile, ParsedShard, ShardHeader, FLAG_WITH_VERIFICATION,
    MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use bale_server_storage_fs::FsBlobStore;
use bale_server_wire::{encode_hash, XetTokenResponse};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn h(seed: u8) -> Hash32 {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    Hash32(b)
}

async fn read_json<T: serde::de::DeserializeOwned>(body: Body) -> T {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn build_two_repo_app() -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep();
    let blobs = Arc::new(FsBlobStore::open(path.join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());

    let authz = ConfigAuthz::new(b"jwt-secret-key-32-bytes-or-more!".to_vec())
        .grant("hub-alice", "alice", "alice/repo", Scope::Write)
        .grant("hub-bob", "bob", "bob/repo", Scope::Write);

    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(authz),
        transfer_secret: [0xAAu8; 32],
        public_base_url: "http://test.invalid".into(),
        default_quota_bytes: None,
        admin_token: None,
    };
    router(svc)
}

async fn issue_token(
    app: &axum::Router,
    hub_token: &str,
    repo: &str,
    scope: &str,
) -> XetTokenResponse {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/models/{repo}/bale-{scope}-token/main"))
        .header("Authorization", format!("Bearer {hub_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token request failed");
    read_json(resp.into_body()).await
}

/// Uploads xorb + shard registering `file` under the bearer's repo. The
/// shard is identical across calls so cross-repo dedup is exercised.
async fn upload_file(app: &axum::Router, token: &str, xorb: XorbHash, file: FileHash) {
    let payload: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
    let body = build_uncompressed_xorb_body(&[&payload]);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "xorb upload failed");

    let shard = ParsedShard {
        header: ShardHeader {
            tag: MDB_SHARD_HEADER_TAG,
            version: MDB_SHARD_HEADER_VERSION,
            footer_size: 0,
        },
        files: vec![ParsedFile {
            file_hash: file,
            file_flags: FLAG_WITH_VERIFICATION,
            entries: vec![FileTermEntry {
                xorb,
                cas_flags: 0,
                unpacked_segment_bytes: 512,
                chunk_idx_start: 0,
                chunk_idx_end: 1,
            }],
            verifications: vec![h(0xE0)],
            sha256: None,
        }],
        cas_blocks: vec![ParsedCasBlock {
            xorb,
            cas_flags: 0,
            num_bytes_in_cas: 512,
            num_bytes_on_disk: 512,
            chunks: vec![CasChunkEntry {
                chunk_hash: ChunkHash(h(0xA0)),
                byte_start: 0,
                unpacked_segment_bytes: 512,
            }],
        }],
        footer: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/shards")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(serialize(&shard)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "shard upload failed");
}

async fn reconstruction_status(app: &axum::Router, token: &str, file: &FileHash) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/reconstructions/{}", encode_hash(&file.0)))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn cross_repo_isolation_and_dedup() {
    let app = build_two_repo_app().await;

    let alice_w = issue_token(&app, "hub-alice", "alice/repo", "write").await;
    let bob_w = issue_token(&app, "hub-bob", "bob/repo", "write").await;

    // `upload_file` builds the body from this same 512-byte payload — derive
    // the xorb hash from it so the server's verification accepts the upload.
    let payload: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
    let xorb = xorb_hash_for_uncompressed_chunks(&[&payload]);
    let file = FileHash(h(0xF0));

    upload_file(&app, &alice_w.access_token, xorb, file).await;
    assert_eq!(
        reconstruction_status(&app, &alice_w.access_token, &file).await,
        StatusCode::OK,
        "alice should see her own file"
    );

    // Bob's token must NOT see the file — 404 (existence not leaked), not 403.
    assert_eq!(
        reconstruction_status(&app, &bob_w.access_token, &file).await,
        StatusCode::NOT_FOUND,
        "bob must not be able to read alice's file"
    );

    // Re-upload from bob: xorb is idempotent (content-addressed), but the
    // shard adds a new (file_hash, repo_id=bob/repo) row.
    upload_file(&app, &bob_w.access_token, xorb, file).await;
    assert_eq!(
        reconstruction_status(&app, &bob_w.access_token, &file).await,
        StatusCode::OK,
        "bob should see his own registration of the same file"
    );

    assert_eq!(
        reconstruction_status(&app, &alice_w.access_token, &file).await,
        StatusCode::OK,
        "alice's access should survive bob's re-upload"
    );
}

#[tokio::test]
async fn missing_file_for_authorized_repo_is_404() {
    // The 404 for "not in your repo" must match "doesn't exist anywhere" —
    // that's the whole point of 404-not-403.
    let app = build_two_repo_app().await;
    let alice_w = issue_token(&app, "hub-alice", "alice/repo", "write").await;
    let nonexistent = FileHash(h(0xFE));
    assert_eq!(
        reconstruction_status(&app, &alice_w.access_token, &nonexistent).await,
        StatusCode::NOT_FOUND,
    );
}
