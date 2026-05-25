//! M12: per-repo scope check on the reconstruction handler.
//!
//! Before this milestone, `/v1/reconstructions/{file_id}` was open to any
//! valid read token — a token for repo A could fetch reconstruction terms
//! for any file_id, including those uploaded to a different repo. This test
//! pins down the new behavior:
//!
//! 1. Alice uploads a file (xorb + shard) into `alice/repo`. Alice's read
//!    token can fetch the reconstruction.
//! 2. Bob has a read token for `bob/repo`. The *same* file_id is invisible
//!    to him — 404, not 403 (so existence is not leaked).
//! 3. Bob uploads the same shard into `bob/repo` (cross-repo dedup; the
//!    xorb is reused under the hood). Bob can now fetch the reconstruction.
//! 4. Alice can still fetch (her registration was not displaced).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use xet_server_authz_mem::ConfigAuthz;
use xet_server_core::{ChunkHash, FileHash, Hash32, Scope, XorbHash};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_shard::{
    build_uncompressed_xorb_body, serialize, CasChunkEntry, FileTermEntry, ParsedCasBlock,
    ParsedFile, ParsedShard, ShardHeader, FLAG_WITH_VERIFICATION, MDB_SHARD_HEADER_TAG,
    MDB_SHARD_HEADER_VERSION,
};
use xet_server_storage_fs::FsBlobStore;
use xet_server_wire::{encode_hash, XetTokenResponse};

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

/// Two distinct repos, each with its own write- and read-token-bearing user.
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
        .uri(format!("/api/models/{repo}/xet-{scope}-token/main"))
        .header("Authorization", format!("Bearer {hub_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token request failed");
    read_json(resp.into_body()).await
}

/// Uploads a xorb + shard registering `file` under the bearer's repo. The
/// shard is identical across calls so re-upload from a different repo
/// exercises cross-repo dedup (chunks already known).
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

    let xorb = XorbHash(h(0x10));
    let file = FileHash(h(0xF0));

    // 1. Alice uploads. Her token can read the reconstruction.
    upload_file(&app, &alice_w.access_token, xorb, file).await;
    assert_eq!(
        reconstruction_status(&app, &alice_w.access_token, &file).await,
        StatusCode::OK,
        "alice should see her own file"
    );

    // 2. Bob's token must NOT see the file. 404 (existence not leaked),
    //    not 403.
    assert_eq!(
        reconstruction_status(&app, &bob_w.access_token, &file).await,
        StatusCode::NOT_FOUND,
        "bob must not be able to read alice's file"
    );

    // 3. Bob re-uploads the same shard into his repo. The xorb is already
    //    on the server (xorb-upload is content-addressed and idempotent),
    //    but the shard creates a new (file_hash, repo_id=bob/repo) row.
    upload_file(&app, &bob_w.access_token, xorb, file).await;
    assert_eq!(
        reconstruction_status(&app, &bob_w.access_token, &file).await,
        StatusCode::OK,
        "bob should see his own registration of the same file"
    );

    // 4. Alice's registration was not displaced by Bob's — both rows
    //    coexist (composite PK on (file_hash, repo_id)).
    assert_eq!(
        reconstruction_status(&app, &alice_w.access_token, &file).await,
        StatusCode::OK,
        "alice's access should survive bob's re-upload"
    );
}

#[tokio::test]
async fn missing_file_for_authorized_repo_is_404() {
    // Sanity check that the 404 we return for "not in your repo" is
    // indistinguishable from "doesn't exist anywhere" — the whole point
    // of using 404 instead of 403.
    let app = build_two_repo_app().await;
    let alice_w = issue_token(&app, "hub-alice", "alice/repo", "write").await;
    let nonexistent = FileHash(h(0xFE));
    assert_eq!(
        reconstruction_status(&app, &alice_w.access_token, &nonexistent).await,
        StatusCode::NOT_FOUND,
    );
}
