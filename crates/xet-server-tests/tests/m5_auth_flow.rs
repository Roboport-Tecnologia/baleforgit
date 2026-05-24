//! M5: full token issuance → upload → download flow using `ConfigAuthz`.
//! Also covers scope enforcement and missing-bearer rejection.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use xet_server_authz_mem::ConfigAuthz;
use xet_server_core::{ChunkHash, FileHash, Hash32, Scope, XorbHash};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_shard::{
    serialize, CasChunkEntry, FileTermEntry, ParsedCasBlock, ParsedFile, ParsedShard, ShardHeader,
    FLAG_WITH_VERIFICATION, MDB_SHARD_HEADER_VERSION, PLACEHOLDER_TAG,
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

async fn build_app() -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    // Leak the tempdir to keep the path alive for the whole test (cheap, test-only).
    let path = dir.into_path();
    let blobs = Arc::new(FsBlobStore::open(path.join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());

    let authz = ConfigAuthz::new(b"jwt-secret-key-32-bytes-or-more!".to_vec())
        .grant("hub-alice", "alice", "alice/big-model", Scope::Write)
        .grant("hub-bob", "bob", "alice/big-model", Scope::Read);

    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(authz),
        transfer_secret: [0x99u8; 32],
        public_base_url: "http://test.invalid".into(),
    };
    router(svc)
}

async fn issue_token(app: &axum::Router, hub_token: &str, scope: &str) -> XetTokenResponse {
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/api/models/alice/big-model/xet-{scope}-token/main"
        ))
        .header("Authorization", format!("Bearer {hub_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token request failed");
    read_json(resp.into_body()).await
}

#[tokio::test]
async fn write_token_unlocks_upload_then_download() {
    let app = build_app().await;

    let tok = issue_token(&app, "hub-alice", "write").await;
    assert_eq!(tok.cas_url, "http://test.invalid");
    assert!(!tok.access_token.is_empty());

    // Upload a xorb.
    let xorb = XorbHash(h(0x10));
    let body: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header("Authorization", format!("Bearer {}", tok.access_token))
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Upload a shard.
    let file = FileHash(h(0xF0));
    let shard = ParsedShard {
        header: ShardHeader {
            tag: PLACEHOLDER_TAG,
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
        .uri("/v1/shards")
        .header("Authorization", format!("Bearer {}", tok.access_token))
        .body(Body::from(serialize(&shard)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Switch to a read token and fetch the reconstruction.
    let read_tok = issue_token(&app, "hub-bob", "read").await;
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/reconstructions/{}", encode_hash(&file.0)))
        .header("Authorization", format!("Bearer {}", read_tok.access_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn read_token_cannot_post_xorb() {
    let app = build_app().await;
    let tok = issue_token(&app, "hub-bob", "read").await;

    let xorb = XorbHash(h(0x11));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header("Authorization", format!("Bearer {}", tok.access_token))
        .body(Body::from(b"junk".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(s.contains("write-scope"), "got: {s}");
}

#[tokio::test]
async fn missing_bearer_is_401() {
    let app = build_app().await;
    let xorb = XorbHash(h(0x12));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .body(Body::from(b"junk".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_jwt_is_401() {
    let app = build_app().await;
    let xorb = XorbHash(h(0x13));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header(
            "Authorization",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.WRONG",
        )
        .body(Body::from(b"junk".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hub_endpoint_rejects_unknown_hub_token() {
    let app = build_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/models/alice/big-model/xet-write-token/main")
        .header("Authorization", "Bearer not-a-known-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hub_endpoint_rejects_unauthorized_write_request() {
    let app = build_app().await;
    // hub-bob is only granted Read; asking for a write token should 403.
    let req = Request::builder()
        .method("GET")
        .uri("/api/models/alice/big-model/xet-write-token/main")
        .header("Authorization", "Bearer hub-bob")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
