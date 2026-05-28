//! Browser file download via `GET /v1/files/{file_id}`.
//!
//! End-to-end check of the streaming endpoint the forge (gitea) 302s into:
//! upload a small file, hit `/v1/files/...?token=&repo=&filename=` with the
//! forge JWT, and assert the bytes round-trip and the filename binding is
//! enforced.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bale_server_authz_mem::AlwaysAllow;
use bale_server_core::{ChunkHash, FileHash, Hash32};
use bale_server_http::{router, Service};
use bale_server_meta_sqlite::SqliteMetadataStore;
use bale_server_shard::{
    serialize, CasChunkEntry, FileTermEntry, ParsedCasBlock, ParsedFile, ParsedShard, ShardHeader,
    MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use bale_server_shard_testing::{
    build_uncompressed_xorb_body, xorb_hash_for_uncompressed_chunks, FLAG_WITH_VERIFICATION,
};
use bale_server_storage_fs::FsBlobStore;
use bale_server_wire::encode_hash;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn h(seed: u8) -> Hash32 {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    Hash32(b)
}

async fn body_to_bytes(body: Body) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

/// Build a JWT-shaped string whose payload carries `FilenameSHA256`. The
/// /v1/files handler only reads the payload (signature is irrelevant — the
/// forge's check_access is the source of truth) so a fake signature is fine.
fn forge_jwt(filename_sha256: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD
        .encode(format!(r#"{{"Op":"download","FilenameSHA256":"{filename_sha256}"}}"#).as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(b"not-verified-by-bale-server");
    format!("{header}.{payload}.{sig}")
}

fn forge_jwt_no_filename() -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"Op":"download"}"#);
    let sig = URL_SAFE_NO_PAD.encode(b"not-verified-by-bale-server");
    format!("{header}.{payload}.{sig}")
}

async fn upload_one_xorb_file(app: &axum::Router) -> (FileHash, Vec<u8>) {
    let chunk_a: Vec<u8> = (0..400u32).map(|i| (i as u8).wrapping_add(0x10)).collect();
    let chunk_b: Vec<u8> = (0..600u32).map(|i| (i as u8).wrapping_add(0x70)).collect();
    let body = build_uncompressed_xorb_body(&[&chunk_a, &chunk_b]);
    let xorb = xorb_hash_for_uncompressed_chunks(&[&chunk_a, &chunk_b]);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header("Authorization", "Bearer upload-token")
        .body(Body::from(body.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let file_hash = FileHash(h(0xF0));
    let shard = ParsedShard {
        header: ShardHeader {
            tag: MDB_SHARD_HEADER_TAG,
            version: MDB_SHARD_HEADER_VERSION,
            footer_size: 0,
        },
        files: vec![ParsedFile {
            file_hash,
            file_flags: FLAG_WITH_VERIFICATION,
            entries: vec![FileTermEntry {
                xorb,
                cas_flags: 0,
                unpacked_segment_bytes: 1000,
                chunk_idx_start: 0,
                chunk_idx_end: 2,
            }],
            verifications: vec![h(0xE0)],
            sha256: None,
        }],
        cas_blocks: vec![ParsedCasBlock {
            xorb,
            cas_flags: 0,
            num_bytes_in_cas: 1000,
            num_bytes_on_disk: body.len() as u32,
            chunks: vec![
                CasChunkEntry {
                    chunk_hash: ChunkHash(h(0xA0)),
                    byte_start: 0,
                    unpacked_segment_bytes: 400,
                },
                CasChunkEntry {
                    chunk_hash: ChunkHash(h(0xA1)),
                    byte_start: 400,
                    unpacked_segment_bytes: 600,
                },
            ],
        }],
        footer: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/shards")
        .header("Authorization", "Bearer upload-token")
        .body(Body::from(serialize(&shard)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut expected = Vec::with_capacity(1000);
    expected.extend_from_slice(&chunk_a);
    expected.extend_from_slice(&chunk_b);
    (file_hash, expected)
}

async fn build_app() -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(dir.path().join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [0u8; 32],
        public_base_url: "http://test.invalid".into(),
        default_quota_bytes: None,
        admin_token: None,
    };
    (router(svc), dir)
}

// AlwaysAllow.check_repo_access returns user "anonymous" and the upload
// path's auth_middleware mints claims carrying `anonymous/repo`. That's the
// repo our shard's file gets attributed to, so the download URL must name
// it explicitly.
const SEEDED_REPO: &str = "anonymous/repo";

#[tokio::test]
async fn streams_assembled_bytes_with_matching_filename() {
    let (app, _dir) = build_app().await;
    let (file_hash, expected) = upload_one_xorb_file(&app).await;

    let filename = "weights.bin";
    let hash = hex::encode(Sha256::digest(filename.as_bytes()));
    let token = forge_jwt(&hash);

    let url = format!(
        "/v1/files/{}?token={}&repo={}&filename={}",
        encode_hash(&file_hash.0),
        token,
        SEEDED_REPO,
        filename,
    );
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp
        .headers()
        .get("content-disposition")
        .expect("content-disposition set")
        .to_str()
        .unwrap()
        .to_string();
    assert!(cd.contains(&format!("filename=\"{filename}\"")), "got {cd}");
    let bytes = body_to_bytes(resp.into_body()).await;
    assert_eq!(bytes, expected, "streamed bytes match upload");
}

#[tokio::test]
async fn rejects_tampered_filename() {
    let (app, _dir) = build_app().await;
    let (file_hash, _) = upload_one_xorb_file(&app).await;

    // JWT pins the hash of "weights.bin" but the URL says "leaked.exe".
    let pinned = hex::encode(Sha256::digest(b"weights.bin"));
    let token = forge_jwt(&pinned);

    let url = format!(
        "/v1/files/{}?token={}&repo={}&filename=leaked.exe",
        encode_hash(&file_hash.0),
        token,
        SEEDED_REPO,
    );
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn no_content_disposition_without_filename_claim() {
    let (app, _dir) = build_app().await;
    let (file_hash, expected) = upload_one_xorb_file(&app).await;

    // Token carries no FilenameSHA256 — even though the URL specifies a name,
    // we serve the bytes without a Content-Disposition (the forge didn't
    // bless this name).
    let token = forge_jwt_no_filename();
    let url = format!(
        "/v1/files/{}?token={}&repo={}&filename=whatever.bin",
        encode_hash(&file_hash.0),
        token,
        SEEDED_REPO,
    );
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("content-disposition").is_none());
    let bytes = body_to_bytes(resp.into_body()).await;
    assert_eq!(bytes, expected);
}

#[tokio::test]
async fn rejects_missing_token() {
    let (app, _dir) = build_app().await;
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/v1/files/{}?repo=anonymous/repo",
            encode_hash(&h(0x00))
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Missing required query param surfaces as 400 from axum's Query rejection.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_repo_returns_404_not_403() {
    let (app, _dir) = build_app().await;
    let (file_hash, _) = upload_one_xorb_file(&app).await;

    // The file exists in SEEDED_REPO. Asking for it under a different repo must
    // not leak presence — same M12 invariant the /v1/reconstructions/ endpoint
    // enforces.
    let token = forge_jwt_no_filename();
    let url = format!(
        "/v1/files/{}?token={}&repo=other/repo",
        encode_hash(&file_hash.0),
        token,
    );
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
