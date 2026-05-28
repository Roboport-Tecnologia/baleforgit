use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bale_server_authz_mem::AlwaysAllow;
use bale_server_core::{BlobStore, ChunkHash, FileHash, Hash32, MetadataStore, XorbHash};
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
use bale_server_wire::{encode_hash, UploadShardResponse, UploadXorbResponse};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

fn h(seed: u8) -> Hash32 {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    Hash32(b)
}

async fn read_body_json<T: serde::de::DeserializeOwned>(body: Body) -> T {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn upload_xorb_then_shard_indexes_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(dir.path().join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let svc = Service {
        blobs: blobs.clone(),
        meta: meta.clone(),
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [0u8; 32],
        public_base_url: "http://test.invalid".into(),
        default_quota_bytes: None,
        admin_token: None,
    };
    let app = router(svc);

    // Server parses the body to extract on-disk frame layout, and verifies the
    // URL hash matches the body's merkle aggregation, so we compute the real
    // xorb hash from the same chunks rather than using a synthetic one.
    let chunk0_payload: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
    let chunk1_payload: Vec<u8> = (0..256u32).map(|i| (i as u8).wrapping_add(0x80)).collect();
    let xorb_body = build_uncompressed_xorb_body(&[&chunk0_payload, &chunk1_payload]);
    let xorb_hash = xorb_hash_for_uncompressed_chunks(&[&chunk0_payload, &chunk1_payload]);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb_hash.0)))
        .header("Authorization", "Bearer test")
        .body(Body::from(xorb_body.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: UploadXorbResponse = read_body_json(resp.into_body()).await;
    assert!(body.was_inserted, "first xorb upload should insert");

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb_hash.0)))
        .header("Authorization", "Bearer test")
        .body(Body::from(xorb_body.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: UploadXorbResponse = read_body_json(resp.into_body()).await;
    assert!(!body.was_inserted, "second xorb upload is a no-op");

    let chunk0 = ChunkHash(h(0xA0));
    let chunk1 = ChunkHash(h(0xA1));
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
                xorb: xorb_hash,
                cas_flags: 0,
                unpacked_segment_bytes: 512,
                chunk_idx_start: 0,
                chunk_idx_end: 2,
            }],
            verifications: vec![h(0xE0)],
            sha256: None,
        }],
        cas_blocks: vec![ParsedCasBlock {
            xorb: xorb_hash,
            cas_flags: 0,
            num_bytes_in_cas: 512,
            num_bytes_on_disk: 512,
            chunks: vec![
                CasChunkEntry {
                    chunk_hash: chunk0,
                    byte_start: 0,
                    unpacked_segment_bytes: 256,
                },
                CasChunkEntry {
                    chunk_hash: chunk1,
                    byte_start: 256,
                    unpacked_segment_bytes: 256,
                },
            ],
        }],
        footer: None,
    };
    let shard_bytes = serialize(&shard);

    let req = Request::builder()
        .method("POST")
        .uri("/shards")
        .header("Authorization", "Bearer test")
        .body(Body::from(shard_bytes))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: UploadShardResponse = read_body_json(resp.into_body()).await;
    assert_eq!(body.result, 1);

    assert!(meta.xorb_exists(&xorb_hash).await.unwrap());

    let loc = meta
        .lookup_chunk(&chunk0)
        .await
        .unwrap()
        .expect("chunk0 known");
    assert_eq!(loc.xorb, xorb_hash);
    assert_eq!(loc.byte_start, 0);

    let loc = meta
        .lookup_chunk(&chunk1)
        .await
        .unwrap()
        .expect("chunk1 known");
    assert_eq!(loc.byte_start, 256);

    let offsets = meta.xorb_chunk_offsets(&xorb_hash).await.unwrap();
    assert_eq!(offsets.len(), 2);

    let terms = meta
        .lookup_file(&file_hash)
        .await
        .unwrap()
        .expect("file known");
    assert_eq!(terms.len(), 1);
    assert_eq!(terms[0].xorb, xorb_hash);
    assert_eq!(terms[0].chunk_idx_end, 2);
    assert!(terms[0].verification.is_some());
}

#[tokio::test]
async fn shard_upload_rejects_missing_xorb() {
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
    let app = router(svc);

    let missing_xorb = XorbHash(h(0xBE));
    let shard = ParsedShard {
        header: ShardHeader {
            tag: MDB_SHARD_HEADER_TAG,
            version: MDB_SHARD_HEADER_VERSION,
            footer_size: 0,
        },
        files: vec![],
        cas_blocks: vec![ParsedCasBlock {
            xorb: missing_xorb,
            cas_flags: 0,
            num_bytes_in_cas: 10,
            num_bytes_on_disk: 10,
            chunks: vec![CasChunkEntry {
                chunk_hash: ChunkHash(h(0xC1)),
                byte_start: 0,
                unpacked_segment_bytes: 10,
            }],
        }],
        footer: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/shards")
        .header("Authorization", "Bearer test")
        .body(Body::from(serialize(&shard)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(s.contains("missing xorb"), "got: {s}");
}

#[tokio::test]
async fn xorb_upload_rejects_malformed_hash() {
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
    let app = router(svc);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/xorbs/default/not-a-real-hash")
        .header("Authorization", "Bearer test")
        .body(Body::from(Bytes::from_static(b"junk")))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn xorb_upload_rejects_body_whose_hash_doesnt_match_url() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(dir.path().join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let svc = Service {
        blobs: blobs.clone(),
        meta: meta.clone(),
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [0u8; 32],
        public_base_url: "http://test.invalid".into(),
        default_quota_bytes: None,
        admin_token: None,
    };
    let app = router(svc);

    // Compute the correct hash for one body but POST under a different,
    // attacker-controlled hash. The server must reject the upload AND not
    // record any metadata for either hash.
    let payload: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
    let body = build_uncompressed_xorb_body(&[&payload]);
    let wrong_hash = XorbHash(h(0xAB));

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&wrong_hash.0)))
        .header("Authorization", "Bearer test")
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(
        s.contains("URL hash"),
        "expected hash-mismatch error, got: {s}"
    );

    // Neither the storage nor the metadata layer should have remembered it.
    assert!(!blobs.xorb_exists(&wrong_hash).await.unwrap());
    assert!(!meta.xorb_exists(&wrong_hash).await.unwrap());
    let real_hash = xorb_hash_for_uncompressed_chunks(&[&payload]);
    assert!(!blobs.xorb_exists(&real_hash).await.unwrap());
    assert!(!meta.xorb_exists(&real_hash).await.unwrap());
}
