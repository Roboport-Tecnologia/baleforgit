use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use xet_server_authz_mem::AlwaysAllow;
use xet_server_core::{ChunkHash, FileHash, Hash32, XorbHash};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_shard::{
    build_uncompressed_xorb_body, parse_xorb_frames, serialize, xorb_hash_for_uncompressed_chunks,
    CasChunkEntry, FileTermEntry, ParsedCasBlock, ParsedFile, ParsedShard, ShardHeader,
    FLAG_WITH_VERIFICATION, MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use xet_server_storage_fs::FsBlobStore;
use xet_server_wire::{encode_hash, QueryReconstructionResponse};

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

#[tokio::test]
async fn upload_then_reconstruct_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(dir.path().join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let secret = [0x42u8; 32];
    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(AlwaysAllow),
        transfer_secret: secret,
        public_base_url: "http://test.invalid".into(),
    };
    let app = router(svc);

    // File lives in two xorbs (a: c0=300B|c1=400B, b: c0=250B|c1=250B|c2=200B)
    // and consumes a[0..2) + b[1..3) = 1150 bytes. Each xorb is a real container
    // (one frame per chunk, compression scheme 0); reconstruction returns frame
    // bytes (header + payload), walked below to extract payloads.
    let a_c0: Vec<u8> = (0..300u32).map(|i| (i as u8).wrapping_add(0x10)).collect();
    let a_c1: Vec<u8> = (0..400u32).map(|i| (i as u8).wrapping_add(0x40)).collect();
    let b_c0: Vec<u8> = (0..250u32).map(|i| (i as u8).wrapping_add(0x80)).collect();
    let b_c1: Vec<u8> = (0..250u32).map(|i| (i as u8).wrapping_add(0xA0)).collect();
    let b_c2: Vec<u8> = (0..200u32).map(|i| (i as u8).wrapping_add(0xC0)).collect();
    let body_a = build_uncompressed_xorb_body(&[&a_c0, &a_c1]);
    let body_b = build_uncompressed_xorb_body(&[&b_c0, &b_c1, &b_c2]);
    let xorb_a = xorb_hash_for_uncompressed_chunks(&[&a_c0, &a_c1]);
    let xorb_b = xorb_hash_for_uncompressed_chunks(&[&b_c0, &b_c1, &b_c2]);

    let post_xorb = |hash: XorbHash, body: Vec<u8>| {
        Request::builder()
            .method("POST")
            .uri(format!("/v1/xorbs/default/{}", encode_hash(&hash.0)))
            .header("Authorization", "Bearer test")
            .body(Body::from(body))
            .unwrap()
    };

    let resp = app
        .clone()
        .oneshot(post_xorb(xorb_a, body_a.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(post_xorb(xorb_b, body_b.clone()))
        .await
        .unwrap();
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
            entries: vec![
                FileTermEntry {
                    xorb: xorb_a,
                    cas_flags: 0,
                    unpacked_segment_bytes: 700,
                    chunk_idx_start: 0,
                    chunk_idx_end: 2,
                },
                FileTermEntry {
                    xorb: xorb_b,
                    cas_flags: 0,
                    unpacked_segment_bytes: 450,
                    chunk_idx_start: 1,
                    chunk_idx_end: 3,
                },
            ],
            verifications: vec![h(0xE1), h(0xE2)],
            sha256: None,
        }],
        cas_blocks: vec![
            ParsedCasBlock {
                xorb: xorb_a,
                cas_flags: 0,
                num_bytes_in_cas: 700,
                num_bytes_on_disk: body_a.len() as u32,
                chunks: vec![
                    CasChunkEntry {
                        chunk_hash: ChunkHash(h(0xA0)),
                        byte_start: 0,
                        unpacked_segment_bytes: 300,
                    },
                    CasChunkEntry {
                        chunk_hash: ChunkHash(h(0xA1)),
                        byte_start: 300,
                        unpacked_segment_bytes: 400,
                    },
                ],
            },
            ParsedCasBlock {
                xorb: xorb_b,
                cas_flags: 0,
                num_bytes_in_cas: 700,
                num_bytes_on_disk: body_b.len() as u32,
                chunks: vec![
                    CasChunkEntry {
                        chunk_hash: ChunkHash(h(0xB0)),
                        byte_start: 0,
                        unpacked_segment_bytes: 250,
                    },
                    CasChunkEntry {
                        chunk_hash: ChunkHash(h(0xB1)),
                        byte_start: 250,
                        unpacked_segment_bytes: 250,
                    },
                    CasChunkEntry {
                        chunk_hash: ChunkHash(h(0xB2)),
                        byte_start: 500,
                        unpacked_segment_bytes: 200,
                    },
                ],
            },
        ],
        footer: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/shards")
        .header("Authorization", "Bearer test")
        .body(Body::from(serialize(&shard)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/reconstructions/{}", encode_hash(&file_hash.0)))
        .header("Authorization", "Bearer test")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let recon: QueryReconstructionResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(recon.offset_into_first_range, 0);
    assert_eq!(recon.terms.len(), 2);
    assert_eq!(recon.fetch_info.len(), 2);

    let mut reconstructed: Vec<u8> = Vec::new();
    for term in &recon.terms {
        let entries = recon
            .fetch_info
            .get(&term.hash)
            .expect("fetch_info present");
        let entry = entries
            .iter()
            .find(|e| e.range.start <= term.range.start && e.range.end >= term.range.end)
            .expect("encompassing fetch_info");
        let req = Request::builder()
            .method("GET")
            .uri(strip_base(&entry.url))
            .header(
                "Range",
                format!("bytes={}-{}", entry.url_range.start, entry.url_range.end),
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PARTIAL_CONTENT,
            "transfer GET status"
        );
        let slice = body_to_bytes(resp.into_body()).await;
        // Compression scheme 0: each frame's payload is the raw chunk bytes.
        let frames = parse_xorb_frames(&slice).expect("term slice parses as frames");
        for f in frames {
            let header_end = f.on_disk_start as usize + 8;
            let payload_end = f.on_disk_start as usize + f.on_disk_len as usize;
            reconstructed.extend_from_slice(&slice[header_end..payload_end]);
        }
    }

    let mut expected = Vec::new();
    expected.extend_from_slice(&a_c0);
    expected.extend_from_slice(&a_c1);
    expected.extend_from_slice(&b_c1);
    expected.extend_from_slice(&b_c2);
    assert_eq!(reconstructed, expected);
}

#[tokio::test]
async fn transfer_url_rejects_tampered_range() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(dir.path().join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [1u8; 32],
        public_base_url: "http://test.invalid".into(),
    };
    let app = router(svc);

    let payload: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
    let body = build_uncompressed_xorb_body(&[&payload]);
    let xorb = xorb_hash_for_uncompressed_chunks(&[&payload]);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header("Authorization", "Bearer test")
        .body(Body::from(body))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    // Missing signature → 400 from query parser.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/xorb/default/{}", encode_hash(&xorb.0)))
        .header("Range", "bytes=0-10")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/xorb/default/{}?s=0&e=10&x=99999999999&sig=00",
            encode_hash(&xorb.0)
        ))
        .header("Range", "bytes=0-10")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reconstruction_404_when_file_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(dir.path().join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [0u8; 32],
        public_base_url: "http://test.invalid".into(),
    };
    let app = router(svc);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/reconstructions/{}", encode_hash(&h(0xAA))))
        .header("Authorization", "Bearer test")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
    assert!(std::str::from_utf8(&bytes)
        .unwrap()
        .contains("file not found"));
}

/// Strip scheme+host from a server-emitted URL so `oneshot` can route it.
fn strip_base(url: &str) -> String {
    if let Some(idx) = url.find("/xorb/") {
        url[idx..].to_string()
    } else {
        url.to_string()
    }
}
