//! M6: global dedup endpoint.
//!
//! Round-trip: register a xorb that contains two chunks (A and B). Query the
//! dedup endpoint for chunk A. Verify the response is a parseable shard whose
//! footer carries a fresh HMAC key, and that the response's CAS Info section
//! lists both A and B with their chunk hashes HMAC-wrapped using that key.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use tower::ServiceExt;
use xet_server_authz_mem::AlwaysAllow;
use xet_server_core::{ChunkHash, ChunkRow, Hash32, MetadataStore, XorbHash, XorbInfo, HASH_LEN};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_shard::parse as parse_shard;
use xet_server_storage_fs::FsBlobStore;
use xet_server_wire::encode_hash;

type HmacSha256 = Hmac<Sha256>;

fn h(seed: u8) -> Hash32 {
    let mut b = [0u8; HASH_LEN];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    Hash32(b)
}

fn wrap(key: &[u8; HASH_LEN], chunk: &ChunkHash) -> [u8; HASH_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(chunk.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

async fn build_app() -> (axum::Router, Arc<SqliteMetadataStore>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep();
    let blobs = Arc::new(FsBlobStore::open(path.join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let svc = Service {
        blobs,
        meta: meta.clone(),
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [0x42u8; 32],
        public_base_url: "http://test.invalid".into(),
    };
    (router(svc), meta)
}

fn get_dedup(chunk: &ChunkHash, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("GET")
        .uri(format!("/v1/chunks/default/{}", encode_hash(&chunk.0)));
    if let Some(t) = bearer {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn dedup_returns_shard_with_hmac_wrapped_chunks() {
    let (app, meta) = build_app().await;

    let xorb = XorbHash(h(0x10));
    let chunk_a = ChunkHash(h(0xA0));
    let chunk_b = ChunkHash(h(0xB0));
    meta.register_xorb(
        &XorbInfo {
            xorb,
            num_chunks: 2,
            num_bytes_in_cas: 700,
            num_bytes_on_disk: 700,
        },
        &[
            ChunkRow {
                chunk_hash: chunk_a,
                chunk_index: 0,
                byte_start: 0,
                unpacked_segment_bytes: 300,
            },
            ChunkRow {
                chunk_hash: chunk_b,
                chunk_index: 1,
                byte_start: 300,
                unpacked_segment_bytes: 400,
            },
        ],
    )
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(get_dedup(&chunk_a, Some("any-bearer")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );

    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let shard = parse_shard(&bytes).expect("response is a parseable shard");

    assert!(
        shard.files.is_empty(),
        "dedup response shard should have no file info"
    );
    assert_eq!(shard.cas_blocks.len(), 1, "expected one CAS block");
    let block = &shard.cas_blocks[0];
    assert_eq!(block.xorb, xorb);
    assert_eq!(block.chunks.len(), 2);

    let footer = shard.footer.expect("dedup response must include footer");
    assert_ne!(
        footer.chunk_hash_hmac_key.0, [0u8; HASH_LEN],
        "HMAC key in footer must be non-zero"
    );
    let key = footer.chunk_hash_hmac_key.0;

    // The CAS Info section's chunk hashes are HMAC-wrapped — neither raw
    // chunk hash should appear in the block.
    for (i, entry) in block.chunks.iter().enumerate() {
        assert_ne!(
            entry.chunk_hash.as_bytes(),
            chunk_a.as_bytes(),
            "raw chunk_a leaked at index {i}"
        );
        assert_ne!(
            entry.chunk_hash.as_bytes(),
            chunk_b.as_bytes(),
            "raw chunk_b leaked at index {i}"
        );
    }

    // The client uses the footer key to HMAC its own candidate chunks and look
    // for matches. We do the same here: both A and B should match.
    let expected_a = wrap(&key, &chunk_a);
    let expected_b = wrap(&key, &chunk_b);
    let entries: Vec<[u8; HASH_LEN]> = block
        .chunks
        .iter()
        .map(|c| *c.chunk_hash.as_bytes())
        .collect();
    assert!(
        entries.contains(&expected_a),
        "wrapped chunk_a not found in response"
    );
    assert!(
        entries.contains(&expected_b),
        "wrapped chunk_b not found in response — this is the cross-chunk dedup signal"
    );

    // Byte offsets and unpacked sizes are pass-through (not wrapped).
    assert_eq!(block.chunks[0].byte_start, 0);
    assert_eq!(block.chunks[0].unpacked_segment_bytes, 300);
    assert_eq!(block.chunks[1].byte_start, 300);
    assert_eq!(block.chunks[1].unpacked_segment_bytes, 400);
}

#[tokio::test]
async fn dedup_returns_404_for_unknown_chunk() {
    let (app, _meta) = build_app().await;
    let unknown = ChunkHash(h(0xEE));
    let resp = app
        .oneshot(get_dedup(&unknown, Some("any-bearer")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dedup_requires_bearer() {
    let (app, _meta) = build_app().await;
    let resp = app
        .oneshot(get_dedup(&ChunkHash(h(0xAA)), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dedup_returns_fresh_key_each_response() {
    // Two back-to-back queries for the same chunk should return different HMAC
    // keys (per-response randomness). If they ever coincide, callers could
    // correlate queries; we treat that as a bug.
    let (app, meta) = build_app().await;

    let xorb = XorbHash(h(0x55));
    let chunk = ChunkHash(h(0x56));
    meta.register_xorb(
        &XorbInfo {
            xorb,
            num_chunks: 1,
            num_bytes_in_cas: 64,
            num_bytes_on_disk: 64,
        },
        &[ChunkRow {
            chunk_hash: chunk,
            chunk_index: 0,
            byte_start: 0,
            unpacked_segment_bytes: 64,
        }],
    )
    .await
    .unwrap();

    let collect = |app: axum::Router| async move {
        let resp = app
            .oneshot(get_dedup(&chunk, Some("any-bearer")))
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        parse_shard(&bytes)
            .unwrap()
            .footer
            .unwrap()
            .chunk_hash_hmac_key
            .0
    };

    let k1 = collect(app.clone()).await;
    let k2 = collect(app).await;
    assert_ne!(k1, k2, "per-response key must be fresh each time");
}
