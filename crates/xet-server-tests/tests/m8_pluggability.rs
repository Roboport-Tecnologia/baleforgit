//! M8 pluggability sanity check.
//!
//! Same wire-level behavior as M5 (token issuance → write upload → read
//! download) but driving the HTTP router with alternate trait impls:
//!
//! - `BlobStore` -> `xet-server-storage-mem::MemBlobStore` (instead of `FsBlobStore`)
//! - `RepoAuthz` -> `xet-server-authz-http::HttpAuthz` talking to an in-process
//!   mock upstream (instead of `ConfigAuthz`'s in-memory map)
//!
//! The point isn't to test the impls themselves (their own crates do that);
//! it's to confirm the trait seams are wide enough that the handlers don't
//! care which impl they're wired to. If anything had to change in
//! `xet-server-http` to make this work, the trait was wrong.

use axum::body::{Body, Bytes as AxumBytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use xet_server_authz_http::HttpAuthz;
use xet_server_core::{ChunkHash, FileHash, Hash32, Scope, XorbHash};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_shard::{
    serialize, CasChunkEntry, FileTermEntry, ParsedCasBlock, ParsedFile, ParsedShard, ShardHeader,
    FLAG_WITH_VERIFICATION, MDB_SHARD_HEADER_TAG, MDB_SHARD_HEADER_VERSION,
};
use xet_server_storage_mem::MemBlobStore;
use xet_server_wire::{encode_hash, QueryReconstructionResponse, XetTokenResponse};

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

async fn read_json<T: serde::de::DeserializeOwned>(body: Body) -> T {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---- Mock upstream "repo authority" (stand-in for GitLab/Gitea) ------------

#[derive(Clone)]
struct UpstreamState(Arc<Vec<(String, String, String, Scope)>>);

async fn upstream_check_access(
    State(s): State<UpstreamState>,
    body: AxumBytes,
) -> Result<(StatusCode, String), StatusCode> {
    #[derive(serde::Deserialize)]
    struct WireReq {
        hub_bearer: String,
        repo: xet_server_core::RepoRef,
        scope: Scope,
    }
    let req: WireReq = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut saw_user = false;
    for (hub, user, rid, granted) in s.0.iter() {
        if hub == &req.hub_bearer {
            saw_user = true;
            if rid == &req.repo.repo_id {
                if matches!(req.scope, Scope::Write) && matches!(granted, Scope::Read) {
                    return Err(StatusCode::FORBIDDEN);
                }
                let body = serde_json::json!({ "user_id": user }).to_string();
                return Ok((StatusCode::OK, body));
            }
        }
    }
    if saw_user {
        Err(StatusCode::FORBIDDEN)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn spawn_upstream(grants: Vec<(String, String, String, Scope)>) -> String {
    let state = UpstreamState(Arc::new(grants));
    let app = Router::new()
        .route("/check_access", post(upstream_check_access))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

// ---- The test --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_against_alternate_impls() {
    // (1) Alternate `RepoAuthz`: HTTP-backed, pointing at a mock upstream.
    let upstream = spawn_upstream(vec![
        (
            "hub-alice".into(),
            "alice".into(),
            "alice/big-model".into(),
            Scope::Write,
        ),
        (
            "hub-bob".into(),
            "bob".into(),
            "alice/big-model".into(),
            Scope::Read,
        ),
    ])
    .await;
    let authz = HttpAuthz::new(upstream, b"jwt-secret-32-bytes-padding-xxxx".to_vec()).unwrap();

    // (2) Alternate `BlobStore`: in-memory.
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());

    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(authz),
        transfer_secret: [0xA1u8; 32],
        public_base_url: "http://test.invalid".into(),
    };
    let app = router(svc);

    // ---- Token issuance via mock-HF endpoint (calls upstream) -------------
    let req = Request::builder()
        .method("GET")
        .uri("/api/models/alice/big-model/xet-write-token/main")
        .header("Authorization", "Bearer hub-alice")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "write token request");
    let write_tok: XetTokenResponse = read_json(resp.into_body()).await;

    // hub-bob is read-only on this repo; write-token request should 403.
    let req = Request::builder()
        .method("GET")
        .uri("/api/models/alice/big-model/xet-write-token/main")
        .header("Authorization", "Bearer hub-bob")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Unknown hub bearer → 401 from upstream, surfaced as 401 to the client.
    let req = Request::builder()
        .method("GET")
        .uri("/api/models/alice/big-model/xet-read-token/main")
        .header("Authorization", "Bearer unknown-hub-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // ---- Upload xorb + shard with the write token --------------------------
    let xorb = XorbHash(h(0x20));
    let body: Vec<u8> = (0..512u32).map(|i| (i as u8).wrapping_mul(3)).collect();
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header(
            "Authorization",
            format!("Bearer {}", write_tok.access_token),
        )
        .body(Body::from(body.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let file = FileHash(h(0xF7));
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
        .header(
            "Authorization",
            format!("Bearer {}", write_tok.access_token),
        )
        .body(Body::from(serialize(&shard)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // ---- Read-token download → reconstruction → byte compare --------------
    let req = Request::builder()
        .method("GET")
        .uri("/api/models/alice/big-model/xet-read-token/main")
        .header("Authorization", "Bearer hub-bob")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let read_tok: XetTokenResponse = read_json(resp.into_body()).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/reconstructions/{}", encode_hash(&file.0)))
        .header("Authorization", format!("Bearer {}", read_tok.access_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let recon: QueryReconstructionResponse =
        serde_json::from_slice(&body_to_bytes(resp.into_body()).await).unwrap();
    assert_eq!(recon.terms.len(), 1);

    // Follow the transfer URL to actually read the xorb bytes back out of
    // MemBlobStore.
    let term = &recon.terms[0];
    let entries = recon
        .fetch_info
        .get(&term.hash)
        .expect("fetch_info present");
    let entry = entries
        .iter()
        .find(|e| e.range.start <= term.range.start && e.range.end >= term.range.end)
        .expect("encompassing fetch_info");
    let path = strip_base(&entry.url);
    let req = Request::builder()
        .method("GET")
        .uri(&path)
        .header(
            "Range",
            format!("bytes={}-{}", entry.url_range.start, entry.url_range.end),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let slice = body_to_bytes(resp.into_body()).await;
    assert_eq!(slice, body, "MemBlobStore round-trip mismatch");
}

fn strip_base(url: &str) -> String {
    if let Some(idx) = url.find("/xorb/") {
        url[idx..].to_string()
    } else {
        url.to_string()
    }
}
