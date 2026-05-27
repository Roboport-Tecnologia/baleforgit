//! Per-owner storage quotas + the usage endpoint that powers the dedup-savings
//! display. Covers: raw vs stored accounting, independence across owners,
//! quota rejection at both xorb upload and shard upload, the cross-owner-dedup
//! charging rule, the admin endpoint's auth, and the cross-owner view scope.

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
use bale_server_wire::{
    encode_hash, OwnerUsageResponse, RepoUsageResponse, SetOwnerQuotaRequest, XetTokenResponse,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

const ADMIN_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ADMIN_BEARER: &str = ADMIN_HEX;

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

struct AppCfg {
    default_quota: Option<u64>,
    admin: bool,
    /// `(hub_token, user, repo)` triples; scope is always Write.
    grants: Vec<(&'static str, &'static str, &'static str)>,
}

async fn build_app(cfg: AppCfg) -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep();
    let blobs = Arc::new(FsBlobStore::open(path.join("blobs")).await.unwrap());
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());
    let mut authz = ConfigAuthz::new(b"jwt-secret-key-32-bytes-or-more!".to_vec());
    for (hub, user, repo) in &cfg.grants {
        authz = authz.grant(*hub, *user, *repo, Scope::Write);
    }
    let admin_token = cfg.admin.then(|| {
        let mut arr = [0u8; 32];
        hex::decode_to_slice(ADMIN_HEX, &mut arr).unwrap();
        arr
    });
    let svc = Service {
        blobs,
        meta,
        authz: Arc::new(authz),
        transfer_secret: [0x77u8; 32],
        public_base_url: "http://test.invalid".into(),
        default_quota_bytes: cfg.default_quota,
        admin_token,
    };
    router(svc)
}

async fn issue_token(app: &axum::Router, hub: &str, repo: &str) -> XetTokenResponse {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/models/{repo}/bale-write-token/main"))
        .header("Authorization", format!("Bearer {hub}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token request failed");
    read_json(resp.into_body()).await
}

fn payload(seed: u8, size: usize) -> Vec<u8> {
    // Deterministic, content-distinct across `seed` so two payloads with the
    // same `size` but different `seed` produce different xorb hashes.
    (0..size).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn xorb_for(seed: u8, size: usize) -> XorbHash {
    xorb_hash_for_uncompressed_chunks(&[&payload(seed, size)])
}

async fn post_xorb(app: &axum::Router, token: &str, seed: u8, size: usize) -> StatusCode {
    let body = build_uncompressed_xorb_body(&[&payload(seed, size)]);
    let xorb = xorb_for(seed, size);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/xorbs/default/{}", encode_hash(&xorb.0)))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

async fn post_shard(
    app: &axum::Router,
    token: &str,
    seed: u8,
    size: u32,
    file: FileHash,
) -> StatusCode {
    let xorb = xorb_for(seed, size as usize);
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
                unpacked_segment_bytes: size,
                chunk_idx_start: 0,
                chunk_idx_end: 1,
            }],
            verifications: vec![h(seed)],
            sha256: None,
        }],
        cas_blocks: vec![ParsedCasBlock {
            xorb,
            cas_flags: 0,
            num_bytes_in_cas: size,
            // For these tests we treat on-disk == in-CAS so the maths is clean;
            // production xorbs would include framing/compression overhead.
            num_bytes_on_disk: size,
            chunks: vec![CasChunkEntry {
                chunk_hash: ChunkHash(h(seed.wrapping_add(0x80))),
                byte_start: 0,
                unpacked_segment_bytes: size,
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
    app.clone().oneshot(req).await.unwrap().status()
}

async fn upload_file(
    app: &axum::Router,
    token: &str,
    seed: u8,
    size: u32,
    file: FileHash,
) -> Result<(), StatusCode> {
    let st = post_xorb(app, token, seed, size as usize).await;
    if st != StatusCode::OK {
        return Err(st);
    }
    let st = post_shard(app, token, seed, size, file).await;
    if st != StatusCode::OK {
        return Err(st);
    }
    Ok(())
}

async fn get_usage(
    app: &axum::Router,
    token: &str,
    owner: &str,
) -> (StatusCode, Option<OwnerUsageResponse>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/usage/{owner}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    if status == StatusCode::OK {
        (status, Some(read_json(resp.into_body()).await))
    } else {
        (status, None)
    }
}

async fn get_repo_usage(
    app: &axum::Router,
    token: &str,
    owner: &str,
    repo: &str,
) -> (StatusCode, Option<RepoUsageResponse>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/usage/repo/{owner}/{repo}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    if status == StatusCode::OK {
        (status, Some(read_json(resp.into_body()).await))
    } else {
        (status, None)
    }
}

async fn set_quota_admin(
    app: &axum::Router,
    bearer: &str,
    owner: &str,
    limit: Option<u64>,
) -> StatusCode {
    let body = serde_json::to_vec(&SetOwnerQuotaRequest { limit_bytes: limit }).unwrap();
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/quotas/{owner}"))
        .header("Authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn dedup_savings_visible_across_owner_repos() {
    // Two repos under alice, same 1024-byte payload → raw doubles, stored
    // stays flat. This is the number the gitea UI will use to show savings.
    let app = build_app(AppCfg {
        default_quota: None,
        admin: false,
        grants: vec![
            ("hub-a-a", "alice", "alice/a"),
            ("hub-a-b", "alice", "alice/b"),
        ],
    })
    .await;
    let t_a = issue_token(&app, "hub-a-a", "alice/a").await.access_token;
    let t_b = issue_token(&app, "hub-a-b", "alice/b").await.access_token;

    upload_file(&app, &t_a, 0xAA, 1024, FileHash(h(0xF1)))
        .await
        .unwrap();
    upload_file(&app, &t_b, 0xAA, 1024, FileHash(h(0xF2)))
        .await
        .unwrap();

    let (status, usage) = get_usage(&app, &t_a, "alice").await;
    assert_eq!(status, StatusCode::OK);
    let u = usage.unwrap();
    assert_eq!(u.owner, "alice");
    assert_eq!(u.raw_bytes, 2048);
    assert_eq!(u.stored_bytes, 1024);
    assert_eq!(u.dedup_savings_bytes, 1024);
    assert!(u.quota_bytes.is_none());
}

#[tokio::test]
async fn owner_accounting_is_independent() {
    let app = build_app(AppCfg {
        default_quota: None,
        admin: false,
        grants: vec![("hub-a", "alice", "alice/a"), ("hub-b", "bob", "bob/x")],
    })
    .await;
    let t_a = issue_token(&app, "hub-a", "alice/a").await.access_token;
    let t_b = issue_token(&app, "hub-b", "bob/x").await.access_token;

    upload_file(&app, &t_a, 0x11, 512, FileHash(h(0xA1)))
        .await
        .unwrap();
    upload_file(&app, &t_b, 0x22, 256, FileHash(h(0xB1)))
        .await
        .unwrap();

    let (_, alice) = get_usage(&app, &t_a, "alice").await;
    let (_, bob) = get_usage(&app, &t_b, "bob").await;
    let alice = alice.unwrap();
    let bob = bob.unwrap();
    assert_eq!((alice.raw_bytes, alice.stored_bytes), (512, 512));
    assert_eq!((bob.raw_bytes, bob.stored_bytes), (256, 256));
}

#[tokio::test]
async fn quota_blocks_at_xorb_upload_when_new_bytes_would_exceed() {
    let app = build_app(AppCfg {
        default_quota: Some(1500),
        admin: false,
        grants: vec![("hub-b", "bob", "bob/x")],
    })
    .await;
    let t = issue_token(&app, "hub-b", "bob/x").await.access_token;

    upload_file(&app, &t, 0x33, 1024, FileHash(h(0xC1)))
        .await
        .unwrap();

    // A second 1024-byte xorb would push bob past the 1500-byte default —
    // rejected at the xorb upload step, before any new shard bytes land.
    let status = post_xorb(&app, &t, 0x44, 1024).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn quota_blocks_at_shard_upload_for_cross_owner_dedup() {
    // The "skip if xorb already exists" shortcut at xorb upload is safe only
    // because the shard upload re-checks: when bob references alice's already-
    // uploaded xorb, bob's `stored_bytes_for_owner` grows by that xorb's size
    // and we must catch that growth here.
    let app = build_app(AppCfg {
        default_quota: None,
        admin: true,
        grants: vec![("hub-a", "alice", "alice/a"), ("hub-b", "bob", "bob/x")],
    })
    .await;

    // Alice uploads first — no quota for her, lands fine.
    let t_a = issue_token(&app, "hub-a", "alice/a").await.access_token;
    upload_file(&app, &t_a, 0x55, 1024, FileHash(h(0xD1)))
        .await
        .unwrap();

    // Bob now has a 500-byte quota, then tries to reference Alice's xorb.
    assert_eq!(
        set_quota_admin(&app, ADMIN_BEARER, "bob", Some(500)).await,
        StatusCode::NO_CONTENT
    );
    let t_b = issue_token(&app, "hub-b", "bob/x").await.access_token;

    // Xorb upload alone should succeed (content-addressed, already exists,
    // skip path) — proving the design point that the xorb step doesn't
    // false-reject on existing content.
    assert_eq!(post_xorb(&app, &t_b, 0x55, 1024).await, StatusCode::OK);

    // But the shard upload, which would attribute the 1024-byte xorb to bob,
    // must be rejected — 1024 > bob's 500-byte cap.
    let status = post_shard(&app, &t_b, 0x55, 1024, FileHash(h(0xD2))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // And the rejection must NOT have left a partial registration behind.
    let (_, bob_usage) = get_usage(&app, &t_b, "bob").await;
    let bob_usage = bob_usage.unwrap();
    assert_eq!(
        bob_usage.stored_bytes, 0,
        "no file rows should have been written"
    );
    assert_eq!(bob_usage.raw_bytes, 0);
}

#[tokio::test]
async fn admin_endpoint_requires_correct_bearer() {
    let app = build_app(AppCfg {
        default_quota: None,
        admin: true,
        grants: vec![("hub-a", "alice", "alice/a")],
    })
    .await;

    // Wrong bearer → 401.
    let st = set_quota_admin(&app, "deadbeefdeadbeefdeadbeefdeadbeef", "alice", Some(10)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Correct bearer → 204; usage endpoint reflects the new limit.
    assert_eq!(
        set_quota_admin(&app, ADMIN_BEARER, "alice", Some(10_000)).await,
        StatusCode::NO_CONTENT
    );
    let t = issue_token(&app, "hub-a", "alice/a").await.access_token;
    let (_, usage) = get_usage(&app, &t, "alice").await;
    assert_eq!(usage.unwrap().quota_bytes, Some(10_000));

    // Null limit clears the override.
    assert_eq!(
        set_quota_admin(&app, ADMIN_BEARER, "alice", None).await,
        StatusCode::NO_CONTENT
    );
    let (_, usage) = get_usage(&app, &t, "alice").await;
    assert!(usage.unwrap().quota_bytes.is_none());
}

#[tokio::test]
async fn admin_endpoint_404_when_disabled() {
    let app = build_app(AppCfg {
        default_quota: None,
        admin: false,
        grants: vec![("hub-a", "alice", "alice/a")],
    })
    .await;
    let st = set_quota_admin(&app, ADMIN_BEARER, "alice", Some(1)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cannot_view_another_owners_usage() {
    let app = build_app(AppCfg {
        default_quota: None,
        admin: false,
        grants: vec![("hub-a", "alice", "alice/a"), ("hub-b", "bob", "bob/x")],
    })
    .await;
    let t_a = issue_token(&app, "hub-a", "alice/a").await.access_token;
    let (status, _) = get_usage(&app, &t_a, "bob").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_bearer_can_view_any_owners_usage() {
    let app = build_app(AppCfg {
        default_quota: None,
        admin: true,
        grants: vec![("hub-a", "alice", "alice/a"), ("hub-b", "bob", "bob/x")],
    })
    .await;
    let t_a = issue_token(&app, "hub-a", "alice/a").await.access_token;
    let t_b = issue_token(&app, "hub-b", "bob/x").await.access_token;
    upload_file(&app, &t_a, 0x91, 256, FileHash(h(0x10)))
        .await
        .unwrap();
    upload_file(&app, &t_b, 0x92, 128, FileHash(h(0x11)))
        .await
        .unwrap();

    // Admin bearer reads both owners — that's the operator-dashboard use case.
    let (sa, alice) = get_usage(&app, ADMIN_BEARER, "alice").await;
    let (sb, bob) = get_usage(&app, ADMIN_BEARER, "bob").await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);
    assert_eq!(alice.unwrap().raw_bytes, 256);
    assert_eq!(bob.unwrap().raw_bytes, 128);

    // A bogus bearer falls through to JWT verification and fails.
    let (st, _) = get_usage(&app, "not-a-real-token", "alice").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn per_repo_usage_isolates_repos_within_one_owner() {
    // alice/a and alice/b share a chunk; the per-repo response shows each
    // repo's full raw size (no cross-repo dedup applied at the per-repo
    // display level), which is what the user asked for.
    let app = build_app(AppCfg {
        default_quota: None,
        admin: true,
        grants: vec![
            ("hub-a-a", "alice", "alice/a"),
            ("hub-a-b", "alice", "alice/b"),
        ],
    })
    .await;
    let t_a = issue_token(&app, "hub-a-a", "alice/a").await.access_token;
    let t_b = issue_token(&app, "hub-a-b", "alice/b").await.access_token;
    // alice/a: file f1 referencing chunk 0xAA (1024).
    upload_file(&app, &t_a, 0xAA, 1024, FileHash(h(0x21)))
        .await
        .unwrap();
    // alice/b: same chunk + a second chunk 0xBB (512) → raw=1536, stored=1536.
    upload_file(&app, &t_b, 0xAA, 1024, FileHash(h(0x22)))
        .await
        .unwrap();
    upload_file(&app, &t_b, 0xBB, 512, FileHash(h(0x23)))
        .await
        .unwrap();

    let (sa, ua) = get_repo_usage(&app, &t_a, "alice", "a").await;
    let (sb, ub) = get_repo_usage(&app, &t_b, "alice", "b").await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);
    let ua = ua.unwrap();
    let ub = ub.unwrap();
    assert_eq!(ua.repo_id, "alice/a");
    assert_eq!(ua.raw_bytes, 1024);
    assert_eq!(ub.repo_id, "alice/b");
    assert_eq!(ub.raw_bytes, 1024 + 512);
    assert_eq!(ub.stored_bytes, 1024 + 512);
    assert_eq!(ub.dedup_savings_bytes, 0);
}

#[tokio::test]
async fn per_repo_usage_admin_bearer_and_scope_rules() {
    let app = build_app(AppCfg {
        default_quota: None,
        admin: true,
        grants: vec![("hub-a", "alice", "alice/a"), ("hub-b", "bob", "bob/x")],
    })
    .await;
    let t_a = issue_token(&app, "hub-a", "alice/a").await.access_token;
    let t_b = issue_token(&app, "hub-b", "bob/x").await.access_token;
    upload_file(&app, &t_a, 0x31, 200, FileHash(h(0x30)))
        .await
        .unwrap();

    // Admin reads any repo, including one with no files (zeros, not 404).
    let (st, u) = get_repo_usage(&app, ADMIN_BEARER, "alice", "a").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(u.unwrap().raw_bytes, 200);
    let (st, u) = get_repo_usage(&app, ADMIN_BEARER, "alice", "never-pushed").await;
    assert_eq!(st, StatusCode::OK);
    let u = u.unwrap();
    assert_eq!(u.raw_bytes, 0);
    assert_eq!(u.stored_bytes, 0);

    // A JWT scoped to bob/x can NOT read alice's repos (403, not 404 — caller
    // can already infer the repo namespace exists from the URL).
    let (st, _) = get_repo_usage(&app, &t_b, "alice", "a").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // A missing bearer is 401.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/usage/repo/alice/a")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
