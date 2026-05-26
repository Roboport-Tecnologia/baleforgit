//! End-to-end `git lfs pull` through git-lfs → bale-lfs-adapter (Go) → baleforgit-server.
//! Pushes a file, wipes the local LFS cache + worktree, then pulls and verifies
//! the bytes round-trip. Skips silently if any of {go, git, git-lfs, git-xet}
//! isn't on PATH.

mod common;
use common::*;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use bale_server_authz_http::HttpAuthz;
use bale_server_core::{Hash32, MetadataStore};
use bale_server_http::{router as xet_router, Service};
use bale_server_meta_sqlite::SqliteMetadataStore;
use bale_server_storage_fs::FsBlobStore;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn git_pull_through_lfs_adapter_to_bale_server() {
    for tool in ["go", "git", "git-lfs", "git-xet"] {
        if !tool_on_path(tool) {
            eprintln!("skipping: `{tool}` not on PATH");
            return;
        }
    }

    let build_dir = tempfile::tempdir().unwrap();
    let adapter_bin = build_adapter(build_dir.path()).expect("lfs-adapter source missing");

    let verifier_url = spawn_verifier().await;
    let authz = HttpAuthz::new(&verifier_url, JWT_SECRET.to_vec()).unwrap();

    let data_dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(
        FsBlobStore::open(data_dir.path().join("blobs"))
            .await
            .unwrap(),
    );
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());

    let xet_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let xet_addr = xet_listener.local_addr().unwrap();
    let xet_url = format!("http://{xet_addr}");

    let svc = Service {
        blobs,
        meta: meta.clone(),
        authz: Arc::new(authz),
        transfer_secret: [0x55u8; 32],
        public_base_url: xet_url.clone(),
    };
    let app = xet_router(svc);
    let xet_handle = tokio::spawn(async move { axum::serve(xet_listener, app).await });

    let adapter = spawn_adapter(&adapter_bin, &xet_url);

    let work_root = tempfile::tempdir().unwrap();
    let work = work_root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    init_lfs_workrepo(&work, &adapter.base_url);

    let out = Command::new("git")
        .args(["lfs", "track", "*.bin"])
        .current_dir(&work)
        .output()
        .expect("git lfs track");
    assert!(out.status.success());
    run_git(&work, &["add", ".gitattributes"]);
    run_git(&work, &["commit", "-q", "-m", "track .bin via lfs"]);

    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let big_path = work.join("big.bin");
    std::fs::write(&big_path, &payload).unwrap();
    run_git(&work, &["add", "big.bin"]);
    run_git(&work, &["commit", "-q", "-m", "add big.bin"]);

    let out = Command::new("git")
        .args(["lfs", "push", "--all", "origin"])
        .current_dir(&work)
        .output()
        .expect("git lfs push");
    assert!(
        out.status.success(),
        "git lfs push failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // If this fails the upload/storage path is broken; if it passes the bug
    // is downstream (adapter reconstruction request or byte streaming).
    let oid: [u8; 32] = Sha256::digest(&payload).into();
    let oid_hex = hex::encode(oid);
    let hit = meta
        .lookup_file_by_sha256(&Hash32(oid))
        .await
        .expect("lookup_file_by_sha256");
    assert!(
        hit.is_some(),
        "expected file with sha256 {oid_hex} after push, got None"
    );

    // Wipe LFS object cache AND worktree file so checkout must hit the server.
    let lfs_cache = work.join(".git/lfs/objects");
    if lfs_cache.exists() {
        std::fs::remove_dir_all(&lfs_cache).unwrap();
    }
    std::fs::remove_file(&big_path).unwrap();

    let out = Command::new("git")
        .args(["lfs", "pull", "origin"])
        .current_dir(&work)
        .output()
        .expect("git lfs pull");
    assert!(
        out.status.success(),
        "git lfs pull failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let pulled = std::fs::read(&big_path).expect("big.bin re-checked out");
    assert_eq!(
        pulled.len(),
        payload.len(),
        "pulled file size {} differs from pushed {}",
        pulled.len(),
        payload.len(),
    );
    assert_eq!(
        pulled, payload,
        "pulled file bytes differ from originally pushed bytes"
    );

    drop(adapter);
    xet_handle.abort();
    let _ = (data_dir, work_root, build_dir);
    tokio::time::sleep(Duration::from_millis(50)).await;
}
