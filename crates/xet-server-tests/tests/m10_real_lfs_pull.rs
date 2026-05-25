//! M10: full end-to-end `git lfs pull` through git-lfs → xet-lfs-adapter (Go)
//! → xet-server. The companion download test to M9.
//!
//! Flow:
//!   1. Push a known file via the same path m9 exercises.
//!   2. Wipe the local lfs object cache and the working-tree file, so the
//!      next checkout has nothing to read from.
//!   3. Run `git lfs pull`, which triggers a batch (operation=download) call.
//!      The adapter advertises `transfer="basic"` with a per-object download
//!      URL pointing back at itself; git-lfs follows that URL and the adapter
//!      streams the file's bytes by querying xet-server's by-sha256
//!      reconstruction endpoint and decoding chunk frames on the fly.
//!   4. Read big.bin and assert it byte-matches the original payload.
//!
//! Tools required on PATH (test skips with eprintln if any are missing):
//!   - `go`, `git`, `git-lfs`, `git-xet`

mod common;
use common::*;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use xet_server_authz_http::HttpAuthz;
use xet_server_core::{Hash32, MetadataStore};
use xet_server_http::{router as xet_router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn git_pull_through_lfs_adapter_to_xet_server() {
    for tool in ["go", "git", "git-lfs", "git-xet"] {
        if !tool_on_path(tool) {
            eprintln!("skipping: `{tool}` not on PATH");
            return;
        }
    }

    let build_dir = tempfile::tempdir().unwrap();
    let adapter_bin = build_adapter(build_dir.path()).expect("lfs-adapter source missing");

    // ---- xet-server stack -------------------------------------------------
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

    // ---- Working git repo + initial push ---------------------------------
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

    // Same deterministic ~300 KiB payload as m9.
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

    // Sanity check: xet-server's metadata layer must know the file by its
    // sha256 OID. If this fails the bug is in the upload/storage path; if it
    // passes the bug is downstream (the adapter's reconstruction request or
    // its byte-streaming logic).
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

    // ---- Wipe local cache and force a re-download ------------------------
    // .git/lfs/objects/ is the LFS object cache. Delete it AND the worktree
    // file so the checkout must call out to the LFS server.
    let lfs_cache = work.join(".git/lfs/objects");
    if lfs_cache.exists() {
        std::fs::remove_dir_all(&lfs_cache).unwrap();
    }
    std::fs::remove_file(&big_path).unwrap();

    // `git lfs pull` = `git lfs fetch && git lfs checkout`. Fetch hits the
    // batch API with operation=download → adapter returns transfer=basic with
    // a download URL pointing at itself → git-lfs GETs that URL → adapter
    // streams bytes from xet-server.
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

    // ---- Byte-for-byte verification --------------------------------------
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
