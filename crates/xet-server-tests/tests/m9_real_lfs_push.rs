//! M9: full end-to-end `git lfs push` through git-lfs → xet-lfs-adapter (Go) →
//! xet-server. Demonstrates the integration path a real GitLab/Gitea Xet
//! deployment would follow: the adapter speaks the standard LFS Batch API,
//! the xet-server is unchanged.
//!
//! Tools required on PATH (test skips with eprintln if any are missing):
//!   - `go`        (to build the adapter)
//!   - `git`       (to drive the repo)
//!   - `git-lfs`   (to trigger the batch API)
//!   - `git-xet`   (the custom transfer agent named "xet")
//!
//! Flow assembled inside the test:
//!
//!   ┌──────────────────────┐
//!   │ git lfs push --all   │   (we don't push refs; LFS objects only)
//!   └──┬───────────────────┘
//!      │ spawns
//!      ▼
//!   ┌──────────┐  /repos/{o}/{r}/objects/batch  ┌────────────────────┐
//!   │  git-lfs │───────────────────────────────▶│ xet-lfs-adapter    │ (Go)
//!   └────┬─────┘                                └────────┬───────────┘
//!        │                                               │ forwards PAT to
//!        │ transfer=xet, action.header=X-Xet-*           │ /api/.../xet-write-token/main
//!        ▼                                               ▼
//!   ┌──────────┐  stdin/stdout JSON   ┌─────────────────────────────────┐
//!   │ git-xet  │─────────────────────▶│         xet-server (Rust)       │
//!   └──────────┘  uploads via HTTP    │  authz-http checks PAT upstream │
//!                                     └──────────────┬──────────────────┘
//!                                                    │ POST /check_access
//!                                                    ▼
//!                                          ┌────────────────────┐
//!                                          │ mock PAT verifier  │ (axum)
//!                                          └────────────────────┘

mod common;
use common::*;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use xet_server_authz_http::HttpAuthz;
use xet_server_http::{router as xet_router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn git_push_through_lfs_adapter_to_xet_server() {
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

    // ---- LFS adapter ------------------------------------------------------
    let adapter = spawn_adapter(&adapter_bin, &xet_url);

    // ---- Working git repo -------------------------------------------------
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

    // ~300 KiB of deterministic non-trivial bytes — enough for CDC to make
    // multiple chunks per xorb.
    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    std::fs::write(work.join("big.bin"), &payload).unwrap();
    run_git(&work, &["add", "big.bin"]);
    run_git(&work, &["commit", "-q", "-m", "add big.bin"]);

    // `git lfs push` pushes only the LFS-tracked objects (not the git refs)
    // to `lfs.url`. Failure here means the LFS chain broke somewhere:
    // batch API → adapter → xet-server token endpoint → git-xet → CAS upload.
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

    // ---- Verify the bytes actually made it to xet-server ------------------
    let n_xorbs = meta.count_xorbs().await.unwrap();
    let n_files = meta.count_files().await.unwrap();
    assert!(n_xorbs > 0, "expected at least one xorb registered");
    assert!(n_files > 0, "expected at least one file registered");

    // Best-effort cleanup. The Drop on `adapter` kills its child; the xet
    // task is detached and dies with the runtime.
    drop(adapter);
    xet_handle.abort();

    // Touch the tempdirs / build_dir so the compiler doesn't drop them early.
    let _ = (data_dir, work_root, build_dir);
    // Give children a moment to settle so background reaper doesn't race the
    // test runner shutting down.
    tokio::time::sleep(Duration::from_millis(50)).await;
}
