//! M11: end-to-end push and pull through the native `git-dfs` filter — no
//! git-lfs, no Go adapter, no whole-file local cache. The flow under test:
//!
//! ```text
//!   git add → filter.dfs.process (long-running) ─▶ git-dfs filter-process
//!                                                  │ chunk (CDC)
//!                                                  │ upload xorbs + shard
//!                                                  ▼ via HTTP
//!                                          ┌──────────────────────────┐
//!                                          │   xet-server (Rust)      │
//!                                          └─────────────┬────────────┘
//!                                                        ▲
//!   git checkout → filter.dfs.process (smudge) ──────────┘ download by file_id
//!                                                          (chunks land in
//!                                                           ~/.cache/dfs/chunks
//!                                                           — shared across repos)
//! ```
//!
//! Skipped (with eprintln) when any of `git` or `cargo` isn't on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use xet_server_authz_mem::AlwaysAllow;
use xet_server_http::{router as xet_router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;

/// Increments `recon_hits` for every request whose path starts with
/// `/v1/reconstructions/`. The hot smudge path is asserted to be a no-op
/// against this counter.
async fn count_recon_hits(
    State(recon_hits): State<Arc<AtomicUsize>>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path().starts_with("/v1/reconstructions/") {
        recon_hits.fetch_add(1, Ordering::Relaxed);
    }
    next.run(req).await
}

fn tool_on_path(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git invocation");
    assert!(
        out.status.success(),
        "git {args:?} in {} failed:\nstdout:\n{}\nstderr:\n{}",
        repo.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn build_git_dfs() -> PathBuf {
    let root = workspace_root();
    let out = Command::new("cargo")
        .args(["build", "-p", "git-dfs", "--quiet"])
        .current_dir(&root)
        .output()
        .expect("cargo build -p git-dfs");
    assert!(
        out.status.success(),
        "cargo build -p git-dfs failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    root.join("target").join("debug").join("git-dfs")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_filter_push_then_pull() {
    for tool in ["git", "cargo"] {
        if !tool_on_path(tool) {
            eprintln!("skipping: `{tool}` not on PATH");
            return;
        }
    }
    let git_dfs_bin = build_git_dfs();
    if !git_dfs_bin.is_file() {
        eprintln!(
            "skipping: built binary not found at {}",
            git_dfs_bin.display()
        );
        return;
    }

    // ---- xet-server stack -------------------------------------------------
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
        authz: Arc::new(AlwaysAllow),
        transfer_secret: [0x55u8; 32],
        public_base_url: xet_url.clone(),
    };
    // Counter so the test can assert that the hot path (after a manifest is
    // cached in `.git/dfs/manifests/` *and* every chunk is in the local
    // chunk cache) makes zero requests to `/v1/reconstructions/`.
    let recon_hits = Arc::new(AtomicUsize::new(0));
    let app = xet_router(svc).layer(from_fn_with_state(recon_hits.clone(), count_recon_hits));
    let xet_handle = tokio::spawn(async move { axum::serve(xet_listener, app).await });

    // ---- Working repo + git-dfs install ----------------------------------
    let work_root = tempfile::tempdir().unwrap();
    let work = work_root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let cache_root = work_root.path().join("dfs-cache");
    std::fs::create_dir_all(&cache_root).unwrap();

    run_git(&work, &["init", "-q", "-b", "main", "."]);
    run_git(&work, &["config", "user.email", "alice@test.invalid"]);
    run_git(&work, &["config", "user.name", "alice"]);

    // Wire git-dfs as the dfs filter driver using the absolute path to the
    // built binary; PATH might not include `target/debug`.
    let filter_cmd = format!("{} filter-process", git_dfs_bin.display());
    run_git(
        &work,
        &["config", "--local", "filter.dfs.process", &filter_cmd],
    );
    run_git(&work, &["config", "--local", "filter.dfs.required", "true"]);
    run_git(&work, &["config", "--local", "dfs.serverUrl", &xet_url]);
    run_git(&work, &["config", "--local", "dfs.token", "test"]);
    run_git(
        &work,
        &[
            "config",
            "--local",
            "dfs.cacheDir",
            cache_root.to_str().unwrap(),
        ],
    );

    std::fs::write(work.join(".gitattributes"), "*.bin filter=dfs -text\n").unwrap();
    run_git(&work, &["add", ".gitattributes"]);
    run_git(&work, &["commit", "-q", "-m", "enable dfs filter"]);

    // ~300 KiB of deterministic non-trivial bytes — enough for CDC to make
    // multiple chunks per xorb.
    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let big_path = work.join("big.bin");
    std::fs::write(&big_path, &payload).unwrap();
    run_git(&work, &["add", "big.bin"]);
    run_git(&work, &["commit", "-q", "-m", "add big.bin via dfs filter"]);

    // ---- Confirm the staged blob is the JSON pointer (not the raw file) --
    let out = Command::new("git")
        .args(["cat-file", "-p", "HEAD:big.bin"])
        .current_dir(&work)
        .output()
        .expect("git cat-file");
    assert!(out.status.success(), "git cat-file failed");
    let blob = String::from_utf8(out.stdout).expect("non-utf8 pointer");
    assert!(
        blob.contains("\"hash\""),
        "expected JSON pointer with `hash` key, got:\n{blob}"
    );
    assert!(
        blob.starts_with('{') && blob.trim_end().ends_with('}'),
        "expected JSON object, got:\n{blob}"
    );
    assert!(
        blob.contains("\"file_size\""),
        "expected file_size key:\n{blob}"
    );

    // ---- Confirm the bytes landed on the server --------------------------
    let n_xorbs = meta.count_xorbs().await.unwrap();
    let n_files = meta.count_files().await.unwrap();
    assert!(n_xorbs > 0, "expected at least one xorb registered");
    assert!(n_files > 0, "expected at least one file registered");

    // ---- Force a smudge round-trip: wipe the worktree file and the chunk
    // ---- cache, then re-check out HEAD. The bytes must come from the server.
    std::fs::remove_file(&big_path).unwrap();
    // Clear the shared chunk cache so the smudge path has to hit the server.
    if cache_root.exists() {
        std::fs::remove_dir_all(&cache_root).unwrap();
        std::fs::create_dir_all(&cache_root).unwrap();
    }
    // Also wipe `.git/dfs/manifests/` so the first smudge truly cold-paths
    // through xet-data and exercises the manifest-save side effect.
    let manifests_dir = work.join(".git").join("dfs").join("manifests");
    if manifests_dir.exists() {
        std::fs::remove_dir_all(&manifests_dir).unwrap();
    }
    let cold_recon_before = recon_hits.load(Ordering::Relaxed);
    run_git(&work, &["checkout", "--", "big.bin"]);
    let cold_recon_after = recon_hits.load(Ordering::Relaxed);
    assert!(
        cold_recon_after > cold_recon_before,
        "expected the cold smudge to hit /v1/reconstructions/ at least once"
    );

    let recovered = std::fs::read(&big_path).expect("worktree file reconstructed");
    assert_eq!(
        recovered.len(),
        payload.len(),
        "size mismatch on reconstruct"
    );
    assert_eq!(recovered, payload, "content mismatch on reconstruct");

    // ---- Cold path must have saved a manifest under `.git/dfs/manifests/`.
    let manifest_files: Vec<_> = std::fs::read_dir(&manifests_dir)
        .expect("manifests dir should exist after cold smudge")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        manifest_files.len(),
        1,
        "expected exactly one cached manifest, found: {manifest_files:?}"
    );
    let manifest_blob = std::fs::read(&manifest_files[0]).unwrap();
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest_blob).expect("manifest is JSON");
    assert!(
        manifest_json
            .get("terms")
            .and_then(|t| t.as_array())
            .is_some(),
        "manifest should contain a non-null `terms` array: {manifest_json}"
    );

    // ---- Hot path: chunks already cached, manifest cached. Second smudge
    // ---- must reconstruct without calling `/v1/reconstructions/` at all.
    std::fs::remove_file(&big_path).unwrap();
    let hot_recon_before = recon_hits.load(Ordering::Relaxed);
    run_git(&work, &["checkout", "--", "big.bin"]);
    let hot_recon_after = recon_hits.load(Ordering::Relaxed);
    assert_eq!(
        hot_recon_before, hot_recon_after,
        "hot smudge should not hit /v1/reconstructions/ (before={hot_recon_before}, after={hot_recon_after})"
    );
    let recovered_hot = std::fs::read(&big_path).expect("worktree file reconstructed (hot)");
    assert_eq!(
        recovered_hot, payload,
        "content mismatch on hot-path reconstruct"
    );

    // ---- And verify there is NO `.git/lfs/` directory anywhere -----------
    let lfs_dir = work.join(".git").join("lfs");
    assert!(
        !lfs_dir.exists(),
        "unexpected .git/lfs directory; the LFS path should not be involved"
    );

    // ---- Cleanup ---------------------------------------------------------
    xet_handle.abort();
    let _ = (data_dir, work_root);
    tokio::time::sleep(Duration::from_millis(50)).await;
}
