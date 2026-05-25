//! End-to-end push + pull through the native `git-dfs` filter (no git-lfs, no
//! Go adapter). Skips silently when `git` or `cargo` isn't on PATH.

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

/// Counts hits on `/v1/reconstructions/*`. The hot smudge path must not
/// increment this counter.
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
    // The hot path (manifest in .git/dfs/manifests/ + chunks in local cache)
    // must make zero requests to /v1/reconstructions/.
    let recon_hits = Arc::new(AtomicUsize::new(0));
    let app = xet_router(svc).layer(from_fn_with_state(recon_hits.clone(), count_recon_hits));
    let xet_handle = tokio::spawn(async move { axum::serve(xet_listener, app).await });

    let work_root = tempfile::tempdir().unwrap();
    let work = work_root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let cache_root = work_root.path().join("dfs-cache");
    std::fs::create_dir_all(&cache_root).unwrap();

    run_git(&work, &["init", "-q", "-b", "main", "."]);
    run_git(&work, &["config", "user.email", "alice@test.invalid"]);
    run_git(&work, &["config", "user.name", "alice"]);

    // Use absolute path: PATH might not include `target/debug`.
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

    // ~300 KiB so CDC produces multiple chunks per xorb.
    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let big_path = work.join("big.bin");
    std::fs::write(&big_path, &payload).unwrap();
    run_git(&work, &["add", "big.bin"]);
    run_git(&work, &["commit", "-q", "-m", "add big.bin via dfs filter"]);

    // Staged blob must be the JSON pointer, not the raw file.
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

    let n_xorbs = meta.count_xorbs().await.unwrap();
    let n_files = meta.count_files().await.unwrap();
    assert!(n_xorbs > 0, "expected at least one xorb registered");
    assert!(n_files > 0, "expected at least one file registered");

    // Force a cold smudge: wipe worktree file, shared chunk cache, and the
    // .git/dfs/manifests/ dir (so the manifest-save side effect is exercised).
    std::fs::remove_file(&big_path).unwrap();
    if cache_root.exists() {
        std::fs::remove_dir_all(&cache_root).unwrap();
        std::fs::create_dir_all(&cache_root).unwrap();
    }
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

    // Cold path must have saved a manifest under .git/dfs/manifests/.
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

    // Hot path: with chunks + manifest cached, second smudge must reconstruct
    // without calling /v1/reconstructions/.
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

    let lfs_dir = work.join(".git").join("lfs");
    assert!(
        !lfs_dir.exists(),
        "unexpected .git/lfs directory; the LFS path should not be involved"
    );

    xet_handle.abort();
    let _ = (data_dir, work_root);
    tokio::time::sleep(Duration::from_millis(50)).await;
}
