//! End-to-end push + pull through the native `git-bale` filter (no git-lfs, no
//! Go adapter). Skips silently when `git` or `cargo` isn't on PATH, or when
//! `cargo build -p git-bale` fails (which happens on CI where the xet-core
//! sibling clone isn't pulled and git-bale has been dropped from the workspace).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use bale_server_authz_mem::AlwaysAllow;
use bale_server_http::{router as xet_router, Service};
use bale_server_meta_sqlite::SqliteMetadataStore;
use bale_server_storage_fs::FsBlobStore;

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

/// Recursively walks `staging_dir` and returns any files named like xorbs
/// (`default.<hex>`) or shards (`<hex>.mdb`) that survived push-pending. A
/// `Vec<_>` of leftover paths is easier to debug than a bare `is_empty`.
fn staging_files_remaining(staging_dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                walk(&path, out);
            } else if ft.is_file() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    let is_xorb = name.strip_prefix("default.").is_some_and(is_64_lower_hex);
                    let is_shard = name.strip_suffix(".mdb").is_some_and(is_64_lower_hex);
                    if is_xorb || is_shard {
                        out.push(path);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    if staging_dir.exists() {
        walk(staging_dir, &mut out);
    }
    out
}

fn is_64_lower_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn build_git_bale() -> Option<PathBuf> {
    let root = workspace_root();
    let out = Command::new("cargo")
        .args(["build", "-p", "git-bale", "--quiet"])
        .current_dir(&root)
        .output()
        .ok()?;
    if !out.status.success() {
        // CI deliberately doesn't pull the xet-core sibling and removes the
        // git-bale workspace member, so this is expected there.
        eprintln!(
            "skipping: `cargo build -p git-bale` failed (xet-core sibling clone \
             missing or git-bale dropped from workspace):\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr),
        );
        return None;
    }
    Some(root.join("target").join("debug").join("git-bale"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_filter_push_then_pull() {
    for tool in ["git", "cargo"] {
        if !tool_on_path(tool) {
            eprintln!("skipping: `{tool}` not on PATH");
            return;
        }
    }
    let git_bale_bin = match build_git_bale() {
        Some(p) => p,
        None => return,
    };
    if !git_bale_bin.is_file() {
        eprintln!(
            "skipping: built binary not found at {}",
            git_bale_bin.display()
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
        default_quota_bytes: None,
        admin_token: None,
    };
    // The hot path (manifest in .git/bale/manifests/ + chunks in local cache)
    // must make zero requests to /v1/reconstructions/.
    let recon_hits = Arc::new(AtomicUsize::new(0));
    let app = xet_router(svc).layer(from_fn_with_state(recon_hits.clone(), count_recon_hits));
    let xet_handle = tokio::spawn(async move { axum::serve(xet_listener, app).await });

    let work_root = tempfile::tempdir().unwrap();
    let work = work_root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let cache_root = work_root.path().join("bale-cache");
    std::fs::create_dir_all(&cache_root).unwrap();

    run_git(&work, &["init", "-q", "-b", "main", "."]);
    run_git(&work, &["config", "user.email", "alice@test.invalid"]);
    run_git(&work, &["config", "user.name", "alice"]);

    // Use absolute path: PATH might not include `target/debug`.
    let filter_cmd = format!("{} filter-process", git_bale_bin.display());
    run_git(
        &work,
        &["config", "--local", "filter.bale.process", &filter_cmd],
    );
    run_git(
        &work,
        &["config", "--local", "filter.bale.required", "true"],
    );
    run_git(&work, &["config", "--local", "bale.serverUrl", &xet_url]);
    run_git(&work, &["config", "--local", "bale.token", "test"]);
    run_git(
        &work,
        &[
            "config",
            "--local",
            "bale.cacheDir",
            cache_root.to_str().unwrap(),
        ],
    );

    std::fs::write(work.join(".gitattributes"), "*.bin filter=bale -text\n").unwrap();
    run_git(&work, &["add", ".gitattributes"]);
    run_git(&work, &["commit", "-q", "-m", "enable bale filter"]);

    // ~300 KiB so CDC produces multiple chunks per xorb.
    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let big_path = work.join("big.bin");
    std::fs::write(&big_path, &payload).unwrap();
    run_git(&work, &["add", "big.bin"]);
    run_git(
        &work,
        &["commit", "-q", "-m", "add big.bin via bale filter"],
    );

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

    // Defer-uploads contract: `git add` writes to <git_dir>/bale/staging/ and
    // does NOT touch the server. The actual upload happens at `push-pending`.
    let staging_dir = work.join(".git").join("bale").join("staging");
    assert!(
        staging_dir.exists(),
        "expected staging dir at {} after `git add`",
        staging_dir.display()
    );

    // Pointer cache: the clean filter persists `<git_dir>/bale/clean-cache/
    // <blake3>` and short-circuits future clean calls for the same content.
    // After the first `git add` there must be at least one entry.
    let cache_dir = work.join(".git").join("bale").join("clean-cache");
    let cache_entries_after_add: Vec<_> = std::fs::read_dir(&cache_dir)
        .expect("clean-cache dir should exist after `git add`")
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(is_64_lower_hex)
        })
        .collect();
    assert!(
        !cache_entries_after_add.is_empty(),
        "expected at least one clean-cache entry after `git add big.bin`"
    );

    // Cache entries are now path-keyed with a chunked verification index.
    // The JSON shape must carry: a version field, a size matching `payload`,
    // and a non-empty `chunks` array with hex hashes.
    let cache_blob = std::fs::read(&cache_entries_after_add[0]).unwrap();
    let cache_json: serde_json::Value =
        serde_json::from_slice(&cache_blob).expect("cache entry is JSON");
    assert_eq!(
        cache_json.get("v").and_then(|v| v.as_u64()),
        Some(3),
        "expected schema v=3"
    );
    assert_eq!(
        cache_json.get("size").and_then(|s| s.as_u64()),
        Some(payload.len() as u64),
        "size field must match the cleaned file"
    );
    let chunks = cache_json
        .get("chunks")
        .and_then(|c| c.as_array())
        .expect("chunks array");
    assert!(!chunks.is_empty(), "chunk list must be non-empty");
    for c in chunks {
        let hash = c.get("hash").and_then(|h| h.as_str()).unwrap();
        assert_eq!(hash.len(), 16, "hash must be 16 hex chars (xxh3-64)");
        assert!(c.get("start").and_then(|x| x.as_u64()).is_some());
        assert!(c.get("end").and_then(|x| x.as_u64()).is_some());
    }

    // Force a second clean of the same content (via re-add) — should be a
    // cache hit, so no new staged xorbs or shards land beyond what's already
    // there. We capture the staging snapshot, re-touch the file's mtime to
    // make git re-run the filter, and re-add. The post-add staging snapshot
    // must be identical to the pre-add one.
    let staging_before_recean = staging_files_remaining(&staging_dir);
    run_git(&work, &["update-index", "--again"]);
    // `update-index --again` may or may not re-run the filter depending on
    // stat caching; the more reliable trigger is to overwrite the worktree
    // file with the same bytes (which bumps mtime) and `git add` it again.
    std::fs::write(&big_path, &payload).unwrap();
    run_git(&work, &["add", "big.bin"]);
    let staging_after_reclean = staging_files_remaining(&staging_dir);
    assert_eq!(
        staging_before_recean, staging_after_reclean,
        "second clean of identical content should hit the pointer cache and not re-stage"
    );
    assert!(
        meta.count_xorbs().await.unwrap() == 0,
        "no xorbs should be on the server before push-pending"
    );
    assert!(
        meta.count_files().await.unwrap() == 0,
        "no files should be on the server before push-pending"
    );

    // Smudge fallback: before push-pending, wiping the worktree and
    // `git checkout --` must reconstruct from staging without hitting the
    // network. The recon counter must not advance.
    std::fs::remove_file(&big_path).unwrap();
    let pre_push_recon_before = recon_hits.load(Ordering::Relaxed);
    run_git(&work, &["checkout", "--", "big.bin"]);
    let pre_push_recon_after = recon_hits.load(Ordering::Relaxed);
    assert_eq!(
        pre_push_recon_before, pre_push_recon_after,
        "pre-push smudge should reconstruct from staging, not /v1/reconstructions/"
    );
    let from_staging = std::fs::read(&big_path).expect("worktree reconstructed from staging");
    assert_eq!(
        from_staging, payload,
        "content mismatch on staging-only reconstruct"
    );

    // Run push-pending. Server should now have the xorbs/shards, and staging
    // should be drained.
    let push_out = Command::new(&git_bale_bin)
        .arg("push-pending")
        .current_dir(&work)
        .output()
        .expect("git-bale push-pending");
    assert!(
        push_out.status.success(),
        "`git-bale push-pending` failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&push_out.stdout),
        String::from_utf8_lossy(&push_out.stderr),
    );
    let n_xorbs = meta.count_xorbs().await.unwrap();
    let n_files = meta.count_files().await.unwrap();
    assert!(
        n_xorbs > 0,
        "expected at least one xorb registered after push-pending"
    );
    assert!(
        n_files > 0,
        "expected at least one file registered after push-pending"
    );
    assert!(
        staging_files_remaining(&staging_dir).is_empty(),
        "push-pending should have drained staging; leftover: {:?}",
        staging_files_remaining(&staging_dir)
    );
    assert!(
        !staging_dir.join("file-index").exists(),
        "push-pending should have removed the file-index/ markers"
    );

    // Force a cold smudge: wipe worktree file, shared chunk cache, and the
    // .git/bale/manifests/ dir (so the manifest-save side effect is exercised).
    std::fs::remove_file(&big_path).unwrap();
    if cache_root.exists() {
        std::fs::remove_dir_all(&cache_root).unwrap();
        std::fs::create_dir_all(&cache_root).unwrap();
    }
    let manifests_dir = work.join(".git").join("bale").join("manifests");
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

    // Cold path must have saved a manifest under .git/bale/manifests/.
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
