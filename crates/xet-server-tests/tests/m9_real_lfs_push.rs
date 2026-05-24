//! M9: full end-to-end `git push` through git-lfs → xet-lfs-adapter (Go) →
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

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes as AxumBytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use xet_server_authz_http::HttpAuthz;
use xet_server_core::Scope;
use xet_server_http::{router as xet_router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;

const JWT_SECRET: &[u8; 32] = b"01234567890123456789012345678901";
const HUB_PAT: &str = "platform-pat-for-alice";
const REPO_OWNER: &str = "alice";
const REPO_NAME: &str = "demo";

fn tool_on_path(name: &str) -> bool {
    // Different tools use different "give me your version" CLIs (`go version`
    // vs `git --version` vs `git-xet --version`). Use `command -v` via the
    // shell so we only check existence, not invocation conventions.
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

// ---- Mock PAT verifier (stand-in for GitLab/Gitea repo authority) ----------

#[derive(Clone)]
struct VerifierState {
    grants: Arc<Vec<(String, String, String, Scope)>>,
}

async fn check_access(
    State(s): State<VerifierState>,
    body: AxumBytes,
) -> Result<(StatusCode, String), StatusCode> {
    #[derive(serde::Deserialize)]
    struct Req {
        hub_bearer: String,
        repo: xet_server_core::RepoRef,
        scope: Scope,
    }
    let req: Req = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    for (pat, user, repo_id, granted) in s.grants.iter() {
        if pat == &req.hub_bearer && repo_id == &req.repo.repo_id {
            if matches!(req.scope, Scope::Write) && matches!(granted, Scope::Read) {
                return Err(StatusCode::FORBIDDEN);
            }
            return Ok((StatusCode::OK, format!(r#"{{"user_id":"{user}"}}"#)));
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

async fn spawn_verifier() -> String {
    let state = VerifierState {
        grants: Arc::new(vec![(
            HUB_PAT.into(),
            "alice".into(),
            format!("{REPO_OWNER}/{REPO_NAME}"),
            Scope::Write,
        )]),
    };
    let app = Router::new()
        .route("/check_access", post(check_access))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

// ---- Adapter binary management ---------------------------------------------

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the test crate; the workspace is two levels up.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn build_adapter(out_dir: &Path) -> Option<PathBuf> {
    let root = workspace_root();
    let src = root.join("lfs-adapter");
    if !src.exists() {
        return None;
    }
    let bin = out_dir.join("xet-lfs-adapter");
    let out = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./...")
        .current_dir(&src)
        .output()
        .expect("invoke go build");
    if !out.status.success() {
        panic!(
            "go build failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Some(bin)
}

struct AdapterProcess {
    child: Child,
    base_url: String,
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_adapter(bin: &Path, xet_server: &str) -> AdapterProcess {
    let mut child = Command::new(bin)
        .args(["--listen", "127.0.0.1:0", "--xet-server", xet_server])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xet-lfs-adapter");

    // First stdout line is "xet-lfs-adapter listening on http://host:port".
    let stdout = child.stdout.take().expect("stdout pipe");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read adapter stdout");
    let base_url = line
        .trim()
        .strip_prefix("xet-lfs-adapter listening on ")
        .expect("unexpected adapter stdout")
        .to_string();

    // Drain remaining stdout in a background thread so the child doesn't
    // block on a full pipe.
    std::thread::spawn(move || {
        let mut sink = reader;
        let mut buf = [0u8; 4096];
        loop {
            match sink.read(&mut buf) {
                Ok(0) | Err(_) => break,
                _ => continue,
            }
        }
    });
    // Same for stderr.
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut sink = stderr;
            let mut buf = [0u8; 4096];
            loop {
                match sink.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    _ => continue,
                }
            }
        });
    }

    AdapterProcess { child, base_url }
}

// ---- The test --------------------------------------------------------------

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

    // ---- Bare + working git repos ----------------------------------------
    let work_root = tempfile::tempdir().unwrap();
    let work = work_root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    run_git(&work, &["init", "-q", "-b", "main", "."]);
    run_git(&work, &["config", "user.email", "alice@test.invalid"]);
    run_git(&work, &["config", "user.name", "alice"]);

    // Remote URL must be http(s)/ssh for git-xet to be willing to derive an
    // auth host from it — it rejects file://. The URL doesn't need to be
    // reachable: we only invoke `git lfs push`, which sends to `lfs.url`
    // (the adapter), not to the remote itself. URL-embedded credentials
    // become Basic auth on the wire and the adapter translates them to
    // Bearer for the xet-server token endpoint.
    let adapter_host = adapter
        .base_url
        .strip_prefix("http://")
        .expect("adapter base_url shape");
    let remote_url =
        format!("http://token:{HUB_PAT}@{adapter_host}/repos/{REPO_OWNER}/{REPO_NAME}");
    run_git(&work, &["remote", "add", "origin", &remote_url]);
    run_git(&work, &["config", "--local", "lfs.url", &remote_url]);

    // Install LFS hooks into this repo's .git/hooks and register the xet
    // transfer agent locally. `git lfs install --local` writes the smudge /
    // pre-push filters into .git/config.
    let out = Command::new("git")
        .args(["lfs", "install", "--local"])
        .current_dir(&work)
        .output()
        .expect("git lfs install");
    assert!(
        out.status.success(),
        "git lfs install:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    run_git(
        &work,
        &[
            "config",
            "--local",
            "lfs.customtransfer.xet.path",
            "git-xet",
        ],
    );
    run_git(
        &work,
        &[
            "config",
            "--local",
            "lfs.customtransfer.xet.args",
            "transfer",
        ],
    );
    run_git(
        &work,
        &[
            "config",
            "--local",
            "lfs.customtransfer.xet.concurrent",
            "true",
        ],
    );
    // Disable LFS locking probes (some git-lfs builds otherwise hit the
    // adapter for /locks/verify, which we don't implement).
    run_git(&work, &["config", "--local", "lfs.locksverify", "false"]);

    // Track *.bin via LFS.
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
    let mut push = Command::new("git");
    push.args(["lfs", "push", "--all", "origin"])
        .current_dir(&work);
    let out = push.output().expect("git lfs push");
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
