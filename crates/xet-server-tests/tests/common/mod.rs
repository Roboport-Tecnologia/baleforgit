//! Shared scaffolding for the m9 (push) and m10 (pull) integration tests.
//!
//! Cargo treats every file in `tests/` as a separate binary, so we put the
//! reusable bits in `tests/common/mod.rs` and pull them in with `mod common;`
//! from each test file. Putting them in a submodule (not a top-level test
//! file) keeps Cargo from compiling them as a standalone test binary.

#![allow(dead_code)] // each test only uses a subset of these helpers

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use axum::body::Bytes as AxumBytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use xet_server_core::Scope;

pub const JWT_SECRET: &[u8; 32] = b"01234567890123456789012345678901";
pub const HUB_PAT: &str = "platform-pat-for-alice";
pub const REPO_OWNER: &str = "alice";
pub const REPO_NAME: &str = "demo";

pub fn tool_on_path(name: &str) -> bool {
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

pub fn run_git(repo: &Path, args: &[&str]) {
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

// ---- Mock PAT verifier (stand-in for the upstream repo authority) -----------

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

/// Spawn the in-process PAT-verifier mock and return its base URL. The single
/// granted PAT is [`HUB_PAT`] with write scope on `{REPO_OWNER}/{REPO_NAME}`.
pub async fn spawn_verifier() -> String {
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

pub fn build_adapter(out_dir: &Path) -> Option<PathBuf> {
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

pub struct AdapterProcess {
    child: Child,
    pub base_url: String,
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn spawn_adapter(bin: &Path, xet_server: &str) -> AdapterProcess {
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

    // Forward remaining stdout / stderr to the parent's stderr in background
    // threads. Cargo captures these unless `--nocapture` is passed; on failure
    // the captured output gets printed under the test name, which is what we
    // want when debugging the adapter from inside a Rust integration test.
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut sink = reader;
        let mut buf = [0u8; 4096];
        loop {
            match sink.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => eprint!("[adapter stdout] {}", String::from_utf8_lossy(&buf[..n])),
            }
        }
    });
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stderr.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => eprint!("[adapter stderr] {}", String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }

    AdapterProcess { child, base_url }
}

/// Initialise an empty git working repo at `work` and configure it to drive
/// LFS through the adapter:
///   - origin remote set to a synthetic http://token:PAT@... URL pointing at
///     the adapter (git-xet rejects file:// schemes when deriving auth hosts)
///   - lfs.url overridden to the same URL
///   - LFS hooks installed locally
///   - git-xet registered as the "xet" custom transfer agent
///   - lfs.locksverify off (we don't expose /locks/verify)
pub fn init_lfs_workrepo(work: &Path, adapter_base_url: &str) -> String {
    run_git(work, &["init", "-q", "-b", "main", "."]);
    run_git(work, &["config", "user.email", "alice@test.invalid"]);
    run_git(work, &["config", "user.name", "alice"]);

    let adapter_host = adapter_base_url
        .strip_prefix("http://")
        .expect("adapter base_url shape");
    let remote_url =
        format!("http://token:{HUB_PAT}@{adapter_host}/repos/{REPO_OWNER}/{REPO_NAME}");
    run_git(work, &["remote", "add", "origin", &remote_url]);
    run_git(work, &["config", "--local", "lfs.url", &remote_url]);

    let out = Command::new("git")
        .args(["lfs", "install", "--local"])
        .current_dir(work)
        .output()
        .expect("git lfs install");
    assert!(
        out.status.success(),
        "git lfs install:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    run_git(
        work,
        &[
            "config",
            "--local",
            "lfs.customtransfer.xet.path",
            "git-xet",
        ],
    );
    run_git(
        work,
        &[
            "config",
            "--local",
            "lfs.customtransfer.xet.args",
            "transfer",
        ],
    );
    run_git(
        work,
        &[
            "config",
            "--local",
            "lfs.customtransfer.xet.concurrent",
            "true",
        ],
    );
    run_git(work, &["config", "--local", "lfs.locksverify", "false"]);

    remote_url
}
