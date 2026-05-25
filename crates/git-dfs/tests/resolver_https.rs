//! End-to-end test for the HTTPS auto-resolution flow:
//!
//!   git remote (origin) ──┬── (discovery)    GET /<owner>/<repo>.git/info/dfs
//!                         ├── (credential)   git credential fill → fake PAT
//!                         └── (exchange)     GET <xet>/api/.../xet-write-token/main
//!
//! Both gitea and xet-server are mocked by a single axum router on a
//! tempfile port — the resolver doesn't care that the same URL serves both
//! roles, since the discovery response and token-exchange response set their
//! own URLs. Skipped (with eprintln) when `git` isn't on PATH.
//!
//! The credential helper is exercised by writing a tiny shell script that
//! echoes a fixed password, and wiring it via `git config credential.helper`
//! on the temp repo.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use git_dfs::config::RawConfig;
use git_dfs::resolver::{resolve, Scope};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn tool_on_path(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[derive(Clone, Default)]
struct MockState {
    /// Echoed back as `server_url` (discovery) and `casUrl` (exchange).
    /// Per-instance so parallel tests don't race on a shared env var.
    base_url: String,
    /// PAT that the mock will accept on the token-exchange endpoint.
    expected_pat: String,
    /// Token string the mock will mint on a valid exchange.
    minted_token: String,
    /// Records that the discovery and exchange endpoints were both hit.
    discovery_called: Arc<Mutex<bool>>,
    exchange_called: Arc<Mutex<bool>>,
}

async fn discovery_handler(
    State(state): State<MockState>,
    AxumPath((_owner, _repo)): AxumPath<(String, String)>,
) -> Json<serde_json::Value> {
    *state.discovery_called.lock().unwrap() = true;
    Json(json!({ "server_url": state.base_url }))
}

async fn exchange_handler(
    State(state): State<MockState>,
    AxumPath((_owner, _repo, _scope, _rev)): AxumPath<(String, String, String, String)>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    *state.exchange_called.lock().unwrap() = true;
    let authz = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", state.expected_pat);
    if authz != expected {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "bad pat" })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "accessToken": state.minted_token,
            "exp": 4_000_000_000u64,
            "casUrl": state.base_url,
        })),
    )
}

fn write_credential_helper_script(dir: &Path, pat: &str) -> std::path::PathBuf {
    let path = dir.join("creds.sh");
    let body = format!(
        "#!/usr/bin/env sh\n\
         # Only respond to the 'get' command.\n\
         if [ \"$1\" = \"get\" ]; then\n\
         \tcat <<EOF\nusername=user2\npassword={pat}\nEOF\n\
         fi\n"
    );
    std::fs::write(&path, body).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_resolve_end_to_end() {
    if !tool_on_path("git") {
        eprintln!("skipping: `git` not on PATH");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let state = MockState {
        base_url: base_url.clone(),
        expected_pat: "0123456789abcdef0123456789abcdef01234567".into(),
        minted_token: "xet-jwt-minted-by-mock".into(),
        ..Default::default()
    };

    let app = Router::new()
        // axum 0.8 disallows literal segments next to a param within one
        // segment, so we match the whole "repo.git" piece as the parameter
        // and ignore the value — `.git` is part of the URL the resolver
        // emits, and the gitea server strips it the same way.
        .route("/{owner}/{repo}/info/dfs", get(discovery_handler))
        .route(
            "/api/models/{owner}/{repo}/{scope}/{rev}",
            get(exchange_handler),
        )
        .with_state(state.clone());

    let server_handle = tokio::spawn(async move { axum::serve(listener, app).await });

    // Build a temp git repo whose `origin` points at the mock.
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().to_path_buf();
    let run_git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run_git(&["init", "-q", "-b", "main", "."]);
    run_git(&[
        "remote",
        "add",
        "origin",
        &format!("{base_url}/user2/repo1.git"),
    ]);

    let helper = write_credential_helper_script(tmp.path(), &state.expected_pat);
    // Clear any inherited helpers (the macOS keychain, libsecret on Linux,
    // etc.) so the test's helper is the only one git consults. Per
    // git-credential docs, an empty-string entry resets the inherited list.
    run_git(&["config", "--local", "--add", "credential.helper", ""]);
    run_git(&[
        "config",
        "--local",
        "--add",
        "credential.helper",
        &format!("!{}", helper.display()),
    ]);

    // Auto-resolution path: both server_url and token absent. cache_dir is
    // required but unused by the resolver itself.
    let raw = RawConfig {
        server_url: None,
        token: None,
        token_expiration: None,
        cache_dir: tmp.path().join("cache"),
        git_dir: Some(repo.join(".git")),
    };

    let resolved = resolve(&raw, Scope::Write)
        .await
        .expect("resolve succeeded");
    assert_eq!(resolved.token, "xet-jwt-minted-by-mock");
    assert_eq!(resolved.server_url, base_url);
    assert_eq!(resolved.token_expiration, 4_000_000_000);

    assert!(
        *state.discovery_called.lock().unwrap(),
        "discovery endpoint was hit"
    );
    assert!(
        *state.exchange_called.lock().unwrap(),
        "exchange endpoint was hit"
    );

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_server_url_skips_discovery() {
    if !tool_on_path("git") {
        eprintln!("skipping: `git` not on PATH");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let state = MockState {
        base_url: base_url.clone(),
        expected_pat: "abababababababababababababababababababab".into(),
        minted_token: "xet-jwt-via-manual-url".into(),
        ..Default::default()
    };
    let app = Router::new()
        .route("/{owner}/{repo}/info/dfs", get(discovery_handler))
        .route(
            "/api/models/{owner}/{repo}/{scope}/{rev}",
            get(exchange_handler),
        )
        .with_state(state.clone());
    let server_handle = tokio::spawn(async move { axum::serve(listener, app).await });

    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().to_path_buf();
    let run_git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
    };
    run_git(&["init", "-q", "-b", "main", "."]);
    run_git(&[
        "remote",
        "add",
        "origin",
        &format!("{base_url}/user2/repo1.git"),
    ]);
    let helper = write_credential_helper_script(tmp.path(), &state.expected_pat);
    // Clear any inherited helpers (the macOS keychain, libsecret on Linux,
    // etc.) so the test's helper is the only one git consults. Per
    // git-credential docs, an empty-string entry resets the inherited list.
    run_git(&["config", "--local", "--add", "credential.helper", ""]);
    run_git(&[
        "config",
        "--local",
        "--add",
        "credential.helper",
        &format!("!{}", helper.display()),
    ]);

    // User has manually pinned dfs.serverUrl. Discovery must be skipped.
    let raw = RawConfig {
        server_url: Some(base_url.clone()),
        token: None,
        token_expiration: None,
        cache_dir: tmp.path().join("cache"),
        git_dir: Some(repo.join(".git")),
    };

    let resolved = resolve(&raw, Scope::Read).await.unwrap();
    assert_eq!(resolved.token, "xet-jwt-via-manual-url");

    assert!(
        !*state.discovery_called.lock().unwrap(),
        "discovery must be skipped when dfs.serverUrl is set"
    );
    assert!(*state.exchange_called.lock().unwrap());

    server_handle.abort();
}
