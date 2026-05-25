//! End-to-end test for the HTTPS auto-resolution flow:
//!
//!   git remote (origin) ──┬── POST /<owner>/<repo>.git/info/dfs/authenticate
//!                         │   (HTTPS Basic auth from `git credential fill`)
//!                         │   → {href, header.Authorization=Bearer <jwt>, expires_at}
//!                         │   The password is verified by gitea and never
//!                         │   leaves it — only the JWT travels onward.
//!                         └── GET <xet>/api/.../xet-{rw}-token/main
//!                             (Bearer the JWT from above)
//!                             → {accessToken, exp, casUrl}
//!
//! Both gitea and xet-server are mocked by a single axum router on a temp
//! port. Skipped (with eprintln) when `git` isn't on PATH.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
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
    /// Echoed back as `href` from authenticate and as `casUrl` from exchange.
    /// Per-instance so parallel tests don't share state.
    base_url: String,
    /// The Basic-auth password the authenticate endpoint will accept.
    expected_password: String,
    /// The JWT the authenticate endpoint mints; also what the exchange
    /// endpoint accepts as a Bearer. Contains a `.` so resolver doesn't
    /// confuse it with a PAT or empty string.
    minted_jwt: String,
    /// Final xet access token the exchange endpoint hands back.
    minted_xet_token: String,
    /// Tracks that both endpoints were hit.
    authenticate_called: Arc<Mutex<bool>>,
    exchange_called: Arc<Mutex<bool>>,
}

async fn authenticate_handler(
    State(state): State<MockState>,
    AxumPath((_owner, _repo)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    *state.authenticate_called.lock().unwrap() = true;
    // Decode Basic auth from the Authorization header.
    let authz = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(b64) = authz.strip_prefix("Basic ") else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"no basic"})));
    };
    use base64::Engine;
    let decoded = match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
        Ok(b) => b,
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(json!({"error":"bad b64"}))),
    };
    let creds = String::from_utf8_lossy(&decoded).to_string();
    let (_user, pass) = match creds.split_once(':') {
        Some(p) => p,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error":"no colon"}))),
    };
    if pass != state.expected_password {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"bad password"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "href": state.base_url,
            "header": { "Authorization": format!("Bearer {}", state.minted_jwt) },
            "expires_at": "2030-01-01T00:00:00Z",
        })),
    )
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
    let expected = format!("Bearer {}", state.minted_jwt);
    if authz != expected {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "bad bearer", "got": authz, "expected": expected })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "accessToken": state.minted_xet_token,
            "exp": 4_000_000_000u64,
            "casUrl": state.base_url,
        })),
    )
}

fn write_credential_helper_script(dir: &Path, password: &str) -> std::path::PathBuf {
    let path = dir.join("creds.sh");
    let body = format!(
        "#!/usr/bin/env sh\n\
         if [ \"$1\" = \"get\" ]; then\n\
         \tcat <<EOF\nusername=user2\npassword={password}\nEOF\n\
         fi\n"
    );
    std::fs::write(&path, body).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

fn build_router(state: MockState) -> Router {
    Router::new()
        // axum 0.8 disallows literal segments next to a param within one
        // segment, so the literal `.git` is captured as part of `{repo}` and
        // ignored — gitea strips it the same way server-side.
        .route(
            "/{owner}/{repo}/info/dfs/authenticate",
            post(authenticate_handler),
        )
        .route(
            "/api/models/{owner}/{repo}/{scope}/{rev}",
            get(exchange_handler),
        )
        .with_state(state)
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
        expected_password: "user-password".into(),
        minted_jwt: "fake.jwt.token".into(),
        minted_xet_token: "xet-jwt-minted-by-mock".into(),
        ..Default::default()
    };

    let server_handle =
        tokio::spawn(axum::serve(listener, build_router(state.clone())).into_future());

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

    let helper = write_credential_helper_script(tmp.path(), &state.expected_password);
    // Clear inherited helpers so our test helper is the only one consulted.
    run_git(&["config", "--local", "--add", "credential.helper", ""]);
    run_git(&[
        "config",
        "--local",
        "--add",
        "credential.helper",
        &format!("!{}", helper.display()),
    ]);

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
        *state.authenticate_called.lock().unwrap(),
        "authenticate endpoint was hit"
    );
    assert!(
        *state.exchange_called.lock().unwrap(),
        "exchange endpoint was hit"
    );

    server_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_server_url_still_calls_authenticate() {
    // Even with a manually-configured `dfs.serverUrl`, the HTTPS flow must
    // still hit gitea's authenticate endpoint to obtain a JWT — that's the
    // whole password-stays-in-gitea property.
    if !tool_on_path("git") {
        eprintln!("skipping: `git` not on PATH");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let state = MockState {
        base_url: base_url.clone(),
        expected_password: "user-password".into(),
        minted_jwt: "fake.jwt.token".into(),
        minted_xet_token: "xet-jwt-via-manual-url".into(),
        ..Default::default()
    };
    let server_handle =
        tokio::spawn(axum::serve(listener, build_router(state.clone())).into_future());

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
    let helper = write_credential_helper_script(tmp.path(), &state.expected_password);
    run_git(&["config", "--local", "--add", "credential.helper", ""]);
    run_git(&[
        "config",
        "--local",
        "--add",
        "credential.helper",
        &format!("!{}", helper.display()),
    ]);

    let raw = RawConfig {
        server_url: Some(base_url.clone()),
        token: None,
        token_expiration: None,
        cache_dir: tmp.path().join("cache"),
        git_dir: Some(repo.join(".git")),
    };

    let resolved = resolve(&raw, Scope::Read).await.unwrap();
    assert_eq!(resolved.token, "xet-jwt-via-manual-url");
    assert!(*state.authenticate_called.lock().unwrap());
    assert!(*state.exchange_called.lock().unwrap());

    server_handle.abort();
}

// `axum::serve(...).into_future()` lets us hand the serve future to a spawn
// without binding `axum` directly to the tokio task signature. Without this
// extension trait we'd need a wrapper async block.
use std::future::IntoFuture;
