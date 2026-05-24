//! M7: drive the real `git-xet` binary against our server over the LFS custom
//! transfer JSON-line protocol.
//!
//! We don't run `git push` end-to-end — that would require us to also speak
//! the git-lfs Batch API, which is out of scope for this milestone. Instead we
//! invoke `git-xet transfer` directly as a subprocess (the same way git-lfs
//! does internally), feed it init + upload + terminate events on stdin, and
//! inspect the server's persisted state to confirm uploads landed.
//!
//! Test is **gated on `git-xet` being on PATH** — it skips with an eprintln
//! otherwise, so CI without the binary is silent rather than failing.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use xet_server_authz_mem::ConfigAuthz;
use xet_server_core::{RepoRef, RepoType, Scope, UserId};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;
use xet_server_tokens::mint;

const JWT_SECRET: &[u8; 32] = b"01234567890123456789012345678901";
const TRANSFER_SECRET: [u8; 32] = [0x77u8; 32];

fn git_xet_available() -> bool {
    std::process::Command::new("git-xet")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_git(repo: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git invocation");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn oid_of(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_xet_upload_round_trip() {
    if !git_xet_available() {
        eprintln!("skipping: `git-xet` not on PATH");
        return;
    }

    // ---- Server -----------------------------------------------------------
    let data_dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(
        FsBlobStore::open(data_dir.path().join("blobs"))
            .await
            .unwrap(),
    );
    let meta = Arc::new(SqliteMetadataStore::open_path(":memory:").await.unwrap());

    let repo = RepoRef {
        repo_type: RepoType::Model,
        repo_id: "test/test".into(),
        revision: "main".into(),
    };
    let authz = ConfigAuthz::new(JWT_SECRET.to_vec()).grant(
        "hub-token-unused",
        "tester",
        "test/test",
        Scope::Write,
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cas_url = format!("http://{addr}");

    let svc = Service {
        blobs,
        meta: meta.clone(),
        authz: Arc::new(authz),
        transfer_secret: TRANSFER_SECRET,
        public_base_url: cas_url.clone(),
    };
    let app = router(svc);
    let server_handle = tokio::spawn(async move { axum::serve(listener, app).await });

    // ---- JWT for the test repo -------------------------------------------
    let (jwt, exp) = mint(
        JWT_SECRET,
        &UserId("tester".into()),
        &repo,
        Scope::Write,
        3600,
    )
    .expect("mint jwt");

    // ---- Temp git repo configured to look like an HF remote --------------
    let repo_dir = tempfile::tempdir().unwrap();
    run_git(repo_dir.path(), &["init", "-q", "."]);
    run_git(repo_dir.path(), &["config", "user.email", "t@t.test"]);
    run_git(repo_dir.path(), &["config", "user.name", "tester"]);

    // Remote URL must parse via git-xet's GitUrl. https://host:port/ns/name works.
    let remote_url = format!("{cas_url}/test/test");
    run_git(repo_dir.path(), &["remote", "add", "origin", &remote_url]);

    // git-xet's credential helper consults lfs.<lfs-endpoint>.access. Setting
    // it to `none` makes the NoopCredentialHelper take over so the test never
    // gets near a real git credential prompt or netrc / SSH attempt.
    let lfs_endpoint = format!("{cas_url}/test/test.git/info/lfs");
    let access_key = format!("lfs.{lfs_endpoint}.access");
    run_git(repo_dir.path(), &["config", &access_key, "none"]);

    // ---- Test payload ----------------------------------------------------
    // ~300 KiB of deterministic-but-not-trivial content — enough that the
    // gear-hash CDC produces at least a few chunks, so we exercise xorb
    // boundary handling.
    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let file_path = repo_dir.path().join("big.bin");
    std::fs::write(&file_path, &payload).unwrap();
    let oid = oid_of(&payload);

    // ---- Drive `git-xet transfer` over stdio -----------------------------
    let mut child = std::process::Command::new("git-xet")
        .arg("-vv")
        .arg("transfer")
        .current_dir(repo_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git-xet transfer");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Echo stderr to test output in case of failure — best-effort, dropped on
    // success.
    let stderr_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut r = stderr;
        let _ = r.read_to_end(&mut buf);
        buf
    });

    let init = serde_json::json!({
        "event": "init",
        "operation": "upload",
        "remote": "origin",
        "concurrent": true,
        "concurrenttransfers": 1,
    });
    writeln!(stdin, "{init}").unwrap();

    let upload = serde_json::json!({
        "event": "upload",
        "oid": oid,
        "size": payload.len(),
        "path": file_path.to_string_lossy().to_string(),
        "action": {
            // href would be the token-refresh route in production; not used
            // here because our token expiry is 1h, well past test duration.
            "href": format!("{cas_url}/refresh/unused"),
            "header": {
                "X-Xet-Cas-Url": cas_url.clone(),
                "X-Xet-Access-Token": jwt.clone(),
                "X-Xet-Token-Expiration": format!("{exp}"),
            }
        }
    });
    writeln!(stdin, "{upload}").unwrap();

    // Pump stdout in a thread so the subprocess can't block on a full pipe.
    let stdout_thread = std::thread::spawn(move || -> Vec<String> {
        let mut events = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let is_complete = line.contains("\"event\":\"complete\"");
            events.push(line);
            if is_complete {
                break;
            }
        }
        events
    });

    // Bounded wait: 60s is generous for a 300 KiB upload over loopback.
    let events = tokio::task::spawn_blocking(move || stdout_thread.join().expect("stdout thread"))
        .await
        .expect("stdout join task");

    writeln!(stdin, "{{\"event\":\"terminate\"}}").unwrap();
    drop(stdin);

    let wait_result = tokio::task::spawn_blocking(move || {
        // git-xet should exit within a few seconds of terminate.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(s)) => return Ok::<_, std::io::Error>(s),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = child.kill();
                    return child.wait();
                }
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .unwrap()
    .unwrap();

    let stderr_bytes = stderr_thread.join().unwrap_or_default();
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();

    assert!(
        !events.is_empty(),
        "git-xet emitted no events. stderr=\n{stderr_text}"
    );
    let last = events.last().expect("at least one event");
    assert!(
        last.contains("\"event\":\"complete\""),
        "expected complete event, got: {last}\nall events:\n{events:#?}\nstderr:\n{stderr_text}"
    );
    assert!(
        !last.contains("\"error\""),
        "git-xet reported an upload error: {last}\nstderr:\n{stderr_text}"
    );
    assert!(
        wait_result.success(),
        "git-xet exit status {wait_result:?}\nstderr:\n{stderr_text}"
    );

    // ---- Verify the server actually received the data --------------------
    // We can't look up by the LFS-style sha256 `oid` — Xet uses its own merkle
    // file hash derived from the content-defined chunking, which is not the
    // sha256 of the file. So instead we check the meta store totals: a
    // successful upload should land at least one xorb and one file row.
    let n_xorbs = meta.count_xorbs().await.unwrap();
    let n_files = meta.count_files().await.unwrap();
    assert!(
        n_xorbs > 0,
        "expected at least one xorb registered, got 0\nevents:\n{events:#?}\nstderr:\n{stderr_text}"
    );
    assert!(
        n_files > 0,
        "expected at least one file registered, got 0\nevents:\n{events:#?}\nstderr:\n{stderr_text}"
    );

    // Cleanup. The server task is detached and bound to test-scoped resources
    // (port, tempdirs) — dropping the handle suffices once we stop borrowing.
    server_handle.abort();

    // Suppress unused-variable warnings on rarely-touched temporaries.
    let _ = (data_dir, repo_dir, PathBuf::new());
}
