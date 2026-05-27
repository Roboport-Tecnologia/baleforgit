//! MinIO integration. `#[ignore]`, so default `cargo test` skips it — run
//! with `cargo test -p bale-server-storage-s3 --test minio -- --ignored`.
//! Skips silently when podman isn't usable.

use aws_credential_types::Credentials;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use bale_server_core::{BlobStore, CoreError, Hash32, ShardHash, XorbHash};
use bale_server_storage_s3::{S3BlobStore, S3Config};
use bytes::Bytes;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

const ACCESS_KEY: &str = "minioadmin";
const SECRET_KEY: &str = "minioadmin";
const IMAGE: &str = "quay.io/minio/minio:RELEASE.2025-01-20T14-49-07Z";
// Generous: covers cold image pull on a fresh runner.
const READY_TIMEOUT: Duration = Duration::from_secs(180);

fn xorb(seed: u8) -> XorbHash {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    XorbHash(Hash32(b))
}

fn shard(seed: u8) -> ShardHash {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = seed.wrapping_add(i as u8);
    }
    ShardHash(Hash32(b))
}

// `podman info` (not `--version`): on macOS the binary is present even when
// the podman-machine VM is stopped, and we don't want to hang on `run`.
fn podman_available() -> bool {
    Command::new("podman")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct MinioGuard {
    container: String,
    endpoint: String,
}

impl MinioGuard {
    async fn start() -> Option<Self> {
        if !podman_available() {
            eprintln!("[minio] podman not usable (binary missing, or `podman info` failed — start `podman machine` on macOS) — skipping");
            return None;
        }
        let port = pick_free_port();
        let container = format!("bale-test-minio-{}", uuid::Uuid::new_v4());

        eprintln!("[minio] launching {IMAGE} on 127.0.0.1:{port}");
        let out = Command::new("podman")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container,
                "-p",
                &format!("127.0.0.1:{port}:9000"),
                "-e",
                &format!("MINIO_ROOT_USER={ACCESS_KEY}"),
                "-e",
                &format!("MINIO_ROOT_PASSWORD={SECRET_KEY}"),
                IMAGE,
                "server",
                "/data",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            eprintln!(
                "[minio] podman run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }

        let endpoint = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .ok()?;
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(r) = client
                .get(format!("{endpoint}/minio/health/ready"))
                .send()
                .await
            {
                if r.status().is_success() {
                    eprintln!("[minio] ready at {endpoint}");
                    return Some(Self {
                        container,
                        endpoint,
                    });
                }
            }
            sleep(Duration::from_millis(250)).await;
        }

        eprintln!("[minio] did not become ready within {READY_TIMEOUT:?}");
        let _ = Command::new("podman")
            .args(["rm", "-f", &container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        None
    }
}

impl Drop for MinioGuard {
    fn drop(&mut self) {
        // `--rm` covers the happy path; this catches the rest (e.g. CI cancel).
        let _ = Command::new("podman")
            .args(["rm", "-f", &self.container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn create_bucket(endpoint: &str, bucket: &str) {
    let creds = Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "minio-test");
    let cfg = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .credentials_provider(creds)
        .force_path_style(true)
        .build();
    let client = aws_sdk_s3::Client::from_conf(cfg);
    // Tolerate "already exists" from a partial previous run on the same VM.
    if let Err(e) = client.create_bucket().bucket(bucket).send().await {
        let msg = format!("{e:?}");
        if !msg.contains("BucketAlreadyOwnedByYou") && !msg.contains("BucketAlreadyExists") {
            panic!("create_bucket failed: {e:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires podman + network; run with --ignored or in CI"]
async fn full_roundtrip_against_minio() {
    let Some(guard) = MinioGuard::start().await else {
        return;
    };
    let bucket = "bale-tests";
    create_bucket(&guard.endpoint, bucket).await;

    let store = S3BlobStore::open(S3Config {
        bucket: bucket.into(),
        region: Some("us-east-1".into()),
        endpoint_url: Some(guard.endpoint.clone()),
        force_path_style: true,
        prefix: "ci/".into(),
        access_key_id: Some(ACCESS_KEY.into()),
        secret_access_key: Some(SECRET_KEY.into()),
        session_token: None,
        // MinIO supports SSE-S3 but only after a KMS key is configured;
        // disable for the throwaway CI bucket.
        disable_sse: true,
    })
    .await
    .expect("open S3BlobStore against MinIO");

    let x = xorb(0x11);
    let body: Vec<u8> = (0u8..=255).collect();
    assert!(store
        .put_xorb(&x, Bytes::from(body.clone()))
        .await
        .expect("put_xorb 1"));
    assert!(store.xorb_exists(&x).await.expect("xorb_exists"));
    assert!(!store
        .put_xorb(&x, Bytes::from(body.clone()))
        .await
        .expect("put_xorb 2"));

    let slice = store
        .get_xorb_range(&x, 100..150)
        .await
        .expect("range read");
    assert_eq!(slice.len(), 50);
    assert_eq!(slice[0], 100);
    assert_eq!(slice[49], 149);

    let missing = xorb(0xAA);
    match store.get_xorb_range(&missing, 0..1).await {
        Err(CoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
    assert!(!store.xorb_exists(&missing).await.unwrap());

    let s = shard(0x55);
    let sbody = Bytes::from_static(b"minio-shard-bytes");
    store.put_shard(&s, sbody.clone()).await.expect("put_shard");
    assert_eq!(store.get_shard(&s).await.expect("get_shard"), sbody);

    let presigned = store
        .presign_xorb_range(&x, 100..150, Duration::from_secs(60))
        .await
        .expect("presign")
        .expect("S3 backend returns Some(url)");
    let resp = reqwest::Client::new()
        .get(&presigned)
        .header("Range", "bytes=100-149")
        .send()
        .await
        .expect("fetch presigned URL");
    assert!(
        resp.status().is_success() || resp.status() == reqwest::StatusCode::PARTIAL_CONTENT,
        "unexpected status from presigned GET: {}",
        resp.status()
    );
    let fetched = resp.bytes().await.expect("read presigned body");
    assert_eq!(fetched.len(), 50);
    assert_eq!(fetched[0], 100);
    assert_eq!(fetched[49], 149);

    // Load-bearing for the reconstruction-handler offload: a signed URL must
    // not work with a different Range than the one it was signed for.
    let wrong = reqwest::Client::new()
        .get(&presigned)
        .header("Range", "bytes=0-49")
        .send()
        .await
        .expect("fetch presigned URL w/ wrong range");
    assert!(
        wrong.status().is_client_error() || wrong.status().is_server_error(),
        "S3 unexpectedly accepted a presigned URL with a mismatched Range: {}",
        wrong.status()
    );
}
