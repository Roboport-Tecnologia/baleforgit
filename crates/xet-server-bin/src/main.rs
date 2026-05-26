// `XET_AUTHZ_HTTP_URL` wins over `XET_GRANTS` when both are set.
// `XET_S3_BUCKET` switches the blob backend from filesystem to S3-compatible.
// See README for full env-var table.

use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use xet_server_authz_http::HttpAuthz;
use xet_server_authz_mem::ConfigAuthz;
use xet_server_core::{BlobStore, Scope};
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;
use xet_server_storage_s3::{S3BlobStore, S3Config};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // tower_http::trace gives per-request access logs; xet_server_http
                // logs JSON error bodies on 4xx/5xx so failures are visible by default.
                "info,sqlx=warn,tower_http::trace=info,xet_server_http=info".into()
            }),
        )
        .init();

    let listen = env::var("XET_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let data_root =
        PathBuf::from(env::var("XET_DATA_ROOT").unwrap_or_else(|_| "./xet-data".into()));
    let db_path = env::var("XET_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_root.join("meta.db"));
    let public_url = env::var("XET_PUBLIC_URL").unwrap_or_else(|_| format!("http://{listen}"));

    let jwt_secret = decode_hex_env("XET_JWT_SECRET_HEX")?;
    if jwt_secret.len() < 32 {
        bail!("XET_JWT_SECRET_HEX must decode to at least 32 bytes");
    }
    let transfer_secret_bytes = decode_hex_env("XET_TRANSFER_SECRET_HEX")?;
    let transfer_secret: [u8; 32] = transfer_secret_bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "XET_TRANSFER_SECRET_HEX must decode to exactly 32 bytes (got {})",
            v.len()
        )
    })?;

    tokio::fs::create_dir_all(&data_root)
        .await
        .with_context(|| format!("creating data root {}", data_root.display()))?;

    let meta = Arc::new(
        SqliteMetadataStore::open_path(&db_path)
            .await
            .map_err(anyhow_from_core)?,
    );

    let listener = tokio::net::TcpListener::bind(&listen).await?;

    // S3 backend opts in via XET_S3_BUCKET; otherwise the local-filesystem
    // store is used. Logging both branches makes the active backend obvious
    // in production logs.
    if let Ok(bucket) = env::var("XET_S3_BUCKET") {
        if bucket.is_empty() {
            bail!("XET_S3_BUCKET is set but empty");
        }
        let s3_cfg = S3Config {
            bucket: bucket.clone(),
            region: env::var("XET_S3_REGION").ok(),
            endpoint_url: env::var("XET_S3_ENDPOINT_URL").ok(),
            force_path_style: env_truthy("XET_S3_FORCE_PATH_STYLE"),
            prefix: env::var("XET_S3_PREFIX").unwrap_or_default(),
            access_key_id: env::var("XET_S3_ACCESS_KEY_ID").ok(),
            secret_access_key: env::var("XET_S3_SECRET_ACCESS_KEY").ok(),
            session_token: env::var("XET_S3_SESSION_TOKEN").ok(),
        };
        let endpoint_for_log = s3_cfg.endpoint_url.clone();
        let blobs = Arc::new(S3BlobStore::open(s3_cfg).await.map_err(anyhow_from_core)?);
        tracing::info!(
            %listen,
            backend = "s3",
            bucket = %bucket,
            endpoint = ?endpoint_for_log,
            %public_url,
            "xet-server up"
        );
        serve(
            listener,
            blobs,
            meta,
            jwt_secret,
            transfer_secret,
            public_url,
        )
        .await?;
    } else {
        let blobs = Arc::new(
            FsBlobStore::open(&data_root)
                .await
                .map_err(anyhow_from_core)?,
        );
        tracing::info!(
            %listen,
            backend = "fs",
            data_root = %data_root.display(),
            %public_url,
            "xet-server up"
        );
        serve(
            listener,
            blobs,
            meta,
            jwt_secret,
            transfer_secret,
            public_url,
        )
        .await?;
    }
    Ok(())
}

async fn serve<B>(
    listener: tokio::net::TcpListener,
    blobs: Arc<B>,
    meta: Arc<SqliteMetadataStore>,
    jwt_secret: Vec<u8>,
    transfer_secret: [u8; 32],
    public_url: String,
) -> Result<()>
where
    B: BlobStore + 'static,
{
    // Service is generic over the authz impl, so each branch builds its own.
    if let Ok(authz_url) = env::var("XET_AUTHZ_HTTP_URL") {
        if authz_url.is_empty() {
            bail!("XET_AUTHZ_HTTP_URL is set but empty");
        }
        let authz = HttpAuthz::new(authz_url.clone(), jwt_secret).map_err(anyhow_from_core)?;
        tracing::info!(%authz_url, "using HttpAuthz upstream");
        let svc = Service {
            blobs,
            meta,
            authz: Arc::new(authz),
            transfer_secret,
            public_base_url: public_url,
        };
        axum::serve(listener, router(svc))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    } else {
        let mut authz = ConfigAuthz::new(jwt_secret);
        if let Ok(raw) = env::var("XET_GRANTS") {
            for (idx, tuple) in raw.split(',').filter(|s| !s.is_empty()).enumerate() {
                let parts: Vec<&str> = tuple.split(':').collect();
                // Never interpolate the tuple itself — parts[0] is a hub bearer token.
                if parts.len() != 4 {
                    bail!(
                        "XET_GRANTS tuple #{idx} malformed: expected 'hub_token:user:repo_id:scope' with 4 fields, got {}",
                        parts.len()
                    );
                }
                let scope = match parts[3] {
                    "read" => Scope::Read,
                    "write" => Scope::Write,
                    other => bail!("invalid scope '{other}' in XET_GRANTS tuple #{idx}"),
                };
                authz = authz.grant(parts[0], parts[1], parts[2], scope);
            }
        } else {
            tracing::warn!(
                "XET_GRANTS is empty and XET_AUTHZ_HTTP_URL is unset; no users authorized — all requests will 401/403"
            );
        }
        let svc = Service {
            blobs,
            meta,
            authz: Arc::new(authz),
            transfer_secret,
            public_base_url: public_url,
        };
        axum::serve(listener, router(svc))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;
    // Both expects fire only if the kernel refuses to install a signal handler
    // (e.g. SIGTERM is masked) — startup-time invariant, not a network input.
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT received, draining in-flight requests"),
        _ = terminate => tracing::info!("SIGTERM received, draining in-flight requests"),
    }
}

fn env_truthy(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn decode_hex_env(name: &str) -> Result<Vec<u8>> {
    let v = env::var(name).with_context(|| format!("{name} not set"))?;
    hex::decode(v.trim()).with_context(|| format!("{name} is not valid hex"))
}

fn anyhow_from_core(e: xet_server_core::CoreError) -> anyhow::Error {
    anyhow::anyhow!("core error: {e}")
}
