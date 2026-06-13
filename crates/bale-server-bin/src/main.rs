mod telemetry;

use anyhow::{bail, Context, Result};
use bale_server_authz_http::HttpAuthz;
use bale_server_authz_mem::ConfigAuthz;
use bale_server_core::{BlobStore, MetadataStore, Scope};
use bale_server_http::{router, Service};
use bale_server_meta_postgres::PostgresMetadataStore;
use bale_server_meta_sqlite::SqliteMetadataStore;
use bale_server_storage_fs::FsBlobStore;
use bale_server_storage_s3::{S3BlobStore, S3Config};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("BALE_GIT_SHA"),
    " ",
    env!("BALE_BUILD_DATE"),
    " ",
    env!("BALE_TARGET"),
    ")"
);

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().skip(1).any(|a| a == "--version" || a == "-V") {
        println!("baleforgit-server {VERSION}");
        return Ok(());
    }

    // Held until end of main so OTLP exporters flush on shutdown.
    let _telemetry = telemetry::init("baleforgit-server")?;
    tracing::info!(version = VERSION, "baleforgit-server starting");

    let listen = env::var("BALE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let data_root =
        PathBuf::from(env::var("BALE_DATA_ROOT").unwrap_or_else(|_| "./xet-data".into()));
    let db_path = env::var("BALE_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_root.join("meta.db"));
    let public_url = match env::var("BALE_PUBLIC_URL") {
        Ok(v) => v,
        Err(_) => {
            // Beyond loopback the http:// default leaks into presigned URLs that
            // won't resolve behind a TLS proxy — warn so it's set explicitly.
            let host = listen.split(':').next().unwrap_or("");
            if !is_loopback(host) {
                tracing::warn!(
                    %listen,
                    "BALE_PUBLIC_URL is unset and server binds beyond loopback; \
                     signed URLs will use 'http://{listen}' — set BALE_PUBLIC_URL \
                     explicitly behind any reverse proxy or TLS terminator"
                );
            }
            format!("http://{listen}")
        }
    };

    let jwt_secret = decode_hex_env("BALE_JWT_SECRET_HEX")?;
    if jwt_secret.len() < 32 {
        bail!("BALE_JWT_SECRET_HEX must decode to at least 32 bytes");
    }
    let transfer_secret_bytes = decode_hex_env("BALE_TRANSFER_SECRET_HEX")?;
    let transfer_secret: [u8; 32] = transfer_secret_bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "BALE_TRANSFER_SECRET_HEX must decode to exactly 32 bytes (got {})",
            v.len()
        )
    })?;

    let default_quota_bytes = match env::var("BALE_DEFAULT_QUOTA_BYTES") {
        Ok(s) => Some(
            s.trim()
                .parse::<u64>()
                .context("BALE_DEFAULT_QUOTA_BYTES must be a non-negative integer")?,
        ),
        Err(_) => None,
    };
    let admin_token = match env::var("BALE_ADMIN_TOKEN_HEX") {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).context("BALE_ADMIN_TOKEN_HEX is not hex")?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "BALE_ADMIN_TOKEN_HEX must decode to exactly 32 bytes (got {})",
                    v.len()
                )
            })?;
            Some(arr)
        }
        Err(_) => None,
    };

    tokio::fs::create_dir_all(&data_root)
        .await
        .with_context(|| format!("creating data root {}", data_root.display()))?;

    let listener = tokio::net::TcpListener::bind(&listen).await?;

    // Metadata store: Postgres when BALE_POSTGRES_URL is set, else local SQLite.
    if let Ok(pg_url) = env::var("BALE_POSTGRES_URL") {
        let pg_url = pg_url.trim();
        if pg_url.is_empty() {
            bail!("BALE_POSTGRES_URL is set but empty");
        }
        tracing::info!(%listen, metadata = "postgres", "metadata store: postgres");
        let meta = Arc::new(
            PostgresMetadataStore::open_url(pg_url)
                .await
                .map_err(anyhow_from_core)?,
        );
        run(
            listener,
            meta,
            &data_root,
            jwt_secret,
            transfer_secret,
            public_url,
            default_quota_bytes,
            admin_token,
        )
        .await?;
    } else {
        tracing::info!(%listen, metadata = "sqlite", db = %db_path.display(), "metadata store: sqlite");
        let meta = Arc::new(
            SqliteMetadataStore::open_path(&db_path)
                .await
                .map_err(anyhow_from_core)?,
        );
        run(
            listener,
            meta,
            &data_root,
            jwt_secret,
            transfer_secret,
            public_url,
            default_quota_bytes,
            admin_token,
        )
        .await?;
    }
    Ok(())
}

// Select the blob store (S3 when BALE_S3_BUCKET is set, else filesystem) and
// serve. Generic over the metadata store so either backend pairs with either
// blob store.
#[allow(clippy::too_many_arguments)]
async fn run<M>(
    listener: tokio::net::TcpListener,
    meta: Arc<M>,
    data_root: &Path,
    jwt_secret: Vec<u8>,
    transfer_secret: [u8; 32],
    public_url: String,
    default_quota_bytes: Option<u64>,
    admin_token: Option<[u8; 32]>,
) -> Result<()>
where
    M: MetadataStore + 'static,
{
    if let Ok(bucket) = env::var("BALE_S3_BUCKET") {
        if bucket.is_empty() {
            bail!("BALE_S3_BUCKET is set but empty");
        }
        let s3_cfg = S3Config {
            bucket: bucket.clone(),
            region: env::var("BALE_S3_REGION").ok(),
            endpoint_url: env::var("BALE_S3_ENDPOINT_URL").ok(),
            // Empty (a compose `${VAR:-}` passthrough) must mean "unset", not a
            // bogus empty endpoint that signs unreachable URLs.
            public_endpoint_url: env::var("BALE_S3_PUBLIC_ENDPOINT_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            force_path_style: env_truthy("BALE_S3_FORCE_PATH_STYLE"),
            prefix: env::var("BALE_S3_PREFIX").unwrap_or_default(),
            access_key_id: env::var("BALE_S3_ACCESS_KEY_ID").ok(),
            secret_access_key: env::var("BALE_S3_SECRET_ACCESS_KEY").ok(),
            session_token: env::var("BALE_S3_SESSION_TOKEN").ok(),
            disable_sse: env_truthy("BALE_S3_DISABLE_SSE"),
        };
        let endpoint_for_log = s3_cfg.endpoint_url.clone();
        let presign_endpoint_for_log = s3_cfg.public_endpoint_url.clone();
        let blobs = Arc::new(S3BlobStore::open(s3_cfg).await.map_err(anyhow_from_core)?);
        tracing::info!(
            backend = "s3",
            bucket = %bucket,
            endpoint = ?endpoint_for_log,
            presign_endpoint = ?presign_endpoint_for_log,
            %public_url,
            "baleforgit-server up"
        );
        serve(
            listener,
            blobs,
            meta,
            jwt_secret,
            transfer_secret,
            public_url,
            default_quota_bytes,
            admin_token,
        )
        .await?;
    } else {
        let blobs = Arc::new(
            FsBlobStore::open(data_root)
                .await
                .map_err(anyhow_from_core)?,
        );
        tracing::info!(
            backend = "fs",
            data_root = %data_root.display(),
            %public_url,
            "baleforgit-server up"
        );
        serve(
            listener,
            blobs,
            meta,
            jwt_secret,
            transfer_secret,
            public_url,
            default_quota_bytes,
            admin_token,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve<B, M>(
    listener: tokio::net::TcpListener,
    blobs: Arc<B>,
    meta: Arc<M>,
    jwt_secret: Vec<u8>,
    transfer_secret: [u8; 32],
    public_url: String,
    default_quota_bytes: Option<u64>,
    admin_token: Option<[u8; 32]>,
) -> Result<()>
where
    B: BlobStore + 'static,
    M: MetadataStore + 'static,
{
    if default_quota_bytes.is_some() {
        tracing::info!(
            limit = ?default_quota_bytes,
            "default per-owner quota active (override per-owner via PUT /v1/quotas/{{owner}})"
        );
    }
    if admin_token.is_none() {
        tracing::info!(
            "BALE_ADMIN_TOKEN_HEX unset; PUT /v1/quotas/{{owner}} disabled (returns 404)"
        );
    }
    // Service is generic over the authz impl, so each branch builds its own.
    if let Ok(authz_url) = env::var("BALE_AUTHZ_HTTP_URL") {
        if authz_url.is_empty() {
            bail!("BALE_AUTHZ_HTTP_URL is set but empty");
        }
        let authz = HttpAuthz::new(authz_url.clone(), jwt_secret).map_err(anyhow_from_core)?;
        tracing::info!(%authz_url, "using HttpAuthz upstream");
        let svc = Service {
            blobs,
            meta,
            authz: Arc::new(authz),
            transfer_secret,
            public_base_url: public_url,
            default_quota_bytes,
            admin_token,
        };
        axum::serve(listener, router(svc))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    } else {
        let mut authz = ConfigAuthz::new(jwt_secret);
        if let Ok(raw) = env::var("BALE_GRANTS") {
            for (idx, tuple) in raw.split(',').filter(|s| !s.is_empty()).enumerate() {
                let parts: Vec<&str> = tuple.split(':').collect();
                // Never interpolate the tuple itself — parts[0] is a hub bearer token.
                if parts.len() != 4 {
                    bail!(
                        "BALE_GRANTS tuple #{idx} malformed: expected 'hub_token:user:repo_id:scope' with 4 fields, got {}",
                        parts.len()
                    );
                }
                let scope = match parts[3] {
                    "read" => Scope::Read,
                    "write" => Scope::Write,
                    other => bail!("invalid scope '{other}' in BALE_GRANTS tuple #{idx}"),
                };
                authz = authz.grant(parts[0], parts[1], parts[2], scope);
            }
        } else {
            tracing::warn!(
                "BALE_GRANTS is empty and BALE_AUTHZ_HTTP_URL is unset; no users authorized — all requests will 401/403"
            );
        }
        let svc = Service {
            blobs,
            meta,
            authz: Arc::new(authz),
            transfer_secret,
            public_base_url: public_url,
            default_quota_bytes,
            admin_token,
        };
        axum::serve(listener, router(svc))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;
    // Both expects fire only if the kernel refuses a signal handler at startup —
    // not a network input.
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

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
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

fn anyhow_from_core(e: bale_server_core::CoreError) -> anyhow::Error {
    anyhow::anyhow!("core error: {e}")
}
