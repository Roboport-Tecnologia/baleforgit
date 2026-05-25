//! Single-binary launcher for the Xet CAS server. Reads configuration from
//! environment variables; constructs the file-system + SQLite + config-authz
//! stack and serves the HTTP router.
//!
//! Env vars:
//! - `XET_LISTEN`           (default `127.0.0.1:8080`)
//! - `XET_DATA_ROOT`        (default `./xet-data`)
//! - `XET_DB_PATH`          (default `<XET_DATA_ROOT>/meta.db`)
//! - `XET_PUBLIC_URL`       (default `http://<XET_LISTEN>`)
//! - `XET_JWT_SECRET_HEX`   (REQUIRED; 32+ bytes of hex)
//! - `XET_TRANSFER_SECRET_HEX` (REQUIRED; exactly 32 bytes of hex / 64 chars)
//!
//! Authz selection (one of):
//! - `XET_AUTHZ_HTTP_URL`   — base URL where the upstream `/check_access`
//!   handler lives (e.g. `http://localhost:3000/-/dfs` for gitea). When set,
//!   xet-server delegates repo-access decisions to that upstream via
//!   `xet-server-authz-http::HttpAuthz`, and `XET_GRANTS` is ignored.
//! - `XET_GRANTS`           — comma-separated `hub_token:user:repo_id:read|write`
//!   tuples for the in-process static authz (dev/test). Used only when
//!   `XET_AUTHZ_HTTP_URL` is unset.
//!   Example: `XET_GRANTS=hub-alice:alice:alice/m:write,hub-bob:bob:alice/m:read`

use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use xet_server_authz_http::HttpAuthz;
use xet_server_authz_mem::ConfigAuthz;
use xet_server_core::Scope;
use xet_server_http::{router, Service};
use xet_server_meta_sqlite::SqliteMetadataStore;
use xet_server_storage_fs::FsBlobStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // tower_http::trace gives per-request access logs (`200 POST
                // /shards`); xet_server_http logs the JSON error body on every
                // 4xx/5xx so failures are visible without flipping RUST_LOG.
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

    let blobs = Arc::new(
        FsBlobStore::open(&data_root)
            .await
            .map_err(anyhow_from_core)?,
    );
    let meta = Arc::new(
        SqliteMetadataStore::open_path(&db_path)
            .await
            .map_err(anyhow_from_core)?,
    );

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, data_root = %data_root.display(), %public_url, "xet-server up");

    // Build the router with the selected authz impl, then serve. Service is
    // generic over A, so the two branches duplicate the build but everything
    // else (blobs, meta, transfer_secret) is shared.
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
            public_base_url: public_url.clone(),
        };
        axum::serve(listener, router(svc)).await?;
    } else {
        let mut authz = ConfigAuthz::new(jwt_secret);
        if let Ok(raw) = env::var("XET_GRANTS") {
            for tuple in raw.split(',').filter(|s| !s.is_empty()) {
                let parts: Vec<&str> = tuple.split(':').collect();
                if parts.len() != 4 {
                    bail!(
                        "XET_GRANTS tuple must be 'hub_token:user:repo_id:scope' (got '{tuple}')"
                    );
                }
                let scope = match parts[3] {
                    "read" => Scope::Read,
                    "write" => Scope::Write,
                    other => bail!("invalid scope '{other}' in XET_GRANTS"),
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
            public_base_url: public_url.clone(),
        };
        axum::serve(listener, router(svc)).await?;
    }
    Ok(())
}

fn decode_hex_env(name: &str) -> Result<Vec<u8>> {
    let v = env::var(name).with_context(|| format!("{name} not set"))?;
    hex::decode(v.trim()).with_context(|| format!("{name} is not valid hex"))
}

fn anyhow_from_core(e: xet_server_core::CoreError) -> anyhow::Error {
    anyhow::anyhow!("core error: {e}")
}
