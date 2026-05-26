//! S3-compatible `BlobStore`. Object layout mirrors `xet-server-storage-fs`
//! (`<prefix>{xorbs,shards}/<aa>/<bb>/<full-hex>`) so the two backends can be
//! rsynced without translation. `presign_xorb_range` returns real S3
//! presigned URLs — reconstruction bytes then bypass our HTTP layer entirely.

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use bytes::Bytes;
use std::ops::Range;
use std::time::Duration;
use xet_server_core::{BlobStore, CoreError, CoreResult, Hash32, ShardHash, XorbHash};

/// Credentials fall back to the default AWS provider chain when
/// `access_key_id` + `secret_access_key` are unset. `prefix` is concatenated
/// verbatim — include a trailing `/` yourself if you want one.
#[derive(Clone, Debug, Default)]
pub struct S3Config {
    pub bucket: String,
    pub region: Option<String>,
    pub endpoint_url: Option<String>,
    /// Required for MinIO and similar backends that don't do virtual-host
    /// addressing.
    pub force_path_style: bool,
    pub prefix: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
}

pub struct S3BlobStore {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3BlobStore {
    pub async fn open(cfg: S3Config) -> CoreResult<Self> {
        if cfg.bucket.is_empty() {
            return Err(CoreError::Internal("S3 bucket must be non-empty".into()));
        }

        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(r) = cfg.region.clone() {
            loader = loader.region(Region::new(r));
        }
        if let Some(ep) = cfg.endpoint_url.clone() {
            loader = loader.endpoint_url(ep);
        }
        if let (Some(ak), Some(sk)) = (cfg.access_key_id.clone(), cfg.secret_access_key.clone()) {
            let creds = Credentials::new(ak, sk, cfg.session_token.clone(), None, "xet-server-cfg");
            loader = loader.credentials_provider(creds);
        }
        let shared = loader.load().await;

        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if cfg.force_path_style {
            builder = builder.force_path_style(true);
        }
        let client = Client::from_conf(builder.build());

        let store = Self {
            client,
            bucket: cfg.bucket,
            prefix: cfg.prefix,
        };

        // Non-fatal startup probe — lets dev loops boot against a bucket the
        // operator hasn't pre-created.
        if let Err(e) = store
            .client
            .head_bucket()
            .bucket(&store.bucket)
            .send()
            .await
        {
            tracing::warn!(
                bucket = %store.bucket,
                error = %display_sdk_error(&e),
                "S3 head_bucket failed at startup — uploads may fail"
            );
        }

        Ok(store)
    }

    fn fanout(prefix: &str, kind: &str, hash: &Hash32) -> String {
        let hex = hex::encode(hash.as_bytes());
        format!("{prefix}{kind}/{}/{}/{}", &hex[0..2], &hex[2..4], hex)
    }

    fn xorb_key(&self, hash: &XorbHash) -> String {
        Self::fanout(&self.prefix, "xorbs", &hash.0)
    }

    fn shard_key(&self, hash: &ShardHash) -> String {
        Self::fanout(&self.prefix, "shards", &hash.0)
    }

    async fn object_exists(&self, key: &str) -> CoreResult<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if is_not_found_head(&e) {
                    Ok(false)
                } else {
                    Err(CoreError::Internal(format!(
                        "s3 head_object {key}: {}",
                        display_sdk_error(&e)
                    )))
                }
            }
        }
    }

    async fn put_object(&self, key: &str, body: Bytes) -> CoreResult<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| {
                CoreError::Internal(format!("s3 put_object {key}: {}", display_sdk_error(&e)))
            })?;
        Ok(())
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put_xorb(&self, hash: &XorbHash, body: Bytes) -> CoreResult<bool> {
        let key = self.xorb_key(hash);
        // Two racers can both see "not exists" and both PUT — benign because
        // the body is content-addressed and the handler verified it upstream.
        if self.object_exists(&key).await? {
            return Ok(false);
        }
        self.put_object(&key, body).await?;
        Ok(true)
    }

    async fn xorb_exists(&self, hash: &XorbHash) -> CoreResult<bool> {
        self.object_exists(&self.xorb_key(hash)).await
    }

    async fn get_xorb_range(&self, hash: &XorbHash, byte_range: Range<u64>) -> CoreResult<Bytes> {
        if byte_range.end < byte_range.start {
            return Err(CoreError::BadRequest("inverted byte range".into()));
        }
        if byte_range.end == byte_range.start {
            return Ok(Bytes::new());
        }
        let key = self.xorb_key(hash);
        // S3 `Range:` is inclusive on both ends; our trait is half-open.
        let range_header = format!("bytes={}-{}", byte_range.start, byte_range.end - 1);
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .range(range_header)
            .send()
            .await
            .map_err(|e| {
                if is_not_found_get(&e) {
                    CoreError::NotFound
                } else {
                    CoreError::Internal(format!("s3 get_object {key}: {}", display_sdk_error(&e)))
                }
            })?;
        let agg = resp
            .body
            .collect()
            .await
            .map_err(|e| CoreError::Internal(format!("s3 body collect: {e}")))?;
        Ok(agg.into_bytes())
    }

    async fn put_shard(&self, hash: &ShardHash, body: Bytes) -> CoreResult<()> {
        let key = self.shard_key(hash);
        if self.object_exists(&key).await? {
            return Ok(());
        }
        self.put_object(&key, body).await
    }

    async fn get_shard(&self, hash: &ShardHash) -> CoreResult<Bytes> {
        let key = self.shard_key(hash);
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                if is_not_found_get(&e) {
                    CoreError::NotFound
                } else {
                    CoreError::Internal(format!("s3 get_object {key}: {}", display_sdk_error(&e)))
                }
            })?;
        let agg = resp
            .body
            .collect()
            .await
            .map_err(|e| CoreError::Internal(format!("s3 body collect: {e}")))?;
        Ok(agg.into_bytes())
    }

    async fn presign_xorb_range(
        &self,
        hash: &XorbHash,
        byte_range: Range<u64>,
        ttl: Duration,
    ) -> CoreResult<Option<String>> {
        if byte_range.end < byte_range.start {
            return Err(CoreError::BadRequest("inverted byte range".into()));
        }
        // Range header is part of the SigV4 payload; the client MUST replay
        // this exact value or S3 returns SignatureDoesNotMatch.
        let range_header = format!("bytes={}-{}", byte_range.start, byte_range.end - 1);
        let cfg = PresigningConfig::expires_in(ttl)
            .map_err(|e| CoreError::Internal(format!("s3 presign config (ttl={ttl:?}): {e}")))?;
        let req = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.xorb_key(hash))
            .range(range_header)
            .presigned(cfg)
            .await
            .map_err(|e| CoreError::Internal(format!("s3 presign: {}", display_sdk_error(&e))))?;
        Ok(Some(req.uri().to_string()))
    }
}

fn is_not_found_head<T>(err: &SdkError<HeadObjectError, T>) -> bool {
    matches!(err, SdkError::ServiceError(svc) if matches!(svc.err(), HeadObjectError::NotFound(_)))
}

fn is_not_found_get<T>(
    err: &SdkError<aws_sdk_s3::operation::get_object::GetObjectError, T>,
) -> bool {
    use aws_sdk_s3::operation::get_object::GetObjectError;
    matches!(err, SdkError::ServiceError(svc) if matches!(svc.err(), GetObjectError::NoSuchKey(_)))
}

/// SdkError's own Display is a generic blurb; the inner service error has
/// the real "AccessDenied" / "NoSuchBucket" text.
fn display_sdk_error<E: std::fmt::Display, R>(err: &SdkError<E, R>) -> String {
    match err {
        SdkError::ServiceError(svc) => format!("service error: {}", svc.err()),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xet_server_core::Hash32;

    #[test]
    fn xorb_key_uses_two_byte_fanout() {
        let store = S3BlobStore {
            client: stub_client(),
            bucket: "b".into(),
            prefix: "p/".into(),
        };
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let key = store.xorb_key(&XorbHash(Hash32(bytes)));
        assert_eq!(
            key,
            "p/xorbs/ab/cd/abcd000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn shard_key_uses_two_byte_fanout() {
        let store = S3BlobStore {
            client: stub_client(),
            bucket: "b".into(),
            prefix: String::new(),
        };
        let mut bytes = [0u8; 32];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        let key = store.shard_key(&ShardHash(Hash32(bytes)));
        assert!(key.starts_with("shards/12/34/1234"));
    }

    #[test]
    fn empty_prefix_does_not_add_leading_slash() {
        let store = S3BlobStore {
            client: stub_client(),
            bucket: "b".into(),
            prefix: String::new(),
        };
        let key = store.xorb_key(&XorbHash(Hash32::ZERO));
        assert!(key.starts_with("xorbs/00/00/"));
    }

    fn stub_client() -> Client {
        let creds = Credentials::new("AKIA0", "0", None, None, "test");
        let cfg = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .build();
        Client::from_conf(cfg)
    }
}
