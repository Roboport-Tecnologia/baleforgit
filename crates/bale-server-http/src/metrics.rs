//! OpenTelemetry instrumentation for the HTTP layer. Safe to wire in
//! unconditionally: with no provider installed (no `OTEL_EXPORTER_OTLP_ENDPOINT`)
//! the global no-op provider drops every sample. The bin opts in via the SDK.

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::{global, KeyValue};
use std::sync::LazyLock;
use std::time::Instant;

const METER_NAME: &str = "bale-server-http";

static HTTP_REQUESTS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    global::meter(METER_NAME)
        .u64_counter("http.server.requests")
        .with_description("HTTP requests handled, labelled by method, matched route, and status.")
        .build()
});

static HTTP_DURATION: LazyLock<Histogram<f64>> = LazyLock::new(|| {
    global::meter(METER_NAME)
        .f64_histogram("http.server.duration")
        .with_unit("s")
        .with_description("Wall-clock request handling latency.")
        .build()
});

pub(crate) static XORBS_UPLOADED: LazyLock<Counter<u64>> = LazyLock::new(|| {
    global::meter(METER_NAME)
        .u64_counter("bale.xorbs.uploaded")
        .with_description("Xorb uploads accepted (POST /v1/xorbs/...).")
        .build()
});

pub(crate) static SHARDS_UPLOADED: LazyLock<Counter<u64>> = LazyLock::new(|| {
    global::meter(METER_NAME)
        .u64_counter("bale.shards.uploaded")
        .with_description("Shard uploads accepted (POST /shards).")
        .build()
});

pub(crate) static UPLOAD_BYTES: LazyLock<Counter<u64>> = LazyLock::new(|| {
    global::meter(METER_NAME)
        .u64_counter("bale.upload.bytes")
        .with_unit("By")
        .with_description("Body bytes accepted by upload endpoints, labelled by kind=xorb|shard.")
        .build()
});

pub(crate) static RECONSTRUCTIONS_SERVED: LazyLock<Counter<u64>> = LazyLock::new(|| {
    global::meter(METER_NAME)
        .u64_counter("bale.reconstructions.served")
        .with_description("Reconstruction responses successfully built (200 only).")
        .build()
});

// Labels with the axum-matched route pattern, not the raw URI: the URI carries
// hashes / owner names that would blow the metric cardinality budget.
pub async fn middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());

    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let elapsed = start.elapsed().as_secs_f64();

    HTTP_REQUESTS.add(
        1,
        &[
            KeyValue::new("http.request.method", method.clone()),
            KeyValue::new("http.route", route.clone()),
            KeyValue::new("http.response.status_code", i64::from(status)),
        ],
    );
    HTTP_DURATION.record(
        elapsed,
        &[
            KeyValue::new("http.request.method", method),
            KeyValue::new("http.route", route),
        ],
    );
    resp
}
