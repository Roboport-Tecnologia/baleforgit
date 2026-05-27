//! OpenTelemetry instrumentation for the HTTP layer.
//!
//! Every instrument is fetched from `opentelemetry::global` — when no provider
//! is installed (the default, e.g. when the binary was launched without
//! `OTEL_EXPORTER_OTLP_ENDPOINT`) the global no-op provider just drops the
//! samples on the floor. So this module is safe to wire in unconditionally;
//! the bin opts in by initialising the SDK side.

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

/// Per-request middleware. Reads the axum-matched route pattern out of the
/// request extensions so labels stay low-cardinality — falling back to a
/// literal "unmatched" rather than the raw URI (which would carry hashes /
/// owner names and blow the cardinality budget on Prometheus / Tempo).
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
