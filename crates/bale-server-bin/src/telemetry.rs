//! Without `OTEL_EXPORTER_OTLP_ENDPOINT` (or its `_TRACES_` / `_METRICS_`
//! siblings) no provider is installed globally and every instrument in the
//! workspace becomes a no-op — that's the "do nothing without a collector" contract.
//!
//! The exporter uses the **blocking** reqwest client (see the `opentelemetry-otlp`
//! features in the root `Cargo.toml`): the batch processor and reader export from
//! a dedicated OS thread with no Tokio reactor, where the async client would panic
//! with "no reactor running" and silently drop every span/metric.

use anyhow::{Context, Result};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{MetricExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Flushes the providers on drop so in-flight spans/metrics reach the collector.
#[must_use = "drop this at process exit to flush OTLP exporters"]
pub struct Guard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(tp) = self.tracer_provider.take() {
            let _ = tp.shutdown();
        }
        if let Some(mp) = self.meter_provider.take() {
            let _ = mp.shutdown();
        }
    }
}

const DEFAULT_FILTER: &str = "info,sqlx=warn,tower_http::trace=info,bale_server_http=info";

pub fn init(service_name: &str) -> Result<Guard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let fmt_layer = tracing_subscriber::fmt::layer();

    // Per OTel spec: a per-signal var beats the generic one; empty counts as unset.
    let traces_endpoint = signal_endpoint("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "/v1/traces");
    let metrics_endpoint = signal_endpoint("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "/v1/metrics");

    if traces_endpoint.is_none() && metrics_endpoint.is_none() {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .init();
        tracing::info!(
            "OTEL_EXPORTER_OTLP_ENDPOINT unset; OpenTelemetry exporters disabled (no-op)"
        );
        return Ok(Guard {
            tracer_provider: None,
            meter_provider: None,
        });
    }

    // OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES (read by the Resource builder)
    // win over this fallback.
    let resource = Resource::builder()
        .with_service_name(service_name.to_string())
        .build();

    let mut guard = Guard {
        tracer_provider: None,
        meter_provider: None,
    };

    if let Some(endpoint) = traces_endpoint.as_deref() {
        let exporter = SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::HttpBinary)
            .build()
            .context("building OTLP span exporter")?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource.clone())
            .build();
        global::set_tracer_provider(provider.clone());
        guard.tracer_provider = Some(provider);
    }

    if let Some(endpoint) = metrics_endpoint.as_deref() {
        let exporter = MetricExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::HttpBinary)
            .build()
            .context("building OTLP metric exporter")?;
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();
        global::set_meter_provider(provider.clone());
        guard.meter_provider = Some(provider);
    }

    // Bridge tracing → OTel only when a tracer provider was installed.
    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);
    if let Some(tp) = guard.tracer_provider.as_ref() {
        let tracer = tp.tracer(service_name.to_string());
        registry
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .init();
    } else {
        registry.init();
    }

    tracing::info!(
        traces = ?traces_endpoint,
        metrics = ?metrics_endpoint,
        "OpenTelemetry OTLP exporters initialized"
    );

    Ok(guard)
}

/// Per-signal var verbatim, else the base endpoint + `signal_path`, per the OTLP/HTTP spec.
fn signal_endpoint(per_signal_var: &str, signal_path: &str) -> Option<String> {
    if let Ok(v) = env::var(per_signal_var) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    let base = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok()?;
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    Some(format!("{}{}", base.trim_end_matches('/'), signal_path))
}
