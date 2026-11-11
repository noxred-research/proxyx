//! OpenTelemetry initialisation for ProxyX processes.
//!
//! Call [`init`] once per process, immediately after [`crate::sentry::init`].
//! Hold the returned [`OtelGuard`] until the process exits — dropping it
//! flushes any spans still buffered in the [`BatchSpanProcessor`].
//!
//! Gated on `OTEL_ENABLED=true|1|yes|on`.  When the env var is absent or
//! falsy this function is a no-op and returns `None`.
//!
//! # Environment variables
//!
//! | Variable | Default |
//! |---|---|
//! | `OTEL_ENABLED` | `false` |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` |
//! | `OTEL_TRACES_SAMPLER_ARG` | `0.1` |
//! | `ENVIRONMENT` | `dev` |
//! | `PROXYX_LOG_JSON` | `false` |

use opentelemetry::{
    global,
    propagation::TextMapPropagator as _,
    trace::{TraceContextExt as _, TracerProvider as _},
};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};
use sentry_tracing::{BreadcrumbLayer, ErrorLayer, SpanLayer};
use tracing::Level;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::filter::{LevelFilter, filter_fn};
use tracing_subscriber::layer::{Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt as _};

const DEFAULT_ENDPOINT: &str = "http://localhost:4317";
const DEFAULT_SAMPLE_RATIO: f64 = 0.1;

/// Held for the process lifetime; shuts down the OTel [`SdkTracerProvider`] on drop.
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("OTel provider shutdown error: {e}");
        }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

/// Build a fmt layer that is either JSON or human-readable depending on
/// `PROXYX_LOG_JSON`.  Generic over the subscriber `S` so it can be pushed
/// onto any layered registry without boxing the outer type.
fn fmt_layer<S>() -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    if env_bool("PROXYX_LOG_JSON", false) {
        Box::new(tracing_subscriber::fmt::layer().json())
    } else {
        Box::new(tracing_subscriber::fmt::layer())
    }
}

/// Construct and register an OTLP [`SdkTracerProvider`].
///
/// Returns the provider so the caller can both use it and hold it for
/// orderly shutdown.
fn build_provider(service_name: &str) -> anyhow::Result<SdkTracerProvider> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_owned());

    let sample_ratio: f64 = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SAMPLE_RATIO);

    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "dev".to_owned());

    let resource = Resource::builder()
        .with_attributes([
            opentelemetry::KeyValue::new("service.name", service_name.to_owned()),
            opentelemetry::KeyValue::new("service.namespace", "proxyx"),
            opentelemetry::KeyValue::new("deployment.environment", environment),
        ])
        .build();

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            sample_ratio,
        ))))
        .with_resource(resource)
        .build();

    Ok(provider)
}

/// Sentry layers: ERROR is an error event, WARN and INFO are breadcrumbs on
/// later events, and spans down to INFO feed Sentry traces (sent only at a
/// non-zero `traces_sample_rate`). The breadcrumb layer goes first so it
/// never sees ERROR, which the error layer owns.
fn sentry_layers<S>() -> Vec<Box<dyn Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    vec![
        SpanLayer::new().with_filter(LevelFilter::INFO).boxed(),
        BreadcrumbLayer::new()
            .with_filter(filter_fn(|meta| {
                matches!(*meta.level(), Level::WARN | Level::INFO)
            }))
            .boxed(),
        ErrorLayer::new().with_filter(LevelFilter::ERROR).boxed(),
    ]
}

/// Initialise the tracing subscriber and, when `OTEL_ENABLED` is set,
/// the OTLP trace pipeline.
///
/// Must be called **after** [`crate::sentry::init`] so that the Sentry SDK
/// is configured before the `sentry_tracing` layer is attached.
///
/// # Panics
///
/// Panics if the global tracing subscriber has already been set (i.e. if
/// called more than once per process).
pub fn init(service_name: &str) -> Option<OtelGuard> {
    init_with_default(service_name, "info")
}

/// Like [`init`] but allows overriding the default log level.
pub fn init_with_default(service_name: &str, default_level: &str) -> Option<OtelGuard> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    let sentry_layer = sentry_layers();

    if !env_bool("OTEL_ENABLED", false) {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(sentry_layer)
            .with(fmt_layer())
            .init();
        return None;
    }

    match build_provider(service_name) {
        Err(e) => {
            // OTel pipeline failed to build — fall back to logging-only subscriber
            // rather than crashing the process.
            eprintln!("OTel init failed (continuing without traces): {e}");
            tracing_subscriber::registry()
                .with(env_filter)
                .with(sentry_layer)
                .with(fmt_layer())
                .init();
            None
        }
        Ok(provider) => {
            let tracer = provider.tracer(service_name.to_owned());
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            global::set_tracer_provider(provider.clone());

            tracing_subscriber::registry()
                .with(env_filter)
                .with(sentry_layer)
                .with(otel_layer)
                .with(fmt_layer())
                .init();

            Some(OtelGuard { provider })
        }
    }
}

/// Prepare a root span: join the caller's trace when `traceparent` (a W3C
/// `traceparent` header value) is given, then record the OTel trace id in
/// the span's `trace_id` field. The span must declare
/// `trace_id = tracing::field::Empty`; JSON log lines inside it then carry
/// the id, so Grafana can jump from Loki to Tempo.
///
/// Does nothing visible when OTel is disabled (the trace id is invalid).
pub fn start_trace(span: &tracing::Span, traceparent: Option<&str>) {
    if let Some(traceparent) = traceparent {
        let carrier =
            std::collections::HashMap::from([("traceparent".to_owned(), traceparent.to_owned())]);
        // OTel may be disabled or this span may be filtered out.
        let _ = span.set_parent(TraceContextPropagator::new().extract(&carrier));
    }
    let trace_id = span.context().span().span_context().trace_id();
    if trace_id != opentelemetry::trace::TraceId::INVALID {
        span.record("trace_id", tracing::field::display(trace_id));
    }
}
