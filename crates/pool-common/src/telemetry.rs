//! Tracing subscriber, OpenTelemetry export and the panic hook. Port of
//! `services/session proxy/crates/common/src/telemetry.rs`.
//!
//! In `main`, in this order: load config, [`crate::sentry::init`], [`init`],
//! [`install_panic_hook`]. Hold the returned [`OtelGuard`] until the process
//! exits; dropping it flushes spans still buffered in the batch processor.
//!
//! HTTP servers call [`start_trace`] on their request span to join the
//! caller's trace and put its id on every log line of the request.
//!
//! # Environment variables
//!
//! | Variable | Default |
//! |---|---|
//! | `RUST_LOG` | `info` |
//! | `OTEL_ENABLED` (`1`, `true`, `yes`, `on`) | `false` |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` |
//! | `OTEL_TRACES_SAMPLER_ARG` | `0.1` |
//! | `ENVIRONMENT` | `dev` |
//!
//! Log format (JSON or text) comes from `Settings::json_logs`.

use std::borrow::Cow;
use std::io;

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
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt as _};

const DEFAULT_ENDPOINT: &str = "http://localhost:4317";
const DEFAULT_SAMPLE_RATIO: f64 = 0.1;

/// Held for the process lifetime; shuts down the OTel provider on drop.
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

fn otel_enabled() -> bool {
    std::env::var("OTEL_ENABLED").is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Hide the credentials of every URL in `text`: `scheme://user:pass@host`
/// becomes `scheme://***@host`. The user-info ends at the last `@`
/// before the first `/`, `?`, `#`, quote, backslash or white space after
/// `://`, so an unescaped `@` in a password does not leak its tail. Text
/// without a user-info comes back borrowed.
pub(crate) fn redact_userinfo(text: &str) -> Cow<'_, str> {
    const END: [char; 6] = ['/', '?', '#', '"', '\'', '\\'];
    let mut out: Option<String> = None;
    let mut done = 0;
    let mut search = 0;
    while let Some(found) = text[search..].find("://") {
        let start = search + found + 3;
        search = start;
        let scheme_len = text[..start - 3]
            .bytes()
            .rev()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            .count();
        if scheme_len == 0 {
            continue;
        }
        let authority_len = text[start..]
            .find(|c: char| c.is_whitespace() || END.contains(&c))
            .unwrap_or(text.len() - start);
        let Some(at) = text[start..start + authority_len].rfind('@') else {
            continue;
        };
        let out = out.get_or_insert_with(|| String::with_capacity(text.len()));
        out.push_str(&text[done..start]);
        out.push_str("***");
        done = start + at;
        search = done + 1;
    }
    match out {
        Some(mut out) => {
            out.push_str(&text[done..]);
            Cow::Owned(out)
        }
        None => Cow::Borrowed(text),
    }
}

/// A [`MakeWriter`] that passes each log record through [`redact_userinfo`]
/// before it reaches the inner writer. The fmt layer writes one record per
/// writer, so the writer buffers until it is flushed or dropped; redaction
/// then covers every field, the message and span fields, in text and JSON.
struct Redacted<M>(M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacted<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.0.make_writer(),
            buf: Vec::new(),
        }
    }
}

struct RedactingWriter<W: io::Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: io::Write> RedactingWriter<W> {
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.buf);
        match std::str::from_utf8(&buf) {
            Ok(text) => self.inner.write_all(redact_userinfo(text).as_bytes()),
            Err(_) => self.inner.write_all(&buf),
        }
    }
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.flush()
    }
}

impl<W: io::Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        // A failed log write has nowhere to be reported.
        let _ = self.emit();
    }
}

/// A fmt layer on redacted `out`, JSON or human-readable. Generic over the
/// subscriber so it goes onto any layered registry.
fn fmt_layer<S, W>(
    json: bool,
    out: W,
) -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let writer = Redacted(out);
    if json {
        Box::new(tracing_subscriber::fmt::layer().json().with_writer(writer))
    } else {
        Box::new(tracing_subscriber::fmt::layer().with_writer(writer))
    }
}

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

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            sample_ratio,
        ))))
        .with_resource(resource)
        .build())
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

/// Install the global tracing subscriber: `RUST_LOG` filter, Sentry layer
/// (ERROR is an event, WARN and INFO are breadcrumbs), the OTLP layer when
/// `OTEL_ENABLED` is set, and the fmt layer (JSON when `json`). Call once
/// per process, after [`crate::sentry::init`].
///
/// # Panics
/// When a global subscriber is already set.
pub fn init(service_name: &str, json: bool) -> Option<OtelGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let sentry_layer = sentry_layers();
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(sentry_layer);

    if !otel_enabled() {
        registry.with(fmt_layer(json, io::stdout)).init();
        return None;
    }
    match build_provider(service_name) {
        Ok(provider) => {
            let tracer = provider.tracer(service_name.to_owned());
            global::set_tracer_provider(provider.clone());
            registry
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .with(fmt_layer(json, io::stdout))
                .init();
            Some(OtelGuard { provider })
        }
        Err(e) => {
            // A broken trace pipeline must not stop the process: log only.
            registry.with(fmt_layer(json, io::stdout)).init();
            tracing::error!(error = ?e, "failed to build the OTel pipeline, continuing without traces");
            None
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

/// Log a panic as one ERROR line before the default hook runs. With
/// `panic = "abort"` the process dies right after, and the line is the only
/// trace in Loki and Sentry.
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "process panicked");
        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use super::*;

    #[test]
    fn url_credentials_are_hidden_and_the_rest_is_kept() {
        for (input, want) in [
            (
                "socks5://user:pass@10.1.2.3:1080",
                "socks5://***@10.1.2.3:1080",
            ),
            ("http://tok@host/path?q=a@b", "http://***@host/path?q=a@b"),
            // an unescaped `@` in the password must not leak its tail
            ("http://u:p@ss@host:8", "http://***@host:8"),
            (
                "a https://u:p@a.test/x and socks5h://v:w@b.test:1 end",
                "a https://***@a.test/x and socks5h://***@b.test:1 end",
            ),
            (r#"{"url":"http://u:p@h\"}"#, r#"{"url":"http://***@h\"}"#),
            // no user-info, or not a URL: unchanged
            ("http://host:80/a@b", "http://host:80/a@b"),
            (
                "mail me at a@b.test, see ://x@y",
                "mail me at a@b.test, see ://x@y",
            ),
            // multi-byte text around and inside the user-info
            ("ü socks5://üser:pä@höst/ ü", "ü socks5://***@höst/ ü"),
        ] {
            assert_eq!(redact_userinfo(input), want, "{input}");
        }
        assert!(matches!(
            redact_userinfo("nothing to hide"),
            Cow::Borrowed(_)
        ));
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Sink {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        fn text(&self) -> String {
            let bytes = self.0.lock().clone();
            String::from_utf8(bytes).expect("utf-8 log output")
        }
    }

    /// Log through the same layer stack as `init` (minus the global install)
    /// and return what reached the sink.
    fn logged(json: bool) -> String {
        let sink = Sink::default();
        let writer = sink.clone();
        let subscriber =
            tracing_subscriber::registry().with(fmt_layer(json, move || writer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let url = "socks5://acct-1:hunter2@203.0.113.7:1080";
            let span = tracing::info_span!("proxyx.test.span", upstream = %url);
            let _enter = span.enter();
            tracing::warn!(upstream = %url, debug_url = ?url, plain = 7, "dial {url} failed");
            tracing::info!("second record, no secret");
        });
        sink.text()
    }

    #[test]
    fn no_log_line_carries_url_credentials_in_text_or_json() {
        for json in [false, true] {
            let out = logged(json);
            for secret in ["acct-1", "hunter2"] {
                assert!(!out.contains(secret), "json={json}: {out}");
            }
            // the host survives, so the line is still useful
            assert!(
                out.contains("socks5://***@203.0.113.7:1080"),
                "json={json}: {out}"
            );
            assert!(
                out.contains("second record, no secret"),
                "json={json}: {out}"
            );
            assert_eq!(out.lines().count(), 2, "one line per record: {out}");
        }
    }

    /// Run `start_trace` on a fresh span under a JSON log layer, with or
    /// without the OTel layer, and return the log line written inside it.
    fn logged_in_started_trace(otel: bool, traceparent: Option<&str>) -> String {
        let sink = Sink::default();
        let writer = sink.clone();
        let provider = SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(otel.then(|| tracing_opentelemetry::layer().with_tracer(provider.tracer("test"))))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(move || writer.clone()),
            );
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("proxyx.test.request", trace_id = tracing::field::Empty);
            start_trace(&span, traceparent);
            let _enter = span.enter();
            tracing::info!("inside the span");
        });
        sink.text()
    }

    #[test]
    fn a_span_joins_the_callers_trace_and_logs_its_id() {
        let out = logged_in_started_trace(
            true,
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        assert!(
            out.contains(r#""trace_id":"4bf92f3577b34da6a3ce929d0e0e4736""#),
            "{out}"
        );
    }

    #[test]
    fn without_otel_the_span_gets_no_trace_id() {
        let out = logged_in_started_trace(
            false,
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        assert!(out.contains("inside the span"), "{out}");
        assert!(!out.contains("trace_id"), "{out}");
    }
}
