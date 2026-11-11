//! Test support: capture finished OTel spans in memory.

use std::future::Future;
use std::sync::Arc;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use parking_lot::Mutex;
use tracing_subscriber::layer::SubscriberExt as _;

/// Finished spans, in the order they ended.
#[derive(Debug, Clone, Default)]
pub struct Spans(Arc<Mutex<Vec<SpanData>>>);

impl Spans {
    pub fn take(&self) -> Vec<SpanData> {
        std::mem::take(&mut *self.0.lock())
    }
}

impl SpanExporter for Spans {
    fn export(&self, batch: Vec<SpanData>) -> impl Future<Output = OTelSdkResult> + Send {
        self.0.lock().extend(batch);
        std::future::ready(Ok(()))
    }
}

/// Install a thread-local subscriber that exports every span into the
/// returned [`Spans`]. Hold the guard for the whole test. Use a
/// current-thread runtime so spawned tasks see the same subscriber.
pub fn capture() -> (Spans, tracing::subscriber::DefaultGuard) {
    let spans = Spans::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(spans.clone())
        .build();
    let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    (spans, guard)
}

/// String value of attribute `key` on `span`, if present.
pub fn attr(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.to_string())
}
