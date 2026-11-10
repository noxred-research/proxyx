pub mod config;
pub mod log;
pub mod metrics;
pub mod redis_connect;
pub mod sentry;
pub mod telemetry;
pub mod types;

/// Generated wire types from `proto/proxyx.proto`.
///
/// `large_enum_variant` is suppressed because `request_log_message::Kind`
/// is prost-generated; the `Request(CapturedRequest)` variant is naturally
/// much larger than `SessionEnd(...)`. Boxing would require touching every
/// pattern-match site in proxy/API for no real benefit — the
/// envelope is constructed once per message and immediately encoded.
#[allow(clippy::large_enum_variant)]
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/proxyx.rs"));
}
