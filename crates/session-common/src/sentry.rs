use sentry::ClientInitGuard;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SentryConfig {
    pub dsn: Option<String>,
    pub environment: Option<String>,
    pub release: Option<String>,
    pub sample_rate: f32,
    pub traces_sample_rate: f32,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            dsn: None,
            environment: None,
            release: None,
            sample_rate: 1.0,
            traces_sample_rate: 0.0,
        }
    }
}

/// The SDK refuses a rate outside 0.0 to 1.0 by panicking; keep a bad
/// configuration value from aborting the process.
fn unit_rate(rate: f32, fallback: f32) -> f32 {
    if rate.is_nan() {
        fallback
    } else {
        rate.clamp(0.0, 1.0)
    }
}

/// Initialize Sentry. Returns guard that must be held until shutdown.
/// If DSN is None, returns None (no-op for local dev).
pub fn init(config: &SentryConfig, service_name: &str) -> Option<ClientInitGuard> {
    let dsn = config.dsn.as_ref()?;

    let environment = config
        .environment
        .clone()
        .unwrap_or_else(|| "development".into());

    let release = config
        .release
        .clone()
        .or_else(|| option_env!("CARGO_PKG_VERSION").map(String::from));

    let mut options = sentry::ClientOptions::new()
        .environment(environment)
        .maybe_release(release)
        .sample_rate(unit_rate(config.sample_rate, 1.0))
        .attach_stacktrace(true)
        .send_default_pii(false);
    // Left unset, traces stay disabled; an explicit 0.0 would still build
    // unsampled transactions for every span.
    let traces_rate = unit_rate(config.traces_sample_rate, 0.0);
    if traces_rate > 0.0 {
        options = options.traces_sample_rate(traces_rate);
    }
    let guard = sentry::init((dsn.as_str(), options));

    sentry::configure_scope(|scope| {
        scope.set_tag("service", service_name);
    });

    Some(guard)
}
