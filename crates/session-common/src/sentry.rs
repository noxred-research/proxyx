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

    let guard = sentry::init((
        dsn.as_str(),
        sentry::ClientOptions {
            release: release.map(Into::into),
            environment: Some(environment.into()),
            sample_rate: config.sample_rate,
            traces_sample_rate: config.traces_sample_rate,
            attach_stacktrace: true,
            send_default_pii: false,
            ..Default::default()
        },
    ));

    sentry::configure_scope(|scope| {
        scope.set_tag("service", service_name);
    });

    Some(guard)
}
