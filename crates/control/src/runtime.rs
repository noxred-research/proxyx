use crate::config::ControlConfig;

/// Guards returned by [`init_process`]. Must be held until the process exits.
pub struct ProcessGuard {
    _sentry: Option<sentry::ClientInitGuard>,
    _otel: Option<common::telemetry::OtelGuard>,
}

/// One-shot process initialisation: Sentry, tracing subscriber, OTel pipeline,
/// and rustls crypto provider.
///
/// Hold the returned [`ProcessGuard`] for the lifetime of the process —
/// dropping it flushes buffered OTel spans and closes the Sentry transport.
pub fn init_process(config: &ControlConfig, service_name: &str) -> ProcessGuard {
    let sentry_guard = common::sentry::init(&config.sentry, service_name);
    // telemetry::init sets up the global tracing subscriber (including the
    // sentry-tracing layer), so it must come after common::sentry::init.
    let otel_guard = common::telemetry::init(&format!("proxyx-{service_name}"));
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider already installed; continuing");
    }
    ProcessGuard {
        _sentry: sentry_guard,
        _otel: otel_guard,
    }
}

pub fn clickhouse_client(
    config: &crate::pipeline::clickhouse::ClickHouseConfig,
) -> clickhouse::Client {
    let mut client = clickhouse::Client::default().with_url(&config.url);
    if let Some(ref db) = config.database {
        client = client.with_database(db);
    }
    if let Some(ref user) = config.user {
        client = client.with_user(user);
    }
    if let Some(ref password) = config.password {
        client = client.with_password(password);
    }
    client
}
