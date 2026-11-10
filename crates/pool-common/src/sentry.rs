//! Sentry error reporting. Call [`init`] first in `main` (before
//! [`crate::telemetry::init`], whose `sentry_tracing` layer needs the client)
//! and keep the guard until exit.

use std::borrow::Cow;
use std::sync::Arc;

use sentry::ClientInitGuard;
use sentry::protocol::{Event, Value};
use serde::Deserialize;

use crate::secret::Secret;
use crate::telemetry::redact_userinfo;

fn redact(text: &mut String) {
    if let Cow::Owned(redacted) = redact_userinfo(text) {
        *text = redacted;
    }
}

fn redact_value(value: &mut Value) {
    match value {
        Value::String(text) => redact(text),
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::Object(fields) => fields.values_mut().for_each(redact_value),
        _ => {}
    }
}

/// Hide URL credentials in everything a log record put on a Sentry event
///: the message, exception texts, breadcrumbs and extra fields.
fn scrub(mut event: Event<'static>) -> Option<Event<'static>> {
    if let Some(message) = &mut event.message {
        redact(message);
    }
    if let Some(entry) = &mut event.logentry {
        redact(&mut entry.message);
    }
    for exception in &mut event.exception.values {
        if let Some(value) = &mut exception.value {
            redact(value);
        }
    }
    for crumb in &mut event.breadcrumbs.values {
        if let Some(message) = &mut crumb.message {
            redact(message);
        }
        crumb.data.values_mut().for_each(redact_value);
    }
    event.extra.values_mut().for_each(redact_value);
    Some(event)
}

/// Env: `PROXYX_POOL_SENTRY__<FIELD>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SentryConfig {
    /// Without a DSN Sentry stays off (local development). Env:
    /// `PROXYX_POOL_SENTRY__DSN`.
    pub dsn: Option<Secret>,
    /// Environment tag of the events (default: `development`). Env:
    /// `PROXYX_POOL_SENTRY__ENVIRONMENT`.
    pub environment: Option<String>,
    /// Release tag of the events (default: the crate version). Env:
    /// `PROXYX_POOL_SENTRY__RELEASE`.
    pub release: Option<String>,
    /// Share of error events sent, 0.0 to 1.0 (default: `1.0`). Env:
    /// `PROXYX_POOL_SENTRY__SAMPLE_RATE`.
    pub sample_rate: f32,
    /// Share of transactions sent, 0.0 to 1.0 (default: `0.0`; traces go to
    /// OTel). Env: `PROXYX_POOL_SENTRY__TRACES_SAMPLE_RATE`.
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

impl SentryConfig {
    /// Refuse what `sentry::init` would panic on (a malformed DSN aborts the
    /// process) or silently misuse (a rate outside 0.0 to 1.0). An empty DSN
    /// leaves Sentry off, as in `sentry::init`. The error never shows the DSN.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(dsn) = self.dsn.as_ref().filter(|dsn| !dsn.is_empty()) {
            dsn.expose()
                .parse::<sentry::types::Dsn>()
                .map_err(|err| anyhow::anyhow!("sentry.dsn is not a valid DSN: {err}"))?;
        }
        for (name, rate) in [
            ("sample_rate", self.sample_rate),
            ("traces_sample_rate", self.traces_sample_rate),
        ] {
            anyhow::ensure!(
                (0.0..=1.0).contains(&rate),
                "sentry.{name} must be between 0.0 and 1.0, got {rate}"
            );
        }
        Ok(())
    }
}

/// Initialize Sentry. The guard flushes pending events when dropped.
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
        dsn.expose(),
        sentry::ClientOptions {
            release: release.map(Into::into),
            environment: Some(environment.into()),
            sample_rate: config.sample_rate,
            traces_sample_rate: config.traces_sample_rate,
            attach_stacktrace: true,
            send_default_pii: false,
            before_send: Some(Arc::new(scrub)),
            ..Default::default()
        },
    ));

    sentry::configure_scope(|scope| {
        scope.set_tag("service", service_name);
    });

    Some(guard)
}

#[cfg(test)]
mod tests {
    use sentry::protocol::{Breadcrumb, Exception};

    use super::*;

    #[test]
    fn sentry_events_lose_url_credentials_everywhere() {
        let url = "http://acct:hunter2@203.0.113.7:8080";
        let mut event = Event {
            message: Some(format!("dial {url} failed")),
            ..Event::default()
        };
        event.exception.values.push(Exception {
            value: Some(format!("error sending to {url}")),
            ..Exception::default()
        });
        event.breadcrumbs.values.push(Breadcrumb {
            message: Some(url.to_owned()),
            data: [(
                "nested".to_owned(),
                Value::Array(vec![Value::String(url.into())]),
            )]
            .into(),
            ..Breadcrumb::default()
        });
        event
            .extra
            .insert("upstream".into(), Value::String(url.into()));

        let scrubbed = scrub(event).expect("event is kept");
        let text = format!("{scrubbed:?}");
        assert!(
            !text.contains("hunter2") && !text.contains("acct"),
            "{text}"
        );
        assert_eq!(
            scrubbed.message.as_deref(),
            Some("dial http://***@203.0.113.7:8080 failed")
        );
    }

    #[test]
    fn the_dsn_never_shows_in_debug_output() {
        let config = SentryConfig {
            dsn: Some(Secret::new("https://publickey@o1.ingest.sentry.io/42")),
            ..SentryConfig::default()
        };
        assert!(!format!("{config:?}").contains("publickey"));
    }
}
