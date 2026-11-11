//! `proxyx gateway | warmer | migrate pool`: the pool gateway roles.
//!
//! Wiring only: load configuration, initialise error reporting and tracing
//! (in that order), then run one role until SIGTERM.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context as _;
use common::config::Settings;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

use crate::{exit_ip, migrate, roles};

/// A pool role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Serve tunnels (CONNECT, SOCKS5, probe) and the control API.
    Gateway,
    /// Keep the ready pools, static inventory and quality checks healthy.
    Warmer,
    /// Apply the Postgres migrations; with `check`, report pending ones and
    /// fail instead of applying them.
    Migrate { check: bool },
}

impl Role {
    /// Fallback of `SERVICE_NAME`: the `service` metric label, trace service
    /// and Sentry tag.
    pub fn default_service(self) -> &'static str {
        match self {
            Self::Gateway => "proxyx-gateway",
            Self::Warmer => "proxyx-warmer",
            Self::Migrate { .. } => "proxyx-migrate",
        }
    }
}

/// Run `role` with the settings of `config` (overrides `PROXYX_POOL_*`).
pub async fn run(config: Option<&Path>, role: Role) -> anyhow::Result<ExitCode> {
    let settings = Settings::load(config)?;
    let service =
        std::env::var("SERVICE_NAME").unwrap_or_else(|_| role.default_service().to_owned());

    let _sentry_guard = common::sentry::init(&settings.sentry, &service);
    let _otel_guard = common::telemetry::init(&service, settings.json_logs);
    common::telemetry::install_panic_hook();

    let cancel = CancellationToken::new();
    let served = match role {
        Role::Migrate { check } => {
            migrate::run(&settings, check).await?;
            return Ok(ExitCode::SUCCESS);
        }
        Role::Gateway => {
            let checks = exit_ip::config(settings.exit_ip_services.as_deref())?;
            roles::check_fd_limit(&settings)?;
            stop_on_signal(&cancel);
            roles::gateway(settings, &service, checks, cancel).await
        }
        Role::Warmer => {
            let checks = exit_ip::config(settings.exit_ip_services.as_deref())?;
            stop_on_signal(&cancel);
            roles::warmer(settings, &service, checks, cancel).await
        }
    };
    // Logged here and nowhere below, so a failure appears once, with its chain.
    Ok(match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = ?err, "proxyx stopped with an error");
            ExitCode::FAILURE
        }
    })
}

/// Cancel `cancel` on SIGTERM (Kubernetes) or ctrl-c (a terminal). A role that
/// is already stopping ignores the signal.
fn stop_on_signal(cancel: &CancellationToken) {
    let cancel = cancel.clone();
    tokio::spawn(async move {
        if let Err(err) = signalled().await {
            tracing::error!(error = ?err, "signal handling failed, stopping");
        }
        cancel.cancel();
    });
}

async fn signalled() -> anyhow::Result<()> {
    let mut term = signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    tokio::select! {
        _ = term.recv() => tracing::info!("sigterm received, shutting down"),
        res = tokio::signal::ctrl_c() => {
            res.context("failed to listen for ctrl-c")?;
            tracing::info!("ctrl-c received, shutting down");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Role;

    /// The real `service` label of the roles is what the metrics docs show, so
    /// the docs cannot drift from `SERVICE_NAME`'s fallback.
    #[test]
    fn the_default_service_names_are_the_ones_the_docs_use() {
        assert_eq!(Role::Gateway.default_service(), "proxyx-gateway");
        assert_eq!(Role::Warmer.default_service(), "proxyx-warmer");
        let docs = include_str!("../../../docs/metrics/pool.md");
        for name in ["proxyx-gateway", "proxyx-warmer"] {
            assert!(
                docs.contains(name),
                "docs/metrics/pool.md does not name {name}"
            );
        }
    }
}
