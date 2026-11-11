//! Shared state of the control API.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use common::Secret;
use common::config::{Settings, read_secret_file};
use common::metrics::Metrics;
use common::types::OrgId;
use store::loaded::Loaded;
use store::{BlockScope, Db, Hot};
use tokio::sync::watch;
use verify::ExitIpChecker;

/// File in `settings.secrets_dir` with the prober's bearer token.
const PROBER_TOKEN_FILE: &str = "prober-token";

/// What the API needs from the gateway's open-tunnel registry.
pub trait TunnelControl: Send + Sync {
    /// Ask the open tunnels of `org` inside `scope` to close; returns how
    /// many were asked.
    fn close_org_scope(&self, org: &OrgId, scope: &BlockScope) -> usize;
}

impl TunnelControl for gateway::Tunnels {
    fn close_org_scope(&self, org: &OrgId, scope: &BlockScope) -> usize {
        gateway::Tunnels::close_org_scope(self, org, scope)
    }
}

/// State of the `/v1` routes, shared behind an `Arc`.
pub struct ApiState {
    pub(crate) db: Db,
    pub(crate) hot: Hot,
    /// Policies, adapters and the snapshot of the last good reload.
    pub(crate) loaded: watch::Receiver<Arc<Loaded>>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) tunnels: Arc<dyn TunnelControl>,
    /// Org whose policy supplies the block and criteria rules for signals
    /// that belong to no org (operator reports, canaries).
    pub(crate) probe_org: OrgId,
    /// Where the git data lives (`settings.data_dir`): a policy delete asks
    /// which policies git defines.
    pub(crate) data_dir: PathBuf,
    /// Checks a customer upstream's exit IP (`validate`, `rotate-secret`).
    pub(crate) exit_ip: ExitIpChecker,
    pub(crate) admin_token: Secret,
    pub(crate) prober_token: Secret,
    /// Signs the probe listener's tokens (`POST /v1/probe/token`); `None`
    /// when no `probe-key` is mounted (no prober in this environment).
    pub(crate) probe_secret: Option<Secret>,
    /// Wrong-credential counts per source ([`crate::auth`]).
    pub(crate) failures: crate::auth::FailureLimiter,
}

impl ApiState {
    /// Read the admin token (`settings.admin_token_file`) and the prober
    /// token (`prober-token` in the secrets directory). `exit_ip` checks
    /// customer upstreams (the same services the gateway and warmer use).
    ///
    /// Fails when a token file is missing or empty, or `settings.probe_org` is
    /// not an org id.
    pub fn new(
        settings: &Settings,
        db: Db,
        hot: Hot,
        loaded: watch::Receiver<Arc<Loaded>>,
        metrics: Arc<Metrics>,
        tunnels: Arc<dyn TunnelControl>,
        exit_ip: ExitIpChecker,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            db,
            hot,
            loaded,
            metrics,
            tunnels,
            probe_org: settings
                .probe_org
                .parse()
                .context("probe_org is not a valid org id")?,
            data_dir: settings.data_dir.clone(),
            exit_ip,
            admin_token: read_secret_file(&settings.admin_token_file)?,
            prober_token: settings.read_secret(PROBER_TOKEN_FILE)?,
            probe_secret: common::probe_token::load_secret(settings)?,
            failures: crate::auth::FailureLimiter::default(),
        })
    }

    /// Refuse a source after `limit` wrong credentials in a minute instead of
    /// the default 20 (tests that send many wrong credentials on purpose).
    #[must_use]
    pub fn with_failure_limit(mut self, limit: u32) -> Self {
        self.failures = crate::auth::FailureLimiter::new(limit);
        self
    }
}
