//! Block signals: tell the pool that a target blocked an exit IP.
//!
//! `POST /v1/block-signals` on the pool control API takes a JSON array of events with HTTP
//! Basic auth, the org key as the password. The pool matches each event to a gateway session of
//! the same org and exit IP and reacts (cooldown, quarantine). Events for unknown sessions, other
//! orgs, a different exit IP, or older than an hour are counted as ignored, not refused.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::gateway::ConnectInfo;
use crate::http;
use crate::secret::Secret;

/// Most events the pool accepts in one request.
pub const MAX_BATCH: usize = 500;
/// Events older than this are ignored by the pool.
pub const MAX_EVENT_AGE: Duration = Duration::from_secs(3_600);
const USERNAME: &str = "px";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What kind of block the target answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    /// HTTP 429.
    RateLimited,
    /// 403 or 503 with a challenge or captcha marker, or a `/sorry/` redirect.
    Challenge,
    /// Repeated plain 403 on one target.
    Forbidden,
    /// Reset or TLS failure after a successful tunnel.
    Reset,
}

/// One block observed through a tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockSignal {
    /// `X-ProxyX-Pool-Session` of the tunnel.
    pub session: String,
    /// `X-ProxyX-Exit-IP` of the tunnel.
    pub exit_ip: IpAddr,
    /// `host:port` that blocked, an IPv6 host in brackets.
    pub target: String,
    /// The kind of block.
    #[serde(rename = "type")]
    pub kind: SignalType,
    /// Unix seconds when the block was seen.
    pub time: i64,
}

impl BlockSignal {
    /// A signal for the tunnel described by `info`, observed now.
    pub fn for_tunnel(info: &ConnectInfo, host: &str, port: u16, kind: SignalType) -> Self {
        Self::at(info, host, port, kind, unix_now())
    }

    /// A signal for the tunnel described by `info`, observed at `time` (Unix seconds).
    pub fn at(info: &ConnectInfo, host: &str, port: u16, kind: SignalType, time: i64) -> Self {
        Self {
            session: info.session.clone(),
            exit_ip: info.exit_ip,
            target: format_target(host, port),
            kind,
            time,
        }
    }
}

/// `host:port`, with brackets around an IPv6 host.
pub fn format_target(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The pool's answer to a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct ReportOutcome {
    /// Events applied (or applied by an earlier attempt of the same batch).
    pub accepted: u32,
    /// Events the pool did not act on: stale, unknown session, other org, different exit IP.
    pub ignored: u32,
}

/// Client of the pool control API's block-signal route.
#[derive(Debug, Clone)]
pub struct PoolControlClient {
    http: reqwest::Client,
    endpoint: Url,
    org_key: Secret,
}

impl PoolControlClient {
    /// A client for the pool control API at `base_url`, authenticated by the org key.
    pub fn new(base_url: &str, org_key: impl Into<Secret>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Self::with_http_client(base_url, org_key, http)
    }

    /// Like [`PoolControlClient::new`] with a caller-built `reqwest::Client`, for a private CA
    /// or a proxy.
    pub fn with_http_client(
        base_url: &str,
        org_key: impl Into<Secret>,
        http: reqwest::Client,
    ) -> Result<Self> {
        let mut endpoint =
            Url::parse(base_url).map_err(|err| Error::InvalidInput(format!("base_url: {err}")))?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.cannot_be_a_base() {
            return Err(Error::InvalidInput(
                "base_url must be an http or https URL".into(),
            ));
        }
        let org_key = org_key.into();
        if org_key.expose().is_empty() {
            return Err(Error::InvalidInput("org key is empty".into()));
        }
        if let Ok(mut segments) = endpoint.path_segments_mut() {
            segments.pop_if_empty().extend(["v1", "block-signals"]);
        }
        Ok(Self {
            http,
            endpoint,
            org_key,
        })
    }

    /// Send `signals` in one request. An empty slice sends nothing.
    ///
    /// More than [`MAX_BATCH`] events are refused locally, as the pool would refuse the whole
    /// batch. The pool marks each applied event by batch and position, so repeating the same
    /// batch after a 5xx does not apply an event twice.
    pub async fn report(&self, signals: &[BlockSignal]) -> Result<ReportOutcome> {
        if signals.is_empty() {
            return Ok(ReportOutcome {
                accepted: 0,
                ignored: 0,
            });
        }
        if signals.len() > MAX_BATCH {
            return Err(Error::InvalidInput(format!(
                "at most {MAX_BATCH} events per batch"
            )));
        }
        let response = self
            .http
            .post(self.endpoint.clone())
            .basic_auth(USERNAME, Some(self.org_key.expose()))
            .json(signals)
            .send()
            .await?;
        http::json(http::check(response).await?).await
    }
}
