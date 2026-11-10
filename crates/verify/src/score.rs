//! Reputation scorers: IPQS, AbuseIPDB and Scamalytics.
//!
//! A scorer receives the exit IP and the API key only (lookup rule): no
//! target, org or client data. The reply is reduced to
//! `{risk, flags, source}`; the raw reply is never kept.

use std::net::IpAddr;

use common::Secret;
use reqwest::{Client, RequestBuilder, Url, header::ACCEPT};
use serde::Deserialize;

use crate::http::read_capped;

const MAX_REPLY_BYTES: usize = 64 * 1024;
/// Look-back window of the AbuseIPDB check.
const ABUSEIPDB_MAX_AGE_DAYS: &str = "90";

/// Which service produced a score. The name is the `service` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScorerKind {
    Ipqs,
    AbuseIpdb,
    Scamalytics,
}

impl ScorerKind {
    const ALL: [Self; 3] = [Self::Ipqs, Self::AbuseIpdb, Self::Scamalytics];

    /// The kind whose [`name`](Self::name) is `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Ipqs => "ipqs",
            Self::AbuseIpdb => "abuseipdb",
            Self::Scamalytics => "scamalytics",
        }
    }
}

/// What the rule looks at besides the number. `proxy` is kept for the report
/// only: residential and ISP exits carry it by design, so the rule ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    pub tor: bool,
    pub proxy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Score {
    /// 0 to 100, higher is worse.
    pub risk: u8,
    pub flags: Flags,
    pub source: ScorerKind,
}

#[derive(Debug, thiserror::Error)]
pub enum ScoreError {
    #[error("scorer base url is not valid")]
    BadUrl,
    /// The message never holds the request URL, which carries the API key.
    #[error("request failed: {0}")]
    Request(reqwest::Error),
    #[error("scorer answered status {0}")]
    Status(u16),
    #[error("scorer reply not understood")]
    Parse,
    #[error("scorer rejected the lookup: {0}")]
    Rejected(String),
}

/// Where a scorer lives and how it authenticates. `base_url` is the origin
/// (`https://ipqualityscore.com`); tests point it at a local stub.
#[derive(Debug, Clone)]
pub struct ScorerAccount {
    pub base_url: String,
    pub key: Secret,
}

#[derive(Debug, Clone)]
pub enum Scorer {
    /// `GET {base}/api/json/ip/{key}/{ip}`
    Ipqs(ScorerAccount),
    /// `GET {base}/api/v2/check?ipAddress={ip}&maxAgeInDays=90`, header `Key`
    AbuseIpdb(ScorerAccount),
    /// `GET {base}/v3/{customer}?key={key}&ip={ip}`
    Scamalytics {
        account: ScorerAccount,
        customer: String,
    },
}

impl Scorer {
    pub fn kind(&self) -> ScorerKind {
        match self {
            Self::Ipqs(_) => ScorerKind::Ipqs,
            Self::AbuseIpdb(_) => ScorerKind::AbuseIpdb,
            Self::Scamalytics { .. } => ScorerKind::Scamalytics,
        }
    }

    /// Look the IP up. No [`ScoreError`] message contains the key.
    pub async fn score(&self, http: &Client, ip: IpAddr) -> Result<Score, ScoreError> {
        let body = self.fetch(http, ip).await?;
        let (risk, flags) = match self {
            Self::Ipqs(_) => ipqs(&body)?,
            Self::AbuseIpdb(_) => abuseipdb(&body)?,
            Self::Scamalytics { .. } => scamalytics(&body)?,
        };
        Ok(Score {
            risk,
            flags,
            source: self.kind(),
        })
    }

    fn request(&self, http: &Client, ip: IpAddr) -> Result<RequestBuilder, ScoreError> {
        match self {
            Self::Ipqs(acct) => {
                let ip = ip.to_string();
                let url = endpoint(
                    &acct.base_url,
                    &["api", "json", "ip", acct.key.expose(), &ip],
                )?;
                Ok(http.get(url))
            }
            Self::AbuseIpdb(acct) => {
                let mut url = endpoint(&acct.base_url, &["api", "v2", "check"])?;
                url.query_pairs_mut()
                    .append_pair("ipAddress", &ip.to_string())
                    .append_pair("maxAgeInDays", ABUSEIPDB_MAX_AGE_DAYS);
                Ok(http
                    .get(url)
                    .header("Key", acct.key.expose())
                    .header(ACCEPT, "application/json"))
            }
            Self::Scamalytics { account, customer } => {
                let mut url = endpoint(&account.base_url, &["v3", customer])?;
                url.query_pairs_mut()
                    .append_pair("key", account.key.expose())
                    .append_pair("ip", &ip.to_string());
                Ok(http.get(url))
            }
        }
    }

    async fn fetch(&self, http: &Client, ip: IpAddr) -> Result<Vec<u8>, ScoreError> {
        let mut resp = self
            .request(http, ip)?
            .send()
            .await
            .map_err(|e| ScoreError::Request(e.without_url()))?;
        if !resp.status().is_success() {
            return Err(ScoreError::Status(resp.status().as_u16()));
        }
        read_capped(&mut resp, MAX_REPLY_BYTES)
            .await
            .map_err(|e| ScoreError::Request(e.without_url()))
    }
}

/// The base URL with percent-encoded path segments appended to its path.
fn endpoint(base: &str, segments: &[&str]) -> Result<Url, ScoreError> {
    let mut url = Url::parse(base).map_err(|_| ScoreError::BadUrl)?;
    url.path_segments_mut()
        .map_err(|()| ScoreError::BadUrl)?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// Round to 0..=100. Rejects values that are not numbers.
fn risk(value: f64) -> Result<u8, ScoreError> {
    if value.is_nan() {
        return Err(ScoreError::Parse);
    }
    // Clamped to 0..=100 first, so the cast cannot truncate.
    Ok(value.round().clamp(0.0, 100.0) as u8)
}

fn decode<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, ScoreError> {
    serde_json::from_slice(body).map_err(|_| ScoreError::Parse)
}

#[derive(Deserialize)]
struct IpqsReply {
    success: bool,
    message: Option<String>,
    fraud_score: Option<f64>,
    proxy: Option<bool>,
    tor: Option<bool>,
    active_tor: Option<bool>,
}

fn ipqs(body: &[u8]) -> Result<(u8, Flags), ScoreError> {
    let r: IpqsReply = decode(body)?;
    if !r.success {
        return Err(ScoreError::Rejected(r.message.unwrap_or_default()));
    }
    let flags = Flags {
        tor: r.tor.unwrap_or(false) || r.active_tor.unwrap_or(false),
        proxy: r.proxy.unwrap_or(false),
    };
    Ok((risk(r.fraud_score.ok_or(ScoreError::Parse)?)?, flags))
}

#[derive(Deserialize)]
struct AbuseReply {
    data: AbuseData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseData {
    abuse_confidence_score: f64,
    is_tor: Option<bool>,
}

fn abuseipdb(body: &[u8]) -> Result<(u8, Flags), ScoreError> {
    let r: AbuseReply = decode(body)?;
    let flags = Flags {
        tor: r.data.is_tor.unwrap_or(false),
        proxy: false,
    };
    Ok((risk(r.data.abuse_confidence_score)?, flags))
}

#[derive(Deserialize)]
struct ScamReply {
    scamalytics: ScamCore,
    external_datasources: Option<ScamSources>,
}

#[derive(Deserialize)]
struct ScamCore {
    status: String,
    scamalytics_score: Option<f64>,
    scamalytics_proxy: Option<ScamProxy>,
}

#[derive(Deserialize)]
struct ScamProxy {
    is_datacenter: Option<bool>,
    is_vpn: Option<bool>,
    is_resproxy: Option<bool>,
}

#[derive(Deserialize)]
struct ScamSources {
    x4bnet: Option<ScamX4b>,
}

#[derive(Deserialize)]
struct ScamX4b {
    is_tor: Option<bool>,
}

fn scamalytics(body: &[u8]) -> Result<(u8, Flags), ScoreError> {
    let r: ScamReply = decode(body)?;
    if r.scamalytics.status != "ok" {
        return Err(ScoreError::Rejected(r.scamalytics.status));
    }
    let proxy = r.scamalytics.scamalytics_proxy.is_some_and(|p| {
        p.is_vpn.unwrap_or(false)
            || p.is_datacenter.unwrap_or(false)
            || p.is_resproxy.unwrap_or(false)
    });
    let tor = r
        .external_datasources
        .and_then(|s| s.x4bnet)
        .and_then(|x| x.is_tor)
        .unwrap_or(false);
    let score = r.scamalytics.scamalytics_score.ok_or(ScoreError::Parse)?;
    Ok((risk(score)?, Flags { tor, proxy }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Resp, Stub, account};

    const KEY: &str = "k e/y";

    fn ip() -> IpAddr {
        "5.6.7.8".parse().expect("valid test value")
    }

    fn scamalytics_scorer(stub: &Stub) -> Scorer {
        Scorer::Scamalytics {
            account: account(stub, KEY),
            customer: "acme".into(),
        }
    }

    /// A scorer service that answers every call with `status` and `body`.
    fn answering(status: u16, body: &'static str) -> Stub {
        Stub::spawn(move |_| Resp::status(status, body))
    }

    async fn lookup(scorer: &Scorer) -> Result<Score, ScoreError> {
        scorer.score(&Client::new(), ip()).await
    }

    #[tokio::test]
    async fn ipqs_reads_fraud_score_and_tor_and_sends_only_ip_and_key() {
        let stub = answering(
            200,
            r#"{"success":true,"message":"Success","fraud_score":87.6,"proxy":true,"vpn":true,"tor":false,"active_tor":true,"country_code":"FR"}"#,
        );
        let score = lookup(&Scorer::Ipqs(account(&stub, KEY)))
            .await
            .expect("call succeeds");
        assert_eq!(score.risk, 88);
        assert_eq!(score.source, ScorerKind::Ipqs);
        assert_eq!((score.flags.tor, score.flags.proxy), (true, true));
        let req = &stub.requests()[0];
        // The key is a path segment (percent-encoded); nothing else is sent.
        assert_eq!(req.path(), "/api/json/ip/k%20e%2Fy/5.6.7.8");
        assert_eq!(req.method, "GET");
        let names: Vec<_> = req
            .headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| ["host", "user-agent", "accept", "accept-encoding"].contains(&n.as_str())),
            "{names:?}"
        );
    }

    #[tokio::test]
    async fn ipqs_failure_replies_are_errors() {
        let stub = answering(
            200,
            r#"{"success":false,"message":"Invalid or unauthorized key."}"#,
        );
        let err = lookup(&Scorer::Ipqs(account(&stub, KEY)))
            .await
            .expect_err("call fails");
        assert!(
            matches!(&err, ScoreError::Rejected(m) if m.starts_with("Invalid")),
            "{err}"
        );
        let stub = answering(200, r#"{"success":true}"#);
        assert!(matches!(
            lookup(&Scorer::Ipqs(account(&stub, KEY))).await,
            Err(ScoreError::Parse)
        ));
    }

    #[tokio::test]
    async fn abuseipdb_reads_confidence_score_and_tor_with_key_in_header() {
        let stub = answering(
            200,
            r#"{"data":{"ipAddress":"5.6.7.8","isPublic":true,"abuseConfidenceScore":100,"isTor":true,"usageType":"Fixed Line ISP"}}"#,
        );
        let score = lookup(&Scorer::AbuseIpdb(account(&stub, KEY)))
            .await
            .expect("call succeeds");
        assert_eq!((score.risk, score.source), (100, ScorerKind::AbuseIpdb));
        assert_eq!((score.flags.tor, score.flags.proxy), (true, false));
        let req = &stub.requests()[0];
        assert_eq!(
            req.path(),
            "/api/v2/check?ipAddress=5.6.7.8&maxAgeInDays=90"
        );
        assert_eq!(req.header("key"), Some(KEY));
        assert!(
            !req.target.contains("k%20e"),
            "key must not travel in the URL"
        );
    }

    #[tokio::test]
    async fn abuseipdb_rate_limit_is_a_status_error() {
        let stub = answering(
            429,
            r#"{"errors":[{"detail":"Daily rate limit exceeded."}]}"#,
        );
        let err = lookup(&Scorer::AbuseIpdb(account(&stub, KEY)))
            .await
            .expect_err("call fails");
        assert!(matches!(err, ScoreError::Status(429)), "{err}");
    }

    #[tokio::test]
    async fn scamalytics_reads_score_tor_and_proxy_flags() {
        let stub = answering(
            200,
            r#"{"scamalytics":{"status":"ok","mode":"live","ip":"5.6.7.8","scamalytics_score":42,"scamalytics_risk":"low",
                    "scamalytics_proxy":{"is_datacenter":false,"is_vpn":false,"is_resproxy":true}},
                   "external_datasources":{"x4bnet":{"is_vpn":false,"is_tor":true}}}"#,
        );
        let score = lookup(&scamalytics_scorer(&stub))
            .await
            .expect("call succeeds");
        assert_eq!((score.risk, score.source), (42, ScorerKind::Scamalytics));
        assert_eq!((score.flags.tor, score.flags.proxy), (true, true));
        assert_eq!(stub.requests()[0].path(), "/v3/acme?key=k+e%2Fy&ip=5.6.7.8");
    }

    #[tokio::test]
    async fn scamalytics_tolerates_essential_tier_nulls_and_rejects_errors() {
        let stub = answering(
            200,
            r#"{"scamalytics":{"status":"ok","scamalytics_score":0,"scamalytics_proxy":{"is_datacenter":false,"is_vpn":false,"is_resproxy":null}},"external_datasources":{"x4bnet":{"is_tor":false}}}"#,
        );
        let score = lookup(&scamalytics_scorer(&stub))
            .await
            .expect("call succeeds");
        assert_eq!((score.risk, score.flags), (0, Flags::default()));
        let stub = answering(200, r#"{"scamalytics":{"status":"error"}}"#);
        assert!(
            matches!(lookup(&scamalytics_scorer(&stub)).await, Err(ScoreError::Rejected(s)) if s == "error")
        );
    }

    #[test]
    fn risk_is_rounded_and_clamped_to_0_100() {
        assert_eq!(risk(0.49).expect("call succeeds"), 0);
        assert_eq!(risk(0.5).expect("call succeeds"), 1);
        assert_eq!(risk(99.5).expect("call succeeds"), 100);
        assert_eq!(risk(250.0).expect("call succeeds"), 100);
        assert_eq!(risk(-3.0).expect("call succeeds"), 0);
        assert!(risk(f64::NAN).is_err());
    }

    #[tokio::test]
    async fn errors_never_contain_the_key() {
        // Connection refused: reqwest would print the URL (which holds the key) if not stripped.
        let acct = ScorerAccount {
            base_url: "http://127.0.0.1:1".into(),
            key: Secret::new("topsecretkey"),
        };
        for scorer in [
            Scorer::Ipqs(acct.clone()),
            Scorer::AbuseIpdb(acct.clone()),
            Scorer::Scamalytics {
                account: acct,
                customer: "acme".into(),
            },
        ] {
            let err = lookup(&scorer).await.expect_err("call fails");
            assert!(matches!(err, ScoreError::Request(_)), "{err}");
            assert!(!format!("{err} {err:?}").contains("topsecretkey"), "{err}");
        }
    }
}
