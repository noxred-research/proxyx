//! Exit-IP quorum.
//!
//! Several echo services are asked, through the upstream, which IP they see.
//! Two of them must return the same IPv4 address; the majority country must
//! equal the wanted region; a static IP must equal its inventory entry. A
//! service that fails is counted in `check_failures_total{service}` and the
//! quorum is taken over the services that answered.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use common::metrics::Metrics;
use common::types::{Region, UpstreamEndpoint};
use reqwest::Client;
use serde::Deserialize;
use tokio::task::JoinSet;

use crate::http::{ClientError, read_capped, upstream_client};

const MAX_REPLY_BYTES: usize = 16 * 1024;

/// The echo services ProxyX knows how to read. The name is the metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    /// JSON with an `ip` field and no country (`{"ip": "..."}`).
    IpJson,
    /// Plain text lines: `ip=` and `loc=` (the country).
    TraceLines,
    /// JSON with `ip` and `country`.
    IpCountryJson,
    /// JSON with `ip` and `country_iso`.
    IpCountryIsoJson,
    /// The provider's own echo endpoint: the IP as plain text, no country.
    ProviderEcho,
}

impl ServiceKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::IpJson => "ip_json",
            Self::TraceLines => "trace_lines",
            Self::IpCountryJson => "ip_country_json",
            Self::IpCountryIsoJson => "ip_country_iso_json",
            Self::ProviderEcho => "provider_echo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckService {
    pub kind: ServiceKind,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct ExitIpConfig {
    /// Public services asked on every check. The provider echo is added per
    /// call through [`ExitQuery::echo_url`].
    pub services: Vec<CheckService>,
    /// Votes the winning IP needs (the "2" of 2-of-3).
    pub min_agree: usize,
    /// Time limit of one service call.
    pub timeout: Duration,
}

impl Default for ExitIpConfig {
    fn default() -> Self {
        let svc = |kind, url: &str| CheckService {
            kind,
            url: url.to_owned(),
        };
        Self {
            services: vec![
                // wire-compat: the public echo services behind the default list
                svc(ServiceKind::IpJson, "https://api.ipify.org?format=json"),
                svc(
                    ServiceKind::TraceLines,
                    "https://www.cloudflare.com/cdn-cgi/trace", // wire-compat
                ),
                svc(ServiceKind::IpCountryJson, "https://ipinfo.io/json"), // wire-compat
                svc(ServiceKind::IpCountryIsoJson, "https://ifconfig.co/json"), // wire-compat
            ],
            min_agree: 2,
            timeout: Duration::from_secs(5),
        }
    }
}

/// What the caller expects from the exit.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExitQuery<'a> {
    /// The majority country must equal this region's country. The city is
    /// advice only and is not checked.
    pub region: Option<&'a Region>,
    /// A static IP's inventory entry: the exit must equal it.
    pub ip: Option<IpAddr>,
    /// The provider's echo endpoint (adapter `echo_url`), asked as one more service.
    pub echo_url: Option<&'a str>,
}

impl<'a> ExitQuery<'a> {
    /// A query for an exit in `region`, with the provider echo if it has one.
    pub fn in_region(region: &'a Region, echo_url: Option<&'a str>) -> Self {
        Self {
            region: Some(region),
            echo_url,
            ..Self::default()
        }
    }
}

/// An exit IP and its country: what one service reports, and the verified
/// exit the quorum settles on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitIp {
    pub ip: Ipv4Addr,
    /// Lowercase ISO 3166-1 alpha-2 country. For a verified exit, the
    /// majority among the agreeing services that report one.
    pub country: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExitIpError {
    /// Too few services answered to form a quorum. The session cannot be
    /// verified (`503 cache_empty` for a new session); this says nothing
    /// about the IP itself.
    #[error("only {answered} service(s) answered, {needed} needed")]
    TooFewAnswers { answered: usize, needed: usize },
    /// Too few services answered and every service that failed ran into its
    /// time limit: a hung exit, not a refusal or a bad login.
    #[error("every failed check service timed out")]
    Timeout,
    /// Too few services answered and every service that failed did so below
    /// HTTP: the upstream refused the connection or the login (407), reset
    /// it or closed it. The check cannot reach any service through this
    /// unit, while a down service behind a healthy upstream answers with a
    /// status.
    #[error("the upstream refused or dropped every check connection")]
    Unreachable,
    /// Enough services answered but no IP won the vote.
    #[error("services disagree on the exit ip")]
    Disagree,
    /// A static IP exits from another address. The message names neither
    /// address: errors are logged, and session IPs stay out of logs.
    #[error("the exit ip differs from the expected one")]
    IpMismatch { expected: IpAddr, got: Ipv4Addr },
    /// The majority country is not the wanted one (or is unknown).
    #[error("exit country {got:?} is not the wanted {expected}")]
    CountryMismatch {
        expected: String,
        got: Option<String>,
    },
    #[error(transparent)]
    Client(#[from] ClientError),
}

impl ExitIpError {
    /// True when the check could not run to a verdict because services or
    /// the upstream were down, as opposed to a verdict against the exit.
    pub fn is_outage(&self) -> bool {
        matches!(
            self,
            Self::TooFewAnswers { .. } | Self::Timeout | Self::Unreachable
        )
    }
}

pub struct ExitIpChecker {
    cfg: ExitIpConfig,
    metrics: Arc<Metrics>,
}

impl ExitIpChecker {
    pub fn new(cfg: ExitIpConfig, metrics: Arc<Metrics>) -> Self {
        Self { cfg, metrics }
    }

    /// Ask every service through `up` and apply the quorum and `query`.
    pub async fn check(
        &self,
        up: &UpstreamEndpoint,
        query: &ExitQuery<'_>,
    ) -> Result<ExitIp, ExitIpError> {
        let client = upstream_client(up, self.cfg.timeout, false).await?;
        let echo = query.echo_url.map(|url| CheckService {
            kind: ServiceKind::ProviderEcho,
            url: url.to_owned(),
        });
        let mut set = JoinSet::new();
        for svc in self.cfg.services.iter().cloned().chain(echo) {
            let client = client.clone();
            set.spawn(async move { (svc.kind, ask(&client, &svc).await) });
        }
        let mut readings = Vec::new();
        let (mut failed, mut timed_out, mut transport) = (0_usize, 0_usize, 0_usize);
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((_, Ok(reading))) => readings.push(reading),
                Ok((kind, Err(err))) => {
                    failed += 1;
                    timed_out += usize::from(err.is_timeout());
                    transport += usize::from(err.is_transport());
                    self.metrics
                        .check_failures_total
                        .with_label_values(&[kind.name()])
                        .inc();
                    tracing::warn!(service = kind.name(), error = %err, "exit ip service failed");
                }
                Err(err) => tracing::error!(error = %err, "exit ip service task died"),
            }
        }

        let exit = match quorum(&readings, self.cfg.min_agree) {
            Err(ExitIpError::TooFewAnswers { .. }) if failed > 0 && timed_out == failed => {
                return Err(ExitIpError::Timeout);
            }
            Err(ExitIpError::TooFewAnswers { .. }) if failed > 0 && transport == failed => {
                return Err(ExitIpError::Unreachable);
            }
            quorum => quorum?,
        };
        if let Some(expected) = query.ip
            && expected != IpAddr::V4(exit.ip)
        {
            return Err(ExitIpError::IpMismatch {
                expected,
                got: exit.ip,
            });
        }
        if let Some(region) = query.region
            && exit.country.as_deref() != Some(region.country())
        {
            return Err(ExitIpError::CountryMismatch {
                expected: region.country().to_owned(),
                got: exit.country,
            });
        }
        Ok(exit)
    }
}

/// The vote. The winner needs `min_agree` votes and strictly more than any
/// other address; the country is the strict majority among the winner's
/// voters that report one.
fn quorum(readings: &[ExitIp], min_agree: usize) -> Result<ExitIp, ExitIpError> {
    let answered = readings.len();
    if answered < min_agree {
        return Err(ExitIpError::TooFewAnswers {
            answered,
            needed: min_agree,
        });
    }
    let tally = count(readings.iter().map(|r| r.ip));
    let best = tally.iter().map(|(_, n)| *n).max().unwrap_or(0);
    let mut leaders = tally.iter().filter(|(_, n)| *n == best);
    let ip = match (leaders.next(), leaders.next()) {
        (Some(&(ip, n)), None) if n >= min_agree => ip,
        _ => return Err(ExitIpError::Disagree),
    };

    let countries = count(
        readings
            .iter()
            .filter(|r| r.ip == ip)
            .filter_map(|r| r.country.as_deref()),
    );
    let reporting: usize = countries.iter().map(|(_, n)| n).sum();
    let country = countries
        .iter()
        .find(|(_, n)| n * 2 > reporting)
        .map(|(c, _)| (*c).to_owned());
    Ok(ExitIp { ip, country })
}

/// Occurrences of each distinct item, in order of first appearance.
fn count<T: PartialEq>(items: impl Iterator<Item = T>) -> Vec<(T, usize)> {
    let mut counts: Vec<(T, usize)> = Vec::new();
    for item in items {
        match counts.iter_mut().find(|(seen, _)| *seen == item) {
            Some((_, n)) => *n += 1,
            None => counts.push((item, 1)),
        }
    }
    counts
}

#[derive(Debug, thiserror::Error)]
enum ServiceError {
    #[error("request failed: {0}")]
    Request(reqwest::Error),
    #[error("status {0}")]
    Status(u16),
    #[error("reply not understood")]
    Parse,
    #[error("reply is not an ipv4 address")]
    NotIpv4,
}

impl ServiceError {
    fn is_timeout(&self) -> bool {
        matches!(self, Self::Request(e) if e.is_timeout())
    }

    /// The request got no HTTP answer from the service and did not time out,
    /// or the upstream proxy refused the login (407): the connection to the
    /// upstream, or through it, failed.
    fn is_transport(&self) -> bool {
        match self {
            Self::Request(e) => !e.is_timeout(),
            Self::Status(407) => true,
            Self::Status(_) | Self::Parse | Self::NotIpv4 => false,
        }
    }
}

async fn ask(client: &Client, svc: &CheckService) -> Result<ExitIp, ServiceError> {
    let mut resp = client
        .get(&svc.url)
        .send()
        .await
        .map_err(|e| ServiceError::Request(e.without_url()))?;
    if !resp.status().is_success() {
        return Err(ServiceError::Status(resp.status().as_u16()));
    }
    let body = read_capped(&mut resp, MAX_REPLY_BYTES)
        .await
        .map_err(|e| ServiceError::Request(e.without_url()))?;
    parse_reply(svc.kind, &body)
}

#[derive(Deserialize)]
struct JsonReply {
    ip: String,
    country: Option<String>,
    country_iso: Option<String>,
}

fn parse_reply(kind: ServiceKind, body: &[u8]) -> Result<ExitIp, ServiceError> {
    let text = std::str::from_utf8(body).map_err(|_| ServiceError::Parse)?;
    let (ip, country) = match kind {
        ServiceKind::IpJson | ServiceKind::IpCountryJson | ServiceKind::IpCountryIsoJson => {
            let reply: JsonReply = serde_json::from_str(text).map_err(|_| ServiceError::Parse)?;
            (reply.ip, reply.country.or(reply.country_iso))
        }
        ServiceKind::TraceLines => {
            let field = |key: &str| {
                text.lines()
                    .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                    .map(str::to_owned)
            };
            (field("ip").ok_or(ServiceError::Parse)?, field("loc"))
        }
        ServiceKind::ProviderEcho => (text.trim().to_owned(), None),
    };
    let ip = match ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| ServiceError::Parse)?
    {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(ServiceError::NotIpv4),
    };
    let country = country
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_lowercase()));
    Ok(ExitIp { ip, country })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Resp, Stub, failures, local_upstream, peer_echo, upstream};

    fn reading(ip: &str, country: Option<&str>) -> ExitIp {
        ExitIp {
            ip: ip.parse().expect("valid test value"),
            country: country.map(str::to_owned),
        }
    }

    #[test]
    fn quorum_needs_two_votes_and_a_clear_winner() {
        let a = reading("1.1.1.1", None);
        let b = reading("2.2.2.2", None);
        let c = reading("3.3.3.3", None);
        assert!(matches!(
            quorum(&[], 2),
            Err(ExitIpError::TooFewAnswers {
                answered: 0,
                needed: 2
            })
        ));
        assert!(matches!(
            quorum(std::slice::from_ref(&a), 2),
            Err(ExitIpError::TooFewAnswers { answered: 1, .. })
        ));
        assert!(matches!(
            quorum(&[a.clone(), b.clone()], 2),
            Err(ExitIpError::Disagree)
        ));
        assert!(matches!(
            quorum(&[a.clone(), b.clone(), c.clone()], 2),
            Err(ExitIpError::Disagree)
        ));
        // 2-2-1 with five services: a tie is not a quorum.
        let tie = [a.clone(), a.clone(), b.clone(), b.clone(), c];
        assert!(matches!(quorum(&tie, 2), Err(ExitIpError::Disagree)));
        let won = quorum(&[a.clone(), b, a], 2).expect("quorum");
        assert_eq!(won.ip, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn country_is_the_strict_majority_of_the_winning_voters() {
        let fr = |ip| reading(ip, Some("fr"));
        let de = |ip| reading(ip, Some("de"));
        let country = |readings: &[ExitIp]| quorum(readings, 2).expect("quorum").country;
        assert_eq!(
            country(&[fr("1.1.1.1"), fr("1.1.1.1"), de("1.1.1.1")]).as_deref(),
            Some("fr")
        );
        // 1-1 split: no majority, so no country.
        assert_eq!(country(&[fr("1.1.1.1"), de("1.1.1.1")]), None);
        // Only voters of the winning IP count: the outlier's country is ignored.
        assert_eq!(
            country(&[fr("1.1.1.1"), fr("1.1.1.1"), de("2.2.2.2")]).as_deref(),
            Some("fr")
        );
        assert_eq!(
            country(&[fr("1.1.1.1"), reading("1.1.1.1", None), de("2.2.2.2")]).as_deref(),
            Some("fr")
        );
    }

    #[test]
    fn replies_parse_per_service() {
        let r = |kind, body: &str| parse_reply(kind, body.as_bytes());
        let country = |kind, body: &str| r(kind, body).expect("call succeeds").country;
        assert_eq!(country(ServiceKind::IpJson, r#"{"ip":"9.9.9.9"}"#), None);
        let cf = r(
            ServiceKind::TraceLines,
            "fl=1\nip=9.9.9.9\nloc=FR\nhttp=http/2\n",
        )
        .expect("call succeeds");
        assert_eq!(
            (cf.ip, cf.country.as_deref()),
            (Ipv4Addr::new(9, 9, 9, 9), Some("fr"))
        );
        // `ip=` must not match a longer key such as `ipv=`.
        assert!(matches!(
            r(ServiceKind::TraceLines, "ipv=1\n"),
            Err(ServiceError::Parse)
        ));
        assert_eq!(
            country(
                ServiceKind::IpCountryJson,
                r#"{"ip":"9.9.9.9","country":"DE","city":"Berlin"}"#
            )
            .as_deref(),
            Some("de")
        );
        assert_eq!(
            country(
                ServiceKind::IpCountryIsoJson,
                r#"{"ip":"9.9.9.9","country_iso":"GB"}"#
            )
            .as_deref(),
            Some("gb")
        );
        assert_eq!(
            r(ServiceKind::ProviderEcho, " 9.9.9.9\n")
                .expect("call succeeds")
                .ip,
            Ipv4Addr::new(9, 9, 9, 9)
        );
        assert!(matches!(
            r(ServiceKind::ProviderEcho, "2001:db8::1"),
            Err(ServiceError::NotIpv4)
        ));
        assert!(matches!(
            r(ServiceKind::IpCountryJson, "not json"),
            Err(ServiceError::Parse)
        ));
        // A malformed country is dropped, not trusted.
        assert_eq!(
            country(
                ServiceKind::IpCountryJson,
                r#"{"ip":"9.9.9.9","country":"France"}"#
            ),
            None
        );
    }

    fn svc(kind: ServiceKind, host: &str) -> CheckService {
        CheckService {
            kind,
            url: format!("http://{host}/"),
        }
    }

    fn config(services: Vec<CheckService>) -> ExitIpConfig {
        ExitIpConfig {
            services,
            min_agree: 2,
            timeout: Duration::from_secs(5),
        }
    }

    fn checker_with(cfg: ExitIpConfig) -> (ExitIpChecker, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::new("test"));
        (ExitIpChecker::new(cfg, Arc::clone(&metrics)), metrics)
    }

    /// The services behind a stub proxy: one of each of three response formats.
    fn checker() -> (ExitIpChecker, Arc<Metrics>) {
        checker_with(config(vec![
            svc(ServiceKind::IpJson, "ip-json.test"),
            svc(ServiceKind::TraceLines, "trace.test"),
            svc(ServiceKind::IpCountryJson, "ip-country.test"),
        ]))
    }

    async fn check(
        checker: &ExitIpChecker,
        stub: &Stub,
        query: &ExitQuery<'_>,
    ) -> Result<ExitIp, ExitIpError> {
        checker.check(&upstream(stub), query).await
    }

    async fn check_ok(checker: &ExitIpChecker, stub: &Stub, query: &ExitQuery<'_>) -> ExitIp {
        check(checker, stub, query).await.expect("call succeeds")
    }

    async fn check_err(checker: &ExitIpChecker, stub: &Stub, query: &ExitQuery<'_>) -> ExitIpError {
        check(checker, stub, query).await.expect_err("call fails")
    }

    /// Reply of a stub service. `ip` empty means the service is down (500).
    fn answer(host: &str, ip: &str, country: &str) -> Resp {
        if ip.is_empty() {
            return Resp::status(500, "boom");
        }
        match host {
            "ip-json.test" => Resp::ok(format!(r#"{{"ip":"{ip}"}}"#)),
            "trace.test" => Resp::ok(format!("ip={ip}\nloc={}\n", country.to_ascii_uppercase())),
            _ => Resp::ok(format!(r#"{{"ip":"{ip}","country":"{country}"}}"#)),
        }
    }

    /// A stub proxy that answers each service with `(ip, country)` by host.
    fn proxy(replies: [(&'static str, &'static str); 3]) -> Stub {
        Stub::spawn(move |req| {
            let host = req.host();
            let (ip, country) = match host.as_str() {
                "ip-json.test" => replies[0],
                "trace.test" => replies[1],
                "ip-country.test" => replies[2],
                _ => return Resp::status(404, ""),
            };
            answer(&host, ip, country)
        })
    }

    #[tokio::test]
    async fn agreeing_services_verify_and_credentials_reach_the_proxy() {
        let stub = proxy([("5.6.7.8", "fr"), ("5.6.7.8", "fr"), ("5.6.7.8", "fr")]);
        let fr: Region = "fr".parse().expect("valid test value");
        let q = ExitQuery {
            region: Some(&fr),
            ip: Some("5.6.7.8".parse().expect("valid test value")),
            echo_url: None,
        };
        let mut up = upstream(&stub);
        up.username = common::Secret::new("user");
        up.password = common::Secret::new("p@ss:word");
        let exit = checker().0.check(&up, &q).await.expect("call succeeds");
        assert_eq!(exit.ip, Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(exit.country.as_deref(), Some("fr"));
        let auth: Vec<_> = stub
            .requests()
            .iter()
            .filter_map(|r| r.header("proxy-authorization"))
            .map(str::to_owned)
            .collect();
        // base64("user:p@ss:word")
        let expected = "Basic dXNlcjpwQHNzOndvcmQ=";
        assert_eq!(auth.len(), 3);
        assert!(auth.iter().all(|a| a == expected), "{auth:?}");
    }

    #[tokio::test]
    async fn two_of_three_is_enough_and_the_outlier_loses() {
        let stub = proxy([("5.6.7.8", "fr"), ("5.6.7.8", "fr"), ("9.9.9.9", "de")]);
        let exit = check_ok(&checker().0, &stub, &ExitQuery::default()).await;
        assert_eq!(exit.ip, Ipv4Addr::new(5, 6, 7, 8));
    }

    #[tokio::test]
    async fn three_different_answers_disagree() {
        let stub = proxy([("1.1.1.1", "fr"), ("2.2.2.2", "fr"), ("3.3.3.3", "fr")]);
        let err = check_err(&checker().0, &stub, &ExitQuery::default()).await;
        assert!(matches!(err, ExitIpError::Disagree), "{err}");
        assert!(!err.is_outage());
    }

    #[tokio::test]
    async fn one_service_down_is_counted_and_the_rest_decide() {
        let stub = proxy([("5.6.7.8", "fr"), ("", ""), ("5.6.7.8", "fr")]);
        let (checker, metrics) = checker();
        let exit = check_ok(&checker, &stub, &ExitQuery::default()).await;
        assert_eq!(exit.ip, Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(failures(&metrics, "trace_lines"), 1);
        assert_eq!(
            failures(&metrics, "ip_json") + failures(&metrics, "ip_country_json"),
            0
        );
    }

    #[tokio::test]
    async fn one_down_and_the_other_two_differ_is_a_disagreement_not_an_outage() {
        let stub = proxy([("1.1.1.1", "fr"), ("", ""), ("2.2.2.2", "fr")]);
        let err = check_err(&checker().0, &stub, &ExitQuery::default()).await;
        assert!(matches!(err, ExitIpError::Disagree), "{err}");
    }

    #[tokio::test]
    async fn too_few_answers_is_an_outage() {
        let stub = proxy([("5.6.7.8", "fr"), ("", ""), ("", "")]);
        let (checker, metrics) = checker();
        let err = check_err(&checker, &stub, &ExitQuery::default()).await;
        assert!(
            matches!(
                err,
                ExitIpError::TooFewAnswers {
                    answered: 1,
                    needed: 2
                }
            ),
            "{err}"
        );
        assert!(err.is_outage());
        assert_eq!(
            failures(&metrics, "trace_lines") + failures(&metrics, "ip_country_json"),
            2
        );
    }

    /// An upstream that answers every request with 407, or
    /// closes every connection, is dead; services that answer 5xx behind a
    /// healthy upstream are only an outage.
    #[tokio::test]
    async fn an_upstream_that_refuses_or_drops_every_connection_is_unreachable() {
        let (checker, _) = checker();
        let refusing = Stub::spawn(|_| Resp::status(407, ""));
        let err = check_err(&checker, &refusing, &ExitQuery::default()).await;
        assert!(matches!(err, ExitIpError::Unreachable), "{err}");
        assert!(err.is_outage());

        // closed without a reply: bind, accept, drop
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let mut up = upstream(&refusing);
        up.host = addr.ip().to_string();
        up.port = addr.port();
        let err = checker
            .check(&up, &ExitQuery::default())
            .await
            .expect_err("call fails");
        assert!(matches!(err, ExitIpError::Unreachable), "{err}");

        // down services behind a healthy upstream: an outage, not a dead unit
        let down = proxy([("", ""), ("", ""), ("", "")]);
        let err = check_err(&checker, &down, &ExitQuery::default()).await;
        assert!(
            matches!(err, ExitIpError::TooFewAnswers { answered: 0, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn ipv6_answers_do_not_vote() {
        let (checker, _) = checker();
        // One v6 answer: the two v4 answers still agree.
        let stub = proxy([("2001:db8::1", "fr"), ("5.6.7.8", "fr"), ("5.6.7.8", "fr")]);
        let exit = check_ok(&checker, &stub, &ExitQuery::default()).await;
        assert_eq!(exit.ip, Ipv4Addr::new(5, 6, 7, 8));
        // Two v6 answers: the lone v4 answer is no quorum.
        let stub = proxy([
            ("2001:db8::1", "fr"),
            ("2001:db8::1", "fr"),
            ("5.6.7.8", "fr"),
        ]);
        let err = check_err(&checker, &stub, &ExitQuery::default()).await;
        assert!(
            matches!(err, ExitIpError::TooFewAnswers { answered: 1, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn country_must_match_by_majority_and_city_is_advice() {
        // The trace, `ip_country_json` and `ip_country_iso_json` kinds all report a country.
        let countries = |cf: &'static str, info: &'static str, ifc: &'static str| {
            Stub::spawn(move |req| match req.host().as_str() {
                "trace.test" => Resp::ok(format!("ip=5.6.7.8\nloc={}\n", cf.to_ascii_uppercase())),
                "ip-country.test" => Resp::ok(format!(r#"{{"ip":"5.6.7.8","country":"{info}"}}"#)),
                "ip-country-iso.test" => {
                    Resp::ok(format!(r#"{{"ip":"5.6.7.8","country_iso":"{ifc}"}}"#))
                }
                _ => Resp::status(404, ""),
            })
        };
        let (checker, _) = checker_with(config(vec![
            svc(ServiceKind::TraceLines, "trace.test"),
            svc(ServiceKind::IpCountryJson, "ip-country.test"),
            svc(ServiceKind::IpCountryIsoJson, "ip-country-iso.test"),
        ]));
        let fr: Region = "fr".parse().expect("valid test value");
        let q = ExitQuery {
            region: Some(&fr),
            ..ExitQuery::default()
        };
        let err = check_err(&checker, &countries("de", "de", "fr"), &q).await;
        assert!(
            matches!(&err, ExitIpError::CountryMismatch { expected, got } if expected == "fr" && got.as_deref() == Some("de")),
            "{err}"
        );
        // Majority fr, one dissenter: passes; a city in the region is not compared.
        let paris: Region = "fr/paris".parse().expect("valid test value");
        let q = ExitQuery {
            region: Some(&paris),
            ..ExitQuery::default()
        };
        assert!(
            check(&checker, &countries("fr", "fr", "de"), &q)
                .await
                .is_ok()
        );
        // No majority (1-1-1) cannot confirm the region.
        let err = check_err(&checker, &countries("fr", "de", "gb"), &q).await;
        assert!(
            matches!(err, ExitIpError::CountryMismatch { got: None, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn unknown_country_cannot_confirm_a_region() {
        // `ip_json` and the provider echo report no country at all.
        let stub = Stub::spawn(|req| {
            Resp::ok(if req.host() == "ip-json.test" {
                r#"{"ip":"5.6.7.8"}"#
            } else {
                "5.6.7.8"
            })
        });
        let (checker, _) = checker_with(config(vec![svc(ServiceKind::IpJson, "ip-json.test")]));
        let fr: Region = "fr".parse().expect("valid test value");
        let q = ExitQuery {
            region: Some(&fr),
            echo_url: Some("http://echo.test/"),
            ip: None,
        };
        let err = check_err(&checker, &stub, &q).await;
        assert!(
            matches!(err, ExitIpError::CountryMismatch { got: None, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn static_ip_must_equal_its_inventory_entry() {
        let (checker, _) = checker();
        let stub = proxy([("5.6.7.8", "fr"), ("5.6.7.8", "fr"), ("5.6.7.8", "fr")]);
        let q = ExitQuery {
            ip: Some("5.6.7.9".parse().expect("valid test value")),
            ..ExitQuery::default()
        };
        let err = check_err(&checker, &stub, &q).await;
        assert!(
            matches!(err, ExitIpError::IpMismatch { expected, got } if expected == "5.6.7.9".parse::<IpAddr>().expect("valid test value") && got == Ipv4Addr::new(5, 6, 7, 8)),
            "{err}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("5.6.7"),
            "a logged mismatch must not print session IPs: {message}"
        );
        // An IPv6 inventory entry can never equal an IPv4 exit.
        let q = ExitQuery {
            ip: Some("2001:db8::1".parse().expect("valid test value")),
            ..ExitQuery::default()
        };
        assert!(matches!(
            check(&checker, &stub, &q).await,
            Err(ExitIpError::IpMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn provider_echo_votes_as_one_more_service() {
        // The two public services disagree; the provider echo breaks the tie.
        let stub = Stub::spawn(|req| match req.host().as_str() {
            "ip-json.test" => Resp::ok(r#"{"ip":"1.1.1.1"}"#),
            "trace.test" => Resp::ok("ip=2.2.2.2\nloc=FR\n"),
            "echo.test" => Resp::ok("2.2.2.2\n"),
            _ => Resp::status(404, ""),
        });
        let (checker, _) = checker_with(config(vec![
            svc(ServiceKind::IpJson, "ip-json.test"),
            svc(ServiceKind::TraceLines, "trace.test"),
        ]));
        let q = ExitQuery {
            echo_url: Some("http://echo.test/ip"),
            ..ExitQuery::default()
        };
        let exit = check_ok(&checker, &stub, &q).await;
        assert_eq!(exit.ip, Ipv4Addr::new(2, 2, 2, 2));
    }

    #[tokio::test]
    async fn socks5_upstream_authenticates_and_resolves_at_the_proxy() {
        let stub = Stub::spawn_socks5(|req| {
            // The name reaches the proxy unresolved (socks5h), as the Host header.
            match req.host().as_str() {
                "ip-json.test" | "ip-country.test" => {
                    Resp::ok(r#"{"ip":"5.6.7.8","country":"fr"}"#)
                }
                _ => Resp::status(404, ""),
            }
        });
        let (checker, metrics) = checker_with(config(vec![
            svc(ServiceKind::IpJson, "ip-json.test"),
            svc(ServiceKind::IpCountryJson, "ip-country.test"),
        ]));
        let mut up = upstream(&stub);
        up.scheme = common::types::UpstreamScheme::Socks5;
        let exit = checker
            .check(&up, &ExitQuery::default())
            .await
            .expect("call succeeds");
        assert_eq!(exit.ip, Ipv4Addr::new(5, 6, 7, 8));
        // A wrong password fails every service below HTTP (the login is
        // refused): the upstream is unreachable, counted per service.
        up.password = common::Secret::new("wrong");
        let err = checker
            .check(&up, &ExitQuery::default())
            .await
            .expect_err("call fails");
        assert!(matches!(err, ExitIpError::Unreachable), "{err}");
        assert_eq!(failures(&metrics, "ip_json"), 1);
        assert_eq!(failures(&metrics, "ip_country_json"), 1);
    }

    #[tokio::test]
    async fn a_proxy_that_never_answers_is_an_outage_after_the_timeout() {
        let up = upstream(&Stub::hanging());
        let mut cfg = config(vec![svc(ServiceKind::IpJson, "ip-json.test")]);
        cfg.timeout = Duration::from_millis(200);
        let (checker, _) = checker_with(cfg);
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            checker.check(&up, &ExitQuery::default()),
        )
        .await
        .expect("the check must end by itself")
        .expect_err("call fails");
        assert!(err.is_outage(), "{err}");
        assert!(matches!(err, ExitIpError::Timeout), "{err}");
    }

    #[tokio::test]
    async fn only_the_first_16_kb_of_a_reply_is_read() {
        // The ip comes after the padding, so a reply cut at the cap has no ip.
        let padded = |pad: usize| {
            let body = format!(r#"{{"pad":"{}","ip":"5.6.7.8"}}"#, "a".repeat(pad));
            Stub::spawn(move |_| Resp::ok(body.clone()))
        };
        let (checker, _) = checker();
        let query = ExitQuery::default();
        assert!(
            check(&checker, &padded(1_000), &query).await.is_ok(),
            "a short reply is read in full"
        );
        let err = check_err(&checker, &padded(MAX_REPLY_BYTES), &query).await;
        assert!(err.is_outage(), "{err}");
    }

    /// A `Local` unit goes out of its own source address with no proxy: the
    /// services see that address as the exit, and the entry's IP is checked
    /// against it.
    #[tokio::test]
    async fn a_local_unit_verifies_the_address_it_binds() {
        let echo = peer_echo().to_string();
        let (checker, _) = checker_with(config(vec![
            svc(ServiceKind::IpJson, &echo),
            svc(ServiceKind::IpCountryJson, &echo),
        ]));
        let ip = |s: &str| Some(s.parse::<IpAddr>().expect("valid test value"));
        let up = local_upstream("127.0.0.2");
        let exit = checker
            .check(
                &up,
                &ExitQuery {
                    ip: ip("127.0.0.2"),
                    ..ExitQuery::default()
                },
            )
            .await
            .expect("exit matches the source");
        assert_eq!(exit.ip, Ipv4Addr::new(127, 0, 0, 2));
        let err = checker
            .check(
                &up,
                &ExitQuery {
                    ip: ip("127.0.0.3"),
                    ..ExitQuery::default()
                },
            )
            .await
            .expect_err("another address is a mismatch");
        assert!(matches!(err, ExitIpError::IpMismatch { .. }), "{err}");
    }
}
