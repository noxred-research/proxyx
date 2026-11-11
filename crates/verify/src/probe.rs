//! Light probe: a few HTTPS GETs per test target through the
//! upstream, reading status, time to first byte and the first 16 KB, and
//! recognising block pages. A block is a block signal.

use std::time::{Duration, Instant};

use common::types::{SignalType, UpstreamEndpoint};
use reqwest::{Client, Response, Url, header::LOCATION};
use tokio::task::JoinSet;

use crate::http::{ClientError, read_capped, upstream_client};
use crate::replace::ProbeRound;

/// Body markers of challenge and captcha pages, lowercase. Looked for only in
/// 403 and 503 answers: a normal page may legitimately embed a captcha.
const CHALLENGE_MARKERS: &[&str] = &[
    "captcha",
    "cf-chl", // detection-data
    "challenge-platform",
    "just a moment",
    "attention required",
    "unusual traffic",
    "datadome", // detection-data
];

#[derive(Debug, Clone, Copy)]
pub struct ProbeConfig {
    /// GETs per target.
    pub samples: usize,
    /// Bytes of body read per GET.
    pub max_body: usize,
    /// Redirects followed per GET. A search engine's `/sorry/` redirect is a block
    /// whenever it is reached.
    pub max_redirects: usize,
    /// Time limit of one request (each redirect hop is one), tunnel setup
    /// included.
    pub timeout: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            samples: 3,
            max_body: 16 * 1024,
            max_redirects: 3,
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A 2xx answer that is not a block. Redirects are followed, so the final
    /// answer is never a 3xx.
    Clean,
    /// The target blocked the request.
    Blocked(SignalType),
    /// No usable answer: connect, TLS, timeout, reset, too many redirects, or
    /// a final status that is neither a 2xx nor a block (404, 5xx, 407, ...;
    /// The probe reads the status, and only a success is a good sample).
    /// Not a block: the cause may be the upstream, the network or the target.
    /// It counts against the IP in `min_success` but never as a block signal.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// Status of the final answer.
    pub status: Option<u16>,
    /// Time from sending the request to the first response headers,
    /// including connection and TLS setup through the upstream.
    pub ttfb: Option<Duration>,
    /// Body bytes read (at most `max_body`).
    pub bytes: usize,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetProbe {
    pub target: Url,
    pub samples: Vec<Sample>,
}

impl TargetProbe {
    /// The block signal of this target: set when a strict majority of the
    /// samples were blocked, so one stray 429 among three does not count. The
    /// type is the most severe among the blocked samples.
    pub fn blocked(&self) -> Option<SignalType> {
        let kinds: Vec<SignalType> = self
            .samples
            .iter()
            .filter_map(|s| match s.outcome {
                Outcome::Blocked(kind) => Some(kind),
                Outcome::Clean | Outcome::Failed => None,
            })
            .collect();
        if kinds.len() * 2 <= self.samples.len() {
            return None;
        }
        kinds.into_iter().max_by_key(|k| severity(*k))
    }
}

fn severity(kind: SignalType) -> u8 {
    match kind {
        SignalType::Challenge => 3,
        SignalType::Forbidden => 2,
        SignalType::RateLimited => 1,
        SignalType::Reset => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// In the order of the targets given.
    pub targets: Vec<TargetProbe>,
}

impl ProbeReport {
    /// The blocked share of this probe, for the replacement rule.
    pub fn round(&self) -> ProbeRound {
        ProbeRound {
            blocked: self
                .targets
                .iter()
                .filter(|t| t.blocked().is_some())
                .count(),
            total: self.targets.len(),
        }
    }
}

pub struct LightProbe {
    cfg: ProbeConfig,
}

impl LightProbe {
    pub fn new(cfg: ProbeConfig) -> Self {
        Self { cfg }
    }

    /// Probe every target through `up`. Targets run concurrently, the samples
    /// of one target one after the other, each on a fresh connection. Failures
    /// of single GETs are reported as [`Outcome::Failed`]; only an upstream
    /// that cannot be turned into an HTTP client is an error.
    pub async fn run(
        &self,
        up: &UpstreamEndpoint,
        targets: &[Url],
    ) -> Result<ProbeReport, ClientError> {
        let client = upstream_client(up, self.cfg.timeout, true).await?;
        let mut set = JoinSet::new();
        for (idx, target) in targets.iter().enumerate() {
            let (client, cfg, target) = (client.clone(), self.cfg, target.clone());
            set.spawn(async move { (idx, probe_target(&client, &cfg, target).await) });
        }
        let mut done = Vec::with_capacity(targets.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(result) => done.push(result),
                Err(err) => tracing::error!(error = %err, "probe task died"),
            }
        }
        done.sort_by_key(|(idx, _)| *idx);
        Ok(ProbeReport {
            targets: done.into_iter().map(|(_, t)| t).collect(),
        })
    }
}

async fn probe_target(client: &Client, cfg: &ProbeConfig, target: Url) -> TargetProbe {
    let mut samples = Vec::with_capacity(cfg.samples);
    for _ in 0..cfg.samples {
        samples.push(sample(client, cfg, &target).await);
    }
    TargetProbe { target, samples }
}

async fn sample(client: &Client, cfg: &ProbeConfig, target: &Url) -> Sample {
    let failed = |status, ttfb| Sample {
        status,
        ttfb,
        bytes: 0,
        outcome: Outcome::Failed,
    };
    let started = Instant::now();
    let mut ttfb = None;
    let mut url = target.clone();
    for _ in 0..=cfg.max_redirects {
        let mut resp = match client.get(url.clone()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::debug!(error = %err.without_url(), "probe request failed");
                return failed(None, ttfb);
            }
        };
        let ttfb_now = *ttfb.get_or_insert_with(|| started.elapsed());
        let status = resp.status();
        if status.is_redirection() {
            let Some(next) = redirect_target(&resp, &url) else {
                return failed(Some(status.as_u16()), Some(ttfb_now));
            };
            if is_sorry(&next) {
                return Sample {
                    status: Some(status.as_u16()),
                    ttfb: Some(ttfb_now),
                    bytes: 0,
                    outcome: Outcome::Blocked(SignalType::Challenge),
                };
            }
            url = next;
            continue;
        }
        // detection-data: the challenge header of a CDN
        let challenged = resp.headers().contains_key("cf-mitigated");
        let body = match read_capped(&mut resp, cfg.max_body).await {
            Ok(body) => body,
            Err(err) => {
                tracing::debug!(error = %err.without_url(), "probe body failed");
                return failed(Some(status.as_u16()), Some(ttfb_now));
            }
        };
        let outcome = match classify(status.as_u16(), challenged || is_sorry(&url), &body) {
            Some(kind) => Outcome::Blocked(kind),
            // Redirects were followed above, so the final answer is never a
            // 3xx: only a 2xx is a success. Any other status (404, 5xx, 407,
            // ...) is not a block but not a usable answer either.
            None if status.is_success() => Outcome::Clean,
            None => Outcome::Failed,
        };
        return Sample {
            status: Some(status.as_u16()),
            ttfb: Some(ttfb_now),
            bytes: body.len(),
            outcome,
        };
    }
    failed(None, ttfb)
}

fn redirect_target(resp: &Response, from: &Url) -> Option<Url> {
    let location = resp.headers().get(LOCATION)?.to_str().ok()?;
    from.join(location).ok()
}

/// The block interstitial of a search engine lives under `/sorry/`.
fn is_sorry(url: &Url) -> bool {
    url.path().starts_with("/sorry/")
}

/// Block type of a final answer. `challenged`: the answer carries a
/// CDN challenge header or sits on a `/sorry/` page.
fn classify(status: u16, challenged: bool, body: &[u8]) -> Option<SignalType> {
    if challenged {
        return Some(SignalType::Challenge);
    }
    match status {
        429 => Some(SignalType::RateLimited),
        403 | 503 => {
            let text = String::from_utf8_lossy(body).to_ascii_lowercase();
            if CHALLENGE_MARKERS.iter().any(|m| text.contains(m)) {
                Some(SignalType::Challenge)
            } else if status == 403 {
                Some(SignalType::Forbidden)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Resp, Stub, upstream};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid test value")
    }

    async fn probe(stub: &Stub, targets: &[&str]) -> ProbeReport {
        let targets: Vec<Url> = targets.iter().map(|t| url(t)).collect();
        LightProbe::new(ProbeConfig::default())
            .run(&upstream(stub), &targets)
            .await
            .expect("call succeeds")
    }

    /// Probe `http://{name}.test/` for every name.
    async fn probe_hosts(stub: &Stub, names: &[&str]) -> ProbeReport {
        let urls: Vec<String> = names.iter().map(|n| format!("http://{n}.test/")).collect();
        let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
        probe(stub, &urls).await
    }

    #[test]
    fn classification_boundaries() {
        let c = classify;
        assert_eq!(
            c(200, false, b"<div class='captcha-widget'>"),
            None,
            "captcha text on a 200 is not a block"
        );
        assert_eq!(c(200, true, b""), Some(SignalType::Challenge));
        assert_eq!(c(429, false, b""), Some(SignalType::RateLimited));
        assert_eq!(c(403, false, b"nope"), Some(SignalType::Forbidden));
        assert_eq!(
            c(403, false, b"Please solve the CAPTCHA"),
            Some(SignalType::Challenge)
        );
        assert_eq!(
            c(403, false, b"<title>Just a moment...</title>"),
            Some(SignalType::Challenge)
        );
        assert_eq!(
            // detection-data: a CDN challenge script path
            c(503, false, b"<script src='/cdn-cgi/challenge-platform/'>"),
            Some(SignalType::Challenge)
        );
        assert_eq!(
            c(503, false, b"maintenance"),
            None,
            "a plain 503 is an outage, not a block"
        );
        assert_eq!(c(404, false, b"captcha"), None);
        assert_eq!(c(500, false, b""), None);
    }

    #[tokio::test]
    async fn a_clean_target_is_three_gets_with_status_ttfb_and_capped_body() {
        let stub = Stub::spawn(|_| Resp::ok(vec![b'a'; 100 * 1024]));
        let report = probe(&stub, &["http://clean.test/"]).await;
        let t = &report.targets[0];
        assert_eq!(stub.hits(), 3);
        assert_eq!(t.samples.len(), 3);
        for s in &t.samples {
            assert_eq!(
                (s.status, s.outcome, s.bytes),
                (Some(200), Outcome::Clean, 16 * 1024)
            );
            assert!(s.ttfb.is_some());
        }
        assert_eq!(t.blocked(), None);
        assert_eq!(report.round().blocked, 0);
        let auth = stub.requests()[0]
            .header("proxy-authorization")
            .map(str::to_owned);
        assert!(auth.is_some_and(|a| a.starts_with("Basic ")));
    }

    #[tokio::test]
    async fn only_a_success_status_is_clean_and_other_statuses_fail_without_blocking() {
        let stub = Stub::spawn(|req| match req.host().as_str() {
            "ok.test" => Resp::ok("hello"),
            "created.test" => Resp::status(201, "made"),
            "gone.test" => Resp::status(404, "no such page"),
            "boom.test" => Resp::status(500, "oops"),
            "outage.test" => Resp::status(503, "maintenance"),
            "forbidden.test" => Resp::status(403, "denied"),
            "limited.test" => Resp::status(429, "slow down"),
            _ => Resp::status(418, ""),
        });
        let names = [
            "ok",
            "created",
            "gone",
            "boom",
            "outage",
            "forbidden",
            "limited",
        ];
        let report = probe_hosts(&stub, &names).await;
        let got: Vec<(Option<u16>, Outcome)> = report
            .targets
            .iter()
            .map(|t| (t.samples[0].status, t.samples[0].outcome))
            .collect();
        assert_eq!(
            got,
            [
                (Some(200), Outcome::Clean),
                (Some(201), Outcome::Clean),
                (Some(404), Outcome::Failed),
                (Some(500), Outcome::Failed),
                (Some(503), Outcome::Failed),
                (Some(403), Outcome::Blocked(SignalType::Forbidden)),
                (Some(429), Outcome::Blocked(SignalType::RateLimited)),
            ]
        );
        // Failed samples are no block signal.
        assert_eq!((report.round().blocked, report.round().total), (2, 7));
    }

    #[tokio::test]
    async fn blocks_are_recognised_per_target() {
        let stub = Stub::spawn(|req| match req.host().as_str() {
            "limited.test" => Resp::status(429, "slow down"),
            "forbidden.test" => Resp::status(403, "denied"),
            "captcha.test" => Resp::status(
                403,
                "<h1>Verify you are human</h1><div class=\"h-captcha\"></div>",
            ),
            // detection-data: the challenge header of a CDN
            "cf.test" => Resp::status(403, "blocked").header("cf-mitigated", "challenge"),
            "sorry.test" => Resp::status(302, "").header(
                "Location",
                "https://search.example.test/sorry/index?continue=x",
            ),
            "fine.test" => Resp::ok("hello"),
            _ => Resp::status(404, ""),
        });
        let report = probe_hosts(
            &stub,
            &["limited", "forbidden", "captcha", "cf", "sorry", "fine"],
        )
        .await;
        let got: Vec<Option<SignalType>> =
            report.targets.iter().map(TargetProbe::blocked).collect();
        assert_eq!(
            got,
            [
                Some(SignalType::RateLimited),
                Some(SignalType::Forbidden),
                Some(SignalType::Challenge),
                Some(SignalType::Challenge),
                Some(SignalType::Challenge),
                None
            ]
        );
        assert_eq!((report.round().blocked, report.round().total), (5, 6));
        // The sorry redirect is detected at the redirect: the interstitial is never fetched.
        assert!(
            stub.requests()
                .iter()
                .all(|r| r.host() != "search.example.test")
        );
    }

    #[tokio::test]
    async fn a_sorry_page_reached_after_other_redirects_is_a_challenge() {
        let stub = Stub::spawn(|req| match (req.host().as_str(), req.path().as_str()) {
            ("g.test", "/") => Resp::status(301, "").header("Location", "http://www.g.test/search"),
            ("www.g.test", "/search") => Resp::status(302, "").header("Location", "/sorry/index"),
            _ => Resp::status(404, ""),
        });
        let report = probe(&stub, &["http://g.test/"]).await;
        assert_eq!(report.targets[0].blocked(), Some(SignalType::Challenge));
        // TTFB is the first response, status the last one seen.
        let s = &report.targets[0].samples[0];
        assert_eq!(s.status, Some(302));
    }

    #[tokio::test]
    async fn ordinary_redirects_are_followed_to_the_final_answer() {
        let stub = Stub::spawn(|req| match req.path().as_str() {
            "/" => Resp::status(301, "").header("Location", "/home"),
            "/home" => Resp::ok("welcome"),
            _ => Resp::status(404, ""),
        });
        let report = probe(&stub, &["http://r.test/"]).await;
        let s = &report.targets[0].samples[0];
        assert_eq!(
            (s.status, s.outcome, s.bytes),
            (Some(200), Outcome::Clean, 7)
        );
        assert_eq!(stub.hits(), 6);
    }

    #[tokio::test]
    async fn a_redirect_loop_fails_without_blocking() {
        let stub = Stub::spawn(|_| Resp::status(302, "").header("Location", "/again"));
        let report = probe(&stub, &["http://loop.test/"]).await;
        let t = &report.targets[0];
        assert!(t.samples.iter().all(|s| s.outcome == Outcome::Failed));
        assert_eq!(t.blocked(), None);
        // 1 request + 3 redirects per sample.
        assert_eq!(stub.hits(), 12);
    }

    #[tokio::test]
    async fn one_blocked_sample_of_three_is_not_a_block_but_two_are() {
        let n = AtomicUsize::new(0);
        let stub = Stub::spawn(move |_| {
            // Calls 0..: 429, 200, 200 | 429, 429, 200
            match n.fetch_add(1, Ordering::SeqCst) {
                0 | 3 | 4 => Resp::status(429, ""),
                _ => Resp::ok("ok"),
            }
        });
        let first = probe(&stub, &["http://a.test/"]).await;
        assert_eq!(first.targets[0].blocked(), None);
        assert_eq!(
            first.targets[0]
                .samples
                .iter()
                .filter(|s| matches!(s.outcome, Outcome::Blocked(_)))
                .count(),
            1
        );
        let second = probe(&stub, &["http://a.test/"]).await;
        assert_eq!(second.targets[0].blocked(), Some(SignalType::RateLimited));
    }

    #[tokio::test]
    async fn the_most_severe_sample_type_names_the_signal() {
        let n = AtomicUsize::new(0);
        let stub = Stub::spawn(move |_| match n.fetch_add(1, Ordering::SeqCst) {
            0 => Resp::status(429, ""),
            1 => Resp::status(403, "captcha"),
            _ => Resp::status(403, "no"),
        });
        let report = probe(&stub, &["http://a.test/"]).await;
        assert_eq!(report.targets[0].blocked(), Some(SignalType::Challenge));
    }

    #[tokio::test]
    async fn an_unreachable_upstream_fails_samples_but_is_not_a_block() {
        let stub = Stub::spawn(|_| Resp::ok(""));
        let mut up = upstream(&stub);
        up.port = 1;
        let targets = [url("http://a.test/")];
        let report = LightProbe::new(ProbeConfig::default())
            .run(&up, &targets)
            .await
            .expect("call succeeds");
        let t = &report.targets[0];
        assert!(
            t.samples
                .iter()
                .all(|s| s.outcome == Outcome::Failed && s.status.is_none())
        );
        assert_eq!((report.round().blocked, report.round().total), (0, 1));
    }
}
