//! `proxyx-intercept doctor`: check the session proxy's configuration and
//! dependencies without starting it.
//!
//! The configuration is loaded the way the proxy loads it, then Redis, the
//! capture broker, the limiter (when it is the rate-limit backend), the CA,
//! the open-files limit and the listener ports are probed. The checks come
//! from `proxyx-diag`, which `proxyx doctor --role intercept` also reads back
//! as JSON.

use std::time::Duration;

use clap::Args;
use diag::ca::{CaEncoding, CaSource, ExpiryThresholds, ca_checks};
use diag::net::{brokers_check, dns_check, port_check, tcp_check, url_host_port};
use diag::redis_checks::{RedisOptions, redis_server, redis_stream};
use diag::{Check, Report, Status, files};

use crate::config::{BrokerKind, CaConfig, Config};
use crate::ratelimit::{FailOpenPolicy, RateLimitBackend};

/// Descriptors the proxy needs besides the tunnels: listeners, Redis and
/// broker connections, files. The pool gateway uses the same margin.
const FD_MARGIN: u64 = 512;

/// Arguments of `proxyx-intercept doctor`.
#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
    /// Treat warnings as failures (exit 1 instead of 2).
    #[arg(long)]
    pub strict: bool,
    /// Bound on every probe, in seconds (`5`, `5s`, `1m`).
    #[arg(long, default_value = "5s", value_parser = parse_timeout, value_name = "DURATION")]
    pub timeout: Duration,
    /// Do not try to bind the listener ports (the proxy may already run here).
    #[arg(long)]
    pub skip_listeners: bool,
}

fn parse_timeout(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let (digits, unit) = text
        .find(|c: char| !c.is_ascii_digit())
        .map_or((text, ""), |i| text.split_at(i));
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("bad duration {text:?}"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n.saturating_mul(60),
        _ => return Err(format!("bad duration unit in {text:?} (use s or m)")),
    };
    if secs == 0 {
        return Err("the timeout must be above zero".to_owned());
    }
    Ok(Duration::from_secs(secs))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Run the checks and return the report.
pub async fn build_report(config_path: Option<&str>, args: &DoctorArgs) -> Report {
    let mut report = Report::new("intercept");
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            let source = config_path.map_or_else(
                || "the default file and PROXYX_INTERCEPT_* variables".to_owned(),
                str::to_owned,
            );
            report.push(
                Check::fail("config.load", format!("{source}: {error:#}"))
                    .hint("fix the key named above; the proxy refuses to start on it"),
            );
            return report;
        }
    };
    report.push(Check::pass(
        "config.load",
        config_path.map_or_else(
            || "settings load from the default file and environment".to_owned(),
            |p| format!("{p} loads"),
        ),
    ));
    report.extend(validate(&config));

    // Redis (sessions, and the capture stream by default).
    let mut redis_opts = RedisOptions::new(args.timeout);
    redis_opts.require_persistence = config.broker_kind == BrokerKind::RedisStream;
    report.extend(redis_server(&config.redis_url, redis_opts).await);
    if let Some((host, _)) = url_host_port(&config.redis_url)
        && host.parse::<std::net::IpAddr>().is_err()
    {
        report.push(dns_check("dns.redis", &host, args.timeout).await);
    }

    // The capture log.
    match config.broker_kind {
        BrokerKind::RedisStream => report.push(
            redis_stream(
                &config.redis_url,
                &config.request_log.stream_name,
                config.request_log.max_stream_len,
                args.timeout,
            )
            .await,
        ),
        BrokerKind::Kafka => {
            if let Ok(Some(kafka)) = config.kafka_config() {
                report.push(brokers_check("broker.reachable", &kafka.brokers, args.timeout).await);
            }
        }
        BrokerKind::Rabbitmq => {
            if let Some(rabbitmq) = &config.rabbitmq
                && let Some((host, port)) = url_host_port(&rabbitmq.url)
            {
                let default_port = if rabbitmq.url.starts_with("amqps://") {
                    5671
                } else {
                    5672
                };
                let target = format!("{host}:{}", port.unwrap_or(default_port));
                report.push(brokers_check("broker.reachable", &target, args.timeout).await);
            }
        }
    }

    // The limiter, when it enforces the rate limits.
    if config.ratelimit.backend == RateLimitBackend::Limiter {
        let mut check = tcp_check(
            "ratelimit.limiter",
            "the limiter",
            &config.ratelimit.limiter_addr,
            args.timeout,
        )
        .await;
        // With fail-open the proxy keeps serving when the limiter is down.
        if check.status == Status::Fail
            && !matches!(config.ratelimit.failopen_policy, FailOpenPolicy::Deny)
        {
            check.status = Status::Warn;
            check.hint = Some(
                "rate limits are not enforced while the limiter is down (failopen_policy is not `deny`)"
                    .to_owned(),
            );
        }
        report.push(check);
    }

    report.extend(ca(&config.ca));

    // Descriptors: two per tunnel.
    let needed = (config.tuning.max_connections as u64)
        .saturating_mul(2)
        .saturating_add(FD_MARGIN);
    report.push(files::fd_limit(
        needed,
        &format!(
            "tuning.max_connections = {}: 2 per tunnel and {FD_MARGIN} spare",
            config.tuning.max_connections
        ),
    ));

    for (id, label, addr) in listeners(&config) {
        report.push(if args.skip_listeners {
            Check::skip(id, format!("{label} {addr}: not tried (--skip-listeners)"))
        } else {
            port_check(id, label, addr)
        });
    }
    report
}

fn listeners(config: &Config) -> Vec<(&'static str, &'static str, std::net::SocketAddr)> {
    let mut all = vec![("listen.connect", "CONNECT listener", config.connect_addr)];
    if let Some(http) = config.http_addr {
        all.push(("listen.http", "HTTP proxy listener", http));
    }
    all.push(("listen.socks", "SOCKS5 listener", config.socks_addr));
    all.push(("listen.api", "admin API", config.api_addr));
    all
}

/// Values the proxy would only trip over later.
fn validate(config: &Config) -> Vec<Check> {
    let mut out = Vec::new();
    if config.broker_kind == BrokerKind::Kafka && !matches!(config.kafka_config(), Ok(Some(_))) {
        out.push(
            Check::fail("config.broker", "broker_kind = \"kafka\" but the [kafka] section is missing")
                .hint("add [kafka] with `brokers = \"host:port,...\"` and `topic`, or use broker_kind = \"redis_stream\""),
        );
    }
    if config.broker_kind == BrokerKind::Rabbitmq && config.rabbitmq.is_none() {
        out.push(
            Check::fail("config.broker", "broker_kind = \"rabbitmq\" but the [rabbitmq] section is missing")
                .hint("add [rabbitmq] with `url = \"amqp://user:pass@host:5672/%2f\"`, or use broker_kind = \"redis_stream\""),
        );
    }
    if config.ratelimit.backend == RateLimitBackend::Limiter
        && config
            .ratelimit
            .limiter_addr
            .parse::<std::net::SocketAddr>()
            .is_err()
        && !config.ratelimit.limiter_addr.contains(':')
    {
        out.push(
            Check::fail(
                "config.ratelimit",
                format!(
                    "ratelimit.limiter_addr {:?} is not host:port",
                    config.ratelimit.limiter_addr
                ),
            )
            .hint("set ratelimit.limiter_addr = \"host:39091\""),
        );
    }
    for (key, value) in [
        ("tuning.max_connections", config.tuning.max_connections),
        (
            "tuning.exchange_channel_capacity",
            config.tuning.exchange_channel_capacity,
        ),
        (
            "request_log.channel_capacity",
            config.request_log.channel_capacity,
        ),
    ] {
        if value == 0 {
            out.push(
                Check::fail("config.tuning", format!("{key} must be above zero")).hint(
                    "a zero here leaves the proxy accepting no connection or capturing nothing",
                ),
            );
        }
    }
    let all = listeners(config);
    for (i, (_, a_label, a)) in all.iter().enumerate() {
        for (_, b_label, b) in &all[i + 1..] {
            if a.port() == b.port()
                && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
            {
                out.push(
                    Check::fail(
                        "listen.distinct",
                        format!("{a_label} {a} and {b_label} {b} use the same port"),
                    )
                    .hint("give every listener its own port"),
                );
            }
        }
    }
    if out.is_empty() {
        out.push(Check::pass("config.valid", "the values are consistent"));
    }
    out
}

/// The CA that signs interception certificates: certificate and key.
fn ca(config: &CaConfig) -> Vec<Check> {
    let (now, th) = (unix_now(), ExpiryThresholds::default());
    match config {
        CaConfig::Env => {
            match CaSource::from_env("PROXYX_INTERCEPT_CA_CERT", Some("PROXYX_INTERCEPT_CA_KEY")) {
                Ok(source) => ca_checks(&source, CaEncoding::PemOrBase64, now, th),
                Err(error) => vec![Check::fail("ca.cert", error)],
            }
        }
        CaConfig::File {
            cert_path,
            key_path,
        } => ca_checks(
            &CaSource::Files {
                cert: cert_path.clone(),
                key: Some(key_path.clone()),
            },
            CaEncoding::Der,
            now,
            th,
        ),
        CaConfig::Generate { data_dir } => {
            let (cert, key) = (data_dir.join("ca.der"), data_dir.join("ca.key.der"));
            let mut out = vec![
                Check::warn(
                    "ca.mode",
                    "ca.type = \"generate\" is for development: use `file` or `env` with a CA the control plane shares",
                )
                .hint("set [ca] type = \"file\" with cert_path and key_path"),
            ];
            if cert.exists() && key.exists() {
                out.extend(ca_checks(
                    &CaSource::Files {
                        cert,
                        key: Some(key),
                    },
                    CaEncoding::Der,
                    now,
                    th,
                ));
            } else {
                out.push(Check::skip(
                    "ca.cert",
                    format!(
                        "{} does not exist yet: it is generated at first start",
                        cert.display()
                    ),
                ));
            }
            out
        }
    }
}

/// `proxyx-intercept doctor`: print the report and return the exit code
/// (0 all clear, 1 a failure or a warning with `--strict`, 2 only warnings).
pub async fn run(config_path: Option<&str>, args: DoctorArgs) -> i32 {
    let report = build_report(config_path, &args).await;
    if args.json {
        match serde_json::to_string_pretty(&report.to_json(args.strict)) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("cannot render the report: {error}"),
        }
    } else {
        print!("{}", report.render_table(args.strict));
    }
    report.exit_code(args.strict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args() -> DoctorArgs {
        DoctorArgs {
            json: false,
            strict: false,
            timeout: Duration::from_secs(2),
            skip_listeners: false,
        }
    }

    /// The test Redis, at the database of the doctor tests (12), or `None`.
    fn redis_url() -> Option<String> {
        let base = std::env::var("PROXYX_TEST_REDIS_URL").ok()?;
        let authority = base.trim_end_matches('/');
        let authority = authority
            .rsplit_once('/')
            .filter(|(h, _)| h.contains("://"))
            .map_or(authority, |(h, _)| h);
        Some(format!("{authority}/12"))
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "proxyx-intercept-doctor-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn status(report: &Report, id: &str) -> Status {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no {id} in {:?}", report.checks))
            .status
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .expect("port")
    }

    fn config_file(dir: &std::path::Path, redis: &str, extra: &str) -> String {
        let path = dir.join("intercept.toml");
        let text = format!(
            "connect_addr = \"127.0.0.1:{}\"\nsocks_addr = \"127.0.0.1:{}\"\napi_addr = \"127.0.0.1:{}\"\nhttp_addr = \"127.0.0.1:{}\"\nredis_url = \"{redis}\"\n{extra}\n[ca]\ntype = \"generate\"\ndata_dir = \"{}\"\n",
            free_port(),
            free_port(),
            free_port(),
            free_port(),
            dir.display()
        );
        std::fs::write(&path, text).expect("write");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn timeouts_parse() {
        assert_eq!(parse_timeout("5"), Ok(Duration::from_secs(5)));
        assert_eq!(parse_timeout("2m"), Ok(Duration::from_secs(120)));
        assert!(parse_timeout("0").is_err());
        assert!(parse_timeout("5h").is_err());
    }

    #[tokio::test]
    async fn a_bad_config_names_the_key_and_the_file() {
        let dir = scratch("bad");
        let path = dir.join("bad.toml");
        std::fs::write(&path, "connect_addr = \"not an address\"\n").expect("write");
        let path = path.to_string_lossy().into_owned();
        let report = build_report(Some(&path), &args()).await;
        assert_eq!(report.checks.len(), 1);
        let check = &report.checks[0];
        assert_eq!(
            (check.id.as_str(), check.status),
            ("config.load", Status::Fail)
        );
        assert!(check.message.contains("connect_addr"), "{}", check.message);
        assert!(check.message.contains("bad.toml"), "{}", check.message);
        assert_eq!(report.exit_code(false), diag::EXIT_FAIL);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_inconsistent_config_fails_before_anything_is_probed() {
        let dir = scratch("inconsistent");
        let path = config_file(
            &dir,
            "redis://127.0.0.1:1",
            "broker_kind = \"kafka\"\n[tuning]\nmax_connections = 0\n",
        );
        let report = build_report(Some(&path), &args()).await;
        assert_eq!(status(&report, "config.broker"), Status::Fail);
        assert_eq!(status(&report, "config.tuning"), Status::Fail);
        // Redis is down on that port, and the bounded probe says so.
        assert_eq!(status(&report, "redis.reachable"), Status::Fail);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_shipped_example_loads() {
        let path = format!(
            "{}/../../examples/intercept.toml",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut skip = args();
        skip.skip_listeners = true;
        let report = build_report(Some(&path), &skip).await;
        assert_eq!(status(&report, "config.load"), Status::Pass, "{report:#?}");
        assert_eq!(status(&report, "config.valid"), Status::Pass, "{report:#?}");
    }

    #[tokio::test]
    async fn a_working_setup_passes() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
            return;
        };
        let dir = scratch("ok");
        let path = config_file(&dir, &url, "");
        let report = build_report(Some(&path), &args()).await;
        for id in [
            "config.load",
            "config.valid",
            "redis.reachable",
            "redis.clock_skew",
            "redis.stream",
            "listen.connect",
            "listen.socks",
            "listen.api",
            "listen.http",
        ] {
            assert_eq!(status(&report, id), Status::Pass, "{id}: {report:#?}");
        }
        // generate mode warns (development only); nothing fails.
        assert_eq!(status(&report, "ca.mode"), Status::Warn);
        assert_eq!(report.summary().fail, 0, "{report:#?}");
        assert_eq!(report.exit_code(false), diag::EXIT_WARN);
        assert_eq!(report.exit_code(true), diag::EXIT_FAIL);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_listener_that_is_taken_fails_and_skip_listeners_skips_it() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
            return;
        };
        let dir = scratch("port");
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = taken.local_addr().expect("addr").port();
        let path = config_file(&dir, &url, "");
        let text = std::fs::read_to_string(&path).expect("read");
        let first = text.lines().next().expect("line").to_owned();
        let text = text.replacen(&first, &format!("connect_addr = \"127.0.0.1:{port}\""), 1);
        std::fs::write(&path, text).expect("write");
        let report = build_report(Some(&path), &args()).await;
        assert_eq!(status(&report, "listen.connect"), Status::Fail);
        let mut skip = args();
        skip.skip_listeners = true;
        let report = build_report(Some(&path), &skip).await;
        assert_eq!(status(&report, "listen.connect"), Status::Skip);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_limiter_backend_is_probed_and_fail_open_makes_it_a_warning() {
        let dir = scratch("limiter");
        let closed = free_port();
        let extra = format!(
            "[ratelimit]\nbackend = \"limiter\"\nlimiter_addr = \"127.0.0.1:{closed}\"\ndefault_burst = 10\ndefault_rpm = 60\nrefill_threshold_pct = 0.25\nrate_limit_max_wait_ms = 10\n[ratelimit.failopen_policy]\ntype = \"deny\"\n"
        );
        let path = config_file(&dir, "redis://127.0.0.1:1", &extra);
        let report = build_report(Some(&path), &args()).await;
        assert_eq!(
            status(&report, "ratelimit.limiter"),
            Status::Fail,
            "{report:#?}"
        );
        let open = extra.replace("type = \"deny\"", "type = \"grant_tokens\"\nvalue = 5");
        let path = config_file(&dir, "redis://127.0.0.1:1", &open);
        let report = build_report(Some(&path), &args()).await;
        assert_eq!(
            status(&report, "ratelimit.limiter"),
            Status::Warn,
            "{report:#?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
