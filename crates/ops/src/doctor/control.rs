//! Control plane: `ControlConfig` as the roles load it, then what they need.

use std::path::Path;

use diag::ca::{CaEncoding, CaSource, ExpiryThresholds, ca_checks};
use diag::net::{brokers_check, dns_check, http_get, port_check, url_host_port};
use diag::redis_checks::{RedisOptions, redis_server, redis_stream};
use diag::{Check, db};
use proxyx_control::capture_store::CaptureBackend;
use proxyx_control::config::{BrokerKind, CaConfig, ControlConfig};

use super::Ctx;
use super::pool::chain;

/// Which control-plane role the checks are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Both,
    Ingester,
}

pub(crate) async fn checks(kind: Kind, config: Option<&Path>, ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    let path = config.map(|p| p.to_string_lossy().into_owned());
    let cfg = match ControlConfig::load(path.as_deref()) {
        Ok(cfg) => cfg,
        Err(error) => {
            let source = path
                .clone()
                .unwrap_or_else(|| "the default file and PROXYX_CONTROL_* variables".to_owned());
            out.push(
                Check::fail("config.load", format!("{source}: {}", chain(&error)))
                    .hint("fix the key named above; the role refuses to start on it"),
            );
            return out;
        }
    };
    out.push(Check::pass(
        "config.load",
        path.map_or_else(
            || "settings load from the default file and environment".to_owned(),
            |p| format!("{p} loads and validates"),
        ),
    ));

    // Backend sections the selected stores need.
    let mut clickhouse_url = None;
    let mut opensearch_url = None;
    match cfg.capture_store.backend {
        CaptureBackend::ClickHouse => match cfg.clickhouse_config() {
            Ok(c) => clickhouse_url = Some(c.url.clone()),
            Err(error) => out.push(
                Check::fail("config.capture_store", chain(&error))
                    .hint("add the [clickhouse] section, or choose another capture_store.backend"),
            ),
        },
        CaptureBackend::OpenSearch => match cfg.opensearch_config() {
            Ok(c) => opensearch_url = Some(c.url.clone()),
            Err(error) => out.push(
                Check::fail("config.capture_store", chain(&error))
                    .hint("add the [capture_store.opensearch] section"),
            ),
        },
    }
    if cfg.broker_kind == BrokerKind::Kafka && !matches!(cfg.kafka_config(), Ok(Some(_))) {
        out.push(
            Check::fail("config.broker", "broker_kind = \"kafka\" but the [kafka] section is missing")
                .hint("add [kafka] with `brokers = \"host:port,...\"` and `topic`, or use broker_kind = \"redis_stream\""),
        );
    }
    if cfg.broker_kind == BrokerKind::Rabbitmq && cfg.rabbitmq.is_none() {
        out.push(
            Check::fail("config.broker", "broker_kind = \"rabbitmq\" but the [rabbitmq] section is missing")
                .hint("add [rabbitmq] with `url = \"amqp://user:pass@host:5672/%2f\"`, or use broker_kind = \"redis_stream\""),
        );
    }

    // Postgres and Redis.
    let pg_checks = db::database(&cfg.database_url, ctx.timeout).await;
    let pg_up = pg_checks
        .first()
        .is_some_and(|c| c.status != diag::Status::Fail);
    out.extend(pg_checks);
    if pg_up {
        out.push(pending_migrations(&cfg.database_url, ctx.timeout).await);
    }
    let mut redis_opts = RedisOptions::new(ctx.timeout);
    redis_opts.require_persistence = cfg.broker_kind == BrokerKind::RedisStream;
    out.extend(redis_server(&cfg.redis_url, redis_opts).await);
    for (id, url) in [
        ("dns.postgres", cfg.database_url.as_str()),
        ("dns.redis", cfg.redis_url.as_str()),
    ] {
        if let Some((host, _)) = url_host_port(url)
            && host.parse::<std::net::IpAddr>().is_err()
        {
            out.push(dns_check(id, &host, ctx.timeout).await);
        }
    }

    // Capture store and broker.
    if let Some(url) = &clickhouse_url {
        out.push(diag::net::clickhouse_ping(url, ctx.timeout).await);
    }
    if let Some(url) = &opensearch_url {
        out.push(opensearch(url, ctx.timeout).await);
    }
    match cfg.broker_kind {
        BrokerKind::RedisStream => {
            out.push(
                redis_stream(
                    &cfg.redis_url,
                    &cfg.request_log_stream,
                    cfg.request_log_max_stream_len,
                    ctx.timeout,
                )
                .await,
            );
        }
        BrokerKind::Kafka => {
            if let Ok(Some(kafka)) = cfg.kafka_config() {
                out.push(brokers_check("broker.reachable", &kafka.brokers, ctx.timeout).await);
            }
        }
        BrokerKind::Rabbitmq => {
            if let Some(rabbitmq) = &cfg.rabbitmq
                && let Some((host, port)) = url_host_port(&rabbitmq.url)
            {
                let default_port = if rabbitmq.url.starts_with("amqps://") {
                    5671
                } else {
                    5672
                };
                let target = format!("{host}:{}", port.unwrap_or(default_port));
                out.push(brokers_check("broker.reachable", &target, ctx.timeout).await);
            }
        }
    }

    // CA.
    out.extend(ca(&cfg.ca));

    // Listeners.
    if kind == Kind::Both {
        out.push(listener(ctx, "listen.api", "control API", cfg.api_addr));
    }
    out.push(listener(
        ctx,
        "listen.ingester_health",
        "ingester health",
        cfg.ingester_health_addr,
    ));
    out
}

/// The control plane's own migration check (`proxyx migrate control --check`).
async fn pending_migrations(url: &str, timeout: std::time::Duration) -> Check {
    let id = "postgres.pending";
    let run = async {
        let db = proxyx_control::db::Db::connect(url, 1).await?;
        proxyx_control::migrations::verify_database(&db).await
    };
    match tokio::time::timeout(timeout * 2, run).await {
        Ok(Ok(())) => Check::pass(id, "the schema is up to date"),
        Ok(Err(error)) => Check::fail(id, chain(&error))
            .hint("run `proxyx migrate control` before starting the roles"),
        Err(_) => Check::fail(id, "reading the migration state timed out"),
    }
}

fn listener(ctx: &Ctx, id: &str, label: &str, addr: std::net::SocketAddr) -> Check {
    if ctx.skip_listeners {
        Check::skip(id, format!("{label} {addr}: not tried (--skip-listeners)"))
    } else {
        port_check(id, label, addr)
    }
}

/// `GET /` of OpenSearch / Elasticsearch: any answer under 500 shows a server;
/// 401/403 means it is there but wants credentials the doctor does not send.
async fn opensearch(url: &str, timeout: std::time::Duration) -> Check {
    let id = "opensearch.ping";
    match http_get(url, timeout).await {
        Ok((status, _)) if status < 400 => {
            Check::pass(id, format!("{} answers HTTP {status}", host_of(url)))
        }
        Ok((401 | 403, _)) => Check::pass(
            id,
            format!(
                "{} answers and asks for credentials (not sent by the doctor)",
                host_of(url)
            ),
        ),
        Ok((status, _)) => Check::fail(id, format!("{} answers HTTP {status}", host_of(url))),
        Err(error) => Check::fail(id, format!("{} is unreachable: {error}", host_of(url)))
            .hint("check capture_store.opensearch.url, TLS (ca_cert) and the network path"),
    }
}

fn host_of(url: &str) -> String {
    url_host_port(url).map_or_else(
        || "the OpenSearch endpoint".to_owned(),
        |(h, p)| p.map_or(h.clone(), |p| format!("{h}:{p}")),
    )
}

/// The CA the control plane hands to clients (certificate only, PEM).
fn ca(config: &CaConfig) -> Vec<Check> {
    let now = unix_now();
    let th = ExpiryThresholds::default();
    match config {
        CaConfig::Env => match CaSource::from_env("PROXYX_CONTROL_CA_CERT", None) {
            Ok(source) => ca_checks(&source, CaEncoding::Pem, now, th),
            Err(error) => vec![Check::fail("ca.cert", error)],
        },
        CaConfig::File { cert_path } => ca_checks(
            &CaSource::Files {
                cert: cert_path.clone(),
                key: None,
            },
            CaEncoding::Pem,
            now,
            th,
        ),
        CaConfig::Generate { data_dir } => {
            let cert = data_dir.join("ca.der");
            let key = data_dir.join("ca.key.der");
            let mut out = vec![
                Check::warn("ca.mode", "ca.type = \"generate\" is for development: use `file` or `env` with the CA the session proxy uses")
                    .hint("set [ca] type = \"file\" with cert_path, or type = \"env\""),
            ];
            if cert.exists() {
                let key = key.exists().then_some(key);
                out.extend(ca_checks(
                    &CaSource::Files { cert, key },
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

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
