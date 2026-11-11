//! Network reachability: TCP connect, DNS, listener ports and HTTP.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinSet;

use crate::report::{Check, timed};

/// Try to connect to `target` (`host:port`) within `timeout`. Every address
/// the name resolves to is tried within the one bound.
pub async fn tcp_connect(target: &str, timeout: Duration) -> Result<SocketAddr, String> {
    let attempt = async {
        let mut last = String::from("the name resolved to no address");
        for addr in lookup_host(target)
            .await
            .map_err(|e| format!("cannot resolve {target}: {e}"))?
        {
            match TcpStream::connect(addr).await {
                Ok(_) => return Ok(addr),
                Err(e) => last = format!("{addr}: {e}"),
            }
        }
        Err(last)
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "{target}: no answer within {} ms",
            timeout.as_millis()
        )),
    }
}

/// The `host` and `port` of a connection URL (`scheme://user:pw@host:port/path`),
/// without credentials. IPv6 literals keep their brackets removed.
pub fn url_host_port(url: &str) -> Option<(String, Option<u16>)> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hosts = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // A libpq URL may list several hosts; the first one is enough here.
    let first = hosts.split(',').next()?;
    let (host, port) = if let Some(v6) = first.strip_prefix('[') {
        let (addr, tail) = v6.split_once(']')?;
        (addr, tail.strip_prefix(':'))
    } else {
        match first.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (first, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_owned(), port.and_then(|p| p.parse().ok())))
}

/// Reachability of one TCP service.
pub async fn tcp_check(id: &str, label: &str, target: &str, timeout: Duration) -> Check {
    let (result, took) = timed(tcp_connect(target, timeout)).await;
    match result {
        Ok(addr) => Check::pass(id, format!("{label} accepts connections at {addr}")),
        Err(error) => Check::fail(id, format!("{label} is unreachable: {error}")).hint(format!(
            "check that {target} is correct, running and not firewalled"
        )),
    }
    .elapsed(took)
}

/// Reachability of a Kafka-compatible broker list (`host:port,host:port`): TCP
/// only, no Kafka handshake. Passes when every broker answers, warns when some
/// do, fails when none does.
pub async fn brokers_check(id: &str, brokers: &str, timeout: Duration) -> Check {
    let list: Vec<String> = brokers
        .split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_owned)
        .collect();
    if list.is_empty() {
        return Check::fail(id, "the broker list is empty")
            .hint("set the brokers to `host:port,host:port`");
    }
    let start = std::time::Instant::now();
    let mut set = JoinSet::new();
    for (i, broker) in list.iter().cloned().enumerate() {
        set.spawn(async move { (i, tcp_connect(&broker, timeout).await) });
    }
    let mut failed: Vec<(usize, String)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((_, Ok(_))) => {}
            Ok((i, Err(error))) => failed.push((i, error)),
            Err(error) => failed.push((usize::MAX, format!("check task failed: {error}"))),
        }
    }
    failed.sort();
    let elapsed = start.elapsed();
    let errors: Vec<String> = failed.into_iter().map(|(_, e)| e).collect();
    if errors.is_empty() {
        Check::pass(
            id,
            format!("all {} broker(s) accept connections", list.len()),
        )
    } else if errors.len() < list.len() {
        Check::warn(
            id,
            format!(
                "{} of {} broker(s) unreachable: {}",
                errors.len(),
                list.len(),
                errors.join("; ")
            ),
        )
        .hint("the cluster is degraded; clients keep working while one broker answers")
    } else {
        Check::fail(id, format!("no broker is reachable: {}", errors.join("; ")))
            .hint("check the broker addresses, the network path and that the cluster is up")
    }
    .elapsed(elapsed)
}

/// Resolve `host` (a name, `host:port`, or an IP literal) within `timeout`.
pub async fn dns_check(id: &str, host: &str, timeout: Duration) -> Check {
    let target = if host
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        host.to_owned()
    } else {
        format!("{host}:0")
    };
    let (result, took) = timed(tokio::time::timeout(timeout, lookup_host(target))).await;
    match result {
        Ok(Ok(addrs)) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.is_empty() {
                Check::fail(id, format!("{host} resolves to no address"))
            } else {
                Check::pass(id, format!("{host} resolves to {}", ips.join(", ")))
            }
        }
        Ok(Err(error)) => Check::fail(id, format!("{host} does not resolve: {error}"))
            .hint("check the name and the resolver this host uses (/etc/resolv.conf)"),
        Err(_) => Check::fail(
            id,
            format!(
                "{host}: DNS gave no answer within {} ms",
                timeout.as_millis()
            ),
        )
        .hint("the resolver is not answering"),
    }
    .elapsed(took)
}

/// Whether `addr` can be bound now. A port that is in use, or one this user
/// may not bind, fails: a role would not start on it.
pub fn port_check(id: &str, label: &str, addr: SocketAddr) -> Check {
    match std::net::TcpListener::bind(addr) {
        Ok(_) => Check::pass(id, format!("{label} {addr} is free")),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            Check::fail(id, format!("{label} {addr} is already in use"))
                .hint("stop the process that holds the port (is the role already running?) or change the address")
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Check::fail(id, format!("{label} {addr}: permission denied"))
                .hint("ports below 1024 need CAP_NET_BIND_SERVICE or a higher port")
        }
        Err(error) => Check::fail(id, format!("{label} {addr} cannot be bound: {error}")),
    }
}

/// `GET url` within `timeout`: the status code and the body (at most 64 KiB).
pub async fn http_get(url: &str, timeout: Duration) -> Result<(u16, String), String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let response = client.get(url).send().await.map_err(|e| describe(&e))?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.map_err(|e| describe(&e))?;
    let cut = &bytes[..bytes.len().min(64 * 1024)];
    Ok((status, String::from_utf8_lossy(cut).into_owned()))
}

/// The error and its causes on one line, without the URL (it may carry a password).
fn describe(error: &reqwest::Error) -> String {
    let mut text = if error.is_timeout() {
        "timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else {
        "request failed".to_owned()
    };
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// ClickHouse over HTTP: `GET <url>/ping` answers `Ok.`.
pub async fn clickhouse_ping(base_url: &str, timeout: Duration) -> Check {
    let id = "clickhouse.ping";
    let url = format!("{}/ping", base_url.trim_end_matches('/'));
    let (result, took) = timed(http_get(&url, timeout)).await;
    match result {
        Ok((200, body)) if body.trim() == "Ok." => Check::pass(id, "ClickHouse answers /ping"),
        Ok((200, body)) => Check::warn(
            id,
            format!(
                "/ping answered 200 with an unexpected body ({:?}): is this ClickHouse?",
                body.trim()
            ),
        ),
        Ok((status, _)) => Check::fail(id, format!("/ping answered HTTP {status}"))
            .hint("point `clickhouse.url` at the HTTP port (8123), not the native port"),
        Err(error) => Check::fail(id, format!("ClickHouse is unreachable: {error}"))
            .hint("check clickhouse.url, that the server runs and that the HTTP port is open"),
    }
    .elapsed(took)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_listening_port_connects_and_a_bound_one_is_in_use() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let check = tcp_check("t.tcp", "svc", &addr.to_string(), Duration::from_secs(2)).await;
        assert_eq!(check.status, crate::Status::Pass, "{check:?}");
        let check = port_check("t.port", "listener", addr);
        assert_eq!(check.status, crate::Status::Fail, "{check:?}");
        assert!(check.message.contains("in use"), "{check:?}");
        drop(listener);
        assert_eq!(
            port_check("t.port", "listener", addr).status,
            crate::Status::Pass
        );
    }

    #[test]
    fn url_hosts_parse() {
        let h = |u: &str| url_host_port(u);
        assert_eq!(
            h("postgres://u:p@db.example:5433/x?sslmode=require"),
            Some(("db.example".into(), Some(5433)))
        );
        assert_eq!(h("redis://localhost"), Some(("localhost".into(), None)));
        assert_eq!(h("redis://[::1]:6380/2"), Some(("::1".into(), Some(6380))));
        assert_eq!(h("postgres://u@a:1,b:2/db"), Some(("a".into(), Some(1))));
        assert_eq!(h("no scheme"), None);
        assert_eq!(h("redis:///x"), None);
    }

    #[tokio::test]
    async fn a_closed_port_fails() {
        let addr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr")
        };
        let check = tcp_check("t.tcp", "svc", &addr.to_string(), Duration::from_secs(2)).await;
        assert_eq!(check.status, crate::Status::Fail, "{check:?}");
    }

    #[tokio::test]
    async fn brokers_are_pass_warn_or_fail_by_how_many_answer() {
        let up = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let up_addr = up.local_addr().expect("addr");
        let down = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr")
        };
        let t = Duration::from_secs(2);
        assert_eq!(
            brokers_check("b", &up_addr.to_string(), t).await.status,
            crate::Status::Pass
        );
        let mixed = format!("{up_addr},{down}");
        assert_eq!(
            brokers_check("b", &mixed, t).await.status,
            crate::Status::Warn
        );
        assert_eq!(
            brokers_check("b", &down.to_string(), t).await.status,
            crate::Status::Fail
        );
        assert_eq!(
            brokers_check("b", " , ", t).await.status,
            crate::Status::Fail
        );
    }

    #[tokio::test]
    async fn dns_resolves_literals_and_localhost_and_rejects_nonsense() {
        let t = Duration::from_secs(3);
        assert_eq!(
            dns_check("d", "127.0.0.1", t).await.status,
            crate::Status::Pass
        );
        assert_eq!(
            dns_check("d", "localhost:5432", t).await.status,
            crate::Status::Pass
        );
        assert_eq!(
            dns_check("d", "no-such-host.invalid", t).await.status,
            crate::Status::Fail
        );
    }

    #[tokio::test]
    async fn a_canned_clickhouse_answers_ping() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\nOk.\n",
                    )
                    .await;
            }
        });
        let check = clickhouse_ping(&format!("http://{addr}/"), Duration::from_secs(3)).await;
        assert_eq!(check.status, crate::Status::Pass, "{check:?}");
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr")
        };
        let check = clickhouse_ping(&format!("http://{closed}"), Duration::from_secs(3)).await;
        assert_eq!(check.status, crate::Status::Fail, "{check:?}");
    }
}
