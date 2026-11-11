//! Edge, limiter and the session proxy.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;

use diag::net::port_check;
use diag::{Check, Report, files};

use super::Ctx;
use super::pool::chain;

/// `proxyx edge --check`: the configuration compiles, references resolve, local
/// addresses are assigned.
pub(crate) fn edge(config: Option<&Path>, explicit: bool) -> Vec<Check> {
    let default = Path::new("/etc/proxyx/edge.toml");
    let path = match config {
        Some(path) => path,
        None if default.is_file() => default,
        None => {
            return vec![if explicit {
                Check::fail(
                    "config.load",
                    "no edge configuration: pass `--config <file>`",
                )
            } else {
                Check::skip("config.load", "no edge configuration found")
            }];
        }
    };
    vec![match proxyx_edge::check(path) {
        Ok(report) => Check::pass(
            "config.load",
            format!(
                "{} loads: {} listener(s), {} user(s), {} rule(s), {} parent(s), {} pool(s)",
                path.display(),
                report.listeners,
                report.users,
                report.rules,
                report.parents,
                report.pools.len()
            ),
        ),
        Err(error) => Check::fail(
            "config.load",
            format!("{}: {}", path.display(), chain(&error)),
        )
        .hint("fix the key named above; `proxyx edge --check` reports the same"),
    }]
}

/// The limiter reads `PROXYX_LIMITER_*` variables; a value it cannot use falls
/// back to its default without a message, which is what this reports.
pub(crate) async fn limiter(ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    for (var, what) in [
        ("PROXYX_LIMITER_MAX_BUCKETS", "bucket capacity"),
        ("PROXYX_LIMITER_SHARDS", "shard count"),
        ("PROXYX_LIMITER_REAPER_MS", "reaper interval"),
        ("PROXYX_LIMITER_MAX_CONNECTIONS", "connection cap"),
        ("PROXYX_LIMITER_IDLE_TIMEOUT_MS", "idle timeout"),
        (
            "PROXYX_LIMITER_TCP_KEEPALIVE_SECS",
            "TCP keepalive interval",
        ),
    ] {
        out.push(limiter_var(var, what, std::env::var(var).ok().as_deref()));
    }
    out.extend(limiter_listeners(
        ctx,
        std::env::var("PROXYX_LIMITER_METRICS_ADDR").ok().as_deref(),
    ));
    // One thread and one descriptor per client connection.
    out.push(files::fd_limit(
        1024,
        "one descriptor per client connection, 1024 as a floor",
    ));
    out
}

fn limiter_listeners(ctx: &Ctx, metrics_addr: Option<&str>) -> Vec<Check> {
    let mut out = Vec::new();
    let listener = |id: &str, label: &str, addr: SocketAddr| {
        if ctx.skip_listeners {
            Check::skip(id, format!("{label} {addr}: not tried (--skip-listeners)"))
        } else {
            port_check(id, label, addr)
        }
    };
    let addr = ctx
        .limiter_addr
        .as_deref()
        .unwrap_or(proxyx_limiter_server::DEFAULT_LISTEN);
    let data_addr = match addr.parse::<SocketAddr>() {
        Ok(parsed) => {
            out.push(listener("listen.limiter", "limiter listener", parsed));
            Some(parsed)
        }
        Err(error) => {
            out.push(
                Check::fail(
                    "listen.limiter",
                    format!("limiter address {addr:?} is not host:port: {error}"),
                )
                .hint(
                    "`proxyx limiter [ADDR]` takes an IP address and port, for example 0.0.0.0:39091",
                ),
            );
            None
        }
    };
    let Some(metrics_addr) = metrics_addr.filter(|v| !v.trim().is_empty()) else {
        out.push(Check::skip(
            "listen.metrics",
            "PROXYX_LIMITER_METRICS_ADDR is unset or empty: metrics listener disabled",
        ));
        return out;
    };
    match metrics_addr.parse::<SocketAddr>() {
        Ok(parsed) => {
            out.push(listener(
                "listen.metrics",
                "limiter metrics listener",
                parsed,
            ));
            if let Some(data_addr) = data_addr {
                let clash = parsed.port() != 0
                    && parsed.port() == data_addr.port()
                    && (parsed.ip() == data_addr.ip()
                        || parsed.ip().is_unspecified()
                        || data_addr.ip().is_unspecified());
                out.push(if clash {
                    Check::fail(
                        "listen.distinct",
                        format!("limiter listener {data_addr} and metrics listener {parsed} use the same port"),
                    )
                    .hint("give every listener its own port")
                } else {
                    Check::pass("listen.distinct", "the listeners use distinct ports")
                });
            }
        }
        Err(error) => out.push(
            Check::fail(
                "listen.metrics",
                format!("PROXYX_LIMITER_METRICS_ADDR = {metrics_addr:?} is not host:port: {error}"),
            )
            .hint("set an IP address and port, for example 127.0.0.1:39092, or unset it"),
        ),
    }
    out
}

fn limiter_var(var: &str, what: &str, value: Option<&str>) -> Check {
    let id = format!(
        "config.{}",
        var.trim_start_matches("PROXYX_LIMITER_").to_lowercase()
    );
    let allows_zero = var == "PROXYX_LIMITER_TCP_KEEPALIVE_SECS";
    match value {
        None => Check::pass(id, format!("{var} is unset: the default {what} applies")),
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 || allows_zero => Check::pass(id, format!("{var} = {n}")),
            _ if allows_zero => Check::warn(id, format!("{var} = {v:?} is not a non-negative integer: the limiter ignores it and uses the default {what}"))
                .hint("set a non-negative whole number (zero disables keepalive), or unset it"),
            _ => Check::warn(id, format!("{var} = {v:?} is not a positive integer: the limiter ignores it and uses the default {what}"))
                .hint("set a positive whole number, or unset it"),
        },
    }
}

/// Run `proxyx-intercept doctor --json` (found next to this executable, else on
/// `PATH`) and take over its report. The session proxy cannot be linked into
/// this binary (BoringSSL against OpenSSL), so it is asked in its own process.
pub(crate) async fn intercept(config: Option<&Path>, explicit: bool, ctx: &Ctx) -> Vec<Check> {
    match find_binary("proxyx-intercept") {
        Some(binary) => intercept_via(&binary, config, ctx).await,
        None => vec![if explicit {
            Check::fail(
                "doctor",
                "the proxyx-intercept binary was not found next to proxyx or on PATH",
            )
            .hint("run `proxyx-intercept doctor` where the session proxy is installed")
        } else {
            Check::skip(
                "doctor",
                "proxyx-intercept is not installed here: run `proxyx-intercept doctor` where it is",
            )
        }],
    }
}

/// [`intercept`] with the binary known.
pub(crate) async fn intercept_via(binary: &Path, config: Option<&Path>, ctx: &Ctx) -> Vec<Check> {
    let id = "doctor";
    let mut command = tokio::process::Command::new(binary);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    command
        .arg("doctor")
        .arg("--json")
        .arg("--timeout")
        .arg(format!("{}s", ctx.timeout.as_secs().max(1)));
    if ctx.skip_listeners {
        command.arg("--skip-listeners");
    }
    command.stdin(Stdio::null()).kill_on_drop(true);
    // Every probe is bounded by the timeout; leave room for several in sequence.
    let limit = ctx.timeout * 6 + std::time::Duration::from_secs(10);
    let output = match tokio::time::timeout(limit, command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return vec![Check::fail(
                id,
                format!("cannot run {}: {error}", binary.display()),
            )];
        }
        Err(_) => {
            return vec![Check::fail(
                id,
                format!("{} did not finish in time", binary.display()),
            )];
        }
    };
    // Exit 1 and 2 carry a report too; anything else without JSON is a crash.
    let text = String::from_utf8_lossy(&output.stdout);
    match Report::from_json(&text) {
        Ok(report) => report.checks,
        Err(error) => vec![Check::fail(
            id,
            format!(
                "{} printed no readable report ({error}); stderr: {}",
                binary.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        )],
    }
}

fn find_binary(name: &str) -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diag::Status;

    fn ctx() -> Ctx {
        Ctx {
            timeout: std::time::Duration::from_secs(2),
            skip_listeners: true,
            limiter_addr: None,
        }
    }

    fn script(name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir =
            std::env::temp_dir().join(format!("proxyx-ops-fake-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("proxyx-intercept");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[tokio::test]
    async fn the_session_proxy_report_is_merged_whatever_its_exit_code() {
        let json = r#"{"schema":1,"subject":"intercept","checks":[{"id":"redis.reachable","status":"pass","message":"up"},{"id":"ca.expiry","status":"warn","message":"soon","hint":"rotate"}]}"#;
        let bin = script("ok", &format!("echo '{json}'\nexit 2"));
        let checks = intercept_via(&bin, Some(Path::new("/etc/x.toml")), &ctx()).await;
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert_eq!(checks[1].status, Status::Warn);
        // The arguments reach the binary.
        let echo = script("args", "printf '%s ' \"$@\" >&2\nexit 1");
        let checks = intercept_via(&echo, Some(Path::new("/etc/x.toml")), &ctx()).await;
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(
            checks[0]
                .message
                .contains("--config /etc/x.toml doctor --json --timeout 2s --skip-listeners"),
            "{checks:?}"
        );
    }

    #[tokio::test]
    async fn a_crashing_or_missing_session_proxy_is_a_failure() {
        let bin = script("crash", "echo boom >&2\nexit 101");
        let checks = intercept_via(&bin, None, &ctx()).await;
        assert_eq!((checks.len(), checks[0].status), (1, Status::Fail));
        assert!(checks[0].message.contains("boom"), "{checks:?}");
        let checks = intercept_via(Path::new("/nonexistent/proxyx-intercept"), None, &ctx()).await;
        assert_eq!(checks[0].status, Status::Fail);
    }

    #[test]
    fn limiter_variables_that_would_be_ignored_warn() {
        assert_eq!(
            limiter_var("PROXYX_LIMITER_SHARDS", "shard count", None).status,
            Status::Pass
        );
        assert_eq!(
            limiter_var("PROXYX_LIMITER_SHARDS", "shard count", Some("16")).status,
            Status::Pass
        );
        for bad in ["0", "-1", "many", ""] {
            assert_eq!(
                limiter_var("PROXYX_LIMITER_SHARDS", "shard count", Some(bad)).status,
                Status::Warn,
                "{bad}"
            );
        }
        assert_eq!(
            limiter_var("PROXYX_LIMITER_MAX_BUCKETS", "x", None).id,
            "config.max_buckets"
        );
    }

    #[test]
    fn limiter_connection_cap_and_idle_timeout_require_positive_integers() {
        for (var, id) in [
            ("PROXYX_LIMITER_MAX_CONNECTIONS", "config.max_connections"),
            ("PROXYX_LIMITER_IDLE_TIMEOUT_MS", "config.idle_timeout_ms"),
        ] {
            for value in [None, Some("1"), Some("1234")] {
                let check = limiter_var(var, "setting", value);
                assert_eq!(check.id, id);
                assert_eq!(check.status, Status::Pass, "{var} = {value:?}");
            }
            for bad in ["0", "-1", "many", "", "18446744073709551616"] {
                let check = limiter_var(var, "setting", Some(bad));
                assert_eq!(check.status, Status::Warn, "{var} = {bad:?}");
                assert!(check.message.contains("uses the default"));
            }
        }
    }

    #[test]
    fn limiter_keepalive_accepts_zero_and_warns_on_malformed_values() {
        let var = "PROXYX_LIMITER_TCP_KEEPALIVE_SECS";
        for value in [None, Some("0"), Some("60"), Some("18446744073709551615")] {
            let check = limiter_var(var, "TCP keepalive interval", value);
            assert_eq!(check.id, "config.tcp_keepalive_secs");
            assert_eq!(check.status, Status::Pass, "{value:?}");
        }
        for bad in ["-1", "many", "", "18446744073709551616"] {
            let check = limiter_var(var, "TCP keepalive interval", Some(bad));
            assert_eq!(check.status, Status::Warn, "{bad:?}");
            assert!(
                check
                    .message
                    .contains("uses the default TCP keepalive interval")
            );
        }
    }

    #[test]
    fn limiter_metrics_unset_or_empty_disables_the_listener() {
        for value in [None, Some(""), Some(" \t")] {
            let checks = limiter_listeners(&ctx(), value);
            let metrics = checks
                .iter()
                .find(|c| c.id == "listen.metrics")
                .expect("metrics check");
            assert_eq!(metrics.status, Status::Skip, "{value:?}");
            assert!(metrics.message.contains("disabled"));
            assert!(!checks.iter().any(|c| c.id == "listen.distinct"));
        }
    }

    #[test]
    fn limiter_metrics_requires_a_socket_address_even_when_listeners_are_skipped() {
        for bad in ["not-an-address", "localhost:39092", "127.0.0.1:65536"] {
            let checks = limiter_listeners(&ctx(), Some(bad));
            let metrics = checks
                .iter()
                .find(|c| c.id == "listen.metrics")
                .expect("metrics check");
            assert_eq!(metrics.status, Status::Fail, "{bad:?}");
        }
        for addr in ["127.0.0.1:39092", "[::1]:39092"] {
            let checks = limiter_listeners(&ctx(), Some(addr));
            for id in ["listen.limiter", "listen.metrics"] {
                let check = checks.iter().find(|c| c.id == id).expect("listener check");
                assert_eq!(check.status, Status::Skip, "{addr}");
                assert!(check.message.contains("--skip-listeners"));
            }
        }
    }

    #[test]
    fn limiter_metrics_checks_an_occupied_port() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve listener");
        let addr = occupied.local_addr().expect("listener address").to_string();
        let mut ctx = ctx();
        ctx.skip_listeners = false;
        ctx.limiter_addr = Some("127.0.0.1:0".to_owned());
        let checks = limiter_listeners(&ctx, Some(&addr));
        let metrics = checks
            .iter()
            .find(|c| c.id == "listen.metrics")
            .expect("metrics check");
        assert_eq!(metrics.status, Status::Fail);
    }

    #[test]
    fn limiter_data_and_metrics_listener_collisions_fail_even_when_skipped() {
        for (data, metrics, status) in [
            ("127.0.0.1:39091", "127.0.0.1:39091", Status::Fail),
            ("0.0.0.0:39091", "127.0.0.1:39091", Status::Fail),
            ("127.0.0.1:39091", "0.0.0.0:39091", Status::Fail),
            ("[::]:39091", "[::1]:39091", Status::Fail),
            ("127.0.0.1:39091", "127.0.0.1:39092", Status::Pass),
            ("127.0.0.1:39091", "127.0.0.2:39091", Status::Pass),
            ("127.0.0.1:0", "127.0.0.1:0", Status::Pass),
        ] {
            let mut ctx = ctx();
            ctx.limiter_addr = Some(data.to_owned());
            let checks = limiter_listeners(&ctx, Some(metrics));
            let distinct = checks
                .iter()
                .find(|c| c.id == "listen.distinct")
                .expect("distinct check");
            assert_eq!(distinct.status, status, "{data}, {metrics}");
        }
    }
}
