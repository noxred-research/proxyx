//! Edge, limiter and the session proxy.

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
    ] {
        out.push(limiter_var(var, what, std::env::var(var).ok().as_deref()));
    }
    let addr = ctx
        .limiter_addr
        .clone()
        .unwrap_or_else(|| proxyx_limiter_server::DEFAULT_LISTEN.to_owned());
    match addr.parse::<std::net::SocketAddr>() {
        Ok(parsed) if ctx.skip_listeners => {
            out.push(Check::skip(
                "listen.limiter",
                format!("limiter listener {parsed}: not tried (--skip-listeners)"),
            ));
        }
        Ok(parsed) => out.push(port_check("listen.limiter", "limiter listener", parsed)),
        Err(error) => out.push(
            Check::fail(
                "listen.limiter",
                format!("limiter address {addr:?} is not host:port: {error}"),
            )
            .hint(
                "`proxyx limiter [ADDR]` takes an IP address and port, for example 0.0.0.0:39091",
            ),
        ),
    }
    // One thread and one descriptor per client connection.
    out.push(files::fd_limit(
        1024,
        "one descriptor per client connection, 1024 as a floor",
    ));
    out
}

fn limiter_var(var: &str, what: &str, value: Option<&str>) -> Check {
    let id = format!(
        "config.{}",
        var.trim_start_matches("PROXYX_LIMITER_").to_lowercase()
    );
    match value {
        None => Check::pass(id, format!("{var} is unset: the default {what} applies")),
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 => Check::pass(id, format!("{var} = {n}")),
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
}
