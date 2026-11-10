//! Command-line arguments of `proxyx-bench` and their validation.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::load::{MAX_CONCURRENCY, MAX_PAYLOAD_BYTES};
use crate::report::Sweep;

/// Run time when neither `--duration` nor `--requests` is given.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(5);

#[derive(Parser, Debug)]
#[command(
    name = "proxyx-bench",
    version,
    about = "Load tool for the ProxyX pool gateway and session proxy"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Drive CONNECT tunnels and HTTP requests through the pool gateway.
    Gateway(GatewayArgs),
    /// Drive CONNECT tunnels through the session proxy, passthrough or intercepted.
    Session(SessionArgs),
}

/// Flags every scenario takes.
#[derive(Args, Debug, Clone)]
pub struct CommonArgs {
    /// Concurrent workers; a comma list runs one level after the other
    /// (a sweep), for example `1,4,16,64`.
    #[arg(long, value_delimiter = ',', default_values_t = [16usize])]
    pub concurrency: Vec<usize>,
    /// How long each level runs, for example `5s` or `500ms`. Default 5s when
    /// `--requests` is not given.
    #[arg(long, value_parser = parse_duration)]
    pub duration: Option<Duration>,
    /// Requests each level runs (failed ones count). Stops the level when it
    /// is spent, or at `--duration`, whichever comes first.
    #[arg(long)]
    pub requests: Option<u64>,
    /// Bytes in every request body and in every response body.
    #[arg(long, default_value_t = 1024)]
    pub payload_bytes: usize,
    /// Reuse each connection for many requests. `--keepalive=false` opens one
    /// connection (one tunnel) per request.
    #[arg(
        long,
        action = ArgAction::Set,
        num_args = 0..=1,
        default_value_t = true,
        default_missing_value = "true",
        require_equals = true
    )]
    pub keepalive: bool,
    /// Limit of one connect or one request; a longer one is a `timeout` error.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub timeout: Duration,
    /// Run the first level for this long before measuring; the result is dropped.
    #[arg(long, default_value = "0s", value_parser = parse_duration)]
    pub warmup: Duration,
    /// Print the report as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
    /// Spawn this binary as the target with a generated configuration, and
    /// stop it afterwards. `proxyx` for the gateway, `proxyx-intercept` for
    /// the session proxy.
    #[arg(long, value_name = "PATH")]
    pub spawn: Option<PathBuf>,
    /// Attach to a running target: sample its CPU and memory and send the
    /// load to `--proxy`.
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,
    /// Directory for generated files (configuration, CA, logs). Default: a
    /// fresh directory under the system temporary directory.
    #[arg(long, value_name = "DIR")]
    pub workdir: Option<PathBuf>,
}

impl CommonArgs {
    /// Check the flags that do not depend on the scenario.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.concurrency.is_empty(),
            "--concurrency needs at least one level"
        );
        for &c in &self.concurrency {
            ensure!(
                (1..=MAX_CONCURRENCY).contains(&c),
                "--concurrency {c} is out of range: use 1 to {MAX_CONCURRENCY}"
            );
        }
        ensure!(
            (1..=MAX_PAYLOAD_BYTES).contains(&self.payload_bytes),
            "--payload-bytes must be between 1 and {MAX_PAYLOAD_BYTES}"
        );
        if let Some(d) = self.duration {
            ensure!(!d.is_zero(), "--duration must be above zero");
        }
        if let Some(n) = self.requests {
            ensure!(n > 0, "--requests must be above zero");
        }
        ensure!(!self.timeout.is_zero(), "--timeout must be above zero");
        match (&self.spawn, self.pid) {
            (Some(_), Some(_)) => bail!("give --spawn or --pid, not both"),
            (None, None) => {
                bail!("give --spawn <binary> to start the target, or --pid <pid> to attach to one")
            }
            (Some(path), None) => ensure!(
                path.is_file(),
                "--spawn {} is not a file (build it first)",
                path.display()
            ),
            (None, Some(pid)) => {
                ensure!(pid > 0, "--pid must be above zero");
                ensure!(
                    crate::target::pid_exists(pid),
                    "--pid {pid}: no such process"
                );
            }
        }
        Ok(())
    }

    /// The sweep these flags describe. `pid` is the process to sample.
    pub fn sweep(&self, pid: Option<u32>) -> Sweep {
        let duration = match (self.duration, self.requests) {
            (None, None) => Some(DEFAULT_DURATION),
            (duration, _) => duration,
        };
        Sweep {
            levels: self.concurrency.clone(),
            duration,
            requests: self.requests,
            keepalive: self.keepalive,
            timeout: self.timeout,
            warmup: self.warmup,
            pid,
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayMode {
    /// CONNECT, then bytes echoed through the tunnel.
    Tunnel,
    /// CONNECT to port 80, then HTTP/1.1 requests over the tunnel.
    Forward,
}

impl GatewayMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tunnel => "tunnel",
            Self::Forward => "forward",
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct GatewayArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long, value_enum, default_value = "tunnel")]
    pub mode: GatewayMode,
    /// Postgres server the spawned gateway uses. The database
    /// `proxyx_ops_bench` is created on it and dropped and rebuilt on every
    /// run, so nothing else may use that name.
    #[arg(long, default_value = "postgres://postgres@127.0.0.1:45400/postgres")]
    pub database_url: String,
    /// Redis for the spawned gateway. It must name a database index that
    /// nothing else uses: the run flushes it.
    #[arg(long, default_value = "redis://127.0.0.1:45401/13")]
    pub redis_url: String,
    /// Username of the load, in the `px` option grammar.
    #[arg(long, default_value = "px-kind-static-cc-fr")]
    pub username: String,
    /// Attach mode: the gateway's CONNECT address.
    #[arg(long)]
    pub proxy: Option<SocketAddr>,
    /// Attach mode: the org key to log in with.
    #[arg(long)]
    pub password: Option<String>,
    /// Attach mode: `host:port` the tunnels ask for. It must answer like the
    /// mode needs: an echo for `tunnel`, an HTTP/1.1 origin for `forward`.
    #[arg(long)]
    pub target: Option<String>,
}

impl GatewayArgs {
    pub fn validate(&self) -> Result<()> {
        self.common.validate()?;
        ensure!(!self.username.is_empty(), "--username must not be empty");
        if self.common.pid.is_some() {
            ensure!(self.proxy.is_some(), "attach mode needs --proxy");
            ensure!(self.password.is_some(), "attach mode needs --password");
            ensure!(self.target.is_some(), "attach mode needs --target");
        } else {
            ensure!(
                self.proxy.is_none() && self.password.is_none() && self.target.is_none(),
                "--proxy, --password and --target only apply with --pid"
            );
        }
        Ok(())
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// The session captures nothing: the proxy only relays the TLS bytes.
    Passthrough,
    /// The session captures the host: the proxy terminates TLS with a
    /// certificate of its own CA, reads the exchange and dials the origin.
    Mitm,
}

impl SessionMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::Mitm => "mitm",
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct SessionArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long, value_enum, default_value = "passthrough")]
    pub mode: SessionMode,
    /// The proxy's Redis, where the session is created.
    #[arg(long, default_value = "redis://127.0.0.1:45401/13")]
    pub redis_url: String,
    /// Key prefix of the proxy's Redis keys (`redis_key_prefix`).
    #[arg(long, default_value = "proxyx_bench")]
    pub redis_prefix: String,
    /// Attach mode: the proxy's CONNECT address.
    #[arg(long)]
    pub proxy: Option<SocketAddr>,
    /// Attach mode, `--mode mitm`: the DER file of the CA the proxy signs with.
    #[arg(long, value_name = "FILE")]
    pub ca_der: Option<PathBuf>,
}

impl SessionArgs {
    pub fn validate(&self) -> Result<()> {
        self.common.validate()?;
        ensure!(
            !self.redis_prefix.is_empty(),
            "--redis-prefix must not be empty"
        );
        if self.common.pid.is_some() {
            ensure!(self.proxy.is_some(), "attach mode needs --proxy");
            if self.mode == SessionMode::Mitm {
                let ca = self.ca_der.as_ref();
                ensure!(
                    ca.is_some_and(|p| p.is_file()),
                    "attach mode with --mode mitm needs --ca-der <existing file>"
                );
            }
        } else {
            ensure!(
                self.proxy.is_none() && self.ca_der.is_none(),
                "--proxy and --ca-der only apply with --pid"
            );
        }
        Ok(())
    }
}

/// `250ms`, `5s`, `2m`, `1h`, or a bare number of seconds (`1.5`).
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let (number, unit) = match text.find(|c: char| c.is_ascii_alphabetic()) {
        Some(i) => text.split_at(i),
        None => (text, "s"),
    };
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a duration: use 500ms, 5s, 2m or 1h"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("{text:?} is not a duration"));
    }
    let seconds = match unit {
        "ms" => value / 1000.0,
        "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => {
            return Err(format!(
                "{text:?} has an unknown unit {unit:?}: use ms, s, m or h"
            ));
        }
    };
    Duration::try_from_secs_f64(seconds).map_err(|_| format!("{text:?} is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("proxyx-bench").chain(args.iter().copied()))
    }

    /// `/bin/sh` is a file on every host the tests run on.
    const SPAWN: &str = "/bin/sh";

    fn session(args: &[&str]) -> SessionArgs {
        let mut all = vec!["session"];
        all.extend_from_slice(args);
        match parse(&all).expect("parse").command {
            Command::Session(a) => a,
            Command::Gateway(_) => unreachable!(),
        }
    }

    fn gateway(args: &[&str]) -> GatewayArgs {
        let mut all = vec!["gateway"];
        all.extend_from_slice(args);
        match parse(&all).expect("parse").command {
            Command::Gateway(a) => a,
            Command::Session(_) => unreachable!(),
        }
    }

    #[test]
    fn durations_parse_with_units_and_bare_seconds() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("5s"), Ok(Duration::from_secs(5)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_duration("1.5"), Ok(Duration::from_millis(1500)));
        assert!(parse_duration("fast").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn the_defaults_are_a_single_level_with_keepalive() {
        let a = session(&["--spawn", SPAWN]);
        assert_eq!(a.common.concurrency, vec![16]);
        assert!(a.common.keepalive);
        assert_eq!(a.common.payload_bytes, 1024);
        assert_eq!(a.mode, SessionMode::Passthrough);
        assert!(a.validate().is_ok());
        let sweep = a.common.sweep(None);
        assert_eq!(sweep.duration, Some(DEFAULT_DURATION));
        assert_eq!(sweep.requests, None);
    }

    #[test]
    fn a_comma_list_is_a_sweep_and_requests_replace_the_default_duration() {
        let a = session(&[
            "--spawn",
            SPAWN,
            "--concurrency",
            "1,4,16",
            "--requests",
            "200",
        ]);
        let sweep = a.common.sweep(Some(7));
        assert_eq!(sweep.levels, vec![1, 4, 16]);
        assert_eq!(sweep.requests, Some(200));
        assert_eq!(sweep.duration, None);
        assert_eq!(sweep.pid, Some(7));
    }

    #[test]
    fn keepalive_can_be_switched_off() {
        assert!(
            !session(&["--spawn", SPAWN, "--keepalive=false"])
                .common
                .keepalive
        );
        assert!(session(&["--spawn", SPAWN, "--keepalive"]).common.keepalive);
    }

    #[test]
    fn bad_numbers_are_refused() {
        for bad in [
            vec!["--concurrency", "0"],
            vec!["--concurrency", "1,0"],
            vec!["--concurrency", "100000"],
            vec!["--payload-bytes", "0"],
            vec!["--payload-bytes", "999999999999"],
            vec!["--requests", "0"],
            vec!["--duration", "0s"],
            vec!["--timeout", "0s"],
        ] {
            let mut args = vec!["--spawn", SPAWN];
            args.extend(bad.iter());
            assert!(session(&args).validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unparseable_flags_fail_at_parse_time() {
        assert!(parse(&["session", "--concurrency", "many"]).is_err());
        assert!(parse(&["session", "--duration", "soon"]).is_err());
        assert!(parse(&["session", "--mode", "sideways"]).is_err());
        assert!(parse(&["bogus"]).is_err());
    }

    #[test]
    fn a_target_is_required_and_spawn_and_pid_exclude_each_other() {
        assert!(session(&[]).validate().is_err());
        let me = std::process::id().to_string();
        let both = session(&["--spawn", SPAWN, "--pid", &me]);
        assert!(both.validate().is_err());
        assert!(session(&["--spawn", "/no/such/binary"]).validate().is_err());
        assert!(
            session(&["--pid", "4294967295", "--proxy", "127.0.0.1:1"])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn attach_mode_needs_its_flags_and_spawn_mode_rejects_them() {
        let me = std::process::id().to_string();
        assert!(session(&["--pid", &me]).validate().is_err());
        assert!(
            session(&["--pid", &me, "--proxy", "127.0.0.1:8443"])
                .validate()
                .is_ok()
        );
        assert!(
            session(&["--pid", &me, "--proxy", "127.0.0.1:8443", "--mode", "mitm"])
                .validate()
                .is_err(),
            "mitm needs the CA file"
        );
        assert!(
            session(&["--spawn", SPAWN, "--proxy", "127.0.0.1:1"])
                .validate()
                .is_err()
        );

        assert!(gateway(&["--pid", &me]).validate().is_err());
        let full = gateway(&[
            "--pid",
            &me,
            "--proxy",
            "127.0.0.1:8080",
            "--password",
            "ak_x",
            "--target",
            "127.0.0.1:9",
        ]);
        assert!(full.validate().is_ok());
        assert!(
            gateway(&["--spawn", SPAWN, "--password", "x"])
                .validate()
                .is_err()
        );
        assert!(
            gateway(&["--spawn", SPAWN, "--username", ""])
                .validate()
                .is_err()
        );
        assert!(gateway(&["--spawn", SPAWN]).validate().is_ok());
    }
}
