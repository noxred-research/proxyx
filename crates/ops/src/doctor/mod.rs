//! `proxyx doctor`: check the roles of this binary without starting them.
//!
//! Each role is checked the way it would start: its configuration is loaded
//! and validated by the role's own loader, then the things it needs are probed
//! (Postgres, Redis, brokers, files, ports). Nothing is written and no role
//! is started. Ids in the report start with the role (`gateway.redis.reachable`).

mod control;
mod misc;
mod pool;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, ValueEnum};
use diag::{Check, Report};

/// A role to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    /// Pool gateway and warmer together (they share one configuration).
    Pool,
    Gateway,
    Warmer,
    /// Control API and ingester together (they share one configuration).
    Control,
    Ingester,
    Limiter,
    /// The session proxy: runs `proxyx-intercept doctor` and merges its report.
    Intercept,
    Edge,
    /// Every role whose configuration is found: an explicit `--config`, a
    /// default file, or the role's environment variables.
    All,
}

impl RoleArg {
    fn name(self) -> &'static str {
        match self {
            Self::Pool => "pool",
            Self::Gateway => "gateway",
            Self::Warmer => "warmer",
            Self::Control => "control",
            Self::Ingester => "ingester",
            Self::Limiter => "limiter",
            Self::Intercept => "intercept",
            Self::Edge => "edge",
            Self::All => "all",
        }
    }
}

/// `proxyx doctor`.
#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Role to check.
    #[arg(long, value_enum, default_value_t = RoleArg::All)]
    pub role: RoleArg,
    /// Configuration file: `PATH` for the one role selected, or `ROLE=PATH`
    /// (`pool`, `control`, `edge`, `intercept`; repeat for several). A role without one
    /// reads its default file and environment, as it does when it starts.
    #[arg(short, long = "config", value_name = "[ROLE=]PATH")]
    pub config: Vec<String>,
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
    /// Treat warnings as failures (exit 1 instead of 2).
    #[arg(long)]
    pub strict: bool,
    /// Bound on every probe: seconds, or `500ms`-style is not accepted, use `5s`, `1m`.
    #[arg(long, default_value = "5s", value_parser = parse_timeout, value_name = "DURATION")]
    pub timeout: Duration,
    /// Do not try to bind the listener ports. Use it where the role already
    /// runs: its own ports are in use then.
    #[arg(long)]
    pub skip_listeners: bool,
    /// Listen address of the limiter to check (`proxyx limiter [ADDR]`).
    #[arg(long, value_name = "ADDR")]
    pub limiter_addr: Option<String>,
}

fn parse_timeout(text: &str) -> Result<Duration, String> {
    let d = common::config::humantime_secs::parse(text)?;
    if d.is_zero() {
        return Err("the timeout must be above zero".to_owned());
    }
    Ok(d)
}

/// What the role checks share.
pub(crate) struct Ctx {
    pub timeout: Duration,
    pub skip_listeners: bool,
    pub limiter_addr: Option<String>,
}

/// Configuration files by role family.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Configs {
    pub pool: Option<PathBuf>,
    pub control: Option<PathBuf>,
    pub edge: Option<PathBuf>,
    pub intercept: Option<PathBuf>,
}

/// Read the `--config` values against the selected role.
pub(crate) fn parse_configs(role: RoleArg, values: &[String]) -> anyhow::Result<Configs> {
    let mut configs = Configs::default();
    for value in values {
        let (family, path) = match value.split_once('=') {
            Some((name, path)) => (name.trim(), path),
            None if role == RoleArg::All => {
                bail!("--config {value}: with --role all, name the role: `--config pool={value}`")
            }
            None => (role.name(), value.as_str()),
        };
        let slot = match family {
            "pool" | "gateway" | "warmer" => &mut configs.pool,
            "control" | "ingester" => &mut configs.control,
            "edge" => &mut configs.edge,
            "intercept" => &mut configs.intercept,
            "limiter" => {
                bail!("the limiter has no configuration file: it reads PROXYX_LIMITER_* variables")
            }
            other => {
                bail!("--config {value}: unknown role `{other}` (pool, control, edge, intercept)")
            }
        };
        if path.is_empty() {
            bail!("--config {value}: the path is empty");
        }
        if slot.replace(PathBuf::from(path)).is_some() {
            bail!("--config: two files for the {family} configuration");
        }
    }
    Ok(configs)
}

/// What to check, one entry per report section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    Pool(pool::Kind, &'static str),
    Control(control::Kind, &'static str),
    Limiter,
    Intercept,
    Edge,
}

fn present(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty())
}

fn any_file(paths: &[&str]) -> bool {
    paths.iter().any(|p| std::path::Path::new(p).is_file())
}

fn limiter_configured(addr: Option<&str>, present: impl Fn(&str) -> bool) -> bool {
    addr.is_some()
        || [
            "PROXYX_LIMITER_MAX_BUCKETS",
            "PROXYX_LIMITER_SHARDS",
            "PROXYX_LIMITER_REAPER_MS",
            "PROXYX_LIMITER_MAX_CONNECTIONS",
            "PROXYX_LIMITER_IDLE_TIMEOUT_MS",
            "PROXYX_LIMITER_TCP_KEEPALIVE_SECS",
            "PROXYX_LIMITER_METRICS_ADDR",
        ]
        .into_iter()
        .any(present)
}

/// The roles `--role all` finds configuration for.
fn detect(configs: &Configs, ctx: &Ctx) -> Vec<Plan> {
    let mut plans = Vec::new();
    if configs.pool.is_some()
        || present("PROXYX_POOL_DATABASE_URL")
        || any_file(&["/etc/proxyx/pool.toml"])
    {
        plans.push(Plan::Pool(pool::Kind::Both, "pool"));
    }
    if configs.control.is_some()
        || present("PROXYX_CONTROL_DATABASE_URL")
        || any_file(&["control.toml", "/etc/proxyx/control.toml"])
    {
        plans.push(Plan::Control(control::Kind::Both, "control"));
    }
    if limiter_configured(ctx.limiter_addr.as_deref(), present) {
        plans.push(Plan::Limiter);
    }
    if configs.edge.is_some() || any_file(&["/etc/proxyx/edge.toml"]) {
        plans.push(Plan::Edge);
    }
    if configs.intercept.is_some()
        || present("PROXYX_INTERCEPT_REDIS_URL")
        || present("PROXYX_INTERCEPT_CONNECT_ADDR")
        || any_file(&["intercept.toml", "/etc/proxyx/intercept.toml"])
    {
        plans.push(Plan::Intercept);
    }
    plans
}

fn plans_for(role: RoleArg, configs: &Configs, ctx: &Ctx) -> Vec<Plan> {
    match role {
        RoleArg::Pool => vec![Plan::Pool(pool::Kind::Both, "pool")],
        RoleArg::Gateway => vec![Plan::Pool(pool::Kind::Gateway, "gateway")],
        RoleArg::Warmer => vec![Plan::Pool(pool::Kind::Warmer, "warmer")],
        RoleArg::Control => vec![Plan::Control(control::Kind::Both, "control")],
        RoleArg::Ingester => vec![Plan::Control(control::Kind::Ingester, "ingester")],
        RoleArg::Limiter => vec![Plan::Limiter],
        RoleArg::Intercept => vec![Plan::Intercept],
        RoleArg::Edge => vec![Plan::Edge],
        RoleArg::All => detect(configs, ctx),
    }
}

/// Run the checks and return the report, without printing it.
pub async fn build_report(args: &DoctorArgs) -> anyhow::Result<Report> {
    let configs = parse_configs(args.role, &args.config)?;
    let ctx = Ctx {
        timeout: args.timeout,
        skip_listeners: args.skip_listeners,
        limiter_addr: args.limiter_addr.clone(),
    };
    let explicit = args.role != RoleArg::All;
    let plans = plans_for(args.role, &configs, &ctx);
    let mut report = Report::new(args.role.name());
    if plans.is_empty() {
        report.push(
            Check::fail(
                "config.found",
                "no role configuration found: no --config, no default file and no role environment variables",
            )
            .hint("pass `--role <role> --config <file>`, or set PROXYX_POOL_DATABASE_URL / PROXYX_CONTROL_DATABASE_URL"),
        );
        return Ok(report);
    }
    for plan in plans {
        let (name, checks) = match plan {
            Plan::Pool(kind, name) => (
                name,
                pool::checks(kind, configs.pool.as_deref(), &ctx).await,
            ),
            Plan::Control(kind, name) => (
                name,
                control::checks(kind, configs.control.as_deref(), &ctx).await,
            ),
            Plan::Limiter => ("limiter", misc::limiter(&ctx).await),
            Plan::Edge => ("edge", misc::edge(configs.edge.as_deref(), explicit)),
            Plan::Intercept => (
                "intercept",
                misc::intercept(configs.intercept.as_deref(), explicit, &ctx).await,
            ),
        };
        report.extend(checks.into_iter().map(|c| c.prefixed(name)));
    }
    Ok(report)
}

/// `proxyx doctor`: print the report (a table, or JSON) and return the exit
/// code: 0 all clear, 1 a failure (or a warning with `--strict`), 2 only
/// warnings. Errors only for unusable arguments.
pub async fn run_doctor(args: DoctorArgs) -> anyhow::Result<i32> {
    let report = build_report(&args).await.context("proxyx doctor")?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json(args.strict))?
        );
    } else {
        print!("{}", report.render_table(args.strict));
    }
    Ok(report.exit_code(args.strict))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn config_values_name_a_role_or_use_the_selected_one() {
        let c = parse_configs(RoleArg::Gateway, &s(&["/etc/p.toml"])).expect("bare");
        assert_eq!(c.pool, Some(PathBuf::from("/etc/p.toml")));
        let c = parse_configs(
            RoleArg::All,
            &s(&["pool=/a", "control=/b", "intercept=/c", "edge=/d"]),
        )
        .expect("named");
        assert_eq!(c.pool, Some(PathBuf::from("/a")));
        assert_eq!(c.control, Some(PathBuf::from("/b")));
        assert_eq!(c.intercept, Some(PathBuf::from("/c")));
        assert_eq!(c.edge, Some(PathBuf::from("/d")));
        assert!(parse_configs(RoleArg::All, &s(&["/bare"])).is_err());
        assert!(parse_configs(RoleArg::All, &s(&["pool=/a", "gateway=/b"])).is_err());
        assert!(parse_configs(RoleArg::All, &s(&["bogus=/a"])).is_err());
        assert!(parse_configs(RoleArg::Limiter, &s(&["/a"])).is_err());
        assert!(parse_configs(RoleArg::Pool, &s(&["pool="])).is_err());
    }

    #[test]
    fn timeouts_parse_and_reject_zero() {
        assert_eq!(parse_timeout("5s"), Ok(Duration::from_secs(5)));
        assert_eq!(parse_timeout("2"), Ok(Duration::from_secs(2)));
        assert!(parse_timeout("0").is_err());
        assert!(parse_timeout("fast").is_err());
    }

    #[test]
    fn every_limiter_variable_selects_the_role_without_a_listen_address() {
        for var in [
            "PROXYX_LIMITER_MAX_BUCKETS",
            "PROXYX_LIMITER_SHARDS",
            "PROXYX_LIMITER_REAPER_MS",
            "PROXYX_LIMITER_MAX_CONNECTIONS",
            "PROXYX_LIMITER_IDLE_TIMEOUT_MS",
            "PROXYX_LIMITER_TCP_KEEPALIVE_SECS",
            "PROXYX_LIMITER_METRICS_ADDR",
        ] {
            assert!(limiter_configured(None, |name| name == var), "{var}");
        }
        assert!(!limiter_configured(None, |_| false));
        assert!(limiter_configured(Some("127.0.0.1:39091"), |_| false));
    }
}
