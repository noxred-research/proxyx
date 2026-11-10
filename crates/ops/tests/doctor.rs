//! `proxyx doctor` on the shipped example files, on broken files, against the
//! local Postgres and Valkey (`PROXYX_TEST_DATABASE_URL`, `PROXYX_TEST_REDIS_URL`;
//! those tests skip with a message when unset), and against closed ports.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use diag::{Report, Status};
use proxyx_ops::doctor::{DoctorArgs, RoleArg, build_report};

const REDIS_DB: &str = "12";

fn repo(path: &str) -> String {
    format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))
}

fn args(role: RoleArg, config: &[String]) -> DoctorArgs {
    DoctorArgs {
        role,
        config: config.to_vec(),
        json: false,
        strict: false,
        timeout: Duration::from_secs(2),
        skip_listeners: true,
        limiter_addr: None,
    }
}

fn status(report: &Report, id: &str) -> Status {
    report
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no {id} in {report:#?}"))
        .status
}

fn message<'a>(report: &'a Report, id: &str) -> &'a str {
    &report
        .checks
        .iter()
        .find(|c| c.id == id)
        .expect("check")
        .message
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("proxyx-ops-doctor-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("addr")
}

fn redis_url() -> Option<String> {
    let base = std::env::var("PROXYX_TEST_REDIS_URL").ok()?;
    let authority = base.trim_end_matches('/');
    let authority = authority
        .rsplit_once('/')
        .filter(|(h, _)| h.contains("://"))
        .map_or(authority, |(h, _)| h);
    Some(format!("{authority}/{REDIS_DB}"))
}

#[tokio::test]
async fn the_shipped_pool_control_and_edge_examples_load() {
    let report = build_report(&args(RoleArg::Gateway, &[repo("examples/pool.toml")]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "gateway.config.load"),
        Status::Pass,
        "{report:#?}"
    );
    assert!(message(&report, "gateway.config.load").contains("pool.toml"));

    let report = build_report(&args(RoleArg::Control, &[repo("examples/control.toml")]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "control.config.load"),
        Status::Pass,
        "{report:#?}"
    );

    let report = build_report(&args(RoleArg::Edge, &[repo("examples/edge-loopback.toml")]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "edge.config.load"),
        Status::Pass,
        "{report:#?}"
    );
}

#[tokio::test]
async fn a_bad_pool_file_names_the_file_and_the_key() {
    let dir = scratch("badpool");
    let typo = dir.join("typo.toml");
    std::fs::write(&typo, "max_connection = 5\n").expect("write");
    let report = build_report(&args(RoleArg::Gateway, &[typo.display().to_string()]))
        .await
        .expect("report");
    assert_eq!(report.checks.len(), 1, "{report:#?}");
    assert_eq!(status(&report, "gateway.config.load"), Status::Fail);
    let m = message(&report, "gateway.config.load");
    assert!(
        m.contains("typo.toml") && m.contains("max_connection"),
        "{m}"
    );
    assert_eq!(report.exit_code(false), 1);

    let wrong_type = dir.join("type.toml");
    std::fs::write(&wrong_type, "max_connections = \"many\"\n").expect("write");
    let report = build_report(&args(RoleArg::Warmer, &[wrong_type.display().to_string()]))
        .await
        .expect("report");
    let m = message(&report, "warmer.config.load");
    assert!(
        m.contains("max_connections") && m.contains("type.toml"),
        "{m}"
    );

    let invalid = dir.join("invalid.toml");
    std::fs::write(&invalid, "reload_every = \"0\"\n").expect("write");
    let report = build_report(&args(RoleArg::Pool, &[invalid.display().to_string()]))
        .await
        .expect("report");
    let m = message(&report, "pool.config.load");
    assert!(
        m.contains("reload_every") && m.contains("invalid.toml"),
        "{m}"
    );

    let missing = build_report(&args(
        RoleArg::Pool,
        &[dir.join("none.toml").display().to_string()],
    ))
    .await
    .expect("report");
    assert!(message(&missing, "pool.config.load").contains("none.toml"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_bad_control_or_edge_file_names_the_key() {
    let dir = scratch("badcontrol");
    let control = dir.join("control.toml");
    std::fs::write(&control, "api_addr = \"nowhere\"\n").expect("write");
    let report = build_report(&args(RoleArg::Control, &[control.display().to_string()]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "control.config.load"),
        Status::Fail,
        "{report:#?}"
    );
    assert!(
        message(&report, "control.config.load").contains("api_addr"),
        "{report:#?}"
    );

    let no_store = dir.join("nostore.toml");
    std::fs::write(
        &no_store,
        "database_url = \"postgres://127.0.0.1:1/x\"\nredis_url = \"redis://127.0.0.1:1\"\n",
    )
    .expect("write");
    let report = build_report(&args(RoleArg::Control, &[no_store.display().to_string()]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "control.config.capture_store"),
        Status::Fail,
        "{report:#?}"
    );
    assert!(message(&report, "control.config.capture_store").contains("[clickhouse]"));

    let edge = dir.join("edge.toml");
    std::fs::write(&edge, "[server]\nnot_a_key = 1\n").expect("write");
    let report = build_report(&args(RoleArg::Edge, &[edge.display().to_string()]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "edge.config.load"),
        Status::Fail,
        "{report:#?}"
    );
    assert!(message(&report, "edge.config.load").contains("edge.toml"));
    let _ = std::fs::remove_dir_all(dir);
}

/// A pool configuration file whose dependencies are `database` and `redis`.
fn pool_config(dir: &Path, database: &str, redis: &str, extra: &str) -> String {
    for sub in ["data/adapters", "secrets"] {
        std::fs::create_dir_all(dir.join(sub)).expect("dir");
    }
    let token = dir.join("secrets/admin-token");
    std::fs::write(&token, "token\n").expect("write");
    std::fs::set_permissions(&token, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("chmod");
    let path = dir.join("pool.toml");
    let (c, s, p, a, o) = (
        free_addr(),
        free_addr(),
        free_addr(),
        free_addr(),
        free_addr(),
    );
    std::fs::write(
        &path,
        format!(
            "database_url = \"{database}\"\nredis_url = \"{redis}\"\n\
             connect_listen = \"{c}\"\nsocks_listen = \"{s}\"\nprobe_listen = \"{p}\"\napi_listen = \"{a}\"\nops_listen = \"{o}\"\n\
             data_dir = \"{d}/data\"\nsecrets_dir = \"{d}/secrets\"\nadmin_token_file = \"{d}/secrets/admin-token\"\n\
             probe_key_file = \"{d}/secrets/probe-key\"\nmax_connections = 100\n{extra}",
            d = dir.display()
        ),
    )
    .expect("write");
    path.display().to_string()
}

#[tokio::test]
async fn closed_dependencies_fail_within_the_timeout() {
    let dir = scratch("closed");
    let path = pool_config(
        &dir,
        "postgres://postgres@127.0.0.1:1/x",
        "redis://127.0.0.1:1",
        "",
    );
    let mut a = args(RoleArg::Gateway, &[path]);
    a.timeout = Duration::from_secs(1);
    let start = Instant::now();
    let report = build_report(&a).await.expect("report");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(
        status(&report, "gateway.postgres.reachable"),
        Status::Fail,
        "{report:#?}"
    );
    assert_eq!(status(&report, "gateway.redis.reachable"), Status::Fail);
    assert_eq!(report.exit_code(false), 1);
    assert_eq!(report.exit_code(true), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_working_pool_setup_has_no_failure() {
    let (Ok(base), Some(redis)) = (std::env::var("PROXYX_TEST_DATABASE_URL"), redis_url()) else {
        eprintln!("SKIP: PROXYX_TEST_DATABASE_URL or PROXYX_TEST_REDIS_URL is not set");
        return;
    };
    let url = store::testing::database(&base, "proxyx_ops_doctor_doctor_ok", true)
        .await
        .expect("database");
    let dir = scratch("ok");
    let path = pool_config(&dir, &url, &redis, "");

    // Not migrated yet: the doctor says which migrations are missing.
    let a = args(RoleArg::Gateway, std::slice::from_ref(&path));
    let report = build_report(&a).await.expect("report");
    assert_eq!(
        status(&report, "gateway.postgres.reachable"),
        Status::Pass,
        "{report:#?}"
    );
    assert_eq!(
        status(&report, "gateway.postgres.pending"),
        Status::Fail,
        "{report:#?}"
    );
    assert!(
        message(&report, "gateway.postgres.pending").contains("init"),
        "{report:#?}"
    );

    store::Db::connect(&url)
        .await
        .expect("connect")
        .migrate()
        .await
        .expect("migrate");
    std::fs::write(dir.join("data/adapters/local.toml"), "[[adapter]]\nid = \"local\"\nkind = \"static\"\nsubtype = \"datacenter\"\nscheme = \"local\"\n").expect("write");
    let report = build_report(&a).await.expect("report");
    for id in [
        "config.load",
        "config.exit_ip_services",
        "postgres.reachable",
        "postgres.version",
        "postgres.migrations",
        "postgres.pending",
        "redis.reachable",
        "redis.clock_skew",
        "data.dir",
        "data.adapters",
        "secrets.dir",
        "secrets.permissions",
        "secrets.admin_token",
        "listen.distinct",
    ] {
        assert_eq!(
            status(&report, &format!("gateway.{id}")),
            Status::Pass,
            "{id}: {report:#?}"
        );
    }
    assert_eq!(status(&report, "gateway.secrets.probe_key"), Status::Skip);
    assert_eq!(
        status(&report, "gateway.listen.connect"),
        Status::Skip,
        "--skip-listeners"
    );
    assert_eq!(report.summary().fail, 0, "{report:#?}");
    let json = report.to_json(false);
    assert_eq!(json["schema"], 1);
    assert_eq!(json["subject"], "gateway");

    // Bound ports are caught, and the same port twice is a configuration error.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let taken_addr = taken.local_addr().expect("addr");
    let text = std::fs::read_to_string(&path).expect("read");
    let text = text
        .lines()
        .map(|l| {
            if l.starts_with("connect_listen") {
                format!("connect_listen = \"{taken_addr}\"")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, &text).expect("write");
    let mut live = args(RoleArg::Gateway, std::slice::from_ref(&path));
    live.skip_listeners = false;
    let report = build_report(&live).await.expect("report");
    assert_eq!(
        status(&report, "gateway.listen.connect"),
        Status::Fail,
        "{report:#?}"
    );
    assert!(message(&report, "gateway.listen.connect").contains("already in use"));
    assert_eq!(status(&report, "gateway.listen.socks"), Status::Pass);
    let text = text
        .lines()
        .map(|l| {
            if l.starts_with("socks_listen") {
                format!("socks_listen = \"{taken_addr}\"")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, &text).expect("write");
    let report = build_report(&a).await.expect("report");
    assert_eq!(
        status(&report, "gateway.listen.distinct"),
        Status::Fail,
        "{report:#?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_open_files_limit_is_checked_against_max_connections() {
    let dir = scratch("fds");
    // 2 per tunnel and 512 spare: far above any real limit.
    let path = pool_config(
        &dir,
        "postgres://postgres@127.0.0.1:1/x",
        "redis://127.0.0.1:1",
        "",
    );
    let text = std::fs::read_to_string(&path)
        .expect("read")
        .replace("max_connections = 100", "max_connections = 4000000000");
    std::fs::write(&path, text).expect("write");
    let report = build_report(&args(RoleArg::Gateway, &[path]))
        .await
        .expect("report");
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
    match diag::files::parse_nofile(&limits) {
        Some((diag::files::Limit::Finite(_), _)) => {
            assert_eq!(
                status(&report, "gateway.system.open_files"),
                Status::Fail,
                "{report:#?}"
            );
            assert!(message(&report, "gateway.system.open_files").contains("8000000512"));
        }
        _ => eprintln!("SKIP: no finite open files limit on this system"),
    }
    // The warmer never carries tunnels: no descriptor check.
    let dir2 = scratch("fds2");
    let path = pool_config(
        &dir2,
        "postgres://postgres@127.0.0.1:1/x",
        "redis://127.0.0.1:1",
        "",
    );
    let report = build_report(&args(RoleArg::Warmer, &[path]))
        .await
        .expect("report");
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.id != "warmer.system.open_files")
    );
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

#[tokio::test]
async fn the_limiter_listener_is_checked_and_its_variables_are_read() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut a = args(RoleArg::Limiter, &[]);
    a.skip_listeners = false;
    a.limiter_addr = Some(taken.local_addr().expect("addr").to_string());
    let report = build_report(&a).await.expect("report");
    assert_eq!(
        status(&report, "limiter.listen.limiter"),
        Status::Fail,
        "{report:#?}"
    );
    a.limiter_addr = Some(free_addr().to_string());
    let report = build_report(&a).await.expect("report");
    assert_eq!(status(&report, "limiter.listen.limiter"), Status::Pass);
    assert_eq!(status(&report, "limiter.config.max_buckets"), Status::Pass);
    a.limiter_addr = Some("not an address".to_owned());
    let report = build_report(&a).await.expect("report");
    assert_eq!(status(&report, "limiter.listen.limiter"), Status::Fail);
}

#[tokio::test]
async fn all_runs_the_roles_that_have_a_configuration() {
    let dir = scratch("all");
    let path = pool_config(
        &dir,
        "postgres://postgres@127.0.0.1:1/x",
        "redis://127.0.0.1:1",
        "",
    );
    let report = build_report(&args(RoleArg::All, &[format!("pool={path}")]))
        .await
        .expect("report");
    assert_eq!(
        status(&report, "pool.config.load"),
        Status::Pass,
        "{report:#?}"
    );
    assert!(
        build_report(&args(RoleArg::All, &["bare.toml".to_owned()]))
            .await
            .is_err()
    );
    let _ = std::fs::remove_dir_all(dir);
}
