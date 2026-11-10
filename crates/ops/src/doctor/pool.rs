//! Pool gateway and warmer: `Settings` as the roles load it, then what they need.

use std::net::SocketAddr;
use std::path::Path;

use common::config::Settings;
use diag::net::{dns_check, port_check, url_host_port};
use diag::redis_checks::{RedisOptions, redis_server};
use diag::{Check, Status, db, files};

use super::Ctx;

/// Descriptors the gateway needs besides the tunnels (listeners, Postgres and
/// Redis connections, the ops server, files). The same margin the gateway
/// applies when it starts.
const FD_MARGIN: u64 = 512;

/// Which pool role the checks are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Both: every check of either.
    Both,
    Gateway,
    Warmer,
}

impl Kind {
    fn gateway(self) -> bool {
        matches!(self, Self::Both | Self::Gateway)
    }
}

/// The error and its causes on one line.
pub(crate) fn chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

pub(crate) async fn checks(kind: Kind, config: Option<&Path>, ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    let settings = match Settings::load(config) {
        Ok(settings) => settings,
        Err(error) => {
            let source = config.map_or_else(
                || "the default file and PROXYX_POOL_* variables".to_owned(),
                |p| p.display().to_string(),
            );
            out.push(
                Check::fail("config.load", format!("{source}: {}", chain(&error)))
                    .hint("fix the key named above; the role refuses to start on it"),
            );
            return out;
        }
    };
    out.push(Check::pass(
        "config.load",
        config.map_or_else(
            || "settings load from the default file and environment".to_owned(),
            |p| format!("{} loads and validates", p.display()),
        ),
    ));
    out.push(
        match proxyx_pool::exit_ip::config(settings.exit_ip_services.as_deref()) {
            Ok(_) => Check::pass(
                "config.exit_ip_services",
                "the exit-IP check services are valid",
            ),
            Err(error) => Check::fail("config.exit_ip_services", chain(&error))
                .hint("fix exit_ip_services (PROXYX_POOL_EXIT_IP_SERVICES)"),
        },
    );

    // Dependencies.
    let pg_checks = db::database(settings.database_url.expose(), ctx.timeout).await;
    let pg_up = pg_checks.first().is_some_and(|c| c.status != Status::Fail);
    out.extend(pg_checks);
    if pg_up {
        out.push(pending_migrations(settings.database_url.expose()).await);
    }
    out.extend(redis_server(settings.redis_url.expose(), RedisOptions::new(ctx.timeout)).await);
    for (id, url) in [
        ("dns.postgres", settings.database_url.expose()),
        ("dns.redis", settings.redis_url.expose()),
    ] {
        if let Some((host, _)) = url_host_port(url)
            && host.parse::<std::net::IpAddr>().is_err()
        {
            out.push(dns_check(id, &host, ctx.timeout).await);
        }
    }

    // Data directory.
    out.extend(data_checks(&settings));

    // Secrets.
    out.push(files::dir_exists(
        "secrets.dir",
        "secrets directory",
        &settings.secrets_dir,
        true,
    ));
    out.push(files::secrets_dir_modes(
        "secrets.permissions",
        &settings.secrets_dir,
    ));
    out.push(files::secret_file(
        "secrets.admin_token",
        "admin token file",
        &settings.admin_token_file,
        kind.gateway(),
    ));
    out.push(files::secret_file(
        "secrets.probe_key",
        "probe key file",
        &settings.probe_key_file,
        false,
    ));

    // Listeners and descriptors.
    out.push(distinct_listeners(&settings, kind));
    if kind.gateway() {
        let needed = (settings.max_connections as u64)
            .saturating_mul(2)
            .saturating_add(FD_MARGIN);
        out.push(files::fd_limit(
            needed,
            &format!(
                "max_connections = {}: 2 per tunnel and {FD_MARGIN} spare",
                settings.max_connections
            ),
        ));
    }
    for (id, label, addr) in listeners(&settings, kind) {
        out.push(if ctx.skip_listeners {
            Check::skip(id, format!("{label} {addr}: not tried (--skip-listeners)"))
        } else {
            port_check(id, label, addr)
        });
    }
    out
}

fn listeners(settings: &Settings, kind: Kind) -> Vec<(&'static str, &'static str, SocketAddr)> {
    let mut all = Vec::new();
    if kind.gateway() {
        all.push((
            "listen.connect",
            "CONNECT listener",
            settings.connect_listen,
        ));
        all.push(("listen.socks", "SOCKS5 listener", settings.socks_listen));
        all.push(("listen.probe", "probe listener", settings.probe_listen));
        all.push(("listen.api", "control API", settings.api_listen));
    }
    all.push(("listen.ops", "ops server", settings.ops_listen));
    all
}

/// Two listeners of one role cannot share a port.
fn distinct_listeners(settings: &Settings, kind: Kind) -> Check {
    let all = listeners(settings, kind);
    for (i, (_, a_label, a)) in all.iter().enumerate() {
        for (_, b_label, b) in &all[i + 1..] {
            let clash = a.port() == b.port()
                && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified());
            if clash {
                return Check::fail(
                    "listen.distinct",
                    format!("{a_label} {a} and {b_label} {b} use the same port"),
                )
                .hint("give every listener its own port");
            }
        }
    }
    Check::pass("listen.distinct", "the listeners use distinct ports")
}

async fn pending_migrations(url: &str) -> Check {
    let id = "postgres.pending";
    let run = async {
        let db = store::Db::connect(url).await?;
        db.pending_migrations().await
    };
    match tokio::time::timeout(std::time::Duration::from_secs(10), run).await {
        Ok(Ok(pending)) if pending.is_empty() => Check::pass(id, "the schema is up to date"),
        Ok(Ok(pending)) => Check::fail(
            id,
            format!(
                "{} migration(s) not applied: {}",
                pending.len(),
                pending.join(", ")
            ),
        )
        .hint("run `proxyx migrate pool` before starting the roles"),
        Ok(Err(error)) => Check::fail(id, format!("cannot read the migration state: {error}")),
        Err(_) => Check::fail(id, "reading the migration state timed out"),
    }
}

/// `adapters/`, `policies/` and `inventory/` of the data directory, loaded as
/// the roles load them.
fn data_checks(settings: &Settings) -> Vec<Check> {
    let mut out = Vec::new();
    let data = &settings.data_dir;
    out.push(files::dir_exists("data.dir", "data directory", data, true));
    let adapters =
        provider::AdapterSet::load(&data.join("adapters"), |name| settings.read_secret(name));
    out.push(match &adapters {
        Ok(set) => Check::pass(
            "data.adapters",
            format!(
                "{} adapter(s) load, their secrets are readable",
                set.iter().count()
            ),
        ),
        Err(error) => Check::fail("data.adapters", error.to_string())
            .hint("the roles refuse to start when an adapter or its secret does not load"),
    });
    out.push(match store::loaded::git_policy_docs(data) {
        Ok(docs) if docs.is_empty() => Check::skip(
            "data.policies",
            "no policy files: policies come from Postgres only",
        ),
        Ok(docs) => match policy::PolicySet::from_docs(docs) {
            Ok(set) => match &adapters {
                Ok(adapters) => match store::loaded::check_session_life(&set, adapters) {
                    Ok(()) => Check::pass(
                        "data.policies",
                        "the policy files merge and fit the adapters",
                    ),
                    Err(error) => Check::fail("data.policies", error.to_string()),
                },
                Err(_) => Check::pass(
                    "data.policies",
                    "the policy files merge (not checked against the adapters, which do not load)",
                ),
            },
            Err(error) => Check::fail("data.policies", error.to_string())
                .hint("fix the policy named above; see docs/policies.md"),
        },
        Err(error) => Check::fail("data.policies", chain(&error)),
    });
    out.push(inventory_secrets(settings));
    out
}

/// Every `credentials` file an inventory entry names must be readable.
fn inventory_secrets(settings: &Settings) -> Check {
    let id = "data.inventory";
    let dir = settings.data_dir.join("inventory");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Check::skip(id, format!("no inventory directory {}", dir.display()));
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    let (mut entries_seen, mut problems) = (0usize, Vec::new());
    for path in files {
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                problems.push(format!("{}: {error}", path.display()));
                continue;
            }
        };
        let table: toml::Table = match text.parse() {
            Ok(table) => table,
            Err(error) => {
                problems.push(format!("{}: {}", path.display(), error.message()));
                continue;
            }
        };
        let Some(list) = table.get("entry").and_then(toml::Value::as_array) else {
            continue;
        };
        for entry in list {
            entries_seen += 1;
            let Some(name) = entry.get("credentials").and_then(toml::Value::as_str) else {
                continue;
            };
            if let Err(error) = settings.read_secret(name) {
                problems.push(format!("{}: {}", path.display(), chain(&error)));
            }
        }
    }
    if problems.is_empty() {
        Check::pass(
            id,
            format!("{entries_seen} inventory entr(ies) read, their credentials files exist"),
        )
    } else {
        Check::fail(id, problems.join("; "))
            .hint("mount the credentials file under secrets_dir or fix the entry")
    }
}
