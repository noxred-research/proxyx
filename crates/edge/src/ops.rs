//! The ops listener: `/metrics`, `/stats`, `/healthz`, `/readyz`.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State as AxState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::breaker::BreakerState;
use crate::conn::Shared;
use crate::metrics::{Activity, CONTENT_TYPE};
use crate::server::Server;

/// Refresh the gauges that are read from live state, then render.
pub fn render_metrics(shared: &Shared) -> String {
    let state = shared.state();
    let m = &shared.metrics;
    for pool in state.all_pools() {
        let name = pool.name();
        let (open, half_open, unhealthy) = pool.states();
        for (label, v) in [
            ("total", pool.len()),
            ("open", open),
            ("half_open", half_open),
            ("unhealthy", unhealthy),
            ("prefixes", pool.prefix_count()),
        ] {
            m.egress_addresses
                .with_label_values(&[name, label])
                .set(v as i64);
        }
    }
    for p in state.parents.all() {
        m.parent_up
            .with_label_values(&[&p.name])
            .set(i64::from(!p.is_down()));
        m.parent_breaker_state
            .with_label_values(&[&p.name])
            .set(p.state().as_i64());
        m.parent_healthy
            .with_label_values(&[&p.name])
            .set(i64::from(p.health.is_healthy()));
    }
    // The writer thread counts what it dropped; the counter follows it.
    let dropped = shared.access_log().dropped();
    let seen = m.access_log_dropped_total.get();
    if dropped > seen {
        m.access_log_dropped_total.inc_by(dropped - seen);
    }
    m.render()
}

async fn metrics(AxState(server): AxState<Arc<Server>>) -> Response {
    let mut r = render_metrics(&server.shared).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    r
}

#[derive(Default, Deserialize)]
struct StatsQuery {
    format: Option<String>,
}

#[derive(Serialize)]
struct Stats {
    listeners: Vec<StatsRow>,
    pools: Vec<StatsRow>,
    nodes: Vec<StatsRow>,
}

#[derive(Serialize)]
struct StatsRow {
    kind: &'static str,
    name: String,
    pool: Option<String>,
    state: &'static str,
    #[serde(flatten)]
    activity: Activity,
}

fn node_state(healthy: bool, breaker: BreakerState) -> &'static str {
    if !healthy {
        return "unhealthy";
    }
    match breaker {
        BreakerState::Closed => "up",
        BreakerState::HalfOpen => "half_open",
        BreakerState::Open => "open",
    }
}

impl Stats {
    fn snapshot(server: &Server) -> Self {
        let state = server.shared.state();
        let activity = server.shared.metrics.activity_snapshot();
        let bound = server.local_addrs();
        let stopping = server.shared.shutdown.is_cancelled();
        let mut listeners: Vec<_> = state
            .listeners
            .iter()
            .map(|(name, listener)| StatsRow {
                kind: "listener",
                name: name.clone(),
                pool: listener
                    .cfg
                    .pool
                    .as_ref()
                    .or(state.cfg.server.default_pool.as_ref())
                    .cloned(),
                state: if stopping {
                    "stopping"
                } else if bound.contains_key(name) {
                    "up"
                } else {
                    "unbound"
                },
                activity: activity.listeners.get(name).copied().unwrap_or_default(),
            })
            .collect();
        let all_pools = state.all_pools();
        let mut pools = Vec::with_capacity(all_pools.len());
        let mut nodes = Vec::new();
        for pool in &all_pools {
            let mut counts = activity.pools.get(pool.name()).copied().unwrap_or_default();
            counts.active = u64::try_from(pool.active()).unwrap_or(u64::MAX);
            pools.push(StatsRow {
                kind: "pool",
                name: pool.name().to_owned(),
                pool: None,
                state: if pool.is_usable() { "up" } else { "down" },
                activity: counts,
            });
            for node in pool.snapshots() {
                nodes.push(StatsRow {
                    kind: "egress",
                    name: node.ip.to_string(),
                    pool: Some(pool.name().to_owned()),
                    state: node_state(node.healthy, node.state),
                    activity: Activity {
                        active: u64::try_from(node.active).unwrap_or(u64::MAX),
                        total_connections: node.attempts,
                        failures: node.failures,
                        latency_seconds: node.latency.map(|latency| latency.as_secs_f64()),
                    },
                });
            }
        }
        for parent in state.parents.all() {
            let counts = parent.stats();
            nodes.push(StatsRow {
                kind: "parent",
                name: parent.name.clone(),
                pool: parent.pool.clone(),
                state: node_state(parent.health.is_healthy(), parent.state()),
                activity: Activity {
                    active: counts.active,
                    total_connections: counts.attempts,
                    failures: counts.failures,
                    latency_seconds: (parent.latency().is_some()
                        && counts.mean_latency_ms.is_finite())
                    .then_some(counts.mean_latency_ms / 1000.0),
                },
            });
        }
        listeners.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        pools.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        nodes.sort_unstable_by(|a, b| (a.kind, &a.pool, &a.name).cmp(&(b.kind, &b.pool, &b.name)));
        Self {
            listeners,
            pools,
            nodes,
        }
    }

    fn csv(&self) -> String {
        let mut out = String::from(
            "kind,name,pool,state,active,total_connections,failures,latency_seconds\r\n",
        );
        for row in self.listeners.iter().chain(&self.pools).chain(&self.nodes) {
            csv_field(&mut out, row.kind);
            out.push(',');
            csv_field(&mut out, &row.name);
            out.push(',');
            csv_field(&mut out, row.pool.as_deref().unwrap_or_default());
            out.push(',');
            csv_field(&mut out, row.state);
            // Writing to a String cannot fail.
            let _ = write!(
                out,
                ",{},{},{},",
                row.activity.active, row.activity.total_connections, row.activity.failures,
            );
            if let Some(latency) = row.activity.latency_seconds {
                let _ = write!(out, "{latency}");
            }
            out.push_str("\r\n");
        }
        out
    }
}

fn csv_field(out: &mut String, value: &str) {
    if value.contains([',', '"', '\r', '\n']) {
        out.push('"');
        for ch in value.chars() {
            if ch == '"' {
                out.push('"');
            }
            out.push(ch);
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

fn accepts_csv(headers: &HeaderMap) -> bool {
    headers.get_all(header::ACCEPT).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|range| {
                let mut parts = range.split(';');
                if !parts
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/csv"))
                {
                    return false;
                }
                parts.all(|part| match part.trim().split_once('=') {
                    Some((name, value)) if name.trim().eq_ignore_ascii_case("q") => value
                        .trim()
                        .parse::<f32>()
                        .is_ok_and(|quality| quality > 0.0 && quality <= 1.0),
                    _ => true,
                })
            })
        })
    })
}

async fn stats(
    AxState(server): AxState<Arc<Server>>,
    Query(query): Query<StatsQuery>,
    headers: HeaderMap,
) -> Response {
    let csv = match query.format.as_deref() {
        Some("csv") => true,
        Some("json") => false,
        None => accepts_csv(&headers),
        Some(_) => {
            return (StatusCode::BAD_REQUEST, "format must be json or csv\n").into_response();
        }
    };
    let snapshot = Stats::snapshot(&server);
    let mut response = if csv {
        (
            [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
            snapshot.csv(),
        )
            .into_response()
    } else {
        axum::Json(snapshot).into_response()
    };
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
    response
}

/// Liveness: the process answers.
async fn healthz() -> &'static str {
    "ok\n"
}

/// Ready when the process is not stopping, a configuration is in force, every
/// configured listener is bound and at least one egress path is healthy.
async fn readyz(AxState(server): AxState<Arc<Server>>) -> Response {
    let r = server.readiness();
    let status = if r.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, r.report()).into_response()
}

pub fn router(server: Arc<Server>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/stats", get(stats))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(server)
}

/// Serve until shutdown. Returns the bound address through `bound`.
pub async fn serve(server: Arc<Server>, addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let app = router(server);
    // Stays up while the proxy drains (`/readyz` answers 503 then) and ends with the process.
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(local)
}
