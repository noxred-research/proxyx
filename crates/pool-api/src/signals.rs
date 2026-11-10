//! Block signals: the session proxy's batches (org key) and operator reports (admin).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use common::types::{Kind, SignalSource, SignalType};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::auth::{Actor, OrgAuth};
use crate::error::{ApiError, ApiJson, ApiJsonList, ApiPath as Path};
use crate::react::{Subject, react};
use crate::state::ApiState;
use crate::wire::parse_host;

/// Events per batch; the session proxy sends small batches.
const MAX_EVENTS: usize = 500;
/// An event older than this says nothing about the IP now.
const MAX_EVENT_AGE: Duration = Duration::from_secs(3_600);

/// One element of the session proxy's array. `org`, `status` and unknown fields are
/// ignored: the org comes from the key, the session from the registry.
#[derive(Deserialize)]
pub(crate) struct Event {
    /// The `X-ProxyX-Pool-Session` of the tunnel.
    session: String,
    exit_ip: IpAddr,
    /// `host:port`, IPv6 bracketed.
    target: String,
    #[serde(rename = "type")]
    ty: SignalType,
    /// Unix seconds.
    time: i64,
}

/// `POST /v1/block-signals`: HTTP Basic, the password is the org key.
pub(crate) async fn block_signals(
    State(state): State<Arc<ApiState>>,
    OrgAuth(org): OrgAuth,
    ApiJsonList(events): ApiJsonList<Vec<Event>>,
) -> Result<Json<Value>, ApiError> {
    if events.len() > MAX_EVENTS {
        return Err(ApiError::bad_request(format!(
            "at most {MAX_EVENTS} events per batch"
        )));
    }
    // A bad event refuses the whole batch before any is applied, so the session proxy's
    // retry of it does not count the earlier events twice.
    let hosts = events
        .iter()
        .map(|e| parse_host(&e.target))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| ApiError::bad_request("an event has an invalid target"))?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let loaded = state.loaded.borrow().clone();
    // What names a batch for its retry: its events in order.
    let batch = store::sha256_hex(
        events
            .iter()
            .map(|e| {
                format!(
                    "{}|{}|{}|{}|{}",
                    e.session,
                    e.exit_ip,
                    e.target,
                    e.ty.as_str(),
                    e.time
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            .as_bytes(),
    );
    let (mut accepted, mut ignored) = (0u32, 0u32);
    for (position, (event, host)) in events.iter().zip(&hosts).enumerate() {
        let fresh = now.saturating_sub(event.time) <= MAX_EVENT_AGE.as_secs().cast_signed();
        let record = if fresh {
            state.hot.session_get(&event.session).await?
        } else {
            None
        };
        // The session must belong to the org that sends the signal, and the
        // exit IP must be the one the gateway reported for it.
        let Some(record) = record.filter(|r| r.org == org && r.ip == event.exit_ip) else {
            ignored += 1;
            continue;
        };
        // The unit and the exit IP of a session differ for a SIM box (the
        // unit is the row key, the exit IP what its last check saw) and for
        // a customer upstream (a key, then the customer's exit): only the
        // partition's adapter says what the unit is.
        let Some(adapter) = loaded.adapters.get(&record.partition.provider) else {
            ignored += 1;
            continue;
        };
        let kind = adapter.kind();
        // the session proxy sends a batch again when it answered 5xx: an event applied
        // before the failing one is marked (by batch and position, so two
        // equal events of one batch both count), and the retry does not
        // apply it again (its blocks would bring the quarantine forward).
        let mark = format!("signal:{org}:{batch}:{position}");
        if state.hot.event_seen(&mark).await? {
            accepted += 1;
            continue;
        }
        let subject = Subject {
            partition: record.partition,
            ip: record.ip,
            unit: record.unit,
            kind,
        };
        react(
            &state,
            &org,
            &subject,
            SignalSource::Client,
            event.ty,
            Some(host.as_str()),
        )
        .await?;
        state.hot.event_done(&mark, MAX_EVENT_AGE).await?;
        accepted += 1;
    }
    state
        .metrics
        .block_signals_ignored_total
        .inc_by(u64::from(ignored));
    Ok(Json(json!({ "accepted": accepted, "ignored": ignored })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorReport {
    /// The target that blocked the IP; unset: the IP is blocked everywhere.
    target: Option<String>,
    #[serde(rename = "type", default = "default_type")]
    ty: SignalType,
    /// A rotating session id, when the IP is a session's exit IP.
    session: Option<String>,
}

fn default_type() -> SignalType {
    SignalType::Forbidden
}

/// `POST /v1/ips/{ip}/block`: an operator reports that an IP is blocked.
/// A static IP is found in the inventory; a rotating one needs `session`.
pub(crate) async fn operator_block(
    State(state): State<Arc<ApiState>>,
    Path(ip): Path<String>,
    Actor(actor): Actor,
    ApiJson(report): ApiJson<OperatorReport>,
) -> Result<Json<Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError::bad_request("the path is not an ip address"))?;
    let host = report
        .target
        .as_deref()
        .map(|t| parse_host(t).ok_or_else(|| ApiError::bad_request("invalid target")))
        .transpose()?;
    let subject = match state.db.inventory_row(ip).await? {
        Some(row) => Subject {
            partition: row.partition(),
            // blocks and cooldowns are keyed by the exit IP of the unit
            ip: row.unit_ip(),
            unit: ip.to_string(),
            kind: Kind::Static,
        },
        None => {
            let session = report.session.ok_or_else(|| {
                ApiError::not_found("ip is not in the inventory; name its session")
            })?;
            let record = state
                .hot
                .session_get(&session)
                .await?
                .filter(|r| r.ip == ip)
                .ok_or_else(|| ApiError::not_found("no such session for this ip"))?;
            let kind = state
                .loaded
                .borrow()
                .adapters
                .get(&record.partition.provider)
                .map(provider::Adapter::kind)
                .ok_or_else(|| ApiError::not_found("the session's provider is not loaded"))?;
            Subject {
                partition: record.partition,
                ip,
                unit: record.unit,
                kind,
            }
        }
    };
    let reaction = react(
        &state,
        &state.probe_org,
        &subject,
        SignalSource::Operator,
        report.ty,
        host.as_deref(),
    )
    .await?;
    // The signal's own audit rows carry `signal:operator`; this one names the
    // person from `X-Operator`.
    state
        .db
        .audit(
            &actor,
            "ip.block_reported",
            &ip.to_string(),
            json!({ "target": host, "type": report.ty, "scope": reaction.label() }),
        )
        .await?;
    Ok(Json(json!({ "scope": reaction.label() })))
}
