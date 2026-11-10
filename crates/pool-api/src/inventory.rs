//! Static inventory routes: replace one provider's list, list rows, and the
//! replacement report of IPs that wait for a new one.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use common::types::{InventoryEntry, IpState, Kind, ProviderId, UpstreamScheme};
use provider::{Adapter, UnitSpec};
use serde::Deserialize;
use serde_json::{Value, json};
use store::InventoryRow;
use time::OffsetDateTime;

use crate::auth::Actor;
use crate::error::{ApiError, ApiJson, ApiPath as Path, ApiQuery as Query};
use crate::state::ApiState;
use crate::wire::{
    MAX_NAME_LEN, ensure_secret_name, ensure_text, is_unusable_exit, parse_arg, plain_host,
    unix_opt,
};

/// Most entries one request may replace.
const MAX_ENTRIES: usize = 10_000;
/// Bound of the ready-set withdrawal of retired IPs after the commit.
const WITHDRAW_BOUND: Duration = Duration::from_secs(5);
/// Block history shown in the replacement report.
const REPORT_BLOCK_HISTORY: Duration = Duration::from_secs(30 * 24 * 3_600);
/// Checks per scoring service shown in the replacement report.
const REPORT_SCORES_PER_SOURCE: i64 = 3;

/// The checks the entry types do not make but the warmer and the gateway rely
/// on: a usable exit address, a plain host, a plain credentials file name, a
/// real rental date and text that Postgres can store. The entry of a `local`
/// adapter has no upstream port (any value is ignored) and its host is the
/// local source address: the adapter renders it, so what it refuses is
/// refused here.
fn ensure_entry(e: &InventoryEntry, adapter: Option<&Adapter>) -> Result<(), ApiError> {
    let local = adapter.filter(|a| a.scheme() == UpstreamScheme::Local);
    ensure_text("plan", &e.plan, MAX_NAME_LEN)?;
    if is_unusable_exit(e.ip) {
        return Err(ApiError::bad_request("ip is not a public address"));
    }
    if e.host.trim() != e.host {
        return Err(ApiError::bad_request("host has surrounding whitespace"));
    }
    plain_host(&e.host)?;
    if let Some(adapter) = local {
        adapter
            .recipe(&UnitSpec::Static {
                entry: e,
                credentials: None,
            })
            .map_err(|err| ApiError::bad_request(format!("local unit refused: {err}")))?;
    } else if e.port == 0 {
        return Err(ApiError::bad_request("port must be 1 to 65535"));
    }
    if let Some(name) = &e.credentials {
        ensure_secret_name("credentials", name)?;
    }
    if let Some(handle) = &e.box_handle {
        ensure_text("box_handle", handle, MAX_NAME_LEN)?;
    }
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct PutBody {
    entries: Vec<InventoryEntry>,
}

/// `PUT /v1/inventory/{provider}`: make the provider's inventory equal to
/// `entries`. Known IPs keep their state; IPs left out are retired.
pub(crate) async fn put(
    State(state): State<Arc<ApiState>>,
    Path(provider): Path<String>,
    Actor(actor): Actor,
    ApiJson(body): ApiJson<PutBody>,
) -> Result<Json<Value>, ApiError> {
    let provider: ProviderId = parse_arg(&provider)?;
    if body.entries.len() > MAX_ENTRIES {
        return Err(ApiError::bad_request(format!(
            "at most {MAX_ENTRIES} entries per request"
        )));
    }
    if let Some(e) = body
        .entries
        .iter()
        .find(|e| e.subtype.kind() != Kind::Static)
    {
        return Err(ApiError::bad_request(format!(
            "{}: a {} subtype is not a static inventory entry",
            e.ip,
            e.subtype.as_str()
        )));
    }
    let loaded = state.loaded.borrow().clone();
    let adapter = loaded.adapters.get(&provider);
    for e in &body.entries {
        ensure_entry(e, adapter).map_err(|err| err.prefixed(&e.ip.to_string()))?;
    }
    let sync = state
        .db
        .replace_inventory(&provider, &body.entries, &actor)
        .await?;
    // Best effort: the warmer also withdraws units that are not leasable. A
    // Redis outage costs a reconnect per IP, so the whole withdrawal gets one
    // bound and the request still answers inside its own 15 s.
    let withdraw = async {
        for ip in &sync.retired {
            match state.db.inventory_row(*ip).await {
                Ok(Some(row)) => {
                    if let Err(error) = state
                        .hot
                        .ready_take(&row.partition(), &ip.to_string())
                        .await
                    {
                        tracing::warn!(%error, %provider, "could not withdraw a retired ip from the ready set");
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, %provider, "could not read a retired ip"),
            }
        }
        // An IP listed in another provider or region now is not leasable in
        // the partition it was in.
        for (ip, from) in &sync.moved {
            if let Err(error) = state.hot.unit_retire(from, &ip.to_string()).await {
                tracing::warn!(%error, %provider, "could not withdraw a moved ip from its old partition");
            }
        }
    };
    if tokio::time::timeout(WITHDRAW_BOUND, withdraw)
        .await
        .is_err()
    {
        tracing::warn!(%provider, "retired ips were not all withdrawn from the ready set in time");
    }
    Ok(Json(json!({
        "provider": provider,
        "added": sync.added,
        "updated": sync.updated,
        "revived": sync.revived,
        "retired": sync.retired,
        "unchanged": sync.unchanged,
    })))
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    provider: Option<String>,
    state: Option<String>,
}

/// `GET /v1/inventory?provider=&state=`
pub(crate) async fn list(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let provider: Option<ProviderId> = query.provider.as_deref().map(parse_arg).transpose()?;
    let ip_state: Option<IpState> = query.state.as_deref().map(parse_arg).transpose()?;
    let rows = state.db.list_inventory(provider.as_ref(), ip_state).await?;
    Ok(Json(
        json!({ "items": rows.iter().map(row_json).collect::<Vec<_>>() }),
    ))
}

fn row_json(r: &InventoryRow) -> Value {
    let e = &r.entry;
    json!({
        "ip": e.ip,
        "provider": e.provider,
        "region": e.region,
        "subtype": e.subtype,
        "plan": e.plan,
        "host": e.host,
        "port": e.port,
        "asn": e.asn,
        "rental_end": e.rental_end,
        "state": r.state.as_str(),
        "state_since": r.state_since.unix_timestamp(),
        "cooldown_until": unix_opt(r.cooldown_until),
        "quarantined_at": unix_opt(r.quarantined_at),
        "retest_at": unix_opt(r.retest_at),
        "offline_since": unix_opt(r.offline_since),
        "last_check_at": unix_opt(r.last_check_at),
        "exit_ip": r.exit_ip,
        "owner": r.owner,
    })
}

/// `GET /v1/inventory/replacements`: one record per IP in `replace_requested`:
/// provider, plan, address, scores per service, block counts per target and the
/// rental end.
pub(crate) async fn replacements(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Value>, ApiError> {
    let rows = state
        .db
        .list_inventory(None, Some(IpState::ReplaceRequested))
        .await?;
    let since = OffsetDateTime::now_utc() - REPORT_BLOCK_HISTORY;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let ip = row.entry.ip;
        let scores = state.db.recent_scores(ip, REPORT_SCORES_PER_SOURCE).await?;
        let mut blocks: BTreeMap<String, u32> = BTreeMap::new();
        for block in state.db.blocks_since(ip, since).await? {
            *blocks
                .entry(block.target.unwrap_or_else(|| "*".to_owned()))
                .or_default() += 1;
        }
        let mut item = row_json(row);
        item["scores"] = scores
            .iter()
            .map(|s| {
                json!({
                    "source": s.source,
                    "risk": s.risk,
                    "flags": s.flags,
                    "checked_at": s.checked_at.unix_timestamp(),
                })
            })
            .collect();
        item["blocks_by_target"] = json!(blocks);
        items.push(item);
    }
    Ok(Json(json!({ "items": items })))
}
