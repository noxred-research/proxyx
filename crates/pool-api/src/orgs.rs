//! Org keys and org blocks.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use common::Secret;
use common::config::humantime_secs;
use common::types::OrgId;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::Actor;
use crate::error::{
    ApiBytes, ApiError, ApiJson, ApiPath as Path, ApiQuery as Query, ensure_object,
    json_content_type,
};
use crate::state::ApiState;
use crate::wire::{MAX_NAME_LEN, block_json, ensure_text, parse_org, parse_scope, random_token};

const MAX_REASON_LEN: usize = 1_000;
/// Longest block `ttl`, like the policy durations.
const MAX_BLOCK_TTL: Duration = Duration::from_secs(366 * 86_400);

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct KeyBody {
    #[serde(default)]
    label: String,
}

/// `POST /v1/orgs/{org}/keys`: create a key and return it. Only the sha256
/// is stored, so this reply is the only time the key can be read.
pub(crate) async fn create_key(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
    headers: HeaderMap,
    ApiBytes(body): ApiBytes,
) -> Result<impl IntoResponse, ApiError> {
    let org = parse_org(&org)?;
    let body: KeyBody = if body.is_empty() {
        KeyBody::default()
    } else {
        if !json_content_type(&headers) {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "expected request with `Content-Type: application/json`",
            ));
        }
        ensure_object(&body)?;
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?
    };
    ensure_text("label", &body.label, MAX_NAME_LEN)?;
    let key = Secret::new(random_token("ak_"));
    state
        .db
        .add_org_key(&org, &key, &body.label, &actor)
        .await?;
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "org": org, "key": key.expose() })),
    ))
}

/// `DELETE /v1/orgs/{org}/keys`: disable every key of the org.
pub(crate) async fn disable_keys(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
) -> Result<Json<Value>, ApiError> {
    let org = parse_org(&org)?;
    let disabled = state.db.disable_org_keys(&org, &actor).await?;
    Ok(Json(json!({ "org": org, "disabled": disabled })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BlockBody {
    org: OrgId,
    /// `ip`, `provider`, `route_class` or `pool`.
    scope: String,
    /// An address, a provider id, `provider:region`, or `shared`/`private`.
    value: String,
    reason: String,
    /// How long the block lasts (`2h`, `30m`); unset: until revoked.
    ttl: Option<String>,
}

/// `POST /v1/org-blocks`: stop an org from using a scope. Open tunnels of
/// the org inside the scope are asked to close.
pub(crate) async fn create_block(
    State(state): State<Arc<ApiState>>,
    Actor(actor): Actor,
    ApiJson(body): ApiJson<BlockBody>,
) -> Result<impl IntoResponse, ApiError> {
    let scope = parse_scope(&body.scope, &body.value).map_err(ApiError::bad_request)?;
    ensure_text("reason", &body.reason, MAX_REASON_LEN)?;
    let ttl: Option<Duration> = body
        .ttl
        .as_deref()
        .map(humantime_secs::parse)
        .transpose()
        .map_err(|e| ApiError::bad_request(format!("ttl: {e}")))?;
    let expires_at = ttl.map(block_expiry).transpose()?;

    let block = state
        .db
        .create_org_block(
            &state.hot,
            &body.org,
            &scope,
            &body.reason,
            &actor,
            expires_at,
        )
        .await?;
    let drained = state.tunnels.close_org_scope(&block.org, &block.scope);
    let mut reply = block_json(&block);
    reply["drained"] = json!(drained);
    Ok((StatusCode::CREATED, Json(reply)))
}

/// When a block with `ttl` ends. The cap is the one policy durations have
/// (366 days): `OffsetDateTime + Duration` panics past year 9999, and a panic
/// aborts the whole process.
fn block_expiry(ttl: Duration) -> Result<OffsetDateTime, ApiError> {
    if ttl > MAX_BLOCK_TTL {
        return Err(ApiError::bad_request("ttl is above the limit of 366 days"));
    }
    OffsetDateTime::now_utc()
        .checked_add(
            time::Duration::try_from(ttl).map_err(|_| ApiError::bad_request("ttl is too long"))?,
        )
        .ok_or_else(|| ApiError::bad_request("ttl is too long"))
}

#[derive(Deserialize)]
pub(crate) struct BlockQuery {
    org: Option<String>,
}

/// `GET /v1/org-blocks?org=`: blocks that are neither revoked nor expired.
pub(crate) async fn list_blocks(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<BlockQuery>,
) -> Result<Json<Value>, ApiError> {
    let org = query.org.as_deref().map(parse_org).transpose()?;
    let blocks = state
        .db
        .active_org_blocks(OffsetDateTime::now_utc())
        .await?;
    let items: Vec<Value> = blocks
        .iter()
        .filter(|b| org.as_ref().is_none_or(|o| *o == b.org))
        .map(block_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// `DELETE /v1/org-blocks/{id}`: lift a block. The cache field stays while
/// another active block of the same org and scope still needs it. A cache
/// failure answers `503` and lifts nothing. Lifting twice answers `404`, but
/// still repeats the cache update.
pub(crate) async fn revoke_block(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Actor(actor): Actor,
) -> Result<Json<Value>, ApiError> {
    let id: Uuid = id
        .parse()
        .map_err(|_| ApiError::bad_request("the id is not a uuid"))?;
    let block = state
        .db
        .revoke_org_block(&state.hot, id, &actor)
        .await?
        .ok_or_else(|| ApiError::not_found("org block not found or already lifted"))?;
    Ok(Json(block_json(&block)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_ttl_is_capped_and_never_overflows_the_clock() {
        // `now + 3_000_000d` is past year 9999: the unchecked sum panicked and
        // the release profile aborted the whole gateway process.
        for days in [367u64, 3_000_000, 4_000_000, 99_999_999_999] {
            assert!(
                block_expiry(Duration::from_secs(days * 86_400)).is_err(),
                "{days}d"
            );
        }
        assert!(block_expiry(Duration::from_secs(u64::MAX)).is_err());
        assert!(block_expiry(Duration::MAX).is_err());
        let at = block_expiry(Duration::from_secs(366 * 86_400)).expect("366d");
        assert!(at > OffsetDateTime::now_utc());
        assert!(block_expiry(Duration::from_secs(1)).is_ok());
    }
}
