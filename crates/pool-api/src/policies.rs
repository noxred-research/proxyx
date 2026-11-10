//! Policy routes. Every write is checked as part of the whole set before it
//! is stored: a policy the set would refuse never reaches Postgres.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use common::types::{IpState, Kind, OrgId, ProviderId};
use policy::{EffectivePolicy, PolicyDoc, PolicySet, Scope};
use provider::AdapterSet;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use store::{InventoryRow, PolicyPut};

use crate::auth::Actor;
use crate::error::{ApiError, ApiJson, ApiPath as Path};
use crate::state::ApiState;
use crate::wire::{MAX_NAME_LEN, ensure_text, parse_org};

/// Most documents one request may write.
const MAX_POLICIES: usize = 200;

/// `GET /v1/policies`: the current version of every policy.
pub(crate) async fn list(State(state): State<Arc<ApiState>>) -> Result<Json<Value>, ApiError> {
    let records = state.db.current_policies().await?;
    let items: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "scope": r.scope,
                "name": r.name,
                "match": r.target,
                "version": r.version,
                "actor": r.actor,
                "created_at": r.created_at.unix_timestamp(),
                "doc": r.doc,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
pub(crate) struct PutBody {
    policies: Vec<PolicyDoc>,
}

/// `PUT /v1/policies`: store each document as a new version when it differs
/// from the current one. A git file that changes later wins over a document
/// written here.
pub(crate) async fn put(
    State(state): State<Arc<ApiState>>,
    Actor(actor): Actor,
    ApiJson(body): ApiJson<PutBody>,
) -> Result<Json<Value>, ApiError> {
    if body.policies.is_empty() || body.policies.len() > MAX_POLICIES {
        return Err(ApiError::bad_request(format!(
            "send between 1 and {MAX_POLICIES} policies"
        )));
    }
    let put = validated_put(&state, body.policies, &actor).await?;
    Ok(Json(put_json(&put)))
}

/// `DELETE /v1/policies/{scope}/{name}`: stop using the current version of a
/// policy written through the API (its versions stay). Deleting an API
/// version of a policy git defines goes back to git's: the next reload (30 s)
/// writes git's document again. A policy whose current version git wrote is
/// git's to remove (`409`: delete its file). The set that remains must still
/// be valid, so a global policy that orgs depend on cannot be dropped from
/// under them. `404` when the policy is not current.
pub(crate) async fn delete(
    State(state): State<Arc<ApiState>>,
    Path((scope, name)): Path<(String, String)>,
    Actor(actor): Actor,
) -> Result<Json<Value>, ApiError> {
    let scope: Scope = serde_json::from_value(Value::String(scope))
        .map_err(|_| ApiError::bad_request("scope is global, route_class or org"))?;
    let current = state.db.current_policies().await?;
    let scope_text = scope.to_string();
    let written_by = current
        .iter()
        .find(|r| r.scope == scope_text && r.name == name)
        .map(|r| r.actor.clone())
        .ok_or_else(|| ApiError::not_found("policy not found"))?;
    if written_by == store::loaded::GITOPS_ACTOR {
        return Err(ApiError::conflict(
            "git wrote this policy: delete its file from the git policy data instead",
        ));
    }
    let adapters = state.loaded.borrow().adapters.clone();
    let data_dir = state.data_dir.clone();
    let kept = (scope_text.clone(), name.clone());
    tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
        let mut rest = Vec::new();
        for record in &current {
            if (record.scope.as_str(), record.name.as_str()) != (kept.0.as_str(), kept.1.as_str()) {
                rest.push(record.doc()?);
            }
        }
        // The next reload writes git's version of this policy back,
        // so the set that remains includes it. A git tree that does not parse
        // is not synced, so nothing comes back then.
        let git = store::loaded::git_policy_docs(&data_dir).unwrap_or_else(|error| {
            tracing::warn!(?error, "git policies do not load, not counting them");
            Vec::new()
        });
        rest.extend(
            git.into_iter()
                .filter(|d| d.scope.to_string() == kept.0 && d.name == kept.1),
        );
        let set = PolicySet::from_docs(rest).map_err(|e| ApiError::bad_request(e.to_string()))?;
        store::loaded::check_session_life(&set, &adapters)
            .map_err(|e| ApiError::bad_request(e.to_string()))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::Error::new(e).context("the policy check panicked")))??;
    if !state
        .db
        .deactivate_policy(&scope_text, &name, &actor)
        .await?
    {
        return Err(ApiError::not_found("policy not found"));
    }
    Ok(Json(json!({
        "deactivated": format!("{scope_text}/{name}"),
        "written_by": written_by,
    })))
}

/// `PUT /v1/orgs/{org}/cache-policy`: the body is one policy document. The
/// scope is `org` and `match` is the org; `name` defaults to `org-<org>`.
pub(crate) async fn put_org(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let org = parse_org(&org)?;
    let Value::Object(mut fields) = body else {
        return Err(ApiError::bad_request("the body must be a policy object"));
    };
    pin(&mut fields, "scope", json!("org"))?;
    pin(&mut fields, "match", json!(org))?;
    fields
        .entry("name")
        .or_insert_with(|| json!(format!("org-{org}")));
    let doc: PolicyDoc = serde_json::from_value(Value::Object(fields))
        .map_err(|e| ApiError::bad_request(format!("invalid policy: {e}")))?;
    let put = validated_put(&state, vec![doc], &actor).await?;
    Ok(Json(put_json(&put)))
}

/// Set `key` to `value`, or refuse when the body names something else.
fn pin(fields: &mut Map<String, Value>, key: &str, value: Value) -> Result<(), ApiError> {
    match fields.get(key) {
        None => {
            fields.insert(key.to_owned(), value);
            Ok(())
        }
        Some(given) if *given == value => Ok(()),
        Some(_) => Err(ApiError::bad_request(format!(
            "{key} must be {value} for this route"
        ))),
    }
}

/// Check `docs` together with every current policy they do not replace, then
/// store them. A policy is stored per `(scope, name)`, so that pair, not the
/// name alone, says which current rows the new documents replace; the check
/// is [`PolicySet::from_docs`], the same one the gateway applies when it
/// loads the stored set.
async fn validated_put(
    state: &ApiState,
    docs: Vec<PolicyDoc>,
    actor: &str,
) -> Result<PolicyPut, ApiError> {
    for doc in &docs {
        ensure_doc_text(doc)?;
    }
    let current = state.db.current_policies().await?;
    let replaced: HashSet<(String, String)> = docs
        .iter()
        .map(|d| (d.scope.to_string(), d.name.clone()))
        .collect();
    let adapters = state.loaded.borrow().adapters.clone();
    let inventory = state.db.list_inventory(None, None).await?;
    let written: Vec<(Scope, Option<String>)> =
        docs.iter().map(|d| (d.scope, d.target.clone())).collect();
    let mut all = docs.clone();
    // Merging every org's policies is CPU the control API shares with the
    // tunnel path: it runs on a blocking thread.
    tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
        for record in &current {
            if !replaced.contains(&(record.scope.clone(), record.name.clone())) {
                all.push(record.doc()?);
            }
        }
        let set = PolicySet::from_docs(all).map_err(|e| ApiError::bad_request(e.to_string()))?;
        // The same two checks the gateway makes when it loads the stored set.
        store::loaded::check_session_life(&set, &adapters)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        ensure_servable(&set, &written, &adapters, &inventory)
    })
    .await
    .map_err(|e| ApiError::from(anyhow::Error::new(e).context("the policy check panicked")))??;
    Ok(state.db.put_policies(&docs, actor).await?)
}

/// Refuse a write whose policy no adapter can serve: every tunnel it
/// governs would answer `503 cache_empty` or `no_healthy_ip`. The gateway
/// walks the policy's kinds, providers and regions the same way: a rotating
/// adapter serves any region it is asked for, a static one only a region with
/// an inventory entry of its own (or of the org, for an org policy). Only the
/// policies the request writes are judged, and only whole: a list where one
/// region or kind can be served passes.
fn ensure_servable(
    set: &PolicySet,
    written: &[(Scope, Option<String>)],
    adapters: &AdapterSet,
    inventory: &[InventoryRow],
) -> Result<(), ApiError> {
    for (scope, target) in written {
        let (org, provider, what): (Option<OrgId>, Option<ProviderId>, String) =
            match (scope, target) {
                (Scope::Global, _) => (None, None, "the global policy".to_owned()),
                (Scope::RouteClass, Some(m)) => (
                    None,
                    Some(
                        m.parse()
                            .map_err(|e| ApiError::bad_request(format!("match: {e}")))?,
                    ),
                    format!("the route_class policy of {m}"),
                ),
                (Scope::Org, Some(m)) => (
                    Some(
                        m.parse()
                            .map_err(|e| ApiError::bad_request(format!("match: {e}")))?,
                    ),
                    None,
                    format!("the policy of org {m}"),
                ),
                // `from_docs` refused a route_class or org policy without `match`.
                _ => continue,
            };
        let policy = match &org {
            Some(org) => set.effective(org, provider.as_ref()),
            None => set.effective_default(provider.as_ref()),
        };
        if !serves(policy, org.as_ref(), provider.as_ref(), adapters, inventory) {
            return Err(ApiError::bad_request(format!(
                "{what} cannot be served: no loaded adapter of its kinds and providers has a \
                 ready region in it (a static provider needs an inventory entry in the region, \
                 a rotating one an adapter in `kinds`)"
            )));
        }
    }
    Ok(())
}

fn serves(
    policy: &EffectivePolicy,
    org: Option<&OrgId>,
    only: Option<&ProviderId>,
    adapters: &AdapterSet,
    inventory: &[InventoryRow],
) -> bool {
    adapters
        .iter()
        .filter(|a| policy.kinds.contains(&a.kind()))
        .filter(|a| policy.providers.is_empty() || policy.providers.contains(a.id()))
        .filter(|a| only.is_none_or(|p| p == a.id()))
        .any(|a| match a.kind() {
            Kind::Rotating => !policy.regions.is_empty(),
            Kind::Static => policy.regions.iter().any(|want| {
                inventory.iter().any(|row| {
                    row.entry.provider == *a.id()
                        && row.state != IpState::Retired
                        && (row.owner.is_none() || row.owner.as_ref() == org)
                        && row.entry.region.satisfies(want)
                })
            }),
        })
}

/// A name Postgres can store and no NUL byte anywhere in the document
/// (`jsonb` refuses it).
fn ensure_doc_text(doc: &PolicyDoc) -> Result<(), ApiError> {
    ensure_text("name", &doc.name, MAX_NAME_LEN)?;
    let value = serde_json::to_value(doc)
        .map_err(|e| ApiError::bad_request(format!("invalid policy: {e}")))?;
    if has_nul(&value) {
        return Err(ApiError::bad_request(
            "a policy must not contain a NUL byte",
        ));
    }
    Ok(())
}

fn has_nul(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains('\0'),
        Value::Array(items) => items.iter().any(has_nul),
        Value::Object(fields) => fields.iter().any(|(k, v)| k.contains('\0') || has_nul(v)),
        _ => false,
    }
}

fn put_json(put: &PolicyPut) -> Value {
    json!({ "stored": put.stored, "unchanged": put.unchanged })
}
