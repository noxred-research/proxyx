//! Customer upstreams (plan section 7): an org's own proxy, managed per org.
//!
//! Routes: `PUT`, `GET` and `DELETE /v1/orgs/{org}/upstream`, plus `POST
//! .../validate` and `POST .../rotate-secret`. A set unit starts as
//! `candidate` and nobody can lease it until `validate` passes. Every change
//! is audited as `customer.set`, `customer.clear`, `customer.rotate` or
//! `customer.validate`; a `PUT`, `rotate-secret` or `DELETE` that lands during
//! a check makes its result stale (`409`, nothing changes).
//!
//! The unit is an inventory row owned by the org (provider `customer` for
//! `http`, `customer_https` for `https`, `customer_socks5` for `socks5`), so
//! only that org can lease it.
//! An org with an upstream is served by it alone: when it is not leasable the
//! tunnel fails closed and never leaves through a shared provider IP. The
//! gateway pins the org from its snapshot, which reloads every 30 s, so a
//! `PUT` or `DELETE` is in force at each gateway pod after its next reload
//!. Until then that pod still follows the previous state: an org
//! that had no upstream keeps leaving through a shared provider IP for up to
//! one reload interval after its first `PUT`, and a `DELETE`
//! answers `504 lease_timeout` for as long. A write-through to Redis would
//! need the gateway's lease path to read it on every tunnel, for a case that
//! is almost always empty, so the window stays: set the upstream before the
//! org's first tunnel. The org's cache policy must still allow the provider
//! and a region that satisfies the
//! upstream's region; a `PUT` or `validate` reply carries a `warning` when the
//! policy's `providers` list leaves the provider out.
//!
//! **Where the login lives.** Vault writes are not available to the service,
//! so, like the session proxy's `orgs.proxy_password`, the username and password are kept
//! in clear text in the ProxyX-private Postgres table `customer_credentials`.
//! No route returns them (not even `GET`), the audit trail never holds them,
//! and they only reach the gateway and warmer through the in-memory snapshot,
//! as [`common::Secret`]. A new or rotated login reaches the gateway at its
//! next reload (30 s).
//!
//! **Address rule.** For an adapter with `public_only` (the shipped `customer`
//! adapters) the host and every address it resolves to must be public
//! routable ([`provider::ensure_public_address`]); the same rule runs again
//! when the adapter renders the endpoint at dial. `vpn-pool` has no such rule
//! and is not managed here.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use common::Secret;
use common::types::{InventoryEntry, OrgId, ProviderId, Region, Subtype, UpstreamScheme};
use provider::{Adapter, UnitSpec};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use store::{CustomerLogin, CustomerUnit, InventoryRow, UnitRecord};
use tokio::net::lookup_host;
use verify::{ExitIp, ExitIpError, ExitQuery};

use crate::auth::Actor;
use crate::error::{ApiError, ApiJson, ApiPath as Path};
use crate::state::ApiState;
use crate::wire::{is_unusable_exit, parse_org, plain_host, unix_opt};

/// Provider of an `http` upstream.
const HTTP_PROVIDER: &str = "customer";
/// Provider of an `https` upstream, with TLS certificate verification.
const HTTPS_PROVIDER: &str = "customer_https";
/// Provider of a `socks5` upstream.
const SOCKS5_PROVIDER: &str = "customer_socks5";

/// Name lookup of a new host.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
/// The exit-IP quorum of one validation. Inside the API's 15 s request bound.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(12);
/// SOCKS5 length-prefixes the login with one byte, so no field is longer.
const MAX_LOGIN_BYTES: usize = 255;

fn provider_for(scheme: UpstreamScheme) -> Result<ProviderId, ApiError> {
    let id = match scheme {
        UpstreamScheme::Http => HTTP_PROVIDER,
        UpstreamScheme::Https => HTTPS_PROVIDER,
        UpstreamScheme::Socks5 => SOCKS5_PROVIDER,
        // A customer must never pick the machine's own addresses as the exit:
        // `local` dials straight from a local source address and the customer
        // would choose which one.
        UpstreamScheme::Local => {
            return Err(ApiError::bad_request(
                "scheme must be http, https or socks5",
            ));
        }
    };
    Ok(id.parse().map_err(anyhow::Error::new)?)
}

fn scheme_of(provider: &ProviderId) -> &'static str {
    if provider.as_str() == SOCKS5_PROVIDER {
        "socks5"
    } else if provider.as_str() == HTTPS_PROVIDER {
        "https"
    } else {
        "http"
    }
}

fn adapter<'a>(
    loaded: &'a store::loaded::Loaded,
    provider: &ProviderId,
) -> Result<&'a Adapter, ApiError> {
    loaded.adapters.get(provider).ok_or_else(|| {
        tracing::error!(%provider, "the customer adapter is not loaded");
        ApiError::unavailable("customer adapter is not configured")
    })
}

/// The row key of an org's unit: a stable address in the unique-local range
/// derived from the org id. It is only a key: never dialed, never an exit
/// IP. The upstream's own address would collide for two orgs behind one
/// provider endpoint, and change whenever DNS answers in another order.
fn unit_key(org: &OrgId) -> IpAddr {
    let digest = Sha256::digest(format!("proxyx/customer-unit/{org}").as_bytes());
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&digest[..16]);
    octets[0] = 0xfd;
    IpAddr::V6(Ipv6Addr::from(octets))
}

/// The addresses of `host`, for the write-time address rule.
async fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, ApiError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let found = tokio::time::timeout(RESOLVE_TIMEOUT, lookup_host((host, port)))
        .await
        .map_err(|_| ApiError::bad_request("the host lookup timed out"))?
        .map_err(|_| ApiError::bad_request("the host does not resolve"))?;
    let mut ips: Vec<IpAddr> = found.map(|a| a.ip()).collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(ApiError::bad_request("the host does not resolve"));
    }
    Ok(ips)
}

/// The write-time address rule: the host and everything it resolves to.
fn ensure_public(adapter: &Adapter, host: &str, resolved: &[IpAddr]) -> Result<(), ApiError> {
    if !adapter.public_only() {
        return Ok(());
    }
    for candidate in
        std::iter::once(host.to_owned()).chain(resolved.iter().map(ToString::to_string))
    {
        provider::ensure_public_address(&candidate)
            .map_err(|_| ApiError::bad_request("the upstream address is not public routable"))?;
    }
    Ok(())
}

fn login_of(
    username: Option<Secret>,
    password: Option<Secret>,
) -> Result<Option<CustomerLogin>, ApiError> {
    match (username, password) {
        (None, None) => Ok(None),
        (Some(username), Some(password)) => {
            ensure_login(&username, &password)?;
            Ok(Some(CustomerLogin { username, password }))
        }
        _ => Err(ApiError::bad_request(
            "username and password are given together",
        )),
    }
}

fn ensure_login(username: &Secret, password: &Secret) -> Result<(), ApiError> {
    if username.is_empty()
        || password.is_empty()
        || username.expose().len() > MAX_LOGIN_BYTES
        || password.expose().len() > MAX_LOGIN_BYTES
    {
        return Err(ApiError::bad_request(format!(
            "username and password are 1 to {MAX_LOGIN_BYTES} bytes"
        )));
    }
    if username.expose().contains('\0') || password.expose().contains('\0') {
        return Err(ApiError::bad_request(
            "username and password must not contain a NUL byte",
        ));
    }
    Ok(())
}

fn pair(login: Option<&CustomerLogin>) -> Option<(Secret, Secret)> {
    login.map(|l| (l.username.clone(), l.password.clone()))
}

fn unit_json(row: &InventoryRow, has_login: bool) -> Value {
    let e = &row.entry;
    json!({
        "org": row.owner,
        "provider": e.provider,
        "scheme": scheme_of(&e.provider),
        "host": e.host,
        "port": e.port,
        "region": e.region,
        "unit": e.ip,
        "state": row.state.as_str(),
        "state_since": row.state_since.unix_timestamp(),
        "leasable": row.state.is_leasable(),
        "exit_ip": row.exit_ip,
        "last_check_at": unix_opt(row.last_check_at),
        "has_login": has_login,
    })
}

/// Take a unit out of the ready set, so no tunnel starts on it.
async fn withdraw(state: &ApiState, row: &InventoryRow) -> Result<(), ApiError> {
    state
        .hot
        .ready_take(&row.partition(), &row.entry.ip.to_string())
        .await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetBody {
    /// `http` (CONNECT) or `socks5`.
    scheme: UpstreamScheme,
    host: String,
    port: u16,
    /// Where the upstream exits, as the org's policy regions name it.
    region: Region,
    username: Option<Secret>,
    password: Option<Secret>,
}

/// `PUT /v1/orgs/{org}/upstream`: set the org's upstream. It starts as
/// `candidate` and is not leased until `validate` passes.
pub(crate) async fn set(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
    ApiJson(body): ApiJson<SetBody>,
) -> Result<Json<Value>, ApiError> {
    let org = parse_org(&org)?;
    if body.port == 0 {
        return Err(ApiError::bad_request("port must be 1 to 65535"));
    }
    let loaded = state.loaded.borrow().clone();
    let provider = provider_for(body.scheme)?;
    let adapter = adapter(&loaded, &provider)?;
    let host = plain_host(&body.host)?;
    // The name first (an internal name is refused without a lookup), then
    // every address it resolves to.
    ensure_public(adapter, &host, &[])?;
    let resolved = resolve(&host, body.port).await?;
    ensure_public(adapter, &host, &resolved)?;
    let login = login_of(body.username, body.password)?;
    let entry = InventoryEntry {
        provider,
        subtype: Subtype::Datacenter,
        plan: "customer".to_owned(),
        ip: unit_key(&org),
        host,
        port: body.port,
        region: body.region,
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    };
    // The adapter's own refusal, the one the gateway applies at dial.
    adapter
        .recipe(&UnitSpec::Static {
            entry: &entry,
            credentials: pair(login.as_ref()),
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "the customer adapter refused an upstream");
            ApiError::bad_request("the adapter refuses this upstream")
        })?;
    let set = state
        .db
        .set_customer_upstream(&org, &entry, login.as_ref(), &actor)
        .await?;
    // Every set is validated again: nothing leases the unit until then.
    withdraw(&state, &set.row).await?;
    if let Some(old) = &set.replaced {
        withdraw(&state, old).await?;
    }
    let mut out = unit_json(&set.row, login.is_some());
    out["set_by"] = json!(actor);
    add_policy_warning(&mut out, &loaded, &org, &set.row.entry.provider);
    Ok(Json(out))
}

/// Say so when the org's effective cache policy lists providers and leaves
/// out this upstream's: the org is pinned to its unit, so every tunnel would
/// fail with `no_healthy_ip` although the check passed.
fn add_policy_warning(
    out: &mut Value,
    loaded: &store::loaded::Loaded,
    org: &OrgId,
    provider: &ProviderId,
) {
    let providers = &loaded.policies.effective(org, Some(provider)).providers;
    if !providers.is_empty() && !providers.contains(provider) {
        out["warning"] = json!(format!(
            "the cache policy of this org lists providers without {provider}: \
             tunnels fail with no_healthy_ip until it is added"
        ));
    }
}

/// `GET /v1/orgs/{org}/upstream`. `set_by` is the actor of the latest `PUT`
/// (the operator named in `X-Operator`), so a client can tell its own work
/// from another's after an interrupted run.
pub(crate) async fn get(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let org = parse_org(&org)?;
    let CustomerUnit { row, .. } = live_upstream(&state, &org).await?;
    let has_login = state.db.customer_login(&org).await?.is_some();
    let mut out = unit_json(&row, has_login);
    out["set_by"] = json!(state.db.last_customer_setter(&org).await?);
    Ok(Json(out))
}

/// `DELETE /v1/orgs/{org}/upstream`: retire the unit and delete the login.
/// No new tunnel starts on it; open tunnels end on their own and the warmer
/// forgets the unit when the last one is gone.
pub(crate) async fn clear(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
) -> Result<Json<Value>, ApiError> {
    let org = parse_org(&org)?;
    let row = state.db.clear_customer_upstream(&org, &actor).await?;
    withdraw(&state, &row).await?;
    Ok(Json(json!({
        "org": org,
        "unit": row.entry.ip,
        "state": "retired",
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateBody {
    password: Secret,
    /// Unset: the stored username stays.
    username: Option<Secret>,
}

/// `POST /v1/orgs/{org}/upstream/rotate-secret`: replace the stored login
/// after a check through the upstream with the new one passed.
pub(crate) async fn rotate_secret(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
    ApiJson(body): ApiJson<RotateBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let org = parse_org(&org)?;
    let CustomerUnit { row, version } = live_upstream(&state, &org).await?;
    let username = match body.username {
        Some(username) => username,
        None => state
            .db
            .customer_login(&org)
            .await?
            .map(|l| l.username)
            .ok_or_else(|| ApiError::bad_request("the upstream has no username: send one"))?,
    };
    ensure_login(&username, &body.password)?;
    let login = CustomerLogin {
        username,
        password: body.password,
    };
    let loaded = state.loaded.borrow().clone();
    let adapter = adapter(&loaded, &row.entry.provider)?;
    match probe(&state, adapter, &row.entry, Some(&login)).await {
        Ok(_) => {
            state
                .db
                .rotate_customer_login(&org, version, &login, &actor)
                .await?;
            Ok((StatusCode::OK, Json(json!({ "org": org, "rotated": true }))))
        }
        Err(failure) => rejected(&state, &actor, &org, "customer.rotate", "rotated", failure).await,
    }
}

/// A check through the upstream failed: audit it and answer `422` with
/// `flag: false` and the failure.
async fn rejected(
    state: &ApiState,
    actor: &str,
    org: &OrgId,
    action: &str,
    flag: &str,
    failure: Failure,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let (reason, error) = (failure.code(), failure.message());
    state
        .db
        .audit(
            actor,
            action,
            org.as_str(),
            json!({ "ok": false, "reason": reason }),
        )
        .await?;
    let mut body = json!({ "org": org, "reason": reason, "error": error });
    body[flag] = json!(false);
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(body)))
}

/// `POST /v1/orgs/{org}/upstream/validate`: dial through the upstream with
/// the stored login and run the exit-IP quorum. A pass makes the unit
/// `available` and leasable by its org; a failure changes nothing (`422`).
pub(crate) async fn validate(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    Actor(actor): Actor,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let org = parse_org(&org)?;
    let CustomerUnit { row, version } = live_upstream(&state, &org).await?;
    let login = state.db.customer_login(&org).await?;
    let loaded = state.loaded.borrow().clone();
    let adapter = adapter(&loaded, &row.entry.provider)?;
    match probe(&state, adapter, &row.entry, login.as_ref()).await {
        Ok(exit) => {
            let exit_ip = IpAddr::V4(exit.ip);
            let row = state
                .db
                .customer_validated(&org, version, exit_ip, &actor)
                .await?;
            state
                .hot
                .ready_put(
                    &row.partition(),
                    &UnitRecord {
                        id: row.entry.ip.to_string(),
                        ip: exit_ip,
                        expires_at: None,
                        ttl: None,
                        owner: Some(org.clone()),
                    },
                )
                .await?;
            let mut out = unit_json(&row, login.is_some());
            out["valid"] = json!(true);
            out["country"] = json!(exit.country);
            add_policy_warning(&mut out, &loaded, &org, &row.entry.provider);
            Ok((StatusCode::OK, Json(out)))
        }
        Err(failure) => rejected(&state, &actor, &org, "customer.validate", "valid", failure).await,
    }
}

/// The org's unit and its version, read before a check through the upstream.
/// The write that records the check's result names this version, so a `PUT`
/// or `DELETE` that lands during the check turns the result away (`409`).
async fn live_upstream(state: &ApiState, org: &OrgId) -> Result<CustomerUnit, ApiError> {
    state
        .db
        .customer_upstream(org)
        .await?
        .ok_or_else(|| ApiError::not_found("customer upstream not found"))
}

/// Why a check through an upstream failed. A closed set: it is returned to
/// the operator and written to the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The adapter refuses the upstream (for example a non-public address).
    Refused,
    /// Too few check services answered through the upstream: it is
    /// unreachable, refuses the login, or the services are down.
    Unverified,
    Disagree,
    CountryMismatch,
    Timeout,
    /// The upstream's exit address is private, loopback or link-local.
    PrivateExit,
}

impl Failure {
    fn code(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Unverified => "unverified",
            Self::Disagree => "exit_disagree",
            Self::CountryMismatch => "country_mismatch",
            Self::Timeout => "timeout",
            Self::PrivateExit => "private_exit",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Refused => "the adapter refuses this upstream",
            Self::Unverified => {
                "too few check services answered through the upstream: it is unreachable, \
                 refuses the login, or the check services are down"
            }
            Self::Disagree => "the check services disagree on the exit ip",
            Self::CountryMismatch => "the exit country is not the region of the upstream",
            Self::Timeout => "the check took too long",
            Self::PrivateExit => "the check services report a private exit address",
        }
    }
}

/// Render the endpoint and run the exit-IP quorum through it. The exit IP is
/// whatever the upstream gives, so there is no address to match; the country
/// must be the declared region's.
async fn probe(
    state: &ApiState,
    adapter: &Adapter,
    entry: &InventoryEntry,
    login: Option<&CustomerLogin>,
) -> Result<ExitIp, Failure> {
    let endpoint = adapter
        .recipe(&UnitSpec::Static {
            entry,
            credentials: pair(login),
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "the customer adapter refused an upstream");
            Failure::Refused
        })?;
    let query = ExitQuery {
        region: Some(&entry.region),
        ip: None,
        echo_url: adapter.echo_url(),
    };
    match tokio::time::timeout(VALIDATE_TIMEOUT, state.exit_ip.check(&endpoint, &query)).await {
        Err(_) | Ok(Err(ExitIpError::Timeout)) => Err(Failure::Timeout),
        // An exit no proxy can have; the same adapter rule as the address
        // check at write time (`public_only`), so a lab adapter can opt out.
        Ok(Ok(exit)) if adapter.public_only() && is_unusable_exit(IpAddr::V4(exit.ip)) => {
            Err(Failure::PrivateExit)
        }
        Ok(Ok(exit)) => Ok(exit),
        Ok(Err(ExitIpError::Disagree)) => Err(Failure::Disagree),
        Ok(Err(ExitIpError::CountryMismatch { .. })) => Err(Failure::CountryMismatch),
        Ok(Err(_)) => Err(Failure::Unverified),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_proxy_schemes_round_trip_without_losing_tls() {
        for (scheme, text) in [
            (UpstreamScheme::Http, "http"),
            (UpstreamScheme::Https, "https"),
            (UpstreamScheme::Socks5, "socks5"),
        ] {
            let provider = provider_for(scheme).expect("customer provider");
            assert_eq!(scheme_of(&provider), text);
        }
        assert!(provider_for(UpstreamScheme::Local).is_err());
    }

    #[test]
    fn hosts_are_plain_names_or_addresses() {
        for ok in [
            "proxy.example.com",
            "8.8.8.8",
            "[2001:4860:4860::8888]",
            "A.b-c.d_e",
        ] {
            assert!(plain_host(ok).is_ok(), "{ok}");
        }
        assert_eq!(
            plain_host("[2001:db8::1]").ok().as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            plain_host("Proxy.Example.COM").ok().as_deref(),
            Some("proxy.example.com")
        );
        for bad in [
            "",
            "proxy.example.com:3128",
            "http://proxy.example.com",
            "user@proxy.example.com",
            "proxy.example.com/path",
            "proxy..example.com",
            "proxy.example.com.",
            "pro xy",
            "proxy\r\nHost: x",
            &"a".repeat(64),
        ] {
            assert!(plain_host(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn an_orgs_unit_key_is_stable_distinct_and_never_a_routable_address() {
        let (acme, other): (OrgId, OrgId) =
            ("acme".parse().expect("org"), "other".parse().expect("org"));
        assert_eq!(unit_key(&acme), unit_key(&acme));
        assert_ne!(unit_key(&acme), unit_key(&other));
        let IpAddr::V6(v6) = unit_key(&acme) else {
            panic!("the key is an IPv6 address");
        };
        assert_eq!(v6.octets()[0], 0xfd, "unique-local range");
    }

    #[test]
    fn a_login_is_both_fields_or_neither_and_fits_socks5() {
        let s = |v: &str| Some(Secret::new(v));
        assert!(matches!(login_of(None, None), Ok(None)));
        assert!(matches!(login_of(s("u"), s("p")), Ok(Some(_))));
        assert!(login_of(s("u"), None).is_err());
        assert!(login_of(None, s("p")).is_err());
        assert!(login_of(s(""), s("p")).is_err());
        assert!(login_of(s("u"), s("")).is_err());
        assert!(login_of(s("u"), s(&"p".repeat(255))).is_ok());
        assert!(login_of(s("u"), s(&"p".repeat(256))).is_err());
    }
}
