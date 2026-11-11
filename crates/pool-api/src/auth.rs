//! The three credentials of the control API.
//!
//! * Admin bearer token: every operator route.
//! * Prober bearer token (a separate secret): `/v1/probe/*`.
//! * Org key as the HTTP Basic password: `/v1/block-signals` ([`OrgAuth`]).
//!   The username may carry inbound options (`px-kind-static`), so only the
//!   password authenticates.
//!
//! **Brute-force limit**. Wrong credentials are counted per
//! source (an IPv4 address, an IPv6 /64) in a fixed 60 s window of the pod's
//! memory, like the tunnel listeners'. A source with 20 failures is answered
//! `429` without a credential check for an org key (so it cannot use
//! `/v1/block-signals` as a Postgres-backed key oracle), and `429` instead of
//! `401` for a wrong bearer token. A correct bearer token always passes: its
//! check is in memory and a locked-out operator would help nobody. The `429`
//! carries `Retry-After`: the seconds left in the source's window. Refusals
//! count in `auth_failures_total` (`unknown_key`, `source_limited`). The
//! count is per pod: another pod, or a restart, starts from zero.
//!
//! An org key is checked against Postgres, and a burst of wrong keys sent at
//! once would all pass a check that only counts a failure after its lookup.
//! So the lookups of one source take turns, one at a time, and the limit is
//! read when a lookup's turn comes: a burst gets exactly the limit's worth of
//! lookups, and a burst of right keys (a session proxy pod posting many signals)
//! waits its turn instead of being refused.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::types::OrgId;
use common::{Cause, Secret};
use sha2::{Digest, Sha256};
use store::KeyStatus;

use crate::error::ApiError;
use crate::state::ApiState;

/// Failures a source may cause per window before it is refused.
const FAILURES_PER_WINDOW: u32 = 20;
/// Fixed window of the per-source count, from the first failure.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Sources counted at once. A full table forgets expired sources first; a
/// source that still finds it full is not counted (the limiter never grows).
const MAX_SOURCES: usize = 10_000;

/// Failed credentials per source, in memory.
pub(crate) struct FailureLimiter {
    limit: u32,
    sources: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    /// Per source: the lookup of an org key that is running ([`Self::turn`]).
    turns: Mutex<HashMap<IpAddr, Arc<tokio::sync::Mutex<()>>>>,
}

impl Default for FailureLimiter {
    fn default() -> Self {
        Self::new(FAILURES_PER_WINDOW)
    }
}

impl FailureLimiter {
    pub(crate) fn new(limit: u32) -> Self {
        Self {
            limit,
            sources: Mutex::default(),
            turns: Mutex::default(),
        }
    }

    /// A source is its IPv4 address or its IPv6 /64.
    fn source_key(addr: IpAddr) -> IpAddr {
        match addr.to_canonical() {
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(octets.into())
            }
            v4 => v4,
        }
    }

    fn limited(&self, source: IpAddr) -> bool {
        self.retry_after(source).is_some()
    }

    /// Whole seconds (at least 1) until a limited source's window ends, or
    /// `None` when the source is not limited.
    fn retry_after(&self, source: IpAddr) -> Option<u64> {
        let sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let &(start, count) = sources.get(&Self::source_key(source))?;
        let left = FAILURE_WINDOW.checked_sub(start.elapsed())?;
        (count >= self.limit).then(|| left.as_secs_f64().ceil().max(1.0) as u64)
    }

    fn charge(&self, source: IpAddr) {
        let key = Self::source_key(source);
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if sources.len() >= MAX_SOURCES && !sources.contains_key(&key) {
            sources.retain(|_, (start, _)| start.elapsed() < FAILURE_WINDOW);
            if sources.len() >= MAX_SOURCES {
                return;
            }
        }
        let entry = sources.entry(key).or_insert_with(|| (Instant::now(), 0));
        if entry.0.elapsed() >= FAILURE_WINDOW {
            *entry = (Instant::now(), 0);
        }
        entry.1 = entry.1.saturating_add(1);
    }

    /// The turn of `source`: whoever holds this mutex is the one org key
    /// lookup the source has running. A full table forgets the turns nobody
    /// holds or waits for; a source that still finds it full gets a turn of
    /// its own (no queueing), so the table never grows past [`MAX_SOURCES`].
    fn turn(&self, source: IpAddr) -> Arc<tokio::sync::Mutex<()>> {
        let key = Self::source_key(source);
        let mut turns = self.turns.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(turn) = turns.get(&key) {
            return Arc::clone(turn);
        }
        if turns.len() >= MAX_SOURCES {
            turns.retain(|_, turn| Arc::strong_count(turn) > 1);
            if turns.len() >= MAX_SOURCES {
                return Arc::default();
            }
        }
        Arc::clone(turns.entry(key).or_default())
    }
}

/// The peer address of a request, when the server records it.
fn peer(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

impl ApiState {
    /// Count a wrong credential of `source` and give the error it is
    /// answered with.
    fn refuse(&self, source: Option<IpAddr>) -> ApiError {
        let retry_after = source.and_then(|s| self.failures.retry_after(s));
        let reason = if retry_after.is_some() {
            "source_limited"
        } else {
            "unknown_key"
        };
        self.metrics
            .auth_failures_total
            .with_label_values(&[reason])
            .inc();
        if let Some(seconds) = retry_after {
            return ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed attempts from this source, retry later",
            )
            .retry_after(seconds);
        }
        if let Some(source) = source {
            self.failures.charge(source);
        }
        ApiError::unauthorized()
    }
}

/// Compare in constant time: both sides are hashed to the same length first,
/// so neither the content nor the length of the expected token leaks.
pub(crate) fn token_matches(given: &str, expected: &Secret) -> bool {
    let a = Sha256::digest(given.as_bytes());
    let b = Sha256::digest(expected.expose().as_bytes());
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn authorization(headers: &HeaderMap) -> Option<(&str, &str)> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')
        .map(|(scheme, rest)| (scheme, rest.trim()))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    authorization(headers)
        .and_then(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer").then_some(token))
}

/// The Basic password: everything after the first `:` of the decoded
/// credentials.
fn basic_password(headers: &HeaderMap) -> Option<Secret> {
    let (scheme, encoded) = authorization(headers)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (_, password) = decoded.split_once(':')?;
    (!password.is_empty()).then(|| Secret::new(password))
}

/// Middleware: the request must carry the admin token.
pub(crate) async fn require_admin(
    State(state): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    match bearer(req.headers()) {
        Some(token) if token_matches(token, &state.admin_token) => Ok(next.run(req).await),
        _ => Err(state.refuse(peer(req.extensions()))),
    }
}

/// Middleware: the request must carry the prober token.
pub(crate) async fn require_prober(
    State(state): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    match bearer(req.headers()) {
        Some(token) if token_matches(token, &state.prober_token) => Ok(next.run(req).await),
        _ => Err(state.refuse(peer(req.extensions()))),
    }
}

/// `POST /v1/probe/token`: a signed password for the probe listener, valid
/// [`common::probe_token::TOKEN_TTL`]. The prober puts it in
/// its browsers' proxy settings instead of a static key, which the browser
/// pool would copy into a BrowserInstance object that many workloads can read.
pub(crate) async fn probe_token(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let secret = state
        .probe_secret
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("no probe secret is configured"))?;
    let token = common::probe_token::issue(secret, std::time::SystemTime::now());
    Ok(Json(serde_json::json!({
        "token": token.expose(),
        "expires_in_s": common::probe_token::TOKEN_TTL.as_secs(),
    })))
}

async fn org_of_key(
    state: &ApiState,
    source: Option<IpAddr>,
    key: &str,
) -> Result<OrgId, ApiError> {
    // The lookups of one source take turns, and the limit is read when the
    // turn comes: a burst of wrong keys gets exactly the limit's worth of
    // Postgres lookups, a burst of right ones just waits.
    let _turn = match source {
        Some(source) => Some(state.failures.turn(source).lock_owned().await),
        None => None,
    };
    if source.is_some_and(|s| state.failures.limited(s)) {
        return Err(state.refuse(source));
    }
    match state.db.verify_org_key(key).await? {
        KeyStatus::Enabled(org) => Ok(org),
        KeyStatus::Disabled => Err(ApiError::forbidden(Cause::OrgDisabled.code())),
        KeyStatus::Unknown => Err(state.refuse(source)),
    }
}

/// The org that owns the org key in the Basic password.
pub(crate) struct OrgAuth(pub OrgId);

impl FromRequestParts<Arc<ApiState>> for OrgAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ApiState>,
    ) -> Result<Self, ApiError> {
        let source = peer(&parts.extensions);
        let key = basic_password(&parts.headers).ok_or_else(ApiError::unauthorized)?;
        org_of_key(state, source, key.expose()).await.map(Self)
    }
}

/// Who an operator route acts for in the audit trail: the optional
/// `X-Operator` header (a short slug, email-like characters allowed), else
/// `admin`. The admin token is shared, so this names the person, it does not
/// authenticate them.
pub(crate) struct Actor(pub String);

impl<S: Send + Sync> FromRequestParts<S> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        let Some(value) = parts.headers.get("x-operator") else {
            return Ok(Self("admin".to_owned()));
        };
        let name = value
            .to_str()
            .ok()
            .filter(|n| {
                !n.is_empty()
                    && n.len() <= 64
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            })
            .ok_or_else(|| {
                ApiError::bad_request("x-operator must be 1 to 64 of [A-Za-z0-9-_.@]")
            })?;
        Ok(Self(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_match_only_when_equal() {
        let expected = Secret::new("s3cret");
        assert!(token_matches("s3cret", &expected));
        for wrong in ["", "s3cre", "s3crets", "S3CRET"] {
            assert!(!token_matches(wrong, &expected), "{wrong:?}");
        }
    }

    #[test]
    fn basic_password_ignores_the_username_and_keeps_colons() {
        let mut h = HeaderMap::new();
        let creds = STANDARD.encode("px-kind-static-cc-fr:key:with:colons");
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {creds}").parse().expect("header"),
        );
        assert_eq!(basic_password(&h), Some(Secret::new("key:with:colons")));

        h.insert(header::AUTHORIZATION, "Bearer abc".parse().expect("header"));
        assert_eq!(basic_password(&h), None);
        assert_eq!(bearer(&h), Some("abc"));

        let empty = STANDARD.encode("user:");
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {empty}").parse().expect("header"),
        );
        assert_eq!(basic_password(&h), None, "an empty key never authenticates");
    }

    #[test]
    fn a_source_is_limited_after_twenty_failures_and_an_ipv6_source_is_its_64() {
        let limiter = FailureLimiter::default();
        let a: IpAddr = "2001:db8:1:2::1".parse().expect("ip");
        let same_64: IpAddr = "2001:db8:1:2:ffff::9".parse().expect("ip");
        let other: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        for _ in 0..FAILURES_PER_WINDOW - 1 {
            limiter.charge(a);
        }
        assert!(limiter.retry_after(a).is_none());
        limiter.charge(same_64);
        assert!(limiter.retry_after(a).is_some());
        assert!(limiter.retry_after(other).is_none());
    }

    /// The lookups of one source take turns, so the limit is
    /// read after the failures before it were counted; another source does
    /// not wait.
    #[tokio::test]
    async fn the_lookups_of_a_source_take_turns_and_other_sources_do_not_wait() {
        let limiter = FailureLimiter::default();
        let a: IpAddr = "192.0.2.7".parse().expect("ip");
        let b: IpAddr = "192.0.2.8".parse().expect("ip");
        let first = limiter.turn(a).lock_owned().await;
        let second = tokio::spawn({
            let turn = limiter.turn(a);
            async move { drop(turn.lock_owned().await) }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!second.is_finished(), "the second lookup waits");
        drop(limiter.turn(b).lock_owned().await);
        drop(first);
        second.await.expect("the second lookup got its turn");
    }

    #[test]
    fn a_full_turn_table_forgets_idle_sources_and_never_grows() {
        let limiter = FailureLimiter::default();
        let busy: IpAddr = "192.0.2.1".parse().expect("ip");
        let held = limiter.turn(busy);
        for i in 0..MAX_SOURCES as u32 {
            limiter.turn(IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]));
        }
        let turns = limiter.turns.lock().expect("lock");
        assert!(turns.len() <= MAX_SOURCES, "{}", turns.len());
        assert!(turns.contains_key(&busy), "a turn somebody holds is kept");
        drop(held);
    }
}
