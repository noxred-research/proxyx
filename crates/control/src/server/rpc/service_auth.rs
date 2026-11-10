//! Authentication of control-plane API callers.
//!
//! `auth_mode = "keys"` (default): `Authorization: Bearer pxk_...` is checked
//! against the `api_keys` table ([`crate::keys`]). `auth_mode =
//! "trusted_headers"`: `x-proxyx-*` principal headers are trusted, as set by an
//! authenticating gateway in front of the API, and `/rpc/*` additionally needs
//! the `X-Forwarded-For` client inside `internal_allowed_cidrs` (outside dev).

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::{Principal, principal_from_headers};
use crate::config::AuthMode;
use crate::server::AppState;

/// The principal of a request, or the status to answer: 401 for missing or
/// wrong credentials, 503 when the key store cannot be reached.
pub async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Principal, StatusCode> {
    match state.config.auth_mode {
        AuthMode::TrustedHeaders => {
            principal_from_headers(headers).map_err(|_| StatusCode::UNAUTHORIZED)
        }
        AuthMode::Keys => {
            let key = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(crate::keys::bearer)
                .ok_or(StatusCode::UNAUTHORIZED)?;
            match state.keys.authenticate(key).await {
                Ok(Some(principal)) => Ok(principal),
                Ok(None) => Err(StatusCode::UNAUTHORIZED),
                Err(err) => {
                    tracing::warn!(error = %err, "api key lookup failed");
                    Err(StatusCode::SERVICE_UNAVAILABLE)
                }
            }
        }
    }
}

pub async fn require_internal_cidr(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if state.config.auth_mode == AuthMode::TrustedHeaders {
        enforce_cidr(&state, &request)?;
    }
    Ok(next.run(request).await)
}

pub async fn require_service_principal(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match authenticate(&state, request.headers()).await? {
        Principal::Service(service) => {
            request.extensions_mut().insert(service);
            Ok(next.run(request).await)
        }
        Principal::User(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

fn enforce_cidr(state: &AppState, request: &Request) -> Result<(), StatusCode> {
    if state.config.env.eq_ignore_ascii_case("dev") {
        return Ok(());
    }
    let Some(ip) = client_ip(request) else {
        return Err(StatusCode::FORBIDDEN);
    };
    if cidr_allowlist_contains(&state.config.internal_allowed_cidrs, ip) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn client_ip(request: &Request) -> Option<IpAddr> {
    if let Some(forwarded) = request.headers().get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first) = value.split(',').next()
        && let Ok(ip) = IpAddr::from_str(first.trim())
    {
        return Some(ip);
    }
    None
}

fn cidr_allowlist_contains(raw: &str, ip: IpAddr) -> bool {
    raw.split(',')
        .map(str::trim)
        .filter(|cidr| !cidr.is_empty())
        .any(|cidr| cidr_contains(cidr, ip))
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return IpAddr::from_str(cidr)
            .map(|single| single == ip)
            .unwrap_or(false);
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (IpAddr::from_str(network), ip) {
        (Ok(IpAddr::V4(net)), IpAddr::V4(addr)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (Ok(IpAddr::V6(net)), IpAddr::V6(addr)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(addr) & mask)
        }
        _ => false,
    }
}
