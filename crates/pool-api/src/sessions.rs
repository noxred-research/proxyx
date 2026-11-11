//! Admin endpoint generation and live sticky-session control.
//!
//! `POST /v1/orgs/{org}/endpoints` takes `gateway_host`, the selected style's
//! `http_port` or `socks5_port`, and optional `count` (1..=10,000), `kind`,
//! `country`, `city`, `provider`, `rotation` (`sticky` or `each`), `ttl`
//! (for example `5m`), `strict`, `style` (`http` or `socks5`) and `format`
//! (`json`, `csv` or `txt`). Sticky rotation, HTTP, JSON and count 1 default.
//! Each sticky endpoint gets a fresh lowercase UUID `sid`. Options use the
//! same parser and policy narrowing as gateway authentication.
//!
//! An optional `org_key` is checked against this org and included only in the
//! returned URLs. Without it URLs have a username but no password; callers
//! supply the password themselves. Neither headers nor stored key hashes are
//! used to reconstruct a password. Responses use `Cache-Control: no-store`.
//!
//! `GET /v1/orgs/{org}/sessions` returns live Redis affinity entries and
//! per-org affinity counters. `DELETE /v1/orgs/{org}/sessions/{sid}` releases
//! the sticky lease and excludes its previous unit for the next acquisition,
//! without closing open tunnels or remapping other orgs. All routes require
//! the admin bearer, share a distributed
//! 60-request/minute/org limit, and audit method outcomes without bodies or
//! credentials, including validation errors and rate-limit refusals.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use common::Secret;
use common::config::humantime_secs;
use common::types::{Kind, ProviderId, Region, Rotation};
use policy::InboundOptions;
use serde::Deserialize;
use serde_json::json;
use store::KeyStatus;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::Actor;
use crate::error::{ApiError, ApiJson, ApiPath as Path};
use crate::state::ApiState;
use crate::wire::{parse_org, plain_host, plain_id};

const REQUESTS_PER_MINUTE: u32 = 60;
const MAX_ENDPOINTS: usize = 10_000;

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Style {
    #[default]
    Http,
    Socks5,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    #[default]
    Json,
    Csv,
    Txt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointsBody {
    gateway_host: String,
    http_port: Option<u16>,
    socks5_port: Option<u16>,
    #[serde(default)]
    style: Style,
    #[serde(default)]
    format: Format,
    #[serde(default = "one")]
    count: usize,
    kind: Option<Kind>,
    country: Option<String>,
    city: Option<String>,
    provider: Option<ProviderId>,
    #[serde(default)]
    rotation: Rotation,
    ttl: Option<String>,
    #[serde(default)]
    strict: bool,
    org_key: Option<Secret>,
}

fn one() -> usize {
    1
}

/// Rate-limit and audit every endpoint/session request without reading its body.
pub(crate) async fn guard(
    State(state): State<Arc<ApiState>>,
    Path(path): Path<HashMap<String, String>>,
    Actor(actor): Actor,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let org = parse_org(path.get("org").map_or("", String::as_str))?;
    let action = match *req.method() {
        Method::POST => "endpoints.generate",
        Method::DELETE => "sessions.rotate",
        _ => "sessions.list",
    };
    let limited = state
        .hot
        .org_api_rate_limit(&org, REQUESTS_PER_MINUTE, Duration::from_secs(60))
        .await;
    let mut response = match limited {
        Ok(0) => next.run(req).await,
        Ok(seconds) => ApiError::new(StatusCode::TOO_MANY_REQUESTS, "org API rate limit exceeded")
            .retry_after(seconds)
            .into_response(),
        Err(error) => ApiError::from(error).into_response(),
    };
    state
        .db
        .audit(
            &actor,
            action,
            org.as_str(),
            json!({"status":response.status().as_u16()}),
        )
        .await?;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

struct Generator {
    authority: String,
    prefix: String,
    scheme: &'static str,
    sticky: bool,
}

impl Generator {
    fn new(body: &EndpointsBody) -> Result<Self, ApiError> {
        if !(1..=MAX_ENDPOINTS).contains(&body.count) {
            return Err(ApiError::bad_request("count must be between 1 and 10000"));
        }
        let host = plain_host(&body.gateway_host)?;
        if host.parse::<IpAddr>().is_ok_and(|ip| ip.is_unspecified()) {
            return Err(ApiError::bad_request(
                "gateway_host must not be an unspecified address",
            ));
        }
        let (scheme, port) = match body.style {
            Style::Http => ("http", body.http_port),
            Style::Socks5 => ("socks5", body.socks5_port),
        };
        let port = port
            .filter(|p| *p != 0)
            .ok_or_else(|| ApiError::bad_request("selected style requires a port above zero"))?;
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut prefix = String::with_capacity(policy::MAX_USERNAME_LEN);
        prefix.push_str("px");
        if let Some(kind) = body.kind {
            let _ = write!(prefix, "-kind-{kind}");
        }
        match (&body.country, &body.city) {
            (Some(country), city) => {
                let region = Region::new(country, city.as_deref())
                    .map_err(|error| ApiError::bad_request(error.to_string()))?;
                let _ = write!(prefix, "-cc-{}", region.country());
                if let Some(city) = region.city() {
                    let _ = write!(prefix, "-city-{city}");
                }
            }
            (None, Some(_)) => return Err(ApiError::bad_request("city requires country")),
            (None, None) => {}
        }
        if let Some(provider) = &body.provider {
            let _ = write!(prefix, "-prov-{provider}");
        }
        if let Some(ttl) = &body.ttl {
            let ttl = humantime_secs::parse(ttl).map_err(ApiError::bad_request)?;
            if ttl.is_zero() {
                return Err(ApiError::bad_request("ttl must be above zero"));
            }
            let _ = write!(prefix, "-ttl-{}s", ttl.as_secs());
        }
        let sticky = body.rotation == Rotation::Sticky;
        prefix.push_str(if sticky { "-rot-sticky" } else { "-rot-each" });
        if body.strict {
            prefix.push_str("-strict-true");
        }
        let generator = Self {
            authority,
            prefix,
            scheme,
            sticky,
        };
        // Include a full-length sid in validation, not just the common prefix.
        InboundOptions::parse(&generator.username(Some("00000000000000000000000000000000")))
            .map_err(|_| ApiError::bad_request("options exceed the gateway username contract"))?;
        Ok(generator)
    }

    fn username(&self, sid: Option<&str>) -> String {
        let mut username =
            String::with_capacity(self.prefix.len() + if self.sticky { 37 } else { 0 });
        username.push_str(&self.prefix);
        if self.sticky {
            username.push_str("-sid-");
            username.push_str(sid.unwrap_or(""));
        }
        username
    }

    fn url(&self, username: &str, encoded_key: Option<&str>) -> String {
        let mut url = String::with_capacity(
            self.scheme.len()
                + 4
                + self.authority.len()
                + username.len()
                + encoded_key.map_or(0, |key| key.len() + 1),
        );
        url.push_str(self.scheme);
        url.push_str("://");
        url.push_str(username);
        if let Some(key) = encoded_key {
            url.push(':');
            url.push_str(key);
        }
        url.push('@');
        url.push_str(&self.authority);
        url
    }
}

/// RFC 3986 userinfo encoding: separators in keys cannot alter the URL.
fn encode_userinfo(out: &mut String, secret: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in secret.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
}

pub(crate) async fn generate(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
    ApiJson(body): ApiJson<EndpointsBody>,
) -> Result<Response, ApiError> {
    let org = parse_org(&org)?;
    let generator = Generator::new(&body)?;
    let username = generator.username(Some("00000000000000000000000000000000"));
    let options = InboundOptions::parse(&username)
        .map_err(|_| ApiError::bad_request("invalid gateway options"))?;
    {
        let loaded = state.loaded.borrow();
        loaded
            .policies
            .effective(&org, body.provider.as_ref())
            .narrow(&options)
            .map_err(|_| ApiError::forbidden("options are not allowed by the org policy"))?;
        if let Some(provider) = &body.provider {
            let adapter = loaded
                .adapters
                .get(provider)
                .ok_or_else(|| ApiError::bad_request("unknown provider"))?;
            if body.kind.is_some_and(|kind| adapter.kind() != kind) {
                return Err(ApiError::bad_request(
                    "provider does not support the selected kind",
                ));
            }
        }
    }
    if let Some(key) = &body.org_key {
        if key.is_empty() || key.expose().len() > 4096 {
            return Err(ApiError::bad_request(
                "org_key must contain 1 to 4096 bytes",
            ));
        }
        if !matches!(state.db.verify_org_key(key.expose()).await?, KeyStatus::Enabled(owner) if owner == org)
        {
            return Err(ApiError::forbidden("org_key does not belong to this org"));
        }
    }
    // Encode the explicit credential once, not once per exported URL.
    let encoded_key = body.org_key.as_ref().map(|key| {
        let mut encoded = String::with_capacity(key.expose().len().saturating_mul(3));
        encode_userinfo(&mut encoded, key.expose());
        encoded
    });
    let is_json = matches!(body.format, Format::Json);
    let mut endpoints = Vec::with_capacity(if is_json { body.count } else { 0 });
    let line_capacity = generator.prefix.len() * 2
        + generator.authority.len()
        + encoded_key.as_ref().map_or(0, String::len)
        + 100;
    let mut text = String::with_capacity(if is_json {
        0
    } else {
        line_capacity * body.count
    });
    if matches!(body.format, Format::Csv) {
        text.push_str("sid,username,url\r\n");
    }
    for _ in 0..body.count {
        let sid = generator
            .sticky
            .then(|| Uuid::new_v4().simple().to_string());
        let username = generator.username(sid.as_deref());
        let url = generator.url(&username, encoded_key.as_deref());
        match body.format {
            Format::Json => endpoints.push(json!({"sid":sid, "username":username, "url":url})),
            Format::Csv => {
                // All fields consist of slugs and percent-encoded userinfo.
                let _ = write!(
                    text,
                    "{},{username},{url}\r\n",
                    sid.as_deref().unwrap_or("")
                );
            }
            Format::Txt => {
                text.push_str(&url);
                text.push('\n');
            }
        }
    }
    Ok(match body.format {
        Format::Json => (
            StatusCode::CREATED,
            Json(json!({"org":org, "count":body.count, "endpoints":endpoints})),
        )
            .into_response(),
        Format::Csv => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
            text,
        )
            .into_response(),
        Format::Txt => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            text,
        )
            .into_response(),
    })
}

pub(crate) async fn list(
    State(state): State<Arc<ApiState>>,
    Path(org): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let org = parse_org(&org)?;
    let records = state.hot.affinity_sessions(&org).await?;
    let affinity = state.hot.affinity_stats(&org).await?;
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let sessions: Vec<_> = records.into_iter().map(|record| {
        json!({
            "sid":record.sticky.strip_prefix("sid:").unwrap_or(&record.sticky),
            "provider":record.partition.provider, "region":record.partition.region,
            "exit_ip":record.ip, "age_seconds":((now - i128::from(record.created_at_ms)).max(0) / 1000),
            "bytes":record.bytes,
        })
    }).collect();
    Ok(Json(
        json!({"org":org,"sessions":sessions,"affinity":affinity}),
    ))
}

pub(crate) async fn rotate(
    State(state): State<Arc<ApiState>>,
    Path((org, sid)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let org = parse_org(&org)?;
    if !plain_id(&sid) {
        return Err(ApiError::bad_request("invalid sid"));
    }
    if !state
        .hot
        .affinity_rotate(&org, &store::sid_sticky(&sid))
        .await?
    {
        return Err(ApiError::not_found("no live session with this sid"));
    }
    Ok(Json(json!({"org":org,"sid":sid,"rotated":true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(extra: serde_json::Value) -> EndpointsBody {
        let mut value = json!({"gateway_host":"proxy.example", "http_port":8080});
        value
            .as_object_mut()
            .expect("base object")
            .extend(extra.as_object().expect("extra object").clone());
        serde_json::from_value(value).expect("endpoint request")
    }

    #[test]
    fn sticky_options_round_trip_with_unique_uuid_ids() {
        let body = body(json!({"kind":"rotating","country":"US","city":"New_York",
            "provider":"webshare","rotation":"sticky","ttl":"5m","strict":true}));
        let generator = Generator::new(&body).expect("generator");
        let sid = Uuid::new_v4().simple().to_string();
        let username = generator.username(Some(&sid));
        let options = InboundOptions::parse(&username).expect("generated username");
        assert_eq!(options.sid.as_deref(), Some(sid.as_str()));
        assert_eq!(options.region.expect("region").to_string(), "us/new_york");
        assert_eq!(options.ttl, Some(Duration::from_secs(300)));
        assert!(username.contains("-strict-true"));
    }

    #[test]
    fn each_rotation_omits_sid_and_key_without_explicit_body_key() {
        let generator = Generator::new(&body(json!({"rotation":"each"}))).expect("generator");
        let username = generator.username(None);
        assert!(!username.contains("-sid-"));
        assert_eq!(
            generator.url(&username, None),
            "http://px-rot-each@proxy.example:8080"
        );
    }

    #[test]
    fn credentials_are_encoded_and_ipv6_authority_is_bracketed() {
        let generator = Generator::new(&body(json!({"gateway_host":"2001:db8::1",
            "style":"socks5", "socks5_port":1080})))
        .expect("IPv6 generator");
        let mut encoded = String::new();
        encode_userinfo(&mut encoded, "a:@/,%\"\r\n");
        assert_eq!(
            generator.url("px", Some(&encoded)),
            "socks5://px:a%3A%40%2F%2C%25%22%0D%0A@[2001:db8::1]:1080"
        );
    }

    #[test]
    fn invalid_counts_hosts_ports_and_option_combinations_are_rejected() {
        for extra in [
            json!({"count":0}),
            json!({"count":10001}),
            json!({"gateway_host":"user@proxy.example"}),
            json!({"gateway_host":"0.0.0.0"}),
            json!({"http_port":0}),
            json!({"style":"socks5"}),
            json!({"city":"paris"}),
            json!({"ttl":"0s"}),
            json!({"provider":"not-encodable"}),
        ] {
            assert!(Generator::new(&body(extra)).is_err());
        }
        assert!(Generator::new(&body(json!({"count":10000}))).is_ok());
    }
}
