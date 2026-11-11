//! The SIM box reset call (`rotate_ip`): one configurable HTTP
//! request per box.

use std::time::Duration;

use common::Secret;
use common::types::ProviderId;
use reqwest::{Method, StatusCode, redirect};

use crate::adapter::{Adapter, read_secret};
use crate::config::{HttpMethod, RotateConfig};
use crate::error::ProviderError;

/// A checked reset call.
#[derive(Debug, Clone)]
pub(crate) struct RotateCall {
    method: Method,
    url: String,
    body: Option<String>,
    bearer: Option<Secret>,
    timeout: Duration,
}

impl RotateCall {
    pub(crate) fn build(
        id: &ProviderId,
        cfg: RotateConfig,
        secrets: &impl Fn(&str) -> anyhow::Result<Secret>,
    ) -> Result<Self, ProviderError> {
        let fail = |reason: String| ProviderError::Config {
            id: id.clone(),
            reason: format!("rotate: {reason}"),
        };
        // `{handle}` may only appear after the authority, so a handle can
        // never steer the call to another host.
        if let Some((_, rest)) = cfg.url.split_once("://")
            && rest
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains(['{', '}']))
        {
            return Err(fail("`{handle}` cannot be in the host".to_owned()));
        }
        check_http_url(&cfg.url.replace("{handle}", "x")).map_err(|e| fail(format!("url: {e}")))?;
        if cfg.timeout.is_zero() {
            return Err(fail("timeout must be above 0".to_owned()));
        }
        let bearer = cfg
            .bearer_file
            .as_deref()
            .map(|n| read_secret(id, n, secrets))
            .transpose()?;
        Ok(Self {
            method: match cfg.method {
                HttpMethod::Get => Method::GET,
                HttpMethod::Post => Method::POST,
                HttpMethod::Put => Method::PUT,
            },
            url: cfg.url,
            body: cfg.body,
            bearer,
            timeout: cfg.timeout,
        })
    }
}

/// An `http` or `https` URL with a host and no stray braces.
pub(crate) fn check_http_url(url: &str) -> Result<(), String> {
    if url.contains(['{', '}']) {
        return Err("holds a brace".to_owned());
    }
    let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("must be an http or https URL with a host".to_owned());
    }
    Ok(())
}

/// Resets a SIM box through the adapter's HTTP call.
#[derive(Debug, Clone)]
pub struct MobileBoxClient {
    http: reqwest::Client,
}

impl MobileBoxClient {
    /// A client that ignores environment proxies and never follows redirects.
    pub fn new() -> Result<Self, ProviderError> {
        // The call goes where the adapter file says, never through an env proxy.
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|e| ProviderError::Client(e.to_string()))?;
        Ok(Self { http })
    }

    /// Send the adapter's reset call for one box. `{handle}` in the URL and
    /// body becomes `handle`, which must be `[A-Za-z0-9_-]{1,64}` (refused,
    /// never escaped; no request is sent). A `2xx` answer is success; whether
    /// the exit IP changed is for the caller to check.
    pub async fn rotate(&self, adapter: &Adapter, handle: &str) -> Result<(), ProviderError> {
        let call = adapter
            .rotate
            .as_ref()
            .ok_or_else(|| ProviderError::NoRotate(adapter.id().clone()))?;
        if handle.is_empty()
            || handle.len() > 64
            || !handle
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(ProviderError::BadHandle);
        }
        let mut req = self
            .http
            .request(call.method.clone(), call.url.replace("{handle}", handle))
            .timeout(call.timeout);
        if let Some(token) = &call.bearer {
            req = req.bearer_auth(token.expose());
        }
        if let Some(body) = &call.body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.replace("{handle}", handle));
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) if resp.status() == StatusCode::TOO_MANY_REQUESTS => {
                Err(ProviderError::RotateRateLimited)
            }
            Ok(resp) => Err(ProviderError::RotateStatus(resp.status().as_u16())),
            Err(e) if e.is_timeout() => Err(ProviderError::RotateTimeout),
            Err(e) => Err(ProviderError::RotateTransport(e.without_url().to_string())),
        }
    }
}
