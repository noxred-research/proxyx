//! HTTP plumbing shared by the REST clients: status to [`Error`] mapping and JSON decoding.

use std::time::Duration;

use reqwest::Response;
use reqwest::header::RETRY_AFTER;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// Longest server message kept in an error.
const MAX_MESSAGE_CHARS: usize = 512;

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

/// Pass a success response through; turn anything else into a typed [`Error`].
pub(crate) async fn check(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let body = response.bytes().await?;
    let message = match serde_json::from_slice::<ErrorBody>(&body) {
        Ok(parsed) => parsed.error,
        Err(_) => String::from_utf8_lossy(&body).into_owned(),
    };
    let message: String = message.chars().take(MAX_MESSAGE_CHARS).collect();
    let code = status.as_u16();
    Err(match code {
        401 | 403 => Error::Auth {
            status: code,
            message,
        },
        404 => Error::NotFound { message },
        409 => Error::Conflict { message },
        500..=599 => Error::Unavailable {
            status: code,
            message,
        },
        _ => Error::Client {
            status: code,
            message,
            retry_after,
        },
    })
}

/// Decode a JSON response body.
pub(crate) async fn json<T: DeserializeOwned>(response: Response) -> Result<T> {
    let body = response.bytes().await?;
    Ok(serde_json::from_slice(&body)?)
}
