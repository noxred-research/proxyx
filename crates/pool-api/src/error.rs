//! Handler errors: a status and a message, answered as `{"error": msg}`.
//!
//! Messages that reach a client describe the client's input. Anything
//! internal (Postgres, Redis, a decode failure) is logged once here and the
//! client gets a generic message.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::json;
use store::StoreError;

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
    /// Seconds for the `Retry-After` header, when the client can retry.
    retry_after: Option<u64>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// The same error with `prefix: ` before its message.
    pub(crate) fn prefixed(mut self, prefix: &str) -> Self {
        self.message = format!("{prefix}: {}", self.message);
        self
    }

    pub(crate) fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }

    /// The same error with a `Retry-After` of `seconds`.
    pub(crate) fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({ "error": self.message }))).into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.into());
        }
        response
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Invalid(reason) => Self::bad_request(reason),
            StoreError::NotFound { what } => Self::not_found(format!("{what} not found")),
            StoreError::Conflict { what } => Self::conflict(format!("{what} already exists")),
            StoreError::InvalidTransition { .. } | StoreError::Stale { .. } => {
                Self::conflict(err.to_string())
            }
            StoreError::Database(_) | StoreError::Redis(_) | StoreError::Migrate(_) => {
                tracing::error!(error = %err, "storage failed");
                Self::unavailable("storage unavailable")
            }
            StoreError::Decode { .. } => {
                tracing::error!(error = %err, "stored value did not decode");
                Self::internal()
            }
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!(error = ?err, "request failed");
        Self::internal()
    }
}

/// Router fallback: an unmatched path answers the documented JSON body.
pub(crate) async fn route_not_found() -> ApiError {
    ApiError::not_found("no such route")
}

/// Router fallback for a matched path with the wrong method (axum adds the
/// `Allow` header).
pub(crate) async fn method_not_allowed() -> ApiError {
    ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// `Path` that answers a bad segment (a non-UTF-8 escape) as `{"error": ...}`
/// instead of plain text.
pub(crate) struct ApiPath<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|rejection| ApiError::new(rejection.status(), rejection.body_text()))
    }
}

/// [`ApiPath`] for the query string.
pub(crate) struct ApiQuery<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|rejection| ApiError::new(rejection.status(), rejection.body_text()))
    }
}

/// The raw body, a rejection (over the limit: `413`) answered as
/// `{"error": ...}`.
pub(crate) struct ApiBytes(pub Bytes);

impl<S: Send + Sync> FromRequest<S> for ApiBytes {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Bytes::from_request(req, state)
            .await
            .map(Self)
            .map_err(|rejection| ApiError::new(rejection.status(), rejection.body_text()))
    }
}

/// `Json` that answers a bad body as `{"error": ...}` instead of plain text.
/// A body over the limit stays `413` and a missing content type `415`; every
/// other fault is `400`. The body must be a JSON object: serde would also fill
/// a struct from an array, which no route documents.
pub(crate) struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        read_json(req, state, ensure_object).await.map(Self)
    }
}

/// [`ApiJson`] for a route whose body is a JSON array.
pub(crate) struct ApiJsonList<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJsonList<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        read_json(req, state, |_| Ok(())).await.map(Self)
    }
}

async fn read_json<S: Send + Sync, T: DeserializeOwned>(
    req: Request,
    state: &S,
    shape: fn(&[u8]) -> Result<(), ApiError>,
) -> Result<T, ApiError> {
    if !json_content_type(req.headers()) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected request with `Content-Type: application/json`",
        ));
    }
    let ApiBytes(body) = ApiBytes::from_request(req, state).await?;
    shape(&body)?;
    match Json::<T>::from_bytes(&body) {
        Ok(Json(value)) => Ok(value),
        Err(rejection) => Err(ApiError::bad_request(rejection.body_text())),
    }
}

/// Refuse a body that is a JSON array. Anything else that is not an object
/// fails to parse into the route's struct with its own message.
pub(crate) fn ensure_object(body: &[u8]) -> Result<(), ApiError> {
    match body.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'[') => Err(ApiError::bad_request("the body must be a JSON object")),
        _ => Ok(()),
    }
}

pub(crate) fn json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .and_then(|v| {
            v.trim()
                .to_ascii_lowercase()
                .strip_prefix("application/")
                .map(|s| s == "json" || s.ends_with("+json"))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_array_is_not_an_object_body() {
        for array in ["[]", "  \n[\"label\"]", "[[\"x\"]]"] {
            assert!(ensure_object(array.as_bytes()).is_err(), "{array:?}");
        }
        for ok in ["{}", " {\"label\":\"a\"}", "", "null", "\"s\""] {
            assert!(ensure_object(ok.as_bytes()).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn only_json_content_types_pass() {
        let with = |ct: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, ct.parse().expect("value"));
            json_content_type(&headers)
        };
        assert!(with("application/json"));
        assert!(with("Application/JSON; charset=utf-8"));
        assert!(with("application/problem+json"));
        assert!(!with("text/plain"));
        assert!(!json_content_type(&HeaderMap::new()));
    }
}
