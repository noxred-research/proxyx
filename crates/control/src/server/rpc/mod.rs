use std::sync::Arc;
pub mod service_auth;

use crate::db::Db;
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::auth::ServicePrincipal;
use crate::capture_store::StoreError;
use crate::policy::{require_service_org, resolve_service_org};
use crate::query::TrafficQuery;
use crate::query::ws::{WsQueryBranch, WsTrafficQuery};
use crate::query::{NonEmpty, SortField, SortOrder};

#[derive(Debug, Clone, Deserialize)]
struct RpcTrafficQuery {
    org_id: Option<String>,
    branches: NonEmpty<crate::query::QueryBranch>,
    cursor: Option<String>,
    end_cursor: Option<String>,
    limit: Option<u32>,
    #[serde(default)]
    order: SortOrder,
    request_body_max_fetch_size: Option<u32>,
    response_body_max_fetch_size: Option<u32>,
}

impl RpcTrafficQuery {
    fn into_scoped(self, principal: &ServicePrincipal) -> Result<TrafficQuery, AppError> {
        let org_id = resolve_service_org(principal, self.org_id)
            .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
        Ok(TrafficQuery {
            org_id: Some(org_id),
            branches: self.branches,
            cursor: self.cursor,
            end_cursor: self.end_cursor,
            limit: self.limit,
            order: self.order,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: self.request_body_max_fetch_size,
            response_body_max_fetch_size: self.response_body_max_fetch_size,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcWsTrafficQuery {
    org_id: Option<String>,
    branches: NonEmpty<WsQueryBranch>,
    cursor: Option<String>,
    limit: Option<u32>,
    #[serde(default)]
    order: SortOrder,
    payload_max_fetch_size: Option<u32>,
}

impl RpcWsTrafficQuery {
    fn into_scoped(self, principal: &ServicePrincipal) -> Result<WsTrafficQuery, AppError> {
        let org_id = resolve_service_org(principal, self.org_id)
            .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
        Ok(WsTrafficQuery {
            org_id: Some(org_id),
            branches: self.branches,
            cursor: self.cursor,
            limit: self.limit,
            order: self.order,
            payload_max_fetch_size: self.payload_max_fetch_size,
        })
    }
}
use crate::session::{
    InsecureUpstreamTlsConflict, OrgRow, SessionManager, UpstreamOverridesConflict,
    replicate_ratelimit,
};
use common::types::{
    CreateSessionRequest, EgressProxy, Org, ProxyType, RateLimitSettings, SessionConfig,
};

pub struct AppState {
    pub config: crate::config::ControlConfig,
    pub session_manager: Arc<SessionManager>,
    pub redis: redis::aio::ConnectionManager,
    pub ca_cert_pem: String,
    pub db: Db,
    pub capture_store: Arc<dyn crate::capture_store::CaptureStore>,
    /// The captures-log producer, for `/health/broker`.
    pub broker_producer: Arc<dyn common::log::CaptureLogProducer>,
    pub default_rate_limit_rpm: u32,
    pub default_rate_limit_burst: u32,
    pub view_store: Arc<crate::view_store::ViewStore>,
    /// API keys of `auth_mode = "keys"`.
    pub keys: crate::keys::KeyStore,
}

#[derive(Deserialize)]
struct ExtendRequest {
    additional_secs: Option<u32>,
    new_ttl_secs: Option<u32>,
}

#[derive(Deserialize)]
struct CreateOrgRequest {
    org_id: String,
    rate_limit_rpm: Option<u32>,
    rate_limit_burst: Option<u32>,
}

#[derive(Deserialize)]
struct SetRateLimitRequest {
    requests_per_minute: Option<u32>,
    burst: Option<u32>,
}

#[derive(Deserialize)]
struct SetProxyRequest {
    proxy_type: String,
    address: String,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: msg.into(),
        }
    }

    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }

    fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.into(),
        }
    }

    fn not_implemented(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            message: msg.into(),
        }
    }

    fn internal(err: impl Into<anyhow::Error>) -> Self {
        let err = err.into();
        match err.downcast_ref::<StoreError>() {
            Some(StoreError::Rejected(msg)) => return Self::bad_request(msg.clone()),
            Some(StoreError::Unsupported(msg)) => return Self::not_implemented(msg.clone()),
            None => {}
        }
        tracing::error!(error = ?err, "internal API error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::internal(err.into())
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sessions", post(create_session))
        .route(
            "/sessions/{session_id}",
            get(get_session)
                .delete(delete_session)
                .patch(extend_session),
        )
        .route("/requests/search", post(search_traffic))
        .route("/requests/count", post(count_traffic))
        .route("/orgs/{org_id}/requests/{id}", get(get_capture))
        .route("/ws/search", post(search_ws_traffic))
        .route("/ws/count", post(count_ws_traffic))
        .route("/orgs/{org_id}/ws-messages/{id}", get(get_ws_capture))
        .route(
            "/orgs/{org_id}/captures/{parent_event_id}/ws-messages",
            get(get_conversation_ws),
        )
        .route("/sequence", get(get_sequence))
        .route("/sessions/{session_id}/status", get(get_session_status))
        .route("/processed", get(get_processed))
        .route("/orgs/{org_id}/rate-limit-state", get(get_rate_limit_state))
        .route("/orgs", get(list_orgs).post(create_org))
        .route("/orgs/{org_id}", get(get_org).delete(delete_org))
        .route(
            "/orgs/{org_id}/rate-limit",
            get(get_rate_limit).put(set_rate_limit),
        )
        .route(
            "/orgs/{org_id}/proxy",
            get(get_proxy).put(set_proxy).delete(delete_proxy),
        )
        .route("/certificate", get(certificate))
        .route("/views", post(create_view))
        .route("/views/{view_id}", get(get_view))
        .with_state(state)
}

pub async fn serve(
    addr: std::net::SocketAddr,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "API server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;
    Ok(())
}

#[tracing::instrument(
    name = "proxyx.session.create",
    skip_all,
    fields(
        org_id = %req.org_id,
        source = %req.source,
        source_id = %req.source_id,
        session_id = tracing::field::Empty,
        attached = tracing::field::Empty,
    ),
)]
async fn create_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<common::types::CreateSessionResponse>), AppError> {
    if req.source_id.trim().is_empty() {
        return Err(AppError::bad_request(
            "source_id is required and must be non-empty",
        ));
    }
    if req.org_id.trim().is_empty() {
        return Err(AppError::bad_request(
            "org_id is required and must be non-empty",
        ));
    }
    for (logical_authority, destination) in &req.upstream_overrides {
        common::types::parse_upstream_override(logical_authority, destination).map_err(
            |error| {
                AppError::bad_request(format!(
                    "invalid upstream_overrides entry {logical_authority:?}: {error}"
                ))
            },
        )?;
    }
    require_service_org(&principal, &req.org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let response = state.session_manager.create(req).await.map_err(|e| {
        if e.downcast_ref::<UpstreamOverridesConflict>().is_some()
            || e.downcast_ref::<InsecureUpstreamTlsConflict>().is_some()
        {
            return AppError::conflict(e.to_string());
        }
        tracing::error!(error = %e, "session creation failed");
        AppError::internal(e)
    })?;
    let span = tracing::Span::current();
    span.record("session_id", tracing::field::display(response.session_id));
    span.record("attached", response.attached);
    Ok((StatusCode::CREATED, Json(response)))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionConfig>, AppError> {
    let session_id = session_id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid session ID"))?;

    let session = state
        .session_manager
        .get(session_id)
        .await?
        .ok_or_else(|| AppError::not_found("Session not found"))?;
    require_service_org(&principal, &session.org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;

    let mut session = session;
    session.egress_proxy = session.egress_proxy.map(EgressProxy::redacted);
    Ok(Json(session))
}

#[tracing::instrument(name = "proxyx.session.delete", skip_all, fields(session_id = %session_id))]
async fn delete_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let session_id = session_id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid session ID"))?;
    if let Some(session) = state.session_manager.get(session_id).await? {
        require_service_org(&principal, &session.org_id)
            .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    }

    let existed = state.session_manager.delete(session_id).await?;
    if existed {
        Ok(StatusCode::OK)
    } else {
        Err(AppError::not_found("Session not found"))
    }
}

#[tracing::instrument(name = "proxyx.session.extend", skip_all, fields(session_id = %session_id))]
async fn extend_session(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(session_id): Path<String>,
    Json(req): Json<ExtendRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_id = session_id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid session ID"))?;
    if let Some(session) = state.session_manager.get(session_id).await? {
        require_service_org(&principal, &session.org_id)
            .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    }

    if req.additional_secs.is_none() && req.new_ttl_secs.is_none() {
        return Err(AppError::bad_request(
            "either additional_secs or new_ttl_secs must be provided",
        ));
    }

    tracing::debug!(
        %session_id,
        additional_secs = ?req.additional_secs,
        new_ttl_secs = ?req.new_ttl_secs,
        "extending session"
    );

    let new_expires = state
        .session_manager
        .extend(session_id, req.additional_secs, req.new_ttl_secs)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found")
                || msg.contains("expired")
                || msg.contains("cannot be extended")
            {
                AppError {
                    status: StatusCode::CONFLICT,
                    message: msg,
                }
            } else {
                AppError::internal(e)
            }
        })?;

    tracing::info!(%session_id, new_expires, "session extended");
    Ok(Json(serde_json::json!({ "expires_at_ms": new_expires })))
}

fn rate_limit_to_db(value: Option<u32>, field: &str) -> Result<Option<i32>, AppError> {
    value
        .map(|value| {
            i32::try_from(value)
                .map_err(|_| AppError::bad_request(format!("{field} must be at most {}", i32::MAX)))
        })
        .transpose()
}

fn db_rate_limit_or_default(
    value: Option<i32>,
    default: u32,
    field: &str,
) -> Result<u32, AppError> {
    match value {
        Some(value) => u32::try_from(value).map_err(|_| {
            AppError::internal(anyhow::anyhow!("{field} contains a negative rate limit"))
        }),
        None => Ok(default),
    }
}

impl OrgRow {
    fn into_org(self, default_rpm: u32, default_burst: u32) -> Result<Org, AppError> {
        let rate_limit_settings = RateLimitSettings {
            requests_per_minute: db_rate_limit_or_default(
                self.rate_limit_rpm,
                default_rpm,
                "rate_limit_rpm",
            )?,
            burst: db_rate_limit_or_default(
                self.rate_limit_burst,
                default_burst,
                "rate_limit_burst",
            )?,
        };
        let egress_proxy = match (self.proxy_type.as_deref(), self.proxy_address.as_deref()) {
            (Some(pt), Some(addr)) => {
                let proxy_type = match pt {
                    "socks5" => ProxyType::Socks5,
                    "http" => ProxyType::Http,
                    _ => {
                        return Ok(Org {
                            org_id: self.id,
                            rate_limit_settings,
                            egress_proxy: None,
                        });
                    }
                };
                // API responses never carry the stored password.
                Some(
                    EgressProxy {
                        proxy_type,
                        address: addr.to_owned(),
                        username: self.proxy_username,
                        password: self.proxy_password,
                    }
                    .redacted(),
                )
            }
            _ => None,
        };
        Ok(Org {
            org_id: self.id,
            rate_limit_settings,
            egress_proxy,
        })
    }
}

async fn create_org(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<StatusCode, AppError> {
    require_service_org(&principal, &req.org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let rpm = rate_limit_to_db(req.rate_limit_rpm, "rate_limit_rpm")?;
    let burst = rate_limit_to_db(req.rate_limit_burst, "rate_limit_burst")?;

    state
        .db
        .create_org(&req.org_id, rpm, burst)
        .await
        .map_err(AppError::internal)?;

    // Replicate effective rate limit to Redis
    let effective_rpm = req.rate_limit_rpm.unwrap_or(state.default_rate_limit_rpm);
    let effective_burst = req
        .rate_limit_burst
        .unwrap_or(state.default_rate_limit_burst);
    if let Err(e) = replicate_ratelimit(
        &mut state.redis.clone(),
        &req.org_id,
        effective_burst,
        effective_rpm,
        &state.config.redis_key_prefix,
    )
    .await
    {
        tracing::warn!(error = %e, org_id = %req.org_id, "failed to replicate rate limit to Redis");
    }

    Ok(StatusCode::CREATED)
}

async fn get_org(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
) -> Result<Json<Org>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let row = state
        .db
        .org(&org_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::not_found("Org not found"))?;

    Ok(Json(row.into_org(
        state.default_rate_limit_rpm,
        state.default_rate_limit_burst,
    )?))
}

async fn delete_org(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
) -> Result<StatusCode, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let deleted = state
        .db
        .delete_org(&org_id)
        .await
        .map_err(AppError::internal)?;

    if deleted > 0 {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::not_found("Org not found"))
    }
}

async fn list_orgs(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<Org>>, AppError> {
    let _ = (query.limit, query.offset);
    let row = state
        .db
        .org(&principal.org_id)
        .await
        .map_err(AppError::internal)?;
    let orgs = match row {
        Some(row) => {
            vec![row.into_org(state.default_rate_limit_rpm, state.default_rate_limit_burst)?]
        }
        None => Vec::new(),
    };
    Ok(Json(orgs))
}

async fn get_rate_limit(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
) -> Result<Json<RateLimitSettings>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let row = state
        .db
        .org_rate_limit(&org_id)
        .await
        .map_err(AppError::internal)?;

    let (requests_per_minute, burst) = row.unwrap_or((None, None));

    Ok(Json(RateLimitSettings {
        requests_per_minute: db_rate_limit_or_default(
            requests_per_minute,
            state.default_rate_limit_rpm,
            "rate_limit_rpm",
        )?,
        burst: db_rate_limit_or_default(burst, state.default_rate_limit_burst, "rate_limit_burst")?,
    }))
}

async fn set_rate_limit(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
    Json(settings): Json<SetRateLimitRequest>,
) -> Result<StatusCode, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let rpm = rate_limit_to_db(settings.requests_per_minute, "requests_per_minute")?;
    let burst = rate_limit_to_db(settings.burst, "burst")?;

    state
        .db
        .set_org_rate_limit(&org_id, rpm, burst)
        .await
        .map_err(AppError::internal)?;

    // Replicate effective rate limit to Redis
    let effective_rpm = settings
        .requests_per_minute
        .unwrap_or(state.default_rate_limit_rpm);
    let effective_burst = settings.burst.unwrap_or(state.default_rate_limit_burst);
    if let Err(e) = replicate_ratelimit(
        &mut state.redis.clone(),
        &org_id,
        effective_burst,
        effective_rpm,
        &state.config.redis_key_prefix,
    )
    .await
    {
        tracing::warn!(error = %e, org_id, "failed to replicate rate limit to Redis");
    }

    Ok(StatusCode::OK)
}

async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
) -> Result<Json<EgressProxy>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let row = state
        .db
        .org_proxy(&org_id)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::not_found("Org not found"))?;

    let (pt, addr, user, pass) = row;
    match (pt.as_deref(), addr) {
        (Some("socks5"), Some(address)) => Ok(Json(
            EgressProxy {
                proxy_type: ProxyType::Socks5,
                address,
                username: user,
                password: pass,
            }
            .redacted(),
        )),
        (Some("http"), Some(address)) => Ok(Json(
            EgressProxy {
                proxy_type: ProxyType::Http,
                address,
                username: user,
                password: pass,
            }
            .redacted(),
        )),
        _ => Err(AppError::not_found("Proxy config not found")),
    }
}

async fn set_proxy(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
    Json(req): Json<SetProxyRequest>,
) -> Result<StatusCode, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    // Validate proxy_type
    match req.proxy_type.as_str() {
        "socks5" | "http" => {}
        _ => {
            return Err(AppError::bad_request(
                "proxy_type must be \"socks5\" or \"http\"",
            ));
        }
    }

    state
        .db
        .set_org_proxy(
            &org_id,
            &req.proxy_type,
            &req.address,
            req.username.as_deref(),
            req.password.as_deref(),
        )
        .await
        .map_err(AppError::internal)?;

    Ok(StatusCode::OK)
}

async fn delete_proxy(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
) -> Result<StatusCode, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let found = state
        .db
        .clear_org_proxy(&org_id)
        .await
        .map_err(AppError::internal)?;

    if found == 0 {
        return Err(AppError::not_found("Org not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn certificate(State(state): State<Arc<AppState>>) -> String {
    state.ca_cert_pem.clone()
}

async fn search_traffic(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(query): Json<RpcTrafficQuery>,
) -> Result<Json<crate::models::SearchResponse>, AppError> {
    let mut query = query.into_scoped(&principal)?;
    crate::query::validate_regex_patterns(&query)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    crate::query::cursor_boundaries(&query).map_err(|e| AppError::bad_request(e.to_string()))?;
    crate::query::bound_to_sessions(&state.db, &mut query).await?;
    state.capture_store.check_http_query(&query)?;
    let results = state.capture_store.search_requests(&query).await?;
    Ok(Json(results))
}

async fn count_traffic(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(query): Json<RpcTrafficQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut query = query.into_scoped(&principal)?;
    crate::query::validate_regex_patterns(&query)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    crate::query::cursor_boundaries(&query).map_err(|e| AppError::bad_request(e.to_string()))?;
    crate::query::bound_to_sessions(&state.db, &mut query).await?;
    state.capture_store.check_http_query(&query)?;
    let count = state.capture_store.count_requests(&query).await?;
    Ok(Json(serde_json::json!({ "count": count })))
}

async fn get_capture(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path((org_id, id)): Path<(String, String)>,
) -> Result<Json<crate::models::HttpCapture>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let id = id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid capture ID"))?;

    let capture = state
        .capture_store
        .get_request(&org_id, id)
        .await?
        .ok_or_else(|| AppError::not_found("Capture not found"))?;

    Ok(Json(capture))
}

async fn search_ws_traffic(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(query): Json<RpcWsTrafficQuery>,
) -> Result<Json<crate::models::WsSearchResponse>, AppError> {
    let query = query.into_scoped(&principal)?;
    crate::query::ws::validate_regex_patterns(&query)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    state.capture_store.check_ws_query(&query)?;
    let results = state.capture_store.search_ws(&query).await?;
    Ok(Json(results))
}

async fn count_ws_traffic(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(query): Json<RpcWsTrafficQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let query = query.into_scoped(&principal)?;
    crate::query::ws::validate_regex_patterns(&query)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    state.capture_store.check_ws_query(&query)?;
    let count = state.capture_store.count_ws(&query).await?;
    Ok(Json(serde_json::json!({ "count": count })))
}

async fn get_ws_capture(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path((org_id, id)): Path<(String, String)>,
) -> Result<Json<crate::models::WsCapture>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let id = id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid ws capture id"))?;

    let capture = state
        .capture_store
        .get_ws_message(&org_id, id)
        .await?
        .ok_or_else(|| AppError::not_found("WS message not found"))?;

    Ok(Json(capture))
}

/// Per-conversation playback. Pins `parent_event_id` into a synthetic
/// single-branch `WsTrafficQuery` and forwards to `ws_search`. Routes
/// to `ws_messages_by_parent` automatically via the routing logic.
#[derive(Deserialize)]
struct ConversationQuery {
    cursor: Option<String>,
    limit: Option<u32>,
    #[serde(default)]
    order: Option<SortOrder>,
    payload_max_fetch_size: Option<u32>,
}

async fn get_conversation_ws(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path((org_id, parent_event_id)): Path<(String, String)>,
    Query(q): Query<ConversationQuery>,
) -> Result<Json<crate::models::WsSearchResponse>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let parent = parent_event_id
        .parse::<Uuid>()
        .map_err(|_| AppError::bad_request("Invalid parent_event_id"))?;
    let query = WsTrafficQuery {
        org_id: Some(org_id),
        branches: NonEmpty(vec![WsQueryBranch {
            parent_event_id: Some(parent.to_string()),
            ..Default::default()
        }]),
        cursor: q.cursor,
        limit: q.limit,
        order: q.order.unwrap_or_default(),
        payload_max_fetch_size: q.payload_max_fetch_size,
    };
    let results = state.capture_store.search_ws(&query).await?;
    Ok(Json(results))
}

#[derive(Deserialize)]
struct SequenceQuery {
    org_id: Option<String>,
    source_id: String,
}

#[derive(Serialize)]
struct SequenceResponse {
    org_id: String,
    source_id: String,
    /// Latest cursor for this `(org_id, source_id)` pair, or None when no
    /// rows exist yet. Opaque to callers — use as `cursor` in subsequent
    /// `/requests/search` calls to resume after the latest captured row.
    cursor: Option<String>,
    /// Deduplicated count of persisted captures for this pair.
    count: u64,
}

/// Returns the latest watermark cursor and deduplicated count for a
/// `(org_id, source_id)` pair. The cursor encodes
/// `(timestamp_nanos, session_offset, id)` lexicographically and is
/// compatible with the search endpoint's pagination.
///
/// The watermark is the newest capture by `(timestamp, session_offset, id)`;
/// the count is deduplicated by capture id and bounded to the
/// `(org_id, source_id)` slice.
async fn get_sequence(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Query(q): Query<SequenceQuery>,
) -> Result<Json<SequenceResponse>, AppError> {
    let org_id = resolve_service_org(&principal, q.org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;

    let sequence = state.capture_store.sequence(&org_id, &q.source_id).await?;

    Ok(Json(SequenceResponse {
        org_id,
        source_id: q.source_id,
        cursor: sequence.cursor,
        count: sequence.count,
    }))
}

#[derive(Deserialize)]
struct ProcessedQuery {
    source_id: String,
    org_id: Option<String>,
}

#[derive(Serialize)]
struct ProcessedResponse {
    all_processed: bool,
}

/// Returns whether the consumer has finished draining requests for a
/// source_id. Reads `session_lifecycle` in Postgres.
async fn get_processed(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Query(q): Query<ProcessedQuery>,
) -> Result<Json<ProcessedResponse>, AppError> {
    let org_id = q.org_id.unwrap_or_else(|| principal.org_id.clone());
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let all_processed = state
        .db
        .source_has_closed_session(&org_id, &q.source_id)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(ProcessedResponse { all_processed }))
}

#[derive(Serialize)]
struct SessionStatusResponse {
    state: String,
    #[serde(with = "time::serde::rfc3339")]
    opened_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    closing_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    closed_at: Option<time::OffsetDateTime>,
}

async fn get_session_status(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, AppError> {
    let session_id: Uuid = session_id
        .parse()
        .map_err(|_| AppError::bad_request("invalid session id"))?;
    let row = state
        .db
        .session_status(session_id)
        .await
        .map_err(AppError::internal)?;
    let row = row.ok_or_else(|| AppError::not_found("session lifecycle row not found"))?;
    require_service_org(&principal, &row.org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    Ok(Json(SessionStatusResponse {
        opened_at: row.opened_at(),
        closing_at: row.closing_at(),
        closed_at: row.closed_at(),
        state: row.state,
    }))
}

#[derive(Serialize)]
struct RateLimitStateResponse {
    org_id: String,
    exists: bool,
    tokens: f64,
    burst: u32,
    rpm: u32,
    last_refill_ms: i64,
}

/// Returns the live token-bucket state for an org from Redis: the bucket hash
/// the session proxy writes and the limits the control plane replicates.
async fn get_rate_limit_state(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(org_id): Path<String>,
) -> Result<Json<RateLimitStateResponse>, AppError> {
    require_service_org(&principal, &org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;
    let mut conn = state.redis.clone();
    let live =
        crate::session::read_ratelimit_state(&mut conn, &org_id, &state.config.redis_key_prefix)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(RateLimitStateResponse {
        org_id,
        exists: live.exists,
        tokens: live.tokens,
        burst: live.burst,
        rpm: live.rpm,
        last_refill_ms: live.last_refill_ms,
    }))
}

#[derive(Deserialize)]
struct CreateViewRequest {
    org_id: Option<String>,
    branches: NonEmpty<crate::query::QueryBranch>,
}

#[derive(Serialize)]
struct CreateViewResponse {
    view_id: Uuid,
    status: String,
    s3_key: Option<String>,
}

#[derive(Serialize)]
struct ViewPollResponse {
    view_id: Uuid,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_rows: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    written_rows: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_rows: Option<i64>,
}

async fn create_view(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Json(req): Json<CreateViewRequest>,
) -> Result<(StatusCode, Json<CreateViewResponse>), AppError> {
    let org_id = resolve_service_org(&principal, req.org_id)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;

    let query = TrafficQuery {
        org_id: Some(org_id.clone()),
        branches: req.branches,
        cursor: None,
        end_cursor: None,
        limit: None,
        order: SortOrder::default(),
        order_by: SortField::Timestamp,
        request_body_max_fetch_size: None,
        response_body_max_fetch_size: None,
    };
    crate::query::validate_regex_patterns(&query)
        .map_err(|e| AppError::bad_request(e.to_string()))?;

    let exporter = state.capture_store.require_view_exporter()?;
    let result = crate::views::create_view(
        &state.config,
        &state.view_store,
        exporter,
        &state.db,
        &org_id,
        query,
    )
    .await?;

    let status_code = if result.status == "completed" {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };

    Ok((
        status_code,
        Json(CreateViewResponse {
            view_id: result.view_id,
            status: result.status,
            s3_key: result.s3_key,
        }),
    ))
}

async fn get_view(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(view_id): Path<Uuid>,
) -> Result<Json<ViewPollResponse>, AppError> {
    let org_id = resolve_service_org(&principal, None)
        .map_err(|_| AppError::forbidden("service principal cannot access requested org"))?;

    let exporter = state.capture_store.require_view_exporter()?;
    let result =
        crate::views::poll_view_status(&state.view_store, exporter, &state.db, &org_id, view_id)
            .await?;

    let result = result.ok_or_else(|| AppError::not_found("traffic view not found"))?;

    Ok(Json(ViewPollResponse {
        view_id: result.view_id,
        status: result.status,
        s3_key: result.s3_key,
        error: result.error,
        read_rows: result.read_rows,
        written_rows: result.written_rows,
        total_rows: result.total_rows,
    }))
}
