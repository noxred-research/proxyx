use std::sync::Arc;

use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::Router;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::post;
use proxyx_control_graphql::TrafficSchema;

use crate::auth::{Principal, UserPrincipal};
use crate::server::AppState;
use crate::server::service::ControllerApiService;

pub fn federation_sdl() -> String {
    proxyx_control_graphql::federation_sdl()
}

pub fn router(state: Arc<AppState>) -> Router {
    let auth_state = Arc::clone(&state);
    let schema = proxyx_control_graphql::build_schema(ControllerApiService::new(state));
    Router::new()
        .route("/", post(graphql_handler).get(graphql_playground))
        .route_layer(middleware::from_fn_with_state(
            auth_state,
            require_user_principal,
        ))
        .with_state(schema)
}

async fn require_user_principal(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match crate::server::rpc::service_auth::authenticate(&state, request.headers()).await? {
        Principal::User(principal) => {
            request.extensions_mut().insert(principal);
            Ok(next.run(request).await)
        }
        Principal::Service(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn graphql_handler(
    State(schema): State<TrafficSchema<ControllerApiService>>,
    Extension(principal): Extension<UserPrincipal>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let request = req.into_inner().data(principal);
    schema.execute(request).await.into()
}

async fn graphql_playground() -> axum::response::Html<String> {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}
