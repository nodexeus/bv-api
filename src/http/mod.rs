use crate::auth::middleware::authorization::AuthorizationService;
use crate::auth::Authorization;
use crate::http::routes::{api_router, unauthenticated_routes};
use crate::server::DbPool;
use axum::{Extension, Router};
use std::sync::Arc;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub mod handlers;
pub mod routes;

pub async fn server(db: DbPool) -> Router {
    let enforcer = Authorization::new().await.unwrap();
    let auth_service = AuthorizationService::new(enforcer);

    api_router()
        .layer(AsyncRequireAuthorizationLayer::new(auth_service))
        // Unauthenticated routes
        .nest("/", unauthenticated_routes())
        // Common layers need to be added first to make it available to ALL routes
        .layer(
            CorsLayer::new()
                .allow_headers(Any)
                .allow_methods(Any)
                .allow_origin(Any),
        )
        .layer(CompressionLayer::new())
        .layer(Extension(Arc::new(db)))
        .layer(TraceLayer::new_for_http())
}
