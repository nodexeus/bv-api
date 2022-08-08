use crate::auth::middleware::authorization::AuthorizationService;
use crate::auth::Authorization;
use crate::routes::{api_router, unauthenticated_routes};
use axum::extract::Extension;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use std::time::Duration;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub type DbPool = Arc<PgPool>;

pub async fn start() -> anyhow::Result<()> {
    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    let db_max_conn: u32 = std::env::var("DB_MAX_CONN")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .unwrap();
    let db_min_conn: u32 = std::env::var("DB_MIN_CONN")
        .unwrap_or_else(|_| "2".to_string())
        .parse()
        .unwrap();

    let enforcer = Authorization::new().await.unwrap();
    let auth_service = AuthorizationService::new(enforcer);
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, port);

    let db = PgPoolOptions::new()
        .max_connections(db_max_conn)
        .min_connections(db_min_conn)
        .max_lifetime(Some(Duration::from_secs(60 * 60 * 24)))
        .idle_timeout(Some(Duration::from_secs(60 * 2)))
        .connect(&db_url)
        .await
        .expect("Could not create db connection pool.");

    let app = api_router()
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
        .layer(TraceLayer::new_for_http());

    Ok(axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?)
}
