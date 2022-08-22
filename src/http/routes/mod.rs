use crate::http::handlers::health;
use axum::routing::get;
use axum::Router;

pub fn unauthenticated_routes() -> Router {
    Router::new().route("/health", get(health))
}
