use crate::server::DbPool;
use axum::extract::{Extension, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// Health handler used indicating system status
/// Returns empty message (assuming all is working properly).
/// DB extension is passed in to check DB status
pub async fn health(Extension(db): Extension<DbPool>) -> impl IntoResponse {
    if db.is_closed() {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json("DB connection is closed"),
        )
    } else {
        (StatusCode::OK, Json(""))
    }
}
