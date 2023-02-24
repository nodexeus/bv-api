use super::mqtt::{MqttAclRequest, MqttAuthRequest};
use crate::models;
use axum::extract::{Extension, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// Health handler used indicating system status
/// Returns empty message (assuming all is working properly).
/// DB extension is passed in to check DB status
pub async fn health(Extension(db): Extension<models::DbPool>) -> impl IntoResponse {
    if db.is_closed() {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json("DB connection is closed"),
        )
    } else {
        (StatusCode::OK, Json(""))
    }
}

pub async fn mqtt_auth(Json(_payload): Json<MqttAuthRequest>) -> impl IntoResponse {
    (StatusCode::NO_CONTENT, Json("{}"))
}
pub async fn mqtt_acl(Json(_payload): Json<MqttAclRequest>) -> impl IntoResponse {
    (StatusCode::NO_CONTENT, Json("{}"))
}
