use crate::http::handlers::health;
use axum::extract::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

pub fn unauthenticated_routes() -> Router {
    let mqtt_router = Router::new()
        // mqtt/auth
        // -> { username: %u => JWT TOKEN }
        .route("/auth", post(mqtt_auth))
        .route("/acl", post(mqtt_acl));

    Router::new()
        .route("/health", get(health))
        .nest("/mqtt", mqtt_router)
}

pub async fn mqtt_auth(Json(_payload): Json<MqttAuthRequest>) -> impl IntoResponse {
    (StatusCode::NO_CONTENT, Json("{}"))
}
pub async fn mqtt_acl(Json(_payload): Json<MqttAclRequest>) -> impl IntoResponse {
    (StatusCode::NO_CONTENT, Json("{}"))
}

#[derive(Deserialize)]
pub struct MqttAuthRequest {
    pub username: String,
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MqttOperationType {
    Publish,
    Subscribe,
}

#[derive(Deserialize)]
pub struct MqttAclRequest {
    pub operation: MqttOperationType,
    pub username: String,
    pub topic: Option<String>,
}
