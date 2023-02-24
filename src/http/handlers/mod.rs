use super::mqtt::{MqttAclRequest, MqttAuthRequest};
use crate::auth::{determine_token_by_str, AnyToken, TokenType};
use crate::http::mqtt::{MqttAclPolicy, MqttHostPolicy, MqttUserPolicy};
use crate::models;
use anyhow::anyhow;
use axum::body::HttpBody;
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

pub async fn mqtt_acl(Json(payload): Json<MqttAclRequest>) -> impl IntoResponse {
    match determine_token_by_str(payload.username.as_str()) {
        Ok(TokenType::UserAuth) => {
            if MqttUserPolicy::allow(payload.username.as_str(), payload.topic)
                .map_err(|e| anyhow!(StatusCode::INTERNAL_SERVER_ERROR))?
            {
                (StatusCode::OK, Json("{}"))
            } else {
                (StatusCode::FORBIDDEN, Json("{}"))
            }
        }
        Ok(TokenType::HostAuth) => {
            if MqttHostPolicy::allow(payload.username.as_str(), payload.topic)? {
                (StatusCode::OK, Json("{}"))
            } else {
                (StatusCode::FORBIDDEN, Json("{}"))
            }
        }
        Ok(_) => (
            StatusCode::NOT_ACCEPTABLE,
            Json("{ \"message\": \"Not supported\"}"),
        ),
        Err(_) => (
            StatusCode::NOT_ACCEPTABLE,
            Json("{ \"message\": \"Unknown\"}"),
        ),
    }
}
