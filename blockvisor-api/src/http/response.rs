//! This module is used to construct `axum::Response` bodies to ensure
//! consistency in our API responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use crate::http::params::ParameterValidationError;

const OK: StatusCode = StatusCode::OK;
const BAD_REQUEST: StatusCode = StatusCode::BAD_REQUEST;
const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
const INTERNAL_SERVER_ERROR: StatusCode = StatusCode::INTERNAL_SERVER_ERROR;
const NOT_FOUND: StatusCode = StatusCode::NOT_FOUND;

#[derive(Clone, Copy)]
pub enum Message {
    BadParams,
    DbClosed,
    Empty,
    Failed,
    Unauthorized,
    NotFound,
    Custom(&'static str),
}

impl From<Message> for &'static str {
    fn from(message: Message) -> Self {
        use Message::*;
        match message {
            BadParams => "Bad params.",
            DbClosed => "DB connection is closed.",
            Empty => "",
            Failed => "Failed.",
            Unauthorized => "Unauthorized.",
            NotFound => "Not found.",
            Custom(msg) => msg,
        }
    }
}

pub fn ok() -> Response {
    (OK, Body::json(Message::Empty)).into_response()
}

pub fn ok_custom(msg: &'static str) -> Response {
    (OK, Body::json(Message::Custom(msg))).into_response()
}

pub fn bad_params() -> Response {
    (BAD_REQUEST, Body::json(Message::BadParams)).into_response()
}

pub fn unauthorized() -> Response {
    (UNAUTHORIZED, Body::json(Message::Unauthorized)).into_response()
}

pub fn failed() -> Response {
    (INTERNAL_SERVER_ERROR, Body::json(Message::Failed)).into_response()
}

pub fn not_found() -> Response {
    (NOT_FOUND, Body::json(Message::NotFound)).into_response()
}

pub fn db_closed() -> Response {
    (INTERNAL_SERVER_ERROR, Body::json(Message::DbClosed)).into_response()
}

/// Create a response for parameter validation errors with detailed error information
pub fn parameter_validation_error(error: ParameterValidationError) -> Response {
    (BAD_REQUEST, Json(error.to_json())).into_response()
}

/// Create a response for a single parameter error
pub fn parameter_error(parameter: &str, error: &str, expected: &str) -> Response {
    let mut validation_error = ParameterValidationError::new("Invalid query parameter");
    validation_error.add_error(parameter, error, expected);
    parameter_validation_error(validation_error)
}

#[derive(Serialize)]
struct Body {
    pub message: &'static str,
}

impl Body {
    fn json(message: Message) -> Json<Self> {
        Json(Body {
            message: message.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status() {
        let ok = ok().into_response().status();
        assert_eq!(ok, OK);

        let unauthorized = unauthorized().into_response().status();
        assert_eq!(unauthorized, UNAUTHORIZED);

        let failed = failed().into_response().status();
        assert_eq!(failed, INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn http_body() {
        let resp = failed().into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, r#"{"message":"Failed."}"#);
    }

    #[tokio::test]
    async fn parameter_validation_error_response() {
        let mut error = ParameterValidationError::new("Invalid parameters");
        error.add_error("org_id", "Invalid UUID format", "Valid UUID string");
        
        let resp = parameter_validation_error(error).into_response();
        assert_eq!(resp.status(), BAD_REQUEST);
        
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        
        // Verify the JSON structure
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "Invalid parameters");
        assert_eq!(json["details"][0]["parameter"], "org_id");
        assert_eq!(json["details"][0]["error"], "Invalid UUID format");
        assert_eq!(json["details"][0]["expected"], "Valid UUID string");
    }

    #[tokio::test]
    async fn parameter_error_response() {
        let resp = parameter_error("limit", "Value too large", "Number between 1 and 1000").into_response();
        assert_eq!(resp.status(), BAD_REQUEST);
        
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        
        // Verify the JSON structure
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["error"], "Invalid query parameter");
        assert_eq!(json["details"][0]["parameter"], "limit");
        assert_eq!(json["details"][0]["error"], "Value too large");
        assert_eq!(json["details"][0]["expected"], "Number between 1 and 1000");
    }
}
