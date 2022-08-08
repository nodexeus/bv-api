//! TODO: Check if still needed

use crate::auth::{JwtToken, TokenError, TokenResult};
use axum::http::header::AUTHORIZATION;
use axum::http::Request as HttpRequest;
use std::str::FromStr;
use tonic::Request as GrpcRequest;

pub type AuthenticationResult = TokenResult<JwtToken>;

/// Helper returning the Bearer token value
fn extract_token_str(value: &str) -> Option<&str> {
    let words = value.split("Bearer").collect::<Vec<&str>>();

    words.get(1).map(|w| w.trim())
}

pub fn get_token_from_http_request<B>(request: &HttpRequest<B>) -> AuthenticationResult {
    match request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|hv| hv.to_str().ok())
        .and_then(extract_token_str)
    {
        Some(token_str) => JwtToken::from_str(token_str),
        None => Err(TokenError::Empty),
    }
}

pub fn get_token_from_grpc_request<B>(request: &GrpcRequest<B>) -> AuthenticationResult {
    match request
        .metadata()
        .get("authorization")
        .and_then(|mv| mv.to_str().ok())
        .and_then(extract_token_str)
    {
        Some(token_str) => JwtToken::from_str(token_str),
        None => Err(TokenError::Empty),
    }
}
