use axum::http::header::AUTHORIZATION;
use axum::http::Request as HttpRequest;
use casbin_authorization::middleware::authentication::*;
use casbin_authorization::{Identifier, JwtToken, TokenHolderType};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use test_macros::*;
use tonic::Request as GrpcRequest;
use uuid::Uuid;

struct TestData {
    pub(crate) now: u64,
}

struct GrpcInner(pub bool);

fn setup() -> TestData {
    env::set_var("JWT_SECRET", "923f3090//§");

    let start = SystemTime::now();

    TestData {
        now: start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
    }
}

#[before(call = "setup")]
#[test]
fn should_get_valid_token_from_http_request() {
    let id = Uuid::new_v4();
    let exp = (_before_values.now as usize) + 60;
    let token = JwtToken::new(id, exp, TokenHolderType::User);
    let encoded = format!("Bearer {}", token.encode().unwrap());
    let request = HttpRequest::builder()
        .header(AUTHORIZATION, encoded)
        .uri("/")
        .method("GET")
        .body(())
        .unwrap();
    let token = get_token_from_http_request(&request).unwrap();

    assert_eq!(token.get_id(), id);
}

#[before(call = "setup")]
#[test]
fn should_not_get_valid_token_from_http_request() {
    let id = Uuid::new_v4();
    let exp = (_before_values.now as usize) + 60;
    let token = JwtToken::new(id, exp, TokenHolderType::User);
    let encoded = token.encode().unwrap();
    let request = HttpRequest::builder()
        .header(AUTHORIZATION, encoded)
        .uri("/")
        .method("GET")
        .body(())
        .unwrap();

    if get_token_from_http_request(&request).is_ok() {
        panic!("It works, but it shouldn't")
    }
}

#[before(call = "setup")]
#[test]
fn should_get_valid_token_from_grpc_request() {
    let id = Uuid::new_v4();
    let exp = (_before_values.now as usize) + 60;
    let token = JwtToken::new(id, exp, TokenHolderType::User);
    let encoded = format!("Bearer {}", token.encode().unwrap());
    let mut request = GrpcRequest::new(GrpcInner(true));

    request
        .metadata_mut()
        .insert("authorization", encoded.parse().unwrap());

    let token = get_token_from_grpc_request(&request).unwrap();

    assert_eq!(token.get_id(), id);
}

#[before(call = "setup")]
#[test]
fn should_not_get_valid_token_from_grpc_request() {
    let id = Uuid::new_v4();
    let exp = (_before_values.now as usize) + 60;
    let token = JwtToken::new(id, exp, TokenHolderType::User);
    let encoded = token.encode().unwrap();
    let mut request = GrpcRequest::new(GrpcInner(true));

    request
        .metadata_mut()
        .insert("authorization", encoded.parse().unwrap());

    if get_token_from_grpc_request(&request).is_ok() {
        panic!("It works, but it shouldn't")
    }
}
