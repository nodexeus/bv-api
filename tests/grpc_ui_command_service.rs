#[allow(dead_code)]
mod setup;

use api::auth::{JwtToken, TokenType, UserAuthToken};
use api::grpc::blockjoy_ui::command_service_client::CommandServiceClient;
use api::grpc::blockjoy_ui::{CommandRequest as GrpcCommandRequest, RequestMeta};
use api::models::User;
use setup::setup;
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

macro_rules! test_response_ok {
    ($func:tt, $db: expr) => {{
        let request_meta = RequestMeta {
            id: Some(Uuid::new_v4().to_string()),
            token: None,
            fields: vec![],
            pagination: None,
        };
        let host = $db.test_host().await;
        let user = $db.admin_user().await;
        let token = UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth).unwrap();
        let inner = GrpcCommandRequest {
            meta: Some(request_meta),
            id: host.id.to_string(),
            params: vec![],
        };
        let mut request = Request::new(inner);

        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.to_base64().unwrap()).parse().unwrap(),
        );
        request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            $db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap());

        assert_grpc_request! { $func, request, tonic::Code::Ok, $db, CommandServiceClient<Channel> };
    }}
}

macro_rules! test_response_internal {
    ($func:tt, $db: expr) => {{
        let request_meta = RequestMeta {
            id: Some(Uuid::new_v4().to_string()),
            token: None,
            fields: vec![],
            pagination: None,
        };
        let host = $db.test_host().await;
        let user = $db.admin_user().await;
        let token = UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth).unwrap();
        let inner = GrpcCommandRequest {
            meta: Some(request_meta),
            id: host.id.to_string(),
            params: vec![],
        };
        let mut request = Request::new(inner);

        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.to_base64().unwrap()).parse().unwrap(),
        );
        request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            $db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap());

        assert_grpc_request! { $func, request, tonic::Code::Internal, $db, CommandServiceClient<Channel> };
    }}
}

macro_rules! test_response_invalid_argument {
    ($func:tt, $db: expr) => {{
        let request_meta = RequestMeta {
            id: Some(Uuid::new_v4().to_string()),
            token: None,
            fields: vec![],
            pagination: None,
        };
        let user = $db.admin_user().await;
        let token = UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth).unwrap();
        let inner = GrpcCommandRequest {
            meta: Some(request_meta),
            id: "".to_string(),
            params: vec![],
        };
        let mut request = Request::new(inner);

        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.to_base64().unwrap()).parse().unwrap(),
        );
        request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            $db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap());

        assert_grpc_request! { $func, request, tonic::Code::InvalidArgument, $db, CommandServiceClient<Channel> };
    }}
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_create_node() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { create_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_create_node() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { create_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_create_node() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { create_node, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_delete_node() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { delete_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_delete_node() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { delete_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_delete_node() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { delete_node, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_start_node() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { start_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_start_node() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { start_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_start_node() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { start_node, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_stop_node() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { stop_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_stop_node() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { stop_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_stop_node() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { stop_node, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_restart_node() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { restart_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_restart_node() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { restart_node, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_restart_node() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { restart_node, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_create_host() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { create_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_create_host() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { create_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_create_host() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { create_host, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_delete_host() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { delete_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_delete_host() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { delete_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_delete_host() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { delete_host, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_start_host() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { start_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_start_host() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { start_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_start_host() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { start_host, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_stop_host() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { stop_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_stop_host() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { stop_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_stop_host() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { stop_host, db }
}

#[before(call = "setup")]
// #[tokio::test]
/// TODO
async fn responds_ok_for_restart_host() {
    let db = Arc::new(_before_values.await);
    test_response_ok! { restart_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_restart_host() {
    let db = Arc::new(_before_values.await);
    test_response_internal! { restart_host, db }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_restart_host() {
    let db = Arc::new(_before_values.await);
    test_response_invalid_argument! { restart_host, db }
}
