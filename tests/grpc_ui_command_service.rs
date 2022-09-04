#[allow(dead_code)]
mod setup;

use crate::setup::get_admin_user;
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::command_service_client::CommandServiceClient;
use api::grpc::blockjoy_ui::{CommandRequest as GrpcCommandRequest, RequestMeta, Uuid as GrpcUuid};
use setup::{server_and_client_stub, setup};
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_create_node() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GrpcCommandRequest {
        meta: Some(request_meta),
        id: None,
        params: vec![],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { create_node, request, tonic::Code::Ok, db, CommandServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_for_create_node() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GrpcCommandRequest {
        meta: Some(request_meta),
        id: None,
        params: vec![],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { create_node, request, tonic::Code::Internal, db, CommandServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_for_create_node() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GrpcCommandRequest {
        meta: Some(request_meta),
        id: None,
        params: vec![],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { create_node, request, tonic::Code::NotFound, db, CommandServiceClient<Channel> };
}
