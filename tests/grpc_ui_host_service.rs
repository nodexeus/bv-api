#[allow(dead_code)]
mod setup;

use crate::setup::{get_admin_user, get_test_host};
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::host_service_client::HostServiceClient;
use api::grpc::blockjoy_ui::{GetHostsRequest, RequestMeta, Uuid as GrpcUuid};
use setup::{server_and_client_stub, setup};
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_without_any_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GetHostsRequest {
        meta: Some(request_meta),
        id: None,
        org_id: None,
        token: None,
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::NotFound, db, HostServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_id_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db.clone()).await;
    let host_id = GrpcUuid::from(get_test_host(&db).await.id);
    let token = user.get_token(&db).await.unwrap();
    let inner = GetHostsRequest {
        meta: Some(request_meta),
        id: Some(host_id),
        org_id: None,
        token: None,
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::NotFound, db, HostServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_org_id_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db.clone()).await;
    let host = get_test_host(&db).await;

    if host.org_id.is_none() {
        println!("NO ORG_ID SET ON HOST");
        return;
    }

    let org_id = Some(GrpcUuid::from(host.org_id.unwrap()));
    let token = user.get_token(&db).await.unwrap();
    let inner = GetHostsRequest {
        meta: Some(request_meta),
        id: None,
        org_id,
        token: None,
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::NotFound, db, HostServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_token_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db.clone()).await;
    let host = get_test_host(&db).await;
    let host_token = host.get_token(&db).await.unwrap().token;
    let token = user.get_token(&db).await.unwrap();
    let inner = GetHostsRequest {
        meta: Some(request_meta),
        id: None,
        org_id: None,
        token: Some(host_token),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::Ok, db, HostServiceClient<Channel> };
}
