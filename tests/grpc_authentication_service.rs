#[allow(dead_code)]
mod setup;

use api::grpc::blockjoy_ui::authentication_service_client::AuthenticationServiceClient;
use api::grpc::blockjoy_ui::{LoginUserRequest, RequestMeta, Uuid as GrpcUuid};
use setup::{server_and_client_stub, setup};
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_credentials() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let inner = LoginUserRequest {
        meta: Some(request_meta),
        email: "admin@here.com".to_string(),
        password: "abc12345".to_string(),
    };

    assert_grpc_request! { login, Request::new(inner), tonic::Code::Ok, db, AuthenticationServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_error_with_invalid_credentials() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let inner = LoginUserRequest {
        meta: Some(request_meta),
        email: "foo@bar.com".to_string(),
        password: "eafe12345".to_string(),
    };

    assert_grpc_request! { login, Request::new(inner), tonic::Code::Unauthenticated, db, AuthenticationServiceClient<Channel> };
}
