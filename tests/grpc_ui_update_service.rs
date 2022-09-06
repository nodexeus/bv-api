#[allow(dead_code)]
mod setup;

use crate::setup::{get_admin_user, server_and_client_stub, setup};
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::update_service_client::UpdateServiceClient;
use api::grpc::blockjoy_ui::{GetUpdatesRequest, RequestMeta, Uuid as GrpcUuid};
use std::sync::Arc;
use test_macros::before;
use tonic::{transport::Channel, Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_token_for_update() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db.clone()).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GetUpdatesRequest {
        meta: Some(request_meta),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { updates, request, tonic::Code::Ok, db, UpdateServiceClient<Channel> };
}
