#[allow(dead_code)]
mod setup;

use crate::setup::get_admin_user;
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::organization_service_client::OrganizationServiceClient;
use api::grpc::blockjoy_ui::{
    CreateOrganizationRequest, Organization, RequestMeta, Uuid as GrpcUuid,
};
use setup::{server_and_client_stub, setup};
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_for_create() {
    let db = Arc::new(_before_values.await);
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let org = Organization {
        name: Some("new-org".to_string()),
        id: None,
        created_at: None,
        updated_at: None,
        member_count: None,
        personal: None,
    };
    let inner = CreateOrganizationRequest {
        meta: Some(request_meta),
        organization: Some(org),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { create, request, tonic::Code::Ok, db, OrganizationServiceClient<Channel> };
}
