#[allow(dead_code)]
mod setup;

use crate::setup::get_admin_user;
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::{GetHostProvisionRequest, RequestMeta, Uuid as GrpcUuid};
use setup::{server_and_client_stub, setup};
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_without_valid_id_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let inner = GetHostProvisionRequest {
        meta: Some(request_meta),
        id: "foo-bar1".to_string(),
    };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_id_for_get() {}
