#[allow(dead_code)]
mod setup;

use crate::setup::{server_and_client_stub, setup};
use api::grpc::blockjoy_ui::dashboard_service_client::DashboardServiceClient;
use api::grpc::blockjoy_ui::{DashboardKpiRequest, RequestMeta, Uuid as GrpcUuid};
use std::sync::Arc;
use test_macros::before;
use tonic::{transport::Channel, Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_with_invalid_token_for_kpis() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let inner = DashboardKpiRequest {
        meta: Some(request_meta),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", "some-invalid-token").parse().unwrap(),
    );

    assert_grpc_request! { kp_is, request, tonic::Code::Unauthenticated, db, DashboardServiceClient<Channel> };
}
