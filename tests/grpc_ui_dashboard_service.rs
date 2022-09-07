#[allow(dead_code)]
mod setup;

use crate::setup::{get_admin_user, server_and_client_stub, setup};
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::dashboard_service_client::DashboardServiceClient;
use api::grpc::blockjoy_ui::{kpi, DashboardKpiRequest, RequestMeta, Uuid as GrpcUuid};
use std::str;
use std::sync::Arc;
use test_macros::before;
use tonic::{transport::Channel, Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_with_invalid_token_for_metrics() {
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

    assert_grpc_request! { metrics, request, tonic::Code::Unauthenticated, db, DashboardServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_token_for_metrics() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = DashboardKpiRequest {
        meta: Some(request_meta),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { metrics, request, tonic::Code::Ok, db, DashboardServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_valid_values_for_metrics() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = DashboardKpiRequest {
        meta: Some(request_meta),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    let (serve_future, mut client) =
        server_and_client_stub::<DashboardServiceClient<Channel>>(db).await;

    let request_future = async {
        match client.metrics(request).await {
            Ok(response) => {
                let inner = response.into_inner();
                let values = inner.values;

                let online_name: i32 = values.first().unwrap().name;
                let offline_name: i32 = values.last().unwrap().name;
                let online_value: i32 = str::from_utf8(
                    values
                        .first()
                        .unwrap()
                        .value
                        .clone()
                        .unwrap()
                        .value
                        .as_slice(),
                )
                .unwrap()
                .parse()
                .unwrap();
                let offline_value: i32 = str::from_utf8(
                    values
                        .last()
                        .unwrap()
                        .value
                        .clone()
                        .unwrap()
                        .value
                        .as_slice(),
                )
                .unwrap()
                .parse()
                .unwrap();

                assert_eq!(online_name, kpi::Name::Online as i32);
                assert_eq!(offline_name, kpi::Name::Offline as i32);
                assert_eq!(online_value, 0);
                assert_eq!(offline_value, 0);
            }
            Err(e) => {
                println!("response ERROR: {:?}", e);
            }
        }
    };

    // Wait for completion, when the client request future completes
    tokio::select! {
        _ = serve_future => panic!("server returned first"),
        _ = request_future => (),
    }
}
