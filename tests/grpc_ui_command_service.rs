mod setup;

use api::grpc::blockjoy_ui::{self, command_service_client};
use tonic::transport;

type Service = command_service_client::CommandServiceClient<transport::Channel>;

async fn valid() -> (setup::Tester, blockjoy_ui::CommandRequest) {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::CommandRequest {
        meta: Some(tester.meta()),
        id: tester.host().await.id.to_string(),
        params: vec![],
    };
    (tester, req)
}

async fn invalid() -> (setup::Tester, blockjoy_ui::CommandRequest) {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::CommandRequest {
        meta: Some(tester.meta()),
        id: "".to_string(),
        params: vec![],
    };
    (tester, req)
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_create_node() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::create_node, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_create_node() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::create_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_create_node() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::create_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_delete_node() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::delete_node, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_delete_node() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::delete_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_delete_node() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::delete_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_start_node() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::start_node, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_start_node() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::start_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_start_node() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::start_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_stop_node() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::stop_node, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_stop_node() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::stop_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_stop_node() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::stop_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_restart_node() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::restart_node, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_restart_node() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::restart_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_restart_node() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::restart_node, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_create_host() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::create_host, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_create_host() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::create_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_create_host() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::create_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_delete_host() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::delete_host, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_delete_host() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::delete_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_delete_host() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::delete_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_start_host() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::start_host, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_start_host() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::start_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_start_host() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::start_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_stop_host() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::stop_host, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_stop_host() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::stop_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_stop_host() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::stop_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// TODO
#[tokio::test]
#[ignore]
async fn responds_ok_for_restart_host() {
    let (tester, req) = valid().await;
    tester.send_admin(Service::restart_host, req).await.unwrap();
}

#[tokio::test]
async fn responds_internal_for_restart_host() {
    let (tester, req) = valid().await;
    let status = tester
        .send_admin(Service::restart_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn responds_invalid_argument_for_restart_host() {
    let (tester, req) = invalid().await;
    let status = tester
        .send_admin(Service::restart_host, req)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
