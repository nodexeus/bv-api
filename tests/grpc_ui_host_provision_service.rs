mod setup;

use api::grpc::blockjoy_ui::{self, host_provision_service_client};
use api::models;
use tonic::transport;

type Service = host_provision_service_client::HostProvisionServiceClient<transport::Channel>;

#[tokio::test]
async fn responds_not_found_without_valid_id_for_get() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::GetHostProvisionRequest {
        meta: Some(tester.meta()),
        id: Some("foo-bar1".to_string()),
    };
    let status = tester.send_admin(Service::get, req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn responds_ok_with_valid_id_for_get() {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org_for(&user).await;

    let req = models::HostProvisionRequest {
        org_id: org.id,
        nodes: None,
    };
    let provision = models::HostProvision::create(req, &tester.db.pool)
        .await
        .unwrap();

    let req = blockjoy_ui::GetHostProvisionRequest {
        meta: Some(tester.meta()),
        id: Some(provision.id),
    };
    tester.send_admin(Service::get, req).await.unwrap();
}

#[tokio::test]
async fn responds_error_with_invalid_provision_for_create() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::CreateHostProvisionRequest {
        meta: Some(tester.meta()),
        host_provision: None,
    };
    let status = tester.send_admin(Service::create, req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn responds_ok_with_valid_provision_for_create() {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org_for(&user).await;
    let provision = blockjoy_ui::HostProvision {
        org_id: org.id.to_string(),
        ..Default::default()
    };
    let req = blockjoy_ui::CreateHostProvisionRequest {
        meta: Some(tester.meta()),
        host_provision: Some(provision),
    };
    tester.send_admin(Service::create, req).await.unwrap();
}
