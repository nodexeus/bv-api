mod setup;

use api::grpc::blockjoy_ui::{self, host_service_client};
use tonic::transport;

type Service = host_service_client::HostServiceClient<transport::Channel>;

#[tokio::test]
async fn responds_invalid_argument_without_any_for_get() {
    let tester = setup::Tester::new().await;
    let req = blockjoy_ui::GetHostsRequest {
        meta: Some(tester.meta()),
        param: None,
    };
    let status = tester.send_admin(Service::get, req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn responds_ok_with_host_id_for_get() {
    let tester = setup::Tester::new().await;
    let host_id = tester.host().await.id.to_string();
    let req = blockjoy_ui::GetHostsRequest {
        meta: Some(tester.meta()),
        param: Some(blockjoy_ui::get_hosts_request::Param::Id(host_id)),
    };
    tester.send_admin(Service::get, req).await.unwrap();
}

#[tokio::test]
async fn responds_ok_with_org_id_for_get() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let org_id = host.org_id.unwrap().to_string();
    let req = blockjoy_ui::GetHostsRequest {
        meta: Some(tester.meta()),
        param: Some(blockjoy_ui::get_hosts_request::Param::OrgId(org_id)),
    };
    tester.send_admin(Service::get, req).await.unwrap();
}

#[tokio::test]
async fn responds_ok_with_pagination_with_org_id_for_get() {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org_for(&user).await;
    let req = blockjoy_ui::GetHostsRequest {
        meta: Some(tester.meta().with_pagination(tester.pagination())),
        param: Some(blockjoy_ui::get_hosts_request::Param::OrgId(
            org.id.to_string(),
        )),
    };
    let max_items: i32 = std::env::var("PAGINATION_MAX_ITEMS")
        .expect("MAX ITEMS NOT SET")
        .parse()
        .expect("Could not parse max items");

    let resp = tester.send_admin(Service::get, req).await.unwrap();
    let meta = resp.meta.unwrap();
    let pagination = meta.pagination.unwrap();
    assert_eq!(pagination.items_per_page, max_items);
    assert_eq!(pagination.current_page, 0);
    assert_eq!(pagination.total_items.unwrap(), 0);
}

#[tokio::test]
async fn responds_ok_with_token_for_get() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let host_token = tester.token_for(&host).await;
    let req = blockjoy_ui::GetHostsRequest {
        meta: Some(tester.meta()),
        param: Some(blockjoy_ui::get_hosts_request::Param::Token(host_token)),
    };
    tester.send_admin(Service::get, req).await.unwrap();
}

#[tokio::test]
async fn responds_ok_with_id_for_delete() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let req = blockjoy_ui::DeleteHostRequest {
        meta: Some(tester.meta()),
        id: host.id.to_string(),
    };
    tester.send_admin(Service::delete, req).await.unwrap();
}

#[tokio::test]
async fn responds_ok_with_host_for_update() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let req = blockjoy_ui::UpdateHostRequest {
        meta: Some(tester.meta()),
        host: Some(host.try_into().unwrap()),
    };
    tester.send_admin(Service::update, req).await.unwrap();
}

#[tokio::test]
async fn responds_ok_with_host_for_create() {
    let tester = setup::Tester::new().await;
    let host = blockjoy_ui::Host {
        name: Some("burli-bua".to_string()),
        ip: Some("127.0.0.1".to_string()),
        ..Default::default()
    };
    let req = blockjoy_ui::CreateHostRequest {
        meta: Some(tester.meta()),
        host: Some(host),
    };
    tester.send_admin(Service::create, req).await.unwrap();
}
