use blockvisor_api::grpc::api;
use tonic::transport::Channel;

use crate::setup::helper::traits::SocketRpc;
use crate::setup::TestServer;

type Service = api::discovery_service_client::DiscoveryServiceClient<Channel>;

#[tokio::test]
async fn discovery_service_urls() {
    let test = TestServer::new().await;

    let req = api::DiscoveryServiceServicesRequest {};
    let resp = test.send_admin(Service::services, req).await.unwrap();

    let expected = test.context().config.mqtt.notification_url();
    assert_eq!(resp.notification_url, expected);
}
