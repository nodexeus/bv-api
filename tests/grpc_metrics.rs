mod setup;

use api::grpc::blockjoy::{self, metrics_service_client};
use api::models;
use tonic::transport;

type Service = metrics_service_client::MetricsServiceClient<transport::Channel>;

#[tokio::test]
async fn responds_ok_for_write() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let auth = tester.host_token(&host);
    let refresh = tester.refresh_for(&auth);
    let node = tester.node().await;
    let mut metrics = std::collections::HashMap::new();
    let metric = blockjoy::Metrics {
        height: Some(10),
        block_age: Some(5),
        staking_status: Some(4),
        consensus: Some(false),
    };
    metrics.insert(node.id.to_string(), metric);
    let req = blockjoy::NodeMetricsRequest { metrics };
    tester
        .send_with(Service::node, req, auth, refresh)
        .await
        .unwrap();
    let node = tester.node().await;
    assert_eq!(node.block_height, Some(10));
    assert_eq!(node.block_age, Some(5));
    assert_eq!(node.staking_status, models::NodeStakingStatus::Validating);
    assert_eq!(node.consensus, Some(false));
}
