#[allow(dead_code)]
mod setup;

use api::grpc::blockjoy::key_files_client;
use api::grpc::blockjoy::KeyFilesGetRequest;
use api::models::{
    self, ContainerStatus, CreateNodeKeyFileRequest, NodeChainStatus, NodeCreateRequest,
    NodeKeyFile, NodeSyncStatus, NodeType, NodeTypeKey,
};
use sqlx::types::Json;
use tonic::transport;
use uuid::Uuid;

type Service = key_files_client::KeyFilesClient<transport::Channel>;

#[tokio::test]
async fn responds_not_found_with_invalid_node_id() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let auth = tester.host_token(&host);
    let refresh = tester.refresh_for(&auth);
    let req = KeyFilesGetRequest {
        request_id: None,
        node_id: Uuid::new_v4().to_string(),
    };
    let status = tester
        .send_with(Service::get, req, auth, refresh)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn responds_ok_with_valid_node_id() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let auth = tester.host_token(&host);
    let refresh = tester.refresh_for(&auth);
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id: tester.org().await.id,
        blockchain_id: tester.blockchain().await.id,
        node_type: Json(NodeType::special_type(NodeTypeKey::Api)),
        chain_status: NodeChainStatus::Unknown,
        sync_status: NodeSyncStatus::Syncing,
        container_status: ContainerStatus::Installing,
        address: None,
        wallet_address: None,
        block_height: None,
        groups: None,
        node_data: None,
        ip_addr: None,
        ip_gateway: Some("192.168.0.1".into()),
        name: None,
        version: None,
        staking_status: None,
        self_update: false,
        key_files: vec![],
    };
    let node = models::Node::create(&req, tester.pool()).await.unwrap();
    let req = CreateNodeKeyFileRequest {
        name: "my-key.txt".to_string(),
        content:
            "asödlfasdf asdfjaöskdjfalsdjföasjdf afa sdffasdfasldfjasödfj asdföalksdföalskdjfa"
                .to_string(),
        node_id: node.id,
    };
    NodeKeyFile::create(req, tester.pool()).await.unwrap();
    let req = KeyFilesGetRequest {
        request_id: None,
        node_id: node.id.to_string(),
    };
    tester
        .send_with(Service::get, req, auth, refresh)
        .await
        .unwrap();
}
