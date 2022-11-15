#[allow(dead_code)]
mod setup;

use api::auth::{HostAuthToken, JwtToken, TokenRole, TokenType};
use api::grpc::blockjoy::key_files_client::KeyFilesClient;
use api::grpc::blockjoy::{KeyFilesGetRequest, KeyFilesSaveRequest, Keyfile};
use api::models::{
    ContainerStatus, CreateNodeKeyFileRequest, Host, Node, NodeChainStatus, NodeCreateRequest,
    NodeKeyFile, NodeSyncStatus, NodeType, NodeTypeKey, Org,
};
use setup::setup;
use sqlx::types::Json;
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::{Request, Status};
use uuid::Uuid;

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_with_invalid_node_id() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let token: HostAuthToken =
        HostAuthToken::create_token_for::<Host>(host, TokenType::HostAuth, TokenRole::Service)
            .unwrap();
    let inner = KeyFilesGetRequest {
        request_id: None,
        node_id: Uuid::new_v4().to_string(),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::NotFound, db, KeyFilesClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_node_id() {
    let db = _before_values.await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let blockchain = db.blockchain().await;
    let token: HostAuthToken =
        HostAuthToken::create_token_for::<Host>(host, TokenType::HostAuth, TokenRole::Service)
            .unwrap();
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id,
        blockchain_id: blockchain.id,
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
    };
    let node = Node::create(&req, &db.pool).await.unwrap();
    let req = CreateNodeKeyFileRequest {
        name: "my-key.txt".to_string(),
        content:
            "asödlfasdf asdfjaöskdjfalsdjföasjdf afa sdffasdfasldfjasödfj asdföalksdföalskdjfa"
                .to_string(),
        node_id: node.id,
    };
    let _ = NodeKeyFile::create(req, &db.pool).await.unwrap();
    let inner = KeyFilesGetRequest {
        request_id: None,
        node_id: node.id.to_string(),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::Ok, db, KeyFilesClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_with_invalid_node_id_for_save() {
    let db = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let token: HostAuthToken =
        HostAuthToken::create_token_for::<Host>(host, TokenType::HostAuth, TokenRole::Service)
            .unwrap();
    let key_file = Keyfile {
        name: "new keyfile".to_string(),
        content: "üöäß@niesfiefasd".to_string().into_bytes(),
    };
    let inner = KeyFilesSaveRequest {
        request_id: None,
        node_id: Uuid::new_v4().to_string(),
        key_files: vec![key_file],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { save, request, tonic::Code::NotFound, db, KeyFilesClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_node_id_for_save() {
    let db = _before_values.await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let blockchain = db.blockchain().await;
    let token: HostAuthToken =
        HostAuthToken::create_token_for::<Host>(host, TokenType::HostAuth, TokenRole::Service)
            .unwrap();
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id,
        blockchain_id: blockchain.id,
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
    };
    let node = Node::create(&req, &db.pool).await.unwrap();
    let key_file = Keyfile {
        name: "new keyfile".to_string(),
        content: "üöäß@niesfiefasd".to_string().into_bytes(),
    };
    let inner = KeyFilesSaveRequest {
        request_id: None,
        node_id: node.id.to_string(),
        key_files: vec![key_file],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { save, request, tonic::Code::Ok, db, KeyFilesClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_error_with_same_node_id_name_twice_for_save() {
    let db = _before_values.await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let blockchain = db.blockchain().await;
    let token: HostAuthToken =
        HostAuthToken::create_token_for::<Host>(host, TokenType::HostAuth, TokenRole::Service)
            .unwrap();
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id,
        blockchain_id: blockchain.id,
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
    };
    let node = Node::create(&req, &db.pool).await.unwrap();
    let key_file = Keyfile {
        name: "new keyfile".to_string(),
        content: "üöäß@niesfiefasd".to_string().into_bytes(),
    };
    let inner = KeyFilesSaveRequest {
        request_id: None,
        node_id: node.id.to_string(),
        key_files: vec![key_file.clone()],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { save, request, tonic::Code::Ok, db, KeyFilesClient<Channel> };

    let inner = KeyFilesSaveRequest {
        request_id: None,
        node_id: node.id.to_string(),
        key_files: vec![key_file],
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );

    assert_grpc_request! { save, request, tonic::Code::InvalidArgument, db, KeyFilesClient<Channel> };
}
