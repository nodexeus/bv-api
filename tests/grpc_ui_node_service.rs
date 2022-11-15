#[allow(dead_code)]
mod setup;

use api::auth::{JwtToken, TokenRole, TokenType, UserAuthToken};
use api::grpc::blockjoy_ui::node_service_client::NodeServiceClient;
use api::grpc::blockjoy_ui::{
    node, CreateNodeRequest, GetNodeRequest, Node as GrpcNode, RequestMeta, UpdateNodeRequest,
};
use api::models::{
    ContainerStatus, Node, NodeChainStatus, NodeCreateRequest, NodeSyncStatus, NodeType,
    NodeTypeKey, Org, User,
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
async fn responds_not_found_without_any_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let user = db.admin_user().await;
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = GetNodeRequest {
        meta: Some(request_meta),
        id: Uuid::new_v4().to_string(),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::NotFound, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_id_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let blockchain = db.blockchain().await;
    let host = db.test_host().await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
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
    let user = db.admin_user().await;
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = GetNodeRequest {
        meta: Some(request_meta),
        id: node.id.to_string(),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::Ok, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_data_for_create() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let blockchain = db.blockchain().await;
    let host = db.test_host().await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id
        .to_string();
    let node = GrpcNode {
        id: None,
        host_id: Some(host.id.to_string()),
        org_id: Some(org_id),
        blockchain_id: Some(blockchain.id.to_string()),
        name: None,
        status: Some(node::NodeStatus::UndefinedApplicationStatus as i32),
        address: None,
        r#type: Some(NodeType::special_type(NodeTypeKey::Api).to_json().unwrap()),
        version: None,
        wallet_address: None,
        block_height: None,
        node_data: None,
        ip: None,
        ip_gateway: Some("192.168.0.1".into()),
        created_at: None,
        updated_at: None,
        groups: vec![],
        staking_status: None,
        sync_status: Some(NodeSyncStatus::Unknown as i32),
        self_update: None,
    };
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = CreateNodeRequest {
        meta: Some(request_meta),
        node: Some(node),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { create, request, tonic::Code::Ok, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_with_invalid_data_for_create() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let node = GrpcNode {
        id: None,
        host_id: None,
        // This is required so the test should fail:
        org_id: None,
        blockchain_id: None,
        name: None,
        status: Some(node::NodeStatus::UndefinedApplicationStatus as i32),
        address: None,
        r#type: Some(NodeType::special_type(NodeTypeKey::Api).to_json().unwrap()),
        version: None,
        wallet_address: None,
        block_height: None,
        node_data: None,
        ip: None,
        ip_gateway: None,
        created_at: None,
        updated_at: None,
        groups: vec![],
        staking_status: None,
        sync_status: Some(NodeSyncStatus::Unknown as i32),
        self_update: None,
    };
    let user = db.admin_user().await;
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = CreateNodeRequest {
        meta: Some(request_meta),
        node: Some(node),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { create, request, tonic::Code::InvalidArgument, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_data_for_update() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let blockchain = db.blockchain().await;
    let host = db.test_host().await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id,
        blockchain_id: blockchain.id,
        node_type: Json(NodeType::special_type(NodeTypeKey::Validator)),
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
    let db_node = Node::create(&req, &db.pool).await.unwrap();
    let node = GrpcNode {
        id: Some(db_node.id.to_string()),
        name: Some("stri-bu".to_string()),
        ..Default::default()
    };
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = UpdateNodeRequest {
        meta: Some(request_meta),
        node: Some(node),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { update, request, tonic::Code::Ok, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_internal_with_invalid_data_for_update() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let blockchain = db.blockchain().await;
    let host = db.test_host().await;
    let user = db.admin_user().await;
    let org_id = Org::find_all_by_user(user.id, &db.pool)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id,
        blockchain_id: blockchain.id,
        node_type: Json(NodeType::special_type(NodeTypeKey::Validator)),
        chain_status: NodeChainStatus::Unknown,
        sync_status: NodeSyncStatus::Syncing,
        container_status: ContainerStatus::Installing,
        address: None,
        wallet_address: None,
        block_height: None,
        groups: None,
        node_data: None,
        ip_addr: None,
        ip_gateway: Some("192.168.0.1".to_string()),
        name: None,
        version: None,
        staking_status: None,
        self_update: false,
    };
    let db_node = Node::create(&req, &db.pool).await.unwrap();
    let node = GrpcNode {
        id: Some(db_node.id.to_string()),
        name: Some("stri-bu".to_string()),
        // This should cause an error
        blockchain_id: None,
        ..Default::default()
    };
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = UpdateNodeRequest {
        meta: Some(request_meta),
        node: Some(node),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { update, request, tonic::Code::Internal, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_not_found_with_invalid_id_for_update() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(Uuid::new_v4().to_string()),
        token: None,
        fields: vec![],
        pagination: None,
    };
    let user = db.admin_user().await;
    let node = GrpcNode {
        // This should cause an error
        id: Some(Uuid::new_v4().to_string()),
        ..Default::default()
    };
    let token =
        UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)
            .unwrap();
    let inner = UpdateNodeRequest {
        meta: Some(request_meta),
        node: Some(node),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    request.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.user_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    assert_grpc_request! { update, request, tonic::Code::NotFound, db, NodeServiceClient<Channel> };
}
