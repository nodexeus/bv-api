#[allow(dead_code)]
mod setup;

use crate::setup::{get_admin_user, get_blockchain, get_test_host};
use api::auth::TokenIdentifyable;
use api::grpc::blockjoy_ui::node_service_client::NodeServiceClient;
use api::grpc::blockjoy_ui::{GetNodeRequest, RequestMeta, Uuid as GrpcUuid};
use api::models::{
    ContainerStatus, Node, NodeChainStatus, NodeCreateRequest, NodeSyncStatus, NodeType, Org,
};
use setup::{server_and_client_stub, setup};
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
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GetNodeRequest {
        meta: Some(request_meta),
        id: None,
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::NotFound, db, NodeServiceClient<Channel> };
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_id_for_get() {
    let db = Arc::new(_before_values.await);
    let request_meta = RequestMeta {
        id: Some(GrpcUuid::from(Uuid::new_v4())),
        token: None,
        fields: vec![],
        limit: None,
    };
    let blockchain = get_blockchain(&db).await;
    let host = get_test_host(&db).await;
    let user = get_admin_user(&db).await;
    let org_id = Org::find_all_by_user(user.id, &db)
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let req = NodeCreateRequest {
        host_id: host.id,
        org_id: org_id,
        blockchain_id: blockchain.id,
        node_type: NodeType::Validator,
        chain_status: NodeChainStatus::Unknown,
        sync_status: NodeSyncStatus::Syncing,
        container_status: ContainerStatus::Installing,
        address: None,
        wallet_address: None,
        block_height: None,
        groups: None,
        node_data: None,
        ip_addr: None,
        name: None,
        version: None,
        staking_status: None,
    };
    let node = Node::create(&req, &db).await.unwrap();
    let user = get_admin_user(&db).await;
    let token = user.get_token(&db).await.unwrap();
    let inner = GetNodeRequest {
        meta: Some(request_meta),
        id: Some(GrpcUuid::from(node.id)),
    };
    let mut request = Request::new(inner);

    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    assert_grpc_request! { get, request, tonic::Code::Ok, db, NodeServiceClient<Channel> };
}
