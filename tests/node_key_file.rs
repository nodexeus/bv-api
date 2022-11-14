mod setup;

use api::models::{
    ContainerStatus, CreateNodeKeyFileRequest, Node, NodeChainStatus, NodeCreateRequest,
    NodeKeyFile, NodeSyncStatus, NodeType, NodeTypeKey, Org,
};
use setup::setup;
use sqlx::types::Json;
use test_macros::before;

#[before(call = "setup")]
#[tokio::test]
async fn can_create_key_file() -> anyhow::Result<()> {
    let db = _before_values.await;
    let host = db.test_host().await;
    let blockchain = db.blockchain().await;
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
        key_files: vec![],
    };
    let node = Node::create(&req, &db.pool).await.unwrap();
    let req = CreateNodeKeyFileRequest {
        name: "my-key.txt".to_string(),
        content:
            "asödlfasdf asdfjaöskdjfalsdjföasjdf afa sdffasdfasldfjasödfj asdföalksdföalskdjfa"
                .to_string(),
        node_id: node.id,
    };
    let file = NodeKeyFile::create(req, &db.pool).await?;

    assert_eq!(file.name(), &"my-key.txt".to_string());

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn cannot_create_key_file_for_unknown_node() -> anyhow::Result<()> {
    let db = _before_values.await;
    let req = CreateNodeKeyFileRequest {
        name: "my-key.txt".to_string(),
        content:
            "asödlfasdf asdfjaöskdjfalsdjföasjdf afa sdffasdfasldfjasödfj asdföalksdföalskdjfa"
                .to_string(),
        node_id: uuid::Uuid::new_v4(),
    };

    assert!(NodeKeyFile::create(req, &db.pool).await.is_err());

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn deletes_key_file_if_node_is_deleted() -> anyhow::Result<()> {
    let db = _before_values.await;
    let host = db.test_host().await;
    let blockchain = db.blockchain().await;
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
        key_files: vec![],
    };
    let node = Node::create(&req, &db.pool).await.unwrap();
    let req = CreateNodeKeyFileRequest {
        name: "my-key.txt".to_string(),
        content:
            "asödlfasdf asdfjaöskdjfalsdjföasjdf afa sdffasdfasldfjasödfj asdföalksdföalskdjfa"
                .to_string(),
        node_id: node.id,
    };
    let file = NodeKeyFile::create(req, &db.pool).await?;

    assert_eq!(file.name(), &"my-key.txt".to_string());

    Node::delete(node.id, &db.pool).await?;

    let cnt: i32 = sqlx::query_scalar("select count(*)::int from node_key_files")
        .fetch_one(&db.pool)
        .await?;

    assert_eq!(cnt, 0);

    Ok(())
}
