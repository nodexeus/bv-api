#[allow(dead_code)]
mod setup;

use api::auth::TokenIdentifyable;
use api::grpc::blockjoy::command_flow_client::CommandFlowClient;
use api::grpc::blockjoy::info_update::Info;
use api::grpc::blockjoy::{self, NodeInfo};
use api::models::{Host, Node};
use setup::server_and_client_stub;
use std::sync::Arc;
use test_macros::*;
use tonic::transport::Channel;
use tonic::Request;

async fn setup() -> (Arc<sqlx::PgPool>, Node) {
    let db = setup::setup().await;
    let node: Node = sqlx::query_as(
        r#"INSERT INTO
                nodes (org_id, host_id, node_type, blockchain_id)
            VALUES
                ((SELECT id FROM orgs LIMIT 1), (SELECT id FROM hosts LIMIT 1), '{"id":404}', (SELECT id FROM blockchains LIMIT 1))
            RETURNING *;"#,
    )
    .fetch_one(&db)
    .await
    .unwrap();
    (Arc::new(db), node)
}

#[before(call = "setup")]
#[tokio::test(flavor = "multi_thread")]
async fn test_that_streaming_does_something_plzzzz() {
    let (db, node) = _before_values.await;
    let hosts = Host::find_all(&db).await.unwrap();
    let host = hosts.first().unwrap();
    let token = host.get_token(&db).await.unwrap();
    // let node: Node = sqlx::query_as("INSERT INTO nodes VALUES (")
    let req = blockjoy::InfoUpdate {
        info: Some(Info::Node(NodeInfo {
            id: Some(node.id.into()),
            name: None,
            ip: None,
            block_height: None,
            onchain_name: None,
            app_status: Some(8),
            container_status: None,
            sync_status: Some(1),
            staking_status: Some(1),
        })),
    };
    let strm = tokio_stream::once(req);
    let mut req = Request::new(strm);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_base64()).parse().unwrap(),
    );

    let (serve_future, mut client) = server_and_client_stub::<CommandFlowClient<Channel>>(db).await;

    let request_future = async {
        let response = client.commands(req).await.unwrap();
        let mut inner = response.into_inner();
        // Stream the entire contents of the response to see if all of them succeed
        while let Some(_resp) = inner.message().await.unwrap() {}
        println!("response OK: {:?}", inner);
    };

    // Wait for completion, when the client request future completes
    tokio::select! {
        _ = serve_future => panic!("server returned first"),
        _ = request_future => (),
    }
}
