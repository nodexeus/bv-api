#[allow(dead_code)]
mod setup;

use api::auth::{HostAuthToken, JwtToken, TokenType};
use api::grpc::blockjoy::command_flow_client::CommandFlowClient;
use api::grpc::blockjoy::info_update::Info;
use api::grpc::blockjoy::{self, NodeInfo};
use api::models::{Host, Node};
use setup::server_and_client_stub;
use test_macros::*;
use tonic::transport::Channel;
use tonic::Request;

async fn setup() -> (api::TestDb, Node) {
    let db = setup::setup().await;
    let node: Node = sqlx::query_as(
        r#"INSERT INTO
                nodes (org_id, host_id, node_type, blockchain_id)
            VALUES
                ((SELECT id FROM orgs LIMIT 1), (SELECT id FROM hosts LIMIT 1), '{"id":404}', (SELECT id FROM blockchains LIMIT 1))
            RETURNING *;"#,
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    (db, node)
}

#[before(call = "setup")]
#[tokio::test(flavor = "multi_thread")]
async fn test_command_flow_works() {
    let (db, node) = _before_values.await;
    let hosts = Host::find_all(&db.pool).await.unwrap();
    let host = hosts.first().unwrap();
    let token = HostAuthToken::create_token_for::<Host>(host, TokenType::HostAuth).unwrap();
    // let node: Node = sqlx::query_as("INSERT INTO nodes VALUES (")
    let req = blockjoy::InfoUpdate {
        info: Some(Info::Node(NodeInfo {
            id: node.id.to_string(),
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
        format!("Bearer {}", token.to_base64().unwrap())
            .parse()
            .unwrap(),
    );
    req.metadata_mut().insert(
        "cookie",
        format!(
            "refresh={}",
            db.host_refresh_token(*token.id()).encode().unwrap()
        )
        .parse()
        .unwrap(),
    );

    let pool = std::sync::Arc::new(db.pool.clone());
    let (serve_future, mut client) =
        server_and_client_stub::<CommandFlowClient<Channel>>(pool).await;

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
