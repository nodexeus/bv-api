mod setup;

use api::grpc::blockjoy::{self, command_flow_client, info_update};
use api::grpc::blockjoy_ui::{self, command_service_client::CommandServiceClient};
use setup::TestStream;
use std::marker::PhantomData;
use tonic::transport;

type Service = command_flow_client::CommandFlowClient<transport::Channel>;

#[tokio::test]
async fn command_flow_works() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let token = tester.token_for(&host).await;
    let req = blockjoy::InfoUpdate {
        info: Some(info_update::Info::Node(blockjoy::NodeInfo {
            id: tester.node().await.id.to_string(),
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

    let mut stream = tester
        .open_stream_with(Service::commands, tokio_stream::once(req), token)
        .await
        .unwrap();
    stream.assert_empty().await;
}

#[tokio::test]
async fn non_existent_node() {
    let tester = setup::Tester::new().await;
    let host = tester.host().await;
    let token = tester.token_for(&host).await;
    let req = blockjoy::InfoUpdate {
        info: Some(info_update::Info::Node(blockjoy::NodeInfo {
            id: "1f950d23-9e53-4ff6-aff7-4ddf6ee39f55".to_string(),
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

    let mut stream = tester
        .open_stream_with(Service::commands, tokio_stream::once(req), token)
        .await
        .unwrap();
    let msg = stream.assert_receives().await.unwrap_err();
    assert_eq!(msg.message(), "Record not found.");
}

#[tokio::test]
async fn concurrent_streams() {
    type CmdService = CommandServiceClient<transport::Channel>;

    let tester = setup::Tester::new().await;
    let host1 = tester.host().await;
    let host2 = tester.host2().await;
    let token1 = tester.token_for(&host1).await;
    let token2 = tester.token_for(&host2).await;

    let mut stream1 = tester
        .open_stream_with(Service::commands, Eternal::new(), &token1)
        .await
        .unwrap();
    let mut stream2 = tester
        .open_stream_with(Service::commands, Eternal::new(), &token2)
        .await
        .unwrap();

    let req = blockjoy_ui::CommandRequest {
        meta: Some(tester.meta()),
        id: host1.id.to_string(),
        params: vec![blockjoy_ui::Parameter {
            name: "resource_id".to_string(),
            value: tester.node().await.id.to_string(),
        }],
    };
    tester
        .send_with(CmdService::start_node, req, &token1)
        .await
        .unwrap();

    let resp = stream1.assert_receives().await.unwrap();
    assert!(resp.r#type.is_some());
    stream2.assert_empty().await;
}

/// The eternal stream that never closes. We use this to keep the stream open after we insert data,
/// so the server doesn't think that the client has stopped listening and we can check for a
/// response.
struct Eternal<T>(PhantomData<T>);

impl<T> Eternal<T> {
    fn new() -> Self {
        Self(Default::default())
    }
}

impl<T> futures_util::Stream for Eternal<T> {
    type Item = T;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Pending
    }
}
