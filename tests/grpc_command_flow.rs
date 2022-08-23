mod setup;

use api::grpc::blockjoy::{
    command_flow_client::CommandFlowClient, command_flow_server::CommandFlowServer,
    info_update::Info, InfoUpdate, NodeInfo, NodeType, Uuid as GrpcUuid,
};
use api::grpc::command_flow::CommandFlowServerImpl;
use api::models::{Host, HostCmd};
use setup::setup;
use sqlx::PgPool;
use std::convert::TryFrom;
use std::future::Future;
use std::sync::Arc;
use tempfile::NamedTempFile;
use test_macros::*;
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{self, Duration};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Channel, Endpoint, Server, Uri};
use tonic::{IntoStreamingRequest, Request, Status};
use tower::service_fn;
use uuid::Uuid;

async fn server_and_client_stub(
    db: Arc<PgPool>,
) -> (impl Future<Output = ()>, CommandFlowClient<Channel>) {
    let socket = NamedTempFile::new().unwrap();
    let socket = Arc::new(socket.into_temp_path());
    std::fs::remove_file(&*socket).unwrap();

    let uds = UnixListener::bind(&*socket).unwrap();
    let stream = UnixListenerStream::new(uds);

    let serve_future = async {
        let result = api::grpc::server(db)
            .await
            .serve_with_incoming(stream)
            .await;

        assert!(result.is_ok());
        dbg!("Server is running");
    };

    let socket = Arc::clone(&socket);
    // Connect to the server over a Unix socket
    // The URL will be ignored.
    let channel = Endpoint::try_from("http://any.url")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = Arc::clone(&socket);
            async move { UnixStream::connect(&*socket).await }
        }))
        .await
        .unwrap();

    let client = CommandFlowClient::new(channel);

    (serve_future, client)
}

fn node_info_requests_iter() -> impl Stream<Item = InfoUpdate> {
    tokio_stream::iter(1..usize::MAX).map(|i| InfoUpdate {
        info: Some(Info::Node(NodeInfo {
            id: Some(GrpcUuid::from(Uuid::new_v4())),
            name: Some("strizzi".into()),
            ip: Some("123.456.789.0".into()),
            block_height: Some(i as i64),
            onchain_name: Some("strizzi-asdfasdf".into()),
            app_status: None,
            container_status: None,
            sync_status: None,
            staking_status: None,
        })),
    })
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_unauthenticated_without_valid_token_for_node_command() {
    let db = Arc::new(_before_values.await);
    let (serve_future, mut client) = server_and_client_stub(db.clone()).await;

    let request_future = async {
        let in_stream = node_info_requests_iter().take(10);

        match client.commands(in_stream).await {
            Ok(response) => {
                let mut response_stream = response.into_inner();

                while let Some(received) = response_stream.next().await {
                    let received = received.unwrap();
                    println!("\treceived message: `{:?}`", received);
                }
            }
            Err(e) => {
                let s = Status::from(e);
                dbg!(&s);
                assert_eq!(tonic::Code::Unauthenticated, s.code());
            }
        }
    };

    // Wait for completion, when the client request future completes
    tokio::select! {
        _ = serve_future => panic!("server returned first"),
        _ = request_future => (),
    }
}

#[before(call = "setup")]
#[tokio::test]
async fn responds_ok_with_valid_token_for_node_command() {
    let db = Arc::new(_before_values.await);
    let (serve_future, mut client) = server_and_client_stub(db.clone()).await;

    let request_future = async {
        println!("creating request");
        let in_stream = node_info_requests_iter().take(10);

        let mut request = Request::new(in_stream).into_streaming_request();

        println!("setting request metadata");

        request
            .metadata_mut()
            .insert("authorization", "1234".to_string().parse().unwrap());

        match client.commands(request).await {
            Ok(response) => {
                println!("got response");
                let mut response_stream = response.into_inner();

                while let Some(received) = response_stream.next().await {
                    let received = received.unwrap();
                    println!("\treceived message: `{:?}`", received);
                }
            }
            Err(e) => {
                println!("got some status");
                let s = Status::from(e);
                dbg!(&s);
                assert_eq!(tonic::Code::Unauthenticated, s.code());
            }
        }
    };

    let db_clone = db.clone();

    let create_commands = async move {
        println!("creating commands");

        let hosts = Host::find_all(&db).await.unwrap();

        // create new command so the DB can notify our server about it
        for host in hosts {
            println!("creating command for host {}", host.id);
            let mut tx = db.begin().await.unwrap();

            sqlx::query("insert into commands (host_id, cmd, sub_cmd) values ($1, $2, $3)")
                .bind(host.id)
                .bind(HostCmd::GetNodeVersion)
                // Using host id again, just to have some valid uuid
                .bind(host.id)
                .execute(&mut tx)
                .await
                .expect("Some error at inserting command");

            tx.commit().await.expect("Some error at committing tx");
        }
    };

    let sleep = time::sleep(Duration::from_secs(1));
    tokio::pin!(sleep);

    // Wait for completion, when the client request future completes
    tokio::select! {
        _ = &mut sleep => {
                create_commands.await;
                db_clone.close().await;
            }
        _ = request_future => (),
        _ = serve_future => panic!("server returned first"),
    }
}
