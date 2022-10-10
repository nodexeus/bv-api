use crate::auth::TokenType;
use crate::errors::Result;
use crate::grpc::blockjoy::{command_flow_server::CommandFlow, Command as GrpcCommand, InfoUpdate};
use crate::grpc::helpers::try_get_token;
use crate::grpc::notification::ChannelNotifier;
use crate::models;
use crate::server::DbPool;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::futures_core::Stream;
use tonic::{Request, Response, Status, Streaming};

mod listener;

pub struct CommandFlowServerImpl {
    db: DbPool,
    notifier: Arc<ChannelNotifier>,
}

impl CommandFlowServerImpl {
    pub fn new(db: DbPool, notifier: Arc<ChannelNotifier>) -> Self {
        Self { db, notifier }
    }
}

type CommandsStream = Pin<Box<dyn Stream<Item = Result<GrpcCommand, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl CommandFlow for CommandFlowServerImpl {
    type CommandsStream = CommandsStream;

    /// This endpoint acts as a bidirectional stream. This means that we are both processing
    /// messages that the user sends to the server, as well as events that happen in the server
    /// itself. Since the setup for this is quite involved, it is implemented with two listener
    /// objects, one listening for messages from the user and one listening for events happening in
    /// the server. The can be found in `mod listener`.
    async fn commands(
        &self,
        request: Request<Streaming<InfoUpdate>>,
    ) -> Result<Response<Self::CommandsStream>, Status> {
        // DB token must be added by middleware beforehand
        let db_token = try_get_token(&request)?.token;
        // Get the host that the user wants to listen to from the current login token.
        let host_id = models::Token::get_host_for_token(&db_token, TokenType::Login, &self.db)
            .await?
            .id;
        // Set the host as online.
        models::Host::toggle_online(host_id, true, &self.db).await?;
        let update_stream = request.into_inner();
        let (rx, host_listener, user_listener) =
            listener::channels(host_id, self.notifier.commands_receiver(), self.db.clone());
        tokio::spawn(user_listener.recv(update_stream));
        tokio::spawn(host_listener.recv());
        let commands_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(commands_stream)))
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{Host, HostCmd};
    use crate::TestDb;
    use http::Uri;
    use sqlx::PgPool;
    use std::convert::TryFrom;
    use std::future::Future;
    use std::sync::Arc;

    use crate::auth::TokenIdentifyable;
    use crate::grpc::blockjoy::command_flow_client::CommandFlowClient;
    use crate::grpc::blockjoy::info_update::Info;
    use crate::grpc::blockjoy::{InfoUpdate, NodeInfo};
    use tempfile::NamedTempFile;
    use test_macros::before;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::time::{self, Duration};
    use tokio_stream::wrappers::UnixListenerStream;
    use tokio_stream::{Stream, StreamExt};
    use tonic::transport::{Channel, Endpoint};
    use tonic::{IntoStreamingRequest, Request};
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
            let result = crate::grpc::server(db)
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
        tokio_stream::iter(1..=10).map(|i| InfoUpdate {
            info: Some(Info::Node(NodeInfo {
                id: Uuid::new_v4().to_string(),
                name: Some("strizzi".into()),
                ip: Some("123.456.789.0".into()),
                block_height: Some(i.into()),
                onchain_name: Some("strizzi-asdfasdf".into()),
                app_status: None,
                container_status: None,
                sync_status: None,
                staking_status: None,
            })),
        })
    }

    pub async fn setup() -> TestDb {
        TestDb::setup().await
    }

    /// TODO: Doesn't look like the test is really working
    #[before(call = "setup")]
    #[tokio::test]
    async fn responds_ok_with_valid_token_for_node_command() {
        let db = Arc::new(_before_values.await);
        let (serve_future, mut client) = server_and_client_stub(Arc::new(db.pool.clone())).await;
        let host = db.test_host().await;
        let token = host.get_token(&db.pool).await.unwrap();

        let request_future = async move {
            println!("creating request");
            let in_stream = node_info_requests_iter().take(10);

            let mut request = Request::new(in_stream).into_streaming_request();

            println!("setting request metadata");

            request.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", token.to_base64()).parse().unwrap(),
            );

            match client.commands(request).await {
                Ok(response) => {
                    println!("got response");
                    let mut response_stream = response.into_inner();

                    while let Some(received) = response_stream.next().await {
                        let received = received.unwrap();
                        println!("\treceived message: `{:?}`", received);
                    }
                }
                Err(s) => {
                    panic!("didn't work: {:?}", s)
                }
            }
        };

        let db_clone = db.clone();

        let create_commands = async move {
            println!("creating commands");

            let hosts = Host::find_all(&db.pool).await.unwrap();

            // create new command so the DB can notify our server about it
            for host in hosts {
                println!("creating command for host {}", host.id);
                let mut tx = db.pool.begin().await.unwrap();

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

        // For whatever reason I need to wait for 1 sec here to make the test work
        time::sleep(Duration::from_secs(1)).await;

        // Wait for completion, when the client request future completes
        tokio::select! {
            _ = &mut sleep => {
                    create_commands.await;
                    db_clone.pool.close().await;
                }
            _ = request_future => (),
            _ = serve_future => panic!("server returned first"),
        }
    }

    #[before(call = "setup")]
    #[tokio::test]
    async fn responds_unauthenticated_without_valid_token_for_node_command() {
        let db = Arc::new(_before_values.await);
        let (serve_future, mut client) = server_and_client_stub(Arc::new(db.pool.clone())).await;

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
                Err(s) => {
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
}
