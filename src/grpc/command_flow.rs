use super::helpers::required;
use crate::auth::TokenType;
use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy::{
    command_flow_server::CommandFlow, info_update::Info as GrpcInfo, Command as GrpcCommand,
    CommandInfo, HostInfo, InfoUpdate, NodeInfo,
};
use crate::grpc::convert::db_command_to_grpc_command;
use crate::grpc::helpers::try_get_token;
use crate::grpc::notification::{ChannelNotification, ChannelNotifier, NotificationPayload};
use crate::models::{self, Command as DbCommand, Host, Node, UpdateInfo};
use crate::server::DbPool;
use anyhow::anyhow;
use sqlx::PgPool;
use std::pin::Pin;
use std::sync::Arc;
use std::{env, error::Error};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::codegen::futures_core::Stream;
use tonic::{Request, Response, Status, Streaming};

#[allow(dead_code)]
fn match_for_io_error(err_status: &Status) -> Option<&std::io::Error> {
    let mut err: &(dyn Error + 'static) = err_status;

    loop {
        if let Some(io_err) = err.downcast_ref() {
            return Some(io_err);
        }

        // h2::Error do not expose std::io::Error with `source()`
        // https://github.com/hyperium/h2/pull/462
        if let Some(h2_err) = err.downcast_ref::<h2::Error>() {
            if let Some(io_err) = h2_err.get_io() {
                return Some(io_err);
            }
        }

        err = match err.source() {
            Some(err) => err,
            None => return None,
        };
    }
}

pub struct CommandFlowServerImpl {
    db: DbPool,
    buffer_size: usize,
    notifier: Arc<ChannelNotifier>,
}

impl CommandFlowServerImpl {
    pub fn new(db: DbPool, notifier: Arc<ChannelNotifier>) -> Self {
        let buffer_size: usize = env::var("BIDI_BUFFER_SIZE")
            .ok()
            .and_then(|bs| bs.parse().ok())
            .unwrap_or(128);

        Self {
            db,
            buffer_size,
            notifier,
        }
    }

    /// Actually perform info update on an identified resource
    async fn handle_info_update<T, R>(info: T, db: DbPool) -> ApiResult<R>
    where
        R: UpdateInfo<T, R>,
    {
        // TODO: check ownership
        R::update_info(info, &db).await
    }

    async fn process_info_update(
        db: Arc<PgPool>,
        update_sender: mpsc::Sender<Result<GrpcCommand, Status>>,
        update: InfoUpdate,
    ) -> ApiResult<()> {
        let info = update.info.ok_or_else(required("update.info"))?;
        match info {
            GrpcInfo::Command(cmd_info) => {
                match Self::handle_info_update::<CommandInfo, DbCommand>(cmd_info, db).await {
                    Ok(_) => Ok(()),
                    Err(e) => match update_sender.send(Err(Status::from(e))).await {
                        Ok(_) => Ok(()),
                        Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    },
                }
            }
            GrpcInfo::Host(host_info) => {
                match Self::handle_info_update::<HostInfo, Host>(host_info, db).await {
                    Ok(_) => Ok(()),
                    Err(e) => match update_sender.send(Err(Status::from(e))).await {
                        Ok(_) => Ok(()),
                        Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    },
                }
            }
            GrpcInfo::Node(node_info) => {
                match Self::handle_info_update::<NodeInfo, Node>(node_info, db).await {
                    Ok(_) => Ok(()),
                    Err(e) => match update_sender.send(Err(Status::from(e))).await {
                        Ok(_) => Ok(()),
                        Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    },
                }
            }
        }
    }

    /// Received notification about new command row, sending corresponding message
    async fn process_notification(
        notification: NotificationPayload,
        db: DbPool,
        sender: mpsc::Sender<Result<GrpcCommand, Status>>,
    ) -> ApiResult<()> {
        let cmd_id = notification.get_id();
        let command = DbCommand::find_by_id(cmd_id, &db).await;

        tracing::info!("Testing for command with ID {}", cmd_id);

        match command {
            Ok(command) => {
                tracing::info!("Command found");
                let msg = db_command_to_grpc_command(command, db.clone()).await?;
                match sender.send(Ok(msg)).await {
                    Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    _ => {
                        tracing::info!("Sent channel notification");
                        Ok(())
                    } // just return unit type if all went well
                }
            }
            Err(e) => {
                tracing::info!("Command with ID {} NOT found", cmd_id);

                let msg = Status::from(e);

                match sender.send(Err(msg)).await {
                    Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    _ => {
                        tracing::info!("Sent channel notification");
                        Ok(())
                    } // just return unit type if all went well
                }
            }
        }
    }

    async fn handle_notifications(
        host_id: uuid::Uuid,
        db: Arc<PgPool>,
        mut notifications: broadcast::Receiver<ChannelNotification>,
        stream_sender: mpsc::Sender<Result<GrpcCommand, Status>>,
        mut stop_tx: mpsc::Receiver<()>,
    ) -> Result<(), Status> {
        tracing::info!("Starting handling channel notifications");

        loop {
            tokio::select! {
                notification = notifications.recv() => {
                    tracing::info!("Received notification");
                    match notification {
                        Ok(ChannelNotification::Command(cmd)) => {
                            tracing::info!("Notification is a command notification: {:?}", cmd);
                            Self::process_notification(cmd, db.clone(), stream_sender.clone()).await?
                        }
                        Ok(_) => tracing::error!("received non Command notification"),
                        Err(e) => {
                            tracing::error!("Channel returned error: {e:?}");
                            break;
                        }
                    }
                },
                // When we receive a stop message, we break the loop
                _ = stop_tx.recv() => break,
            }
        }

        // Connection broke
        Host::toggle_online(host_id, false, &db).await?;
        Ok(())
    }
}

#[tonic::async_trait]
impl CommandFlow for CommandFlowServerImpl {
    type CommandsStream = Pin<Box<dyn Stream<Item = Result<GrpcCommand, Status>> + Send + 'static>>;

    async fn commands(
        &self,
        request: Request<Streaming<InfoUpdate>>,
    ) -> Result<Response<Self::CommandsStream>, Status> {
        // DB token must be added by middleware beforehand
        let db_token = try_get_token(&request)?.token;
        let host_id = models::Token::get_host_for_token(&db_token, TokenType::Login, &self.db)
            .await?
            .id;

        Host::toggle_online(host_id, true, &self.db).await?;

        let (tx, rx) = mpsc::channel(self.buffer_size);

        // We will use this channel to signal to our event listener to stop when the user closes it
        // stream.
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let mut update_stream = request.into_inner();

        // Clones intended to be moved inside async closures
        let db = self.db.clone();
        let sender = tx.clone();

        // Create task handling incoming updates
        tokio::spawn(async move {
            tracing::debug!("Started waiting for InfoUpdates");
            while let Some(Ok(update)) = update_stream.next().await {
                Self::process_info_update(db.clone(), sender.clone(), update).await?
            }

            tracing::debug!("Stopped waiting for InfoUpdates");
            // Since we are done, we should instruct the other task to also stop.
            stop_tx
                .send(())
                .await
                .map_err(|_| Status::internal("Channel error"))?;

            // Connection broke or closed
            match Host::toggle_online(host_id, false, &db).await {
                Ok(_) => Ok(()),
                Err(e) => Err(Status::from(e)),
            }
        });

        let db = self.db.clone();
        let sender = tx;
        let notifier = self.notifier.commands_receiver();

        // Create task handling incoming notifications
        let notification_task = Self::handle_notifications(host_id, db, notifier, sender, stop_rx);
        tokio::spawn(notification_task);

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
    use crate::grpc::blockjoy::info_update::Info;
    use crate::grpc::blockjoy::{command_flow_client::CommandFlowClient, Uuid as GrpcUuid};
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

    pub async fn get_test_host(db: &PgPool) -> Host {
        sqlx::query("select h.*, t.token, t.role from hosts h right join tokens t on h.id = t.host_id where name = 'Host-1'")
            .map(Host::from)
            .fetch_one(db)
            .await
            .unwrap()
    }

    fn node_info_requests_iter() -> impl Stream<Item = InfoUpdate> {
        tokio_stream::iter(1..=10).map(|i| InfoUpdate {
            info: Some(Info::Node(NodeInfo {
                id: Some(GrpcUuid::from(Uuid::new_v4())),
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
        let host = get_test_host(&db.pool).await;
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
