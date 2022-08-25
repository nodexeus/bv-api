use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy::{
    command_flow_server::CommandFlow, info_update::Info as GrpcInfo, Command as GrpcCommand,
    Command, InfoUpdate, NodeInfo,
};
use crate::models::{Command as DbCommand, Host};
use crate::models::{Node, UpdateInfo};
use crate::server::DbPool;
use anyhow::anyhow;
use sqlx::postgres::{PgListener, PgNotification};
use sqlx::PgPool;
use std::pin::Pin;
use std::sync::Arc;
use std::{env, error::Error};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::codegen::futures_core::Stream;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

#[allow(dead_code)]
fn match_for_io_error(err_status: &Status) -> Option<&std::io::Error> {
    let mut err: &(dyn Error + 'static) = err_status;

    loop {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
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
}

impl CommandFlowServerImpl {
    pub fn new(db: DbPool) -> Self {
        let buffer_size: usize = env::var("BIDI_BUFFER_SIZE")
            .map(|bs| bs.parse::<usize>())
            .unwrap()
            .unwrap_or(128);

        Self { db, buffer_size }
    }

    /// Actually perform info update on an identified resource
    async fn handle_info_update<T, R>(info: T, db: DbPool) -> ApiResult<R>
    where
        R: UpdateInfo<T, R>,
    {
        // TODO: check ownership
        R::update_info(info, db).await
    }

    async fn process_info_update(
        db: Arc<PgPool>,
        update_sender: Sender<Result<Command, Status>>,
        update: InfoUpdate,
    ) -> ApiResult<()> {
        let update_result = match update.info.unwrap() {
            GrpcInfo::Command(_cmd_info) => unimplemented!(), // Self::handle_info_update::<CommandInfo, Command>(cmd_info, db),
            GrpcInfo::Host(_host_info) => unimplemented!(), // Self::handle_info_update::<HostInfo, Host>(host_info, db),
            GrpcInfo::Node(node_info) => Self::handle_info_update::<NodeInfo, Node>(node_info, db),
        }
        .await;

        match update_result {
            // send status info if error occurred
            Err(e) => match update_sender.send(Err(Status::from(e))).await {
                Ok(_) => Ok(()),
                Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
            },
            _ => Ok(()), // just return unit type if all went well
        }
    }

    /// Received notification about new command row, sending corresponding message
    async fn process_notification(
        notification: PgNotification,
        db: DbPool,
        sender: Sender<Result<Command, Status>>,
    ) -> ApiResult<()> {
        let cmd_id = Uuid::parse_str(notification.payload()).unwrap();
        let command = DbCommand::find_by_id(cmd_id, &db).await;

        match command {
            Ok(command) => {
                let msg = GrpcCommand::from(command);
                match sender.send(Ok(msg)).await {
                    Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    _ => Ok(()), // just return unit type if all went well
                }
            }
            Err(e) => {
                let msg = Status::from(e);

                match sender.send(Err(msg)).await {
                    Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {}", e))),
                    _ => Ok(()), // just return unit type if all went well
                }
            }
        }
    }

    #[cfg(not(test))]
    async fn handle_notifications(
        host_id: Uuid,
        db: Arc<PgPool>,
        sender: Sender<Result<Command, Status>>,
    ) -> Result<(), Status> {
        let mut db_listener = PgListener::connect_with(&db.clone()).await.unwrap();

        if let Err(e) = db_listener.listen("new_commands").await {
            tracing::error!("Couldn't create PgListener: {:?}", e);
            return Err(Status::resource_exhausted(format!("{}", e)));
        }

        while let Ok(notification) = db_listener.recv().await {
            Self::process_notification(notification, db.clone(), sender.clone()).await?
        }

        // Connection broke
        match Host::toggle_online(host_id, false, &db.clone()).await {
            Ok(_) => Ok(()),
            Err(e) => Err(Status::from(e)),
        }
    }

    #[cfg(test)]
    async fn handle_notifications(
        host_id: Uuid,
        db: Arc<PgPool>,
        sender: Sender<Result<Command, Status>>,
    ) -> Result<(), Status> {
        let mut db_listener = PgListener::connect_with(&db.clone()).await.unwrap();

        if let Err(e) = db_listener.listen("new_commands").await {
            tracing::error!("Couldn't create PgListener: {:?}", e);
            return Err(Status::resource_exhausted(format!("{}", e)));
        }

        let mut cnt: usize = 0;

        while let Ok(notification) = db_listener.recv().await {
            if cnt > 4 {
                break;
            }

            Self::process_notification(notification, db.clone(), sender.clone()).await?;

            cnt += 1;
        }

        // Connection broke
        match Host::toggle_online(host_id, false, &db.clone()).await {
            Ok(_) => Ok(()),
            Err(e) => Err(Status::from(e)),
        }
    }
}

#[tonic::async_trait]
impl CommandFlow for CommandFlowServerImpl {
    type CommandsStream = Pin<Box<dyn Stream<Item = Result<GrpcCommand, Status>> + Send + 'static>>;

    async fn commands(
        &self,
        request: Request<Streaming<InfoUpdate>>,
    ) -> Result<Response<Self::CommandsStream>, Status> {
        // Host must be added by middleware beforehand
        let host_id = match request.extensions().get::<Host>() {
            Some(host) => host.id,
            None => return Err(Status::permission_denied("No authorizable found")),
        };

        // Host::toggle_online(host_id, true, &self.db).await?;

        let (tx, rx) = mpsc::channel(self.buffer_size);
        let mut update_stream = request.into_inner();

        // Clones intended to be moved inside async closures
        let db = self.db.clone();
        let sender = tx.clone();

        // Create task handling incoming updates
        let handle_updates = tokio::spawn(async move {
            while let Some(Ok(update)) = update_stream.next().await {
                Self::process_info_update(db.clone(), sender.clone(), update).await?
            }

            // Connection broke
            match Host::toggle_online(host_id, false, &db.clone()).await {
                Ok(_) => Ok(()),
                Err(e) => Err(Status::from(e)),
            }
        });

        let db = self.db.clone();
        let sender = tx.clone();

        // Create task handling incoming DB notifications
        let handle_notifications =
            tokio::spawn(Self::handle_notifications(host_id, db.clone(), sender));

        // Join handles to ensure max. concurrency
        match tokio::try_join!(handle_updates, handle_notifications) {
            Ok(_) => tracing::info!("All tasks finished"),
            Err(e) => tracing::error!("Error in some task: {}", e),
        }

        let commands_stream = ReceiverStream::new(rx);

        Ok(Response::new(
            Box::pin(commands_stream) as Self::CommandsStream
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{Host, HostCmd};
    use http::Uri;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;
    use std::convert::TryFrom;
    use std::future::Future;
    use std::sync::Arc;

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

    async fn setup() -> PgPool {
        dotenv::dotenv().ok();

        let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
        if db_url.contains("digitalocean") {
            panic!("Attempting to use production db?");
        }
        let db_max_conn = std::env::var("DB_MAX_CONN")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap();

        PgPoolOptions::new()
            .max_connections(db_max_conn)
            .connect(&db_url)
            .await
            .expect("Could not create db connection pool.")
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
                Err(s) => {
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
