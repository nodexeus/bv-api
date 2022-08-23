use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy::{
    command_flow_server::CommandFlow, info_update::Info as GrpcInfo, Command as GrpcCommand,
    Command, CommandInfo, HostInfo, InfoUpdate, NodeInfo as GrpcNodeInfo, NodeInfo,
};
use crate::models::{Command as DbCommand, Host};
use crate::models::{Node, UpdateInfo};
use crate::server::DbPool;
use anyhow::anyhow;
use sqlx::postgres::{PgListener, PgNotification};
use sqlx::PgPool;
use std::pin::Pin;
use std::sync::Arc;
use std::{env, error::Error, io::ErrorKind};
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
            /*
            match Host::toggle_online(host_id, false, &db.clone()).await {
                Ok(_) => Ok(()),
                Err(e) => Err(Status::from(e)),
            }
             */
            Ok(())
        });

        let db = self.db.clone();
        let sender = tx.clone();

        // Create task handling incoming DB notifications
        let handle_notifications = tokio::spawn(async move {
            let mut db_listener = PgListener::connect_with(&db.clone()).await.unwrap();

            if let Err(e) = db_listener.listen("new_commands").await {
                tracing::error!("Couldn't create PgListener: {:?}", e);
                return Err(Status::resource_exhausted(format!("{}", e)));
            }

            while let Ok(notification) = db_listener.recv().await {
                Self::process_notification(notification, db.clone(), sender.clone()).await?
            }

            // Connection broke
            /*
            match Host::toggle_online(host_id, false, &db.clone()).await {
                Ok(_) => Ok(()),
                Err(e) => Err(Status::from(e)),
            }
             */
            Ok(())
        });

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
