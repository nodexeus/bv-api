use crate::errors::{ApiError, Result};
use crate::grpc::helpers::required;
use crate::grpc::{blockjoy, convert, notification};
use crate::models;
use anyhow::anyhow;
use futures_util::StreamExt;
use std::sync;
use tokio::sync::mpsc::Sender;
use tokio::sync::{broadcast, mpsc};

type Message = Result<blockjoy::Command, tonic::Status>;

/// Sets up a set of channels that communicate with each other to handle the messages we need to
/// handle. These are:
/// 1. The updates sent by the host that the user is wanting to listen to. These need to be sent to
///    filtered for relevance (i.e. they need to be related to the current host_id), and then sent
///    to the user.
/// 2. The commands to the host that are sent by the user. Those need to be written to the
///    database.
/// 3. Since we are listening to updates sent by the host, our host-listening-task will never
///    finish. Therefore we need to give a shutdown message to make our host listener stop whenever
///    our user listener stops listening.
pub fn channels(
    host_id: uuid::Uuid,
    host_messages: broadcast::Receiver<notification::ChannelNotification>,
    db: sync::Arc<sqlx::PgPool>,
) -> (mpsc::Receiver<Message>, HostListener, UserListener) {
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (tx, rx) = mpsc::channel(buffer_size());

    let host_listener = HostListener {
        host_id,
        sender: tx.clone(),
        stop: stop_rx,
        messages: host_messages,
        db: db.clone(),
    };
    let user_listener = UserListener {
        host_id,
        sender: tx,
        stop: stop_tx,
        db,
    };
    (rx, host_listener, user_listener)
}

fn buffer_size() -> usize {
    std::env::var("BIDI_BUFFER_SIZE")
        .ok()
        .and_then(|bs| bs.parse().ok())
        .unwrap_or(128)
}

/// This struct listens to the messages being sent by the hosts channel.
pub struct HostListener {
    /// The id of the currently considered host.
    host_id: uuid::Uuid,
    /// This is the channel we can use to send messages to the user.
    sender: mpsc::Sender<Message>,
    /// The messages that are being broadcast by the system. Note that we need to filter them for
    /// relevance using the current `host_id`.
    messages: broadcast::Receiver<notification::ChannelNotification>,
    /// When this channel yields a message we can stop listening.
    stop: mpsc::Receiver<()>,
    /// A reference to a database pool.
    db: sync::Arc<sqlx::PgPool>,
}

impl HostListener {
    /// Starts the HostListener by listening for messages from the host channel, and from the stop
    /// channel. When we receive a message from the host channel, we offload to the
    /// `process_notification` function.
    pub async fn recv(mut self) -> Result<(), tonic::Status> {
        use notification::ChannelNotification::*;

        tracing::info!("Starting handling channel notifications");
        loop {
            tokio::select! {
                message = self.messages.recv() => {
                    tracing::info!("Received notification");
                    match message {
                        Ok(Command(cmd)) => self.process_notification(cmd).await?,
                        Ok(_) => tracing::error!("received non Command notification"),
                        Err(e) => {
                            tracing::error!("Channel returned error: {e:?}");
                            break;
                        }
                    }
                },
                // When we receive a stop message, we break the loop
                _ = self.stop.recv() => break,
            }
        }
        // Connection broke
        models::Host::toggle_online(self.host_id, false, &self.db).await?;
        Ok(())
    }

    /// In this function we decide what to do with the provided notification and then do it. This
    /// means that we get the relevant command from the database, then filter it to decide if it
    /// should be sent to the user, and if so, we perform the action
    async fn process_notification(
        &self,
        notification: notification::NotificationPayload,
    ) -> Result<()> {
        tracing::info!("Notification is a command notification: {notification:?}");

        let cmd_id = notification.get_id();
        let command = models::Command::find_by_id(cmd_id, &self.db).await;

        tracing::info!("Testing for command with ID {cmd_id}");

        match command {
            Ok(command) => {
                tracing::info!("Command found");
                let msg = convert::db_command_to_grpc_command(command, &self.db).await?;
                if !self.relevant(&msg).await? {
                    // If the field was not relevant we are done and can just return Ok(())
                    return Ok(());
                }
                match self.sender.send(Ok(msg)).await {
                    Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {e}"))),
                    _ => {
                        tracing::info!("Sent channel notification");
                        Ok(())
                    } // just return unit type if all went well
                }
            }
            Err(e) => {
                tracing::info!("Command with ID {} NOT found", cmd_id);

                match self.sender.send(Err(e.into())).await {
                    Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {e}"))),
                    _ => {
                        tracing::info!("Sent channel error notification");
                        Ok(())
                    } // just return unit type if all went well
                }
            }
        }
    }

    /// Checks whether a command is relevant for the currently specified host. We use this for
    /// filtering messages before we send them to the user. If the command is relevant for the
    /// current channel, we return `true` from this function.
    async fn relevant(&self, command: &blockjoy::Command) -> Result<bool> {
        use blockjoy::command::Type::*;

        let content = if let Some(content) = command.r#type.as_ref() {
            content
        } else {
            // Do not send empty messages
            return Ok(false);
        };
        let host_id: uuid::Uuid = match content {
            Host(cmd) => cmd.id.as_ref().ok_or_else(required("id"))?.try_into()?,
            Node(cmd) => {
                let node_id = cmd.id.as_ref().ok_or_else(required("id"))?.try_into()?;
                models::Host::find_by_node(node_id, &self.db).await?.id
            }
        };
        Ok(host_id == self.host_id)
    }
}

/// This struct listens to the messages coming from the user. For each message that comes in we
/// write the result to the database, and when the messages are done, we have to signal the
/// `UserListener` to also finish by using the `stop` channel.
pub struct UserListener {
    /// The host we are sending messages about.
    host_id: uuid::Uuid,
    /// This is the channel we can use to send messages to the user.
    sender: Sender<Message>,
    /// We can use this channel to inform the host listener that it should stop listening for
    /// messages, since it will never stop on its own.
    stop: mpsc::Sender<()>,
    /// A database pool.
    db: sync::Arc<sqlx::PgPool>,
}

impl UserListener {
    /// Start receiving messages from the `messsages` channel. It is specified as an argument to
    /// the recv function rather than as a field of the `UserListener` struct because the
    /// `tonic::Streaming` type is not `Sync`, meaning we cannot hold a reference to it across
    /// await points, meaning we would not be able to use `&self` anywhere.
    pub async fn recv(self, mut messages: tonic::Streaming<blockjoy::InfoUpdate>) -> Result<()> {
        tracing::debug!("Started waiting for InfoUpdates");
        while let Some(Ok(update)) = messages.next().await {
            self.process_info_update(update).await?;
        }

        tracing::debug!("Stopped waiting for InfoUpdates");
        // Since we are done, we should instruct the other task to also stop.
        self.stop
            .send(())
            .await
            .map_err(|_| tonic::Status::internal("Channel error"))?;

        // Connection broke or closed
        models::Host::toggle_online(self.host_id, false, &self.db).await?;
        Ok(())
    }

    async fn process_info_update(&self, update: blockjoy::InfoUpdate) -> Result<()> {
        use blockjoy::info_update::Info;

        match update.info.ok_or_else(required("update.info"))? {
            Info::Command(cmd_info) => {
                let res = Self::update_info::<models::Command, _>(cmd_info, &self.db).await;
                self.handle_err(res).await
            }
            Info::Host(host_info) => {
                let res = Self::update_info::<models::Host, _>(host_info, &self.db).await;
                self.handle_err(res).await
            }
            Info::Node(node_info) => {
                let res = Self::update_info::<models::Node, _>(node_info, &self.db).await;
                self.handle_err(res).await
            }
        }
    }

    /// Actually perform info update on an identified resource
    async fn update_info<R, T>(info: T, db: &sqlx::PgPool) -> Result<R>
    where
        R: models::UpdateInfo<T, R>,
    {
        R::update_info(info, db).await
    }

    /// This function is used by `process_info_update` to send messages about failures to the user.
    async fn handle_err<T>(&self, res: Result<T>) -> Result<()> {
        // If we had an `Ok`, there is no message about failure to send, so we break off.
        let err = match res {
            Ok(_) => return Ok(()),
            Err(e) => e,
        };
        // Try to send the message to the user and if that fails, our handlig function fails as well.
        match self.sender.send(Err(err.into())).await {
            Ok(_) => Ok(()),
            Err(e) => Err(ApiError::UnexpectedError(anyhow!("Sender error: {e}"))),
        }
    }
}
