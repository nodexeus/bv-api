use crate::grpc::blockjoy_ui::command_service_server::CommandService;
use crate::grpc::blockjoy_ui::{CommandRequest, CommandResponse, ResponseMeta};
use crate::grpc::notification::{ChannelNotification, ChannelNotifier, NotificationPayload};
use crate::models::{Command, CommandRequest as DbCommandRequest, HostCmd};
use crate::server::DbPool;
use crossbeam_channel::SendError;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct CommandServiceImpl {
    db: DbPool,
    notifier: ChannelNotifier,
}

impl CommandServiceImpl {
    pub fn new(db: DbPool, notifier: ChannelNotifier) -> Self {
        Self { db, notifier }
    }

    async fn create_command(
        &self,
        host_id: Uuid,
        cmd: HostCmd,
        sub_cmd: Option<String>,
    ) -> crate::errors::Result<Command> {
        let req = DbCommandRequest { cmd, sub_cmd };

        Command::create(host_id, req, &self.db).await
    }

    fn send_notification(
        &self,
        notification: ChannelNotification,
    ) -> Result<(), SendError<ChannelNotification>> {
        tracing::debug!("Sending notification: {:?}", notification);
        self.notifier.commands_sender().send(notification)
    }
}

macro_rules! create_command {
    ($obj:expr, $req:expr, $cmd:expr, $sub_cmd:expr) => {{
        let inner = $req.into_inner();

        match inner.id {
            Some(host_id) => {
                match $obj
                    .create_command(Uuid::from(host_id), $cmd, $sub_cmd)
                    .await
                {
                    Ok(cmd) => {
                        let notification =
                            ChannelNotification::Command(NotificationPayload::new(cmd.id));

                        match $obj.send_notification(notification) {
                            Ok(_) => {
                                let response_meta =
                                    ResponseMeta::from_meta(inner.meta).with_message(cmd.id);
                                let response = CommandResponse {
                                    meta: Some(response_meta),
                                };

                                Ok(Response::new(response))
                            }
                            Err(e) => Err(Status::internal(e.to_string())),
                        }
                    }
                    Err(e) => Err(Status::from(e)),
                }
            }
            None => Err(Status::not_found("No host ID provided")),
        }
    }};
}

#[tonic::async_trait]
impl CommandService for CommandServiceImpl {
    async fn create_node(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::CreateNode, None }
    }

    async fn delete_node(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::DeleteNode, None }
    }

    async fn start_node(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::RestartNode, None }
    }

    async fn stop_node(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::ShutdownNode, None }
    }

    async fn restart_node(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::RestartNode, None }
    }

    async fn create_host(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::CreateBVS, None }
    }

    async fn delete_host(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::RemoveBVS, None }
    }

    async fn start_host(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::RestartBVS, None }
    }

    async fn stop_host(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::StopBVS, None }
    }

    async fn restart_host(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        create_command! { self, request, HostCmd::RestartBVS, None }
    }

    async fn execute_generic(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}
