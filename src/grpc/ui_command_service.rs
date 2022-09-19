use crate::grpc::blockjoy_ui::command_service_server::CommandService;
use crate::grpc::blockjoy_ui::{
    response_meta, CommandRequest, CommandResponse, Parameter, ResponseMeta,
};
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
        params: Vec<Parameter>,
    ) -> Result<Command, Status> {
        match Self::get_resource_id_from_params(params) {
            Ok(resource_id) => {
                let req = DbCommandRequest {
                    cmd,
                    sub_cmd,
                    resource_id,
                };

                Ok(Command::create(host_id, req, &self.db).await?)
            }
            Err(status) => Err(status),
        }
    }

    fn send_notification(
        &self,
        notification: ChannelNotification,
    ) -> Result<(), SendError<ChannelNotification>> {
        tracing::debug!("Sending notification: {:?}", notification);
        self.notifier.commands_sender().send(notification)
    }

    fn get_resource_id_from_params(params: Vec<Parameter>) -> Result<Uuid, Status> {
        for param in params {
            if param.name == "resource_id" {
                return match param.value {
                    Some(val) => Ok(Uuid::from_slice(val.value.as_slice())
                        .map_err(|e| Status::internal(e.to_string()))
                        .unwrap()),
                    None => Err(Status::internal("Resource ID can't be empty")),
                };
            }
        }

        Err(Status::internal("Resource ID not available"))
    }
}

macro_rules! create_command {
    ($obj:expr, $req:expr, $cmd:expr, $sub_cmd:expr) => {{
        let inner = $req.into_inner();

        match inner.id {
            Some(host_id) => {
                let cmd = $obj
                    .create_command(Uuid::from(host_id), $cmd, $sub_cmd, inner.params)
                    .await?;

                let notification = ChannelNotification::Command(NotificationPayload::new(cmd.id));

                match $obj.send_notification(notification) {
                    Ok(_) => {
                        let response_meta = ResponseMeta {
                            status: response_meta::Status::Success.into(),
                            origin_request_id: inner.meta.unwrap().id,
                            messages: vec![cmd.id.to_string()],
                            pagination: None,
                        };
                        let response = CommandResponse {
                            meta: Some(response_meta),
                        };

                        Ok(Response::new(response))
                    }
                    Err(e) => Err(Status::internal(e.to_string())),
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
