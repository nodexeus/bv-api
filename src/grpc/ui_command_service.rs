use crate::grpc::blockjoy_ui::command_service_server::CommandService;
use crate::grpc::blockjoy_ui::{CommandRequest, CommandResponse};
use crate::server::DbPool;
use tonic::{Request, Response, Status};

pub struct CommandServiceImpl {
    db: DbPool,
}

impl CommandServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl CommandService for CommandServiceImpl {
    async fn create_node(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn delete_node(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn start_node(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn stop_node(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn restart_node(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn create_host(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn delete_host(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn start_host(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn stop_host(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn restart_host(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }

    async fn execute_generic(
        &self,
        _request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        todo!()
    }
}
