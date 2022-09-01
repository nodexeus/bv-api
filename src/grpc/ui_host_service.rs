use tonic::{Request, Response, Status};
use crate::grpc::blockjoy_ui::{CreateHostRequest, CreateHostResponse, DeleteHostRequest, DeleteHostResponse, GetHostsRequest, GetHostsResponse, UpdateHostRequest, UpdateHostResponse};
use crate::grpc::blockjoy_ui::host_service_server::HostService;
use crate::server::DbPool;

pub struct HostServiceImpl {
    db: DbPool,
}

impl HostServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl HostService for HostServiceImpl {
    async fn get(&self, request: Request<GetHostsRequest>) -> Result<Response<GetHostsResponse>, Status> {
        todo!()
    }

    async fn create(&self, _request: Request<CreateHostRequest>) -> Result<Response<CreateHostResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn update(&self, _request: Request<UpdateHostRequest>) -> Result<Response<UpdateHostResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn delete(&self, _request: Request<DeleteHostRequest>) -> Result<Response<DeleteHostResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}