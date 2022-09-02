use crate::grpc::blockjoy_ui::node_service_server::NodeService;
use crate::grpc::blockjoy_ui::{
    CreateNodeRequest, CreateNodeResponse, GetNodeRequest, GetNodeResponse, UpdateNodeRequest,
    UpdateNodeResponse,
};
use crate::server::DbPool;
use tonic::{Request, Response, Status};

pub struct NodeServiceImpl {
    db: DbPool,
}

impl NodeServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl NodeService for NodeServiceImpl {
    async fn get(
        &self,
        _request: Request<GetNodeRequest>,
    ) -> Result<Response<GetNodeResponse>, Status> {
        todo!()
    }

    async fn create(
        &self,
        _request: Request<CreateNodeRequest>,
    ) -> Result<Response<CreateNodeResponse>, Status> {
        todo!()
    }

    async fn update(
        &self,
        _request: Request<UpdateNodeRequest>,
    ) -> Result<Response<UpdateNodeResponse>, Status> {
        todo!()
    }
}
