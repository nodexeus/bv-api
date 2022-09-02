use crate::grpc::blockjoy_ui::node_service_server::NodeService;
use crate::grpc::blockjoy_ui::{
    response_meta, CreateNodeRequest, CreateNodeResponse, GetNodeRequest, GetNodeResponse,
    Node as GrpcNode, UpdateNodeRequest, UpdateNodeResponse,
};
use crate::grpc::helpers::success_response_meta;
use crate::models::Node;
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

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
        request: Request<GetNodeRequest>,
    ) -> Result<Response<GetNodeResponse>, Status> {
        let inner = request.into_inner();

        match inner.id {
            Some(node_id) => {
                let node_id = Uuid::from(node_id);

                match Node::find_by_id(&node_id, &self.db).await {
                    Ok(node) => {
                        let response_meta = success_response_meta(
                            response_meta::Status::Success as i32,
                            inner.meta.unwrap().id,
                        );
                        let response = GetNodeResponse {
                            meta: Some(response_meta),
                            node: Some(GrpcNode::from(node)),
                        };

                        Ok(Response::new(response))
                    }
                    Err(e) => Err(Status::from(e)),
                }
            }
            None => Err(Status::not_found("No node ID provided")),
        }
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
