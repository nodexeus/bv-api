use crate::grpc::blockjoy_ui::node_service_server::NodeService;
use crate::grpc::blockjoy_ui::{
    CreateNodeRequest, CreateNodeResponse, GetNodeRequest, GetNodeResponse, Node as GrpcNode,
    ResponseMeta, UpdateNodeRequest, UpdateNodeResponse,
};
use crate::grpc::notification::{ChannelNotification, ChannelNotifier, NotificationPayload};
use crate::models::{Node, NodeInfo};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct NodeServiceImpl {
    db: DbPool,
    notifier: ChannelNotifier,
}

impl NodeServiceImpl {
    pub fn new(db: DbPool, notifier: ChannelNotifier) -> Self {
        Self { db, notifier }
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
                        let response = GetNodeResponse {
                            meta: Some(ResponseMeta::from_meta(inner.meta)),
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
        request: Request<CreateNodeRequest>,
    ) -> Result<Response<CreateNodeResponse>, Status> {
        let inner = request.into_inner();
        let fields = inner.node.unwrap().into();

        match Node::create(&fields, &self.db).await {
            Ok(node) => {
                let response_meta = ResponseMeta::from_meta(inner.meta).with_message(node.id);
                let response = CreateNodeResponse {
                    meta: Some(response_meta),
                };
                let payload = NotificationPayload::new(node.id);
                let notification = ChannelNotification::Node(payload);

                match self.notifier.nodes_sender().send(notification) {
                    Ok(_) => Ok(Response::new(response)),
                    Err(e) => Err(Status::internal(format!("{}", e))),
                }
            }
            Err(e) => Err(Status::from(e)),
        }
    }

    async fn update(
        &self,
        request: Request<UpdateNodeRequest>,
    ) -> Result<Response<UpdateNodeResponse>, Status> {
        let inner = request.into_inner();
        let node = inner.node.unwrap();
        let node_id = Uuid::from(node.id.clone().unwrap());
        let fields: NodeInfo = node.into();

        match Node::update_info(&node_id, &fields, &self.db).await {
            Ok(_) => {
                let response = UpdateNodeResponse {
                    meta: Some(ResponseMeta::from_meta(inner.meta)),
                };
                Ok(Response::new(response))
            }
            Err(e) => Err(Status::from(e)),
        }
    }
}
