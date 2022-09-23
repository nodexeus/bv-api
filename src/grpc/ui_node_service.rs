use crate::grpc::blockjoy_ui::node_service_server::NodeService;
use crate::grpc::blockjoy_ui::{
    CreateNodeRequest, CreateNodeResponse, GetNodeRequest, GetNodeResponse, ListNodesRequest,
    ListNodesResponse, Node as GrpcNode, ResponseMeta, UpdateNodeRequest, UpdateNodeResponse,
};
use crate::grpc::notification::{ChannelNotification, ChannelNotifier, NotificationPayload};
use crate::models::{Command, CommandRequest, HostCmd, Node, NodeInfo};
use crate::server::DbPool;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::helpers::{internal, required};

pub struct NodeServiceImpl {
    db: DbPool,
    notifier: Arc<ChannelNotifier>,
}

impl NodeServiceImpl {
    pub fn new(db: DbPool, notifier: Arc<ChannelNotifier>) -> Self {
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
        let node_id = inner.id.ok_or_else(required("id"))?;
        let node = Node::find_by_id(&node_id.into(), &self.db).await?;
        let response = GetNodeResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            node: Some(GrpcNode::from(node)),
        };
        Ok(Response::new(response))
    }

    async fn list(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let inner = request.into_inner();
        let org_id = inner
            .org_id
            .ok_or_else(|| Status::internal("Missing org ID"))
            .unwrap();
        let mut response = ListNodesResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            nodes: vec![],
        };

        response.nodes = match Node::find_all_by_org(Uuid::from(org_id), &self.db).await {
            Ok(nodes) => nodes.iter().map(GrpcNode::from).collect(),
            Err(_) => vec![],
        };

        Ok(Response::new(response))
    }

    async fn create(
        &self,
        request: Request<CreateNodeRequest>,
    ) -> Result<Response<CreateNodeResponse>, Status> {
        let inner = request.into_inner();
        let fields = inner.node.unwrap().into();

        let node = Node::create(&fields, &self.db).await?;
        let req = CommandRequest {
            cmd: HostCmd::CreateNode,
            sub_cmd: None,
            resource_id: node.id,
        };

        let cmd = Command::create(fields.host_id, req, &self.db).await?;
        let payload = NotificationPayload::new(cmd.id);
        let notification = ChannelNotification::Command(payload);

        // Sending commands receiver (in command_flow.rs)
        self.notifier
            .commands_sender()
            .send(notification)
            .map_err(internal)?;
        let payload = NotificationPayload::new(node.id);
        let notification = ChannelNotification::Node(payload);

        // Sending notification to nodes receiver (in ui_update_service.rs)
        self.notifier
            .nodes_sender()
            .send(notification)
            .map_err(internal)?;
        let response_meta = ResponseMeta::from_meta(inner.meta).with_message(node.id);
        let response = CreateNodeResponse {
            meta: Some(response_meta),
        };
        Ok(Response::new(response))
    }

    async fn update(
        &self,
        request: Request<UpdateNodeRequest>,
    ) -> Result<Response<UpdateNodeResponse>, Status> {
        let inner = request.into_inner();
        let node = inner.node.unwrap();
        let node_id = Uuid::from(node.id.clone().unwrap());
        let fields: NodeInfo = node.into();

        Node::update_info(&node_id, &fields, &self.db).await?;
        let response = UpdateNodeResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
        };
        Ok(Response::new(response))
    }
}
