use super::helpers::{internal, required};
use crate::errors::ApiError;
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
        let node = Node::find_by_id(node_id.try_into()?, &self.db).await?;
        let response = GetNodeResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            node: Some(node.try_into()?),
        };
        Ok(Response::new(response))
    }

    async fn list(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let inner = request.into_inner();
        let org_id = inner.org_id.ok_or_else(|| internal("Missing org ID"))?;
        let nodes = Node::find_all_by_org(org_id.try_into()?, &self.db).await?;
        let nodes: Result<_, ApiError> = nodes.iter().map(GrpcNode::try_from).collect();
        let response = ListNodesResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            nodes: nodes?,
        };
        Ok(Response::new(response))
    }

    async fn create(
        &self,
        request: Request<CreateNodeRequest>,
    ) -> Result<Response<CreateNodeResponse>, Status> {
        let inner = request.into_inner();
        let fields = inner.node.ok_or_else(required("node"))?.try_into()?;
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
        let node = inner.node.ok_or_else(required("node"))?;
        let node_id = node
            .id
            .as_ref()
            .ok_or_else(required("node.id"))?
            .try_into()?;
        let fields: NodeInfo = node.into();

        Node::update_info(&node_id, &fields, &self.db).await?;
        let response = UpdateNodeResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
        };
        Ok(Response::new(response))
    }
}
