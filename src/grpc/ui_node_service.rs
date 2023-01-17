use super::helpers::{internal, required};
use crate::auth::UserAuthToken;
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::node_service_server::NodeService;
use crate::grpc::blockjoy_ui::{
    CreateNodeRequest, CreateNodeResponse, DeleteNodeRequest, GetNodeRequest, GetNodeResponse,
    ListNodesRequest, ListNodesResponse, Node as GrpcNode, ResponseMeta, UpdateNodeRequest,
    UpdateNodeResponse,
};
use crate::grpc::notification::{ChannelNotification, ChannelNotifier, NotificationPayload};
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models;
use crate::models::{
    Command, CommandRequest, HostCmd, IpAddress, Node, NodeCreateRequest, NodeInfo,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct NodeServiceImpl {
    db: models::DbPool,
    notifier: Arc<ChannelNotifier>,
}

impl NodeServiceImpl {
    pub fn new(db: models::DbPool, notifier: Arc<ChannelNotifier>) -> Self {
        Self { db, notifier }
    }
}

#[tonic::async_trait]
impl NodeService for NodeServiceImpl {
    async fn get(
        &self,
        request: Request<GetNodeRequest>,
    ) -> Result<Response<GetNodeResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let node_id = inner.id.parse().map_err(ApiError::from)?;
        let mut conn = self.db.conn().await?;
        let node = Node::find_by_id(node_id, &mut conn).await?;
        let response = GetNodeResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            node: Some(node.try_into()?),
        };
        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn list(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let filters = inner.filter.clone();
        let org_id = inner.org_id.parse().map_err(ApiError::from)?;
        let pagination = inner
            .meta
            .clone()
            .ok_or_else(|| Status::invalid_argument("Metadata missing"))?;
        let pagination = pagination
            .pagination
            .ok_or_else(|| Status::invalid_argument("Pagination missing"))?;
        let offset = pagination.items_per_page * (pagination.current_page - 1);

        let mut conn = self.db.conn().await?;
        let nodes = match filters {
            None => {
                Node::find_all_by_org(org_id, offset, pagination.items_per_page, &mut conn).await?
            }
            Some(filter) => {
                let filter = filter
                    .try_into()
                    .map_err(|_| Status::internal("Unexpected error at filtering"))?;

                Node::find_all_by_filter(
                    org_id,
                    filter,
                    offset,
                    pagination.items_per_page,
                    &mut conn,
                )
                .await?
            }
        };

        let nodes: Result<_, ApiError> = nodes.iter().map(GrpcNode::try_from).collect();
        let response = ListNodesResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            nodes: nodes?,
        };
        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn create(
        &self,
        request: Request<CreateNodeRequest>,
    ) -> Result<Response<CreateNodeResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let mut fields: NodeCreateRequest = inner.node.ok_or_else(required("node"))?.try_into()?;
        let mut tx = self.db.begin().await?;
        let node = Node::create(&mut fields, &mut tx).await?;
        let req = CommandRequest {
            cmd: HostCmd::CreateNode,
            sub_cmd: None,
            resource_id: node.id,
        };

        let cmd = Command::create(node.host_id, req, &mut tx).await?;
        tx.commit().await?;
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
        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn update(
        &self,
        request: Request<UpdateNodeRequest>,
    ) -> Result<Response<UpdateNodeResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let node = inner.node.ok_or_else(required("node"))?;
        let node_id = node.id.as_deref();
        let node_id = node_id
            .ok_or_else(required("node.id"))?
            .parse()
            .map_err(ApiError::from)?;
        let fields: NodeInfo = node.try_into()?;

        let mut tx = self.db.begin().await?;
        Node::update_info(&node_id, &fields, &mut tx).await?;
        tx.commit().await?;
        let response = UpdateNodeResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
        };
        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn delete(&self, request: Request<DeleteNodeRequest>) -> Result<Response<()>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = request
            .extensions()
            .get::<UserAuthToken>()
            .ok_or_else(required("User token"))?
            .clone();
        let inner = request.into_inner();
        let node_id = inner.id.parse().map_err(ApiError::from)?;
        let mut tx = self.db.begin().await?;
        let node = Node::find_by_id(node_id, &mut tx).await?;

        if Node::belongs_to_user_org(node.org_id, *token.id(), &mut tx).await? {
            // 1. Delete node, if the node belongs to the current user
            // Key files are deleted automatically because of 'on delete cascade' in tables DDL
            Node::delete(node_id, &mut tx).await?;

            let host_id = node.host_id;
            // 2. Do NOT delete reserved IP addresses, but set assigned to false
            let ip = IpAddress::find_by_node(node.ip_addr.unwrap_or_default(), &mut tx).await?;

            IpAddress::unassign(ip.id, host_id, &mut tx).await?;

            // Send delete node command
            let req = CommandRequest {
                cmd: HostCmd::DeleteNode,
                sub_cmd: None,
                resource_id: node_id,
            };
            let del_cmd = Command::create(node.host_id, req, &mut tx).await?;
            tx.commit().await?;
            let payload = NotificationPayload::new(del_cmd.id);
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

            Ok(response_with_refresh_token::<()>(refresh_token, ())?)
        } else {
            Err(Status::permission_denied("User cannot delete node"))
        }
    }
}
