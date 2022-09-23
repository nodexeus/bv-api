use crate::auth::FindableById;
use crate::grpc::blockjoy_ui::update_notification::Notification;
use crate::grpc::blockjoy_ui::update_service_server::UpdateService;
use crate::grpc::blockjoy_ui::{
    GetUpdatesRequest, GetUpdatesResponse, Host as GrpcHost, Node as GrpcNode, ResponseMeta,
    UpdateNotification,
};
use crate::grpc::notification::{ChannelNotification, ChannelNotifier};
use crate::models::{Host, Node};
use crate::server::DbPool;
use std::env;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::futures_core::Stream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct UpdateServiceImpl {
    db: DbPool,
    notifier: Arc<ChannelNotifier>,
    buffer_size: usize,
}

impl UpdateServiceImpl {
    pub fn new(db: DbPool, notifier: Arc<ChannelNotifier>) -> Self {
        let buffer_size: usize = env::var("BIDI_BUFFER_SIZE")
            .map(|bs| bs.parse::<usize>())
            .unwrap()
            .unwrap_or(128);

        Self {
            db,
            notifier,
            buffer_size,
        }
    }

    pub async fn host_payload(id: Uuid, db: DbPool) -> Option<Notification> {
        match Host::find_by_id(id, &db).await {
            Ok(host) => {
                let n_host = GrpcHost::from(host);
                let notification = Notification::Host(n_host);

                Some(notification)
            }
            Err(e) => {
                tracing::error!("Host ID {} not found: {}", id, e);
                None
            }
        }
    }

    pub async fn node_payload(id: Uuid, db: DbPool) -> Option<Notification> {
        match Node::find_by_id(&id, &db).await {
            Ok(node) => {
                let n_node = GrpcNode::from(node);
                let notification = Notification::Node(n_node);

                Some(notification)
            }
            Err(e) => {
                tracing::error!("Node ID {} not found: {}", id, e);
                None
            }
        }
    }
}

#[tonic::async_trait]
impl UpdateService for UpdateServiceImpl {
    type UpdatesStream =
        Pin<Box<dyn Stream<Item = Result<GetUpdatesResponse, Status>> + Send + 'static>>;

    async fn updates(
        &self,
        request: Request<GetUpdatesRequest>,
    ) -> Result<Response<Self::UpdatesStream>, Status> {
        let inner = request.into_inner();

        let host_response_meta = ResponseMeta::from_meta(inner.meta);
        let node_response_meta = host_response_meta.clone();
        let mut hosts_receiver = self.notifier.hosts_receiver();
        let mut nodes_receiver = self.notifier.nodes_receiver();
        let (tx_hosts, rx) = mpsc::channel(self.buffer_size);
        let tx_nodes = tx_hosts.clone();
        let db = self.db.clone();

        let handle_host_updates = tokio::spawn(async move {
            while let Ok(host) = hosts_receiver.recv().await {
                match host {
                    ChannelNotification::Host(payload) => {
                        let notification_payload =
                            UpdateServiceImpl::host_payload(payload.get_id(), db.clone()).await;
                        let notification = UpdateNotification {
                            notification: notification_payload,
                        };
                        let response = GetUpdatesResponse {
                            meta: Some(host_response_meta.clone()),
                            update: Some(notification),
                        };

                        if let Err(e) = tx_hosts.send(Ok(response)).await {
                            tracing::error!("Couldn't send update: {}", e.to_string())
                        }
                    }
                    _ => tracing::error!("Received non Host notification on host channel"),
                }
            }
        });

        let db = self.db.clone();

        let handle_node_updates = tokio::spawn(async move {
            while let Ok(node) = nodes_receiver.recv().await {
                match node {
                    ChannelNotification::Node(payload) => {
                        let notification_payload =
                            UpdateServiceImpl::node_payload(payload.get_id(), db.clone()).await;
                        let notification = UpdateNotification {
                            notification: notification_payload,
                        };
                        let response = GetUpdatesResponse {
                            meta: Some(node_response_meta.clone()),
                            update: Some(notification),
                        };

                        if let Err(e) = tx_nodes.send(Ok(response)).await {
                            tracing::error!("Couldn't send update: {}", e.to_string())
                        }
                    }
                    _ => tracing::error!("Received non Node notification on node channel"),
                }
            }
        });

        // Join handles to ensure max. concurrency
        match tokio::try_join!(handle_host_updates, handle_node_updates) {
            Ok(_) => tracing::info!("All tasks finished"),
            Err(e) => tracing::error!("Error in some task: {}", e),
        }

        let updates_stream = ReceiverStream::new(rx);

        Ok(Response::new(
            Box::pin(updates_stream) as Self::UpdatesStream
        ))
    }
}
