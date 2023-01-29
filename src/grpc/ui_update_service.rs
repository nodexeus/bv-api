use crate::auth::{FindableById, UserAuthToken};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::update_notification::Notification;
use crate::grpc::blockjoy_ui::update_service_server::UpdateService;
use crate::grpc::blockjoy_ui::{
    self, GetUpdatesRequest, GetUpdatesResponse, ResponseMeta, UpdateNotification,
};
use crate::grpc::helpers::{required, try_get_token};
use crate::grpc::notification::Notify;
use crate::models;
use crate::models::{Host, Node};
use sqlx::postgres::PgListener;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::futures_core::Stream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct UpdateServiceImpl {
    db: models::DbPool,
}

impl UpdateServiceImpl {
    pub fn new(db: models::DbPool) -> Self {
        Self { db }
    }

    pub async fn host_payload(
        id: Uuid,
        _user_id: Uuid,
        db: models::DbPool,
    ) -> Option<Notification> {
        let mut conn = db.conn().await.ok()?;
        let host = Host::find_by_id(id, &mut conn)
            .await
            .map_err(|e| tracing::error!("Host ID {id} not found: {e}"))
            .ok()?;
        let host = blockjoy_ui::Host::from_model(host, &mut conn).await.ok()?;
        Some(Notification::Host(host))
    }

    pub async fn node_payload(
        id: Uuid,
        _user_id: Uuid,
        db: models::DbPool,
    ) -> Option<Notification> {
        let mut conn = db.conn().await.ok()?;
        let node = Node::find_by_id(id, &mut conn)
            .await
            .map_err(|e| tracing::error!("Node ID {id} not found: {e}"))
            .ok()?;
        let node = blockjoy_ui::Node::from_model(node, &mut conn).await.ok()?;
        Some(Notification::Node(node))
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
        let mut db_listener = PgListener::connect_with(&self.db.inner()).await.unwrap();
        let mut conn = self.db.conn().await?;
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let org_id = Uuid::parse_str(token.data().get("org_id").ok_or_else(required("org_id"))?)
            .map_err(ApiError::from)?;
        let user_id = token.id().to_string();
        let nodes: Vec<String> = Node::find_all_by_org(org_id, 0, 100, &mut conn)
            .await?
            .into_iter()
            .map(|n| Node::broadcast_channel(n.id))
            .collect();
        let nodes: Vec<&str> = nodes.iter().map(|s| &**s).collect();

        db_listener
            // Couldn't build a IntoIterator<Item = &str> to use ::listen_all
            .listen_all(nodes)
            .await
            .map_err(ApiError::from)?;

        let inner = request.into_inner();
        // spawn and channel are required if you want handle "disconnect" functionality
        // the `out_stream` will not be polled after client disconnect
        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            tracing::info!("client {} connected", user_id.clone());
            let res_meta = Some(ResponseMeta::from_meta(inner.meta));

            while let Ok(notification) = db_listener.recv().await {
                let node_id: Uuid = notification.payload().parse().unwrap_or_default();
                match Node::find_by_id(node_id, &mut conn).await {
                    Ok(node) => {
                        let node: blockjoy_ui::Node = node.try_into().unwrap();
                        let res = GetUpdatesResponse {
                            meta: res_meta.clone(),
                            update: Some(UpdateNotification {
                                notification: Some(Notification::Node(node)),
                            }),
                        };
                        match tx.send(Result::<_, Status>::Ok(res)).await {
                            Ok(_) => {}
                            Err(_item) => {
                                // output_stream was build from rx and both are dropped
                                break;
                            }
                        }
                    }
                    Err(e) => tracing::error!("Node not found: {e}"),
                }
            }
            tracing::info!("client {user_id} disconnected");
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output_stream) as Self::UpdatesStream))
    }
}
