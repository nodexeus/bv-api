use crate::auth::FindableById;
use crate::grpc::blockjoy_ui::update_notification::Notification;
use crate::grpc::blockjoy_ui::update_service_server::UpdateService;
use crate::grpc::blockjoy_ui::{self, GetUpdatesRequest, GetUpdatesResponse};
use crate::grpc::notification::Notifier;
use crate::models;
use crate::models::{Host, Node};
use sqlx::postgres::PgListener;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
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

    pub async fn host_payload(id: Uuid, user_id: Uuid, db: models::DbPool) -> Option<Notification> {
        let mut conn = db.conn().await.ok()?;
        let host = Host::find_by_id(id, &mut conn)
            .await
            .map_err(|e| tracing::error!("Host ID {id} not found: {e}"))
            .ok()?;
        let host = blockjoy_ui::Host::from_model(host, &mut conn).await.ok()?;
        Some(Notification::Host(host))
    }

    pub async fn node_payload(id: Uuid, user_id: Uuid, db: models::DbPool) -> Option<Notification> {
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
        let mut db_listener = PgListener::connect_with(&self.db.clone()).await.unwrap();

        db_listener.listen("").await?;

        // spawn and channel are required if you want handle "disconnect" functionality
        // the `out_stream` will not be polled after client disconnect
        let (tx, rx) = mpsc::channel(128);
        tokio::spawn(async move {
            while let Ok(notification) = db_listener.recv().await {
                match tx.send(Result::<_, Status>::Ok(notification)).await {
                    Ok(_) => {
                        // item (server response) was queued to be send to client
                    }
                    Err(_item) => {
                        // output_stream was build from rx and both are dropped
                        break;
                    }
                }
            }
            println!("\tclient disconnected");
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(output_stream) as Self::UpdatesStream))
    }
}
