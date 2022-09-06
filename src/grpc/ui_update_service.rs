use crate::grpc::blockjoy_ui::update_service_server::UpdateService;
use crate::grpc::blockjoy_ui::{GetUpdatesRequest, GetUpdatesResponse};
use crate::grpc::notification::ChannelNotifier;
use crate::server::DbPool;
use std::pin::Pin;
use tonic::codegen::futures_core::Stream;
use tonic::{Request, Response, Status};

pub struct UpdateServiceImpl {
    db: DbPool,
    notifier: ChannelNotifier,
}

impl UpdateServiceImpl {
    pub fn new(db: DbPool, notifier: ChannelNotifier) -> Self {
        Self { db, notifier }
    }
}

#[tonic::async_trait]
impl UpdateService for UpdateServiceImpl {
    type UpdatesStream =
        Pin<Box<dyn Stream<Item = Result<GetUpdatesResponse, Status>> + Send + 'static>>;

    async fn updates(
        &self,
        _request: Request<GetUpdatesRequest>,
    ) -> Result<Response<Self::UpdatesStream>, Status> {
        todo!()
    }
}
