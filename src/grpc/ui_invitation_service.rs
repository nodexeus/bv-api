use crate::grpc::blockjoy_ui::invitation_service_server::InvitationService;
use crate::grpc::blockjoy_ui::{
    CreateInvitationRequest, CreateInvitationResponse, InvitationRequest, InvitationsResponse,
    ListPendingInvitationRequest, ListReceivedInvitationRequest,
};
use crate::grpc::helpers::required;
use crate::grpc::notification::ChannelNotifier;
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models::Invitation;
use crate::server::DbPool;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct InvitationServiceImpl {
    db: DbPool,
    notifier: Arc<ChannelNotifier>,
}

impl InvitationServiceImpl {
    pub fn new(db: DbPool, notifier: Arc<ChannelNotifier>) -> Self {
        Self { db, notifier }
    }
}

#[tonic::async_trait]
impl InvitationService for InvitationServiceImpl {
    async fn create(
        &self,
        request: Request<CreateInvitationRequest>,
    ) -> Result<Response<CreateInvitationResponse>, Status> {
        todo!()
    }

    async fn list_pending(
        &self,
        request: Request<ListPendingInvitationRequest>,
    ) -> Result<Response<InvitationsResponse>, Status> {
        todo!()
    }

    async fn list_received(
        &self,
        request: Request<ListReceivedInvitationRequest>,
    ) -> Result<Response<InvitationsResponse>, Status> {
        todo!()
    }

    async fn accept(&self, request: Request<InvitationRequest>) -> Result<Response<()>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let invitation = inner
            .invitation
            .ok_or_else(|| Status::invalid_argument("Invitation missing"))?;

        // Invitation::accept(invitation.&self.db).await?;

        Ok(response_with_refresh_token::<()>(refresh_token, ())?)
    }

    async fn decline(&self, request: Request<InvitationRequest>) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn revoke(&self, request: Request<InvitationRequest>) -> Result<Response<()>, Status> {
        todo!()
    }
}
