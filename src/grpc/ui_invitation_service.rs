use crate::auth::{FindableById, InvitationToken};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::invitation_service_server::InvitationService;
use crate::grpc::blockjoy_ui::{
    CreateInvitationRequest, CreateInvitationResponse, Invitation as GrpcInvitation,
    InvitationRequest, InvitationsResponse, ListPendingInvitationRequest,
    ListReceivedInvitationRequest, ResponseMeta,
};
use crate::grpc::helpers::try_get_token;
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models::{Invitation, User};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct InvitationServiceImpl {
    db: DbPool,
}

impl InvitationServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl InvitationService for InvitationServiceImpl {
    async fn create(
        &self,
        request: Request<CreateInvitationRequest>,
    ) -> Result<Response<CreateInvitationResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let invitation = GrpcInvitation {
            created_by_id: None,
            created_for_org_id: Some(inner.created_for_org_id),
            invitee_email: Some(inner.invitee_email),
            created_at: None,
            accepted_at: None,
            declined_at: None,
        };

        Invitation::create(&invitation, &self.db).await?;

        let response_meta = ResponseMeta::from_meta(inner.meta);
        let response = CreateInvitationResponse {
            meta: Some(response_meta),
        };

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn list_pending(
        &self,
        request: Request<ListPendingInvitationRequest>,
    ) -> Result<Response<InvitationsResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let org_id = Uuid::parse_str(inner.org_id.as_str()).map_err(ApiError::from)?;
        let invitations: Vec<GrpcInvitation> = Invitation::pending(org_id, &self.db)
            .await?
            .iter()
            .map(|i| i.try_into().unwrap_or_default())
            .collect();

        let response_meta = ResponseMeta::from_meta(inner.meta);
        let response = InvitationsResponse {
            meta: Some(response_meta),
            invitations,
        };

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    /// TODO: Currently users can list received invitations for other users by guessing the ID
    async fn list_received(
        &self,
        request: Request<ListReceivedInvitationRequest>,
    ) -> Result<Response<InvitationsResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let user_id = Uuid::parse_str(inner.user_id.as_str()).map_err(ApiError::from)?;
        let email = User::find_by_id(user_id, &self.db).await?.email;
        let invitations: Vec<GrpcInvitation> = Invitation::received(email, &self.db)
            .await?
            .iter()
            .map(|i| i.try_into().unwrap_or_default())
            .collect();
        let response_meta = ResponseMeta::from_meta(inner.meta);
        let response = InvitationsResponse {
            meta: Some(response_meta),
            invitations,
        };

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn accept(&self, request: Request<InvitationRequest>) -> Result<Response<()>, Status> {
        let token = try_get_token::<_, InvitationToken>(&request)?;
        let invitation_id = *token.id();

        Invitation::accept(invitation_id, &self.db).await?;

        Ok(response_with_refresh_token::<()>(
            get_refresh_token(&request),
            (),
        )?)
    }

    async fn decline(&self, request: Request<InvitationRequest>) -> Result<Response<()>, Status> {
        let token = try_get_token::<_, InvitationToken>(&request)?;
        let invitation_id = *token.id();

        Invitation::decline(invitation_id, &self.db).await?;

        Ok(response_with_refresh_token::<()>(
            get_refresh_token(&request),
            (),
        )?)
    }

    async fn revoke(&self, request: Request<InvitationRequest>) -> Result<Response<()>, Status> {
        let token = try_get_token::<_, InvitationToken>(&request)?;
        let invitation_id = *token.id();

        Invitation::revoke(invitation_id, &self.db).await?;

        Ok(response_with_refresh_token::<()>(
            get_refresh_token(&request),
            (),
        )?)
    }
}
