use crate::auth::{FindableById, InvitationToken, JwtToken, UserAuthToken};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::invitation_service_server::InvitationService;
use crate::grpc::blockjoy_ui::{
    CreateInvitationRequest, CreateInvitationResponse, Invitation as GrpcInvitation,
    InvitationRequest, InvitationsResponse, ListPendingInvitationRequest,
    ListReceivedInvitationRequest, ResponseMeta,
};
use crate::grpc::helpers::try_get_token;
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::mail::MailClient;
use crate::models::{Invitation, Org, OrgRole, User};
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
        let creator_id = try_get_token::<_, UserAuthToken>(&request)?.get_id();
        let creator = User::find_by_id(creator_id, &self.db).await?;
        let inner = request.into_inner();
        let invitation = GrpcInvitation {
            created_by_id: Some(creator_id.to_string()),
            created_for_org_id: Some(inner.created_for_org_id),
            invitee_email: Some(inner.invitee_email),
            created_at: None,
            accepted_at: None,
            declined_at: None,
            created_by_user_name: None,
            created_for_org_name: None,
        };

        let db_invitation = Invitation::create(&invitation, &self.db).await?;

        let response_meta = ResponseMeta::from_meta(inner.meta);
        let response = CreateInvitationResponse {
            meta: Some(response_meta),
        };
        let invitee = User {
            id: Default::default(),
            email: db_invitation.invitee_email.clone(),
            first_name: "".to_string(),
            last_name: "".to_string(),
            hashword: "".to_string(),
            salt: "".to_string(),
            refresh: None,
            fee_bps: 0,
            staking_quota: 0,
            created_at: Default::default(),
            confirmed_at: None,
        };

        MailClient::new()
            .invitation(&db_invitation, &creator, &invitee, "1 week".to_string())
            .await?;

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    /// TODO: Role should be checked by policies
    async fn list_pending(
        &self,
        request: Request<ListPendingInvitationRequest>,
    ) -> Result<Response<InvitationsResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let user_id = try_get_token::<_, UserAuthToken>(&request)?.get_id();
        let inner = request.into_inner();
        let org_id = Uuid::parse_str(inner.org_id.as_str()).map_err(ApiError::from)?;
        let org_user = Org::find_org_user(&user_id, &org_id, &self.db).await?;

        match org_user.role {
            OrgRole::Member => Err(Status::permission_denied(format!(
                "User {} is not allowed to list pending invitations on org {}",
                user_id, org_id
            ))),
            OrgRole::Admin | OrgRole::Owner => {
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
        }
    }

    async fn list_received(
        &self,
        request: Request<ListReceivedInvitationRequest>,
    ) -> Result<Response<InvitationsResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user = User::find_by_id(token.get_id(), &self.db).await?;
        let inner = request.into_inner();
        let invitations: Vec<GrpcInvitation> = Invitation::received(user.email, &self.db)
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

        let invitation = Invitation::accept(invitation_id, &self.db).await?;
        let new_member = User::find_by_email(invitation.invitee_email(), &self.db).await?;

        Org::add_member(
            &new_member.id,
            invitation.created_for_org(),
            OrgRole::Member,
            &self.db,
        )
        .await?;

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
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user_id = *token.id();
        let grpc_invitation = request
            .into_inner()
            .invitation
            .ok_or_else(|| Status::invalid_argument("invitation missing"))?;
        let invitee_email = grpc_invitation
            .invitee_email
            .ok_or_else(|| Status::invalid_argument("invitee email missing"))?;
        let invitation =
            Invitation::find_by_creator_for_email(user_id, invitee_email, &self.db).await?;

        // Check if user belongs to org, the role is already checked by the auth middleware
        Org::find_org_user(
            &invitation.created_by_user,
            &invitation.created_for_org,
            &self.db,
        )
        .await?;

        Invitation::revoke(invitation.id, &self.db).await?;

        Ok(response_with_refresh_token::<()>(refresh_token, ())?)
    }
}
