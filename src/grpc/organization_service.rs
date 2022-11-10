use crate::auth::UserAuthToken;
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::organization_service_server::OrganizationService;
use crate::grpc::blockjoy_ui::{
    CreateOrganizationRequest, CreateOrganizationResponse, DeleteOrganizationRequest,
    DeleteOrganizationResponse, GetOrganizationsRequest, GetOrganizationsResponse, Organization,
    OrganizationMemberRequest, OrganizationMemberResponse, ResponseMeta,
    RestoreOrganizationRequest, RestoreOrganizationResponse, UpdateOrganizationRequest,
    UpdateOrganizationResponse, User as GrpcUiUser,
};
use crate::grpc::helpers::pagination_parameters;
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models::{Org, OrgRequest, OrgRole};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::helpers::{required, try_get_token};

pub struct OrganizationServiceImpl {
    db: DbPool,
}

impl OrganizationServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl OrganizationService for OrganizationServiceImpl {
    async fn get(
        &self,
        request: Request<GetOrganizationsRequest>,
    ) -> Result<Response<GetOrganizationsResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user_id = *token.id();
        let inner = request.into_inner();
        let organizations: Vec<Org> = Org::find_all_by_user(user_id, &self.db).await?;
        let organizations: Result<_, ApiError> =
            organizations.iter().map(Organization::try_from).collect();
        let inner = GetOrganizationsResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            organizations: organizations?,
        };

        Ok(response_with_refresh_token(refresh_token, inner)?)
    }

    async fn create(
        &self,
        request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<CreateOrganizationResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user_id = *token.id();
        let inner = request.into_inner();
        let org = inner.organization.ok_or_else(required("organization"))?;
        let name = org.name.ok_or_else(required("organization.name"))?;
        let org_request = OrgRequest { name };
        let org = Org::create(&org_request, &user_id, &self.db).await?;
        let response_meta = ResponseMeta::from_meta(inner.meta).with_message(org.id);
        let inner = CreateOrganizationResponse {
            meta: Some(response_meta),
        };
        Ok(response_with_refresh_token(refresh_token, inner)?)
    }

    async fn update(
        &self,
        request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<UpdateOrganizationResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user_id = *token.id();
        let inner = request.into_inner();
        let org = inner.organization.ok_or_else(required("organization"))?;
        let org_id = Uuid::parse_str(org.id.ok_or_else(required("organization.id"))?.as_str())
            .map_err(ApiError::from)?;
        let update = OrgRequest {
            name: org.name.ok_or_else(required("organization.name"))?,
        };

        match Org::update(org_id, update, &user_id, &self.db).await {
            Ok(_) => {
                let meta = ResponseMeta::from_meta(inner.meta);
                let inner = UpdateOrganizationResponse { meta: Some(meta) };
                Ok(response_with_refresh_token(refresh_token, inner)?)
            }
            Err(e) => Err(Status::from(e)),
        }
    }

    async fn delete(
        &self,
        request: Request<DeleteOrganizationRequest>,
    ) -> Result<Response<DeleteOrganizationResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user_id = *token.id();
        let inner = request.into_inner();
        let org_id = Uuid::parse_str(inner.id.as_str()).map_err(ApiError::from)?;
        let member = Org::find_org_user(&user_id, &org_id, &self.db).await?;

        // Only owner or admins may delete orgs
        if member.role == OrgRole::Member {
            Err(Status::permission_denied(format!(
                "User {} has no sufficient privileges to delete org {}",
                user_id, org_id
            )))
        } else {
            Org::delete(org_id, &self.db).await?;

            let meta = ResponseMeta::from_meta(inner.meta);
            let inner = DeleteOrganizationResponse { meta: Some(meta) };

            Ok(response_with_refresh_token(refresh_token, inner)?)
        }
    }

    async fn restore(
        &self,
        request: Request<RestoreOrganizationRequest>,
    ) -> Result<Response<RestoreOrganizationResponse>, Status> {
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user_id = token.id().clone();
        let inner = request.into_inner();
        let org_id = Uuid::parse_str(inner.id.as_str()).map_err(ApiError::from)?;
        let member = Org::find_org_user(&user_id, &org_id, &self.db).await?;

        // Only owner or admins may restore orgs
        if member.role == OrgRole::Member {
            Err(Status::permission_denied(format!(
                "User {} has no sufficient privileges to restore org {}",
                user_id, org_id
            )))
        } else {
            let org = Org::restore(org_id, &self.db).await?;
            let meta = ResponseMeta::from_meta(inner.meta);
            let inner = RestoreOrganizationResponse {
                meta: Some(meta),
                organization: Some(org.try_into()?),
            };

            Ok(Response::new(inner))
        }
    }

    async fn members(
        &self,
        request: Request<OrganizationMemberRequest>,
    ) -> Result<Response<OrganizationMemberResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let meta = inner.meta.ok_or_else(required("meta"))?;
        let org_id = Uuid::parse_str(inner.id.as_str()).map_err(ApiError::from)?;

        let (limit, offset) = pagination_parameters(meta.pagination.clone())?;
        let users = Org::find_all_member_users_paginated(&org_id, limit, offset, &self.db).await?;
        let users: Result<_, ApiError> = users.iter().map(GrpcUiUser::try_from).collect();
        let inner = OrganizationMemberResponse {
            meta: Some(ResponseMeta::from_meta(meta).with_pagination()),
            users: users?,
        };

        Ok(response_with_refresh_token(refresh_token, inner)?)
    }
}
