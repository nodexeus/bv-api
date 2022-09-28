use crate::grpc::blockjoy_ui::organization_service_server::OrganizationService;
use crate::grpc::blockjoy_ui::{
    CreateOrganizationRequest, CreateOrganizationResponse, DeleteOrganizationRequest,
    DeleteOrganizationResponse, GetOrganizationsRequest, GetOrganizationsResponse, Organization,
    OrganizationMemberRequest, OrganizationMemberResponse, ResponseMeta, UpdateOrganizationRequest,
    UpdateOrganizationResponse, User as GrpcUiUser,
};
use crate::grpc::helpers::pagination_parameters;
use crate::models::{Org, OrgRequest};
use crate::server::DbPool;
use tonic::{Request, Response, Status};

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
        let db_token = try_get_token(&request)?;
        let user_id = db_token.try_user_id()?;
        let inner = request.into_inner();
        let organizations: Vec<Organization> = Org::find_all_by_user(user_id, &self.db)
            .await?
            .iter()
            .map(Organization::from)
            .collect();
        let inner = GetOrganizationsResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            organizations,
        };

        Ok(Response::new(inner))
    }

    async fn create(
        &self,
        request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<CreateOrganizationResponse>, Status> {
        let db_token = try_get_token(&request)?;
        let user_id = db_token.try_user_id()?;
        let inner = request.into_inner();
        let org = inner.organization.ok_or_else(required("organization"))?;
        let name = org.name.ok_or_else(required("organization.name"))?;
        let org_request = OrgRequest { name };
        let org = Org::create(&org_request, &user_id, &self.db).await?;
        let response_meta = ResponseMeta::from_meta(inner.meta).with_message(org.id);
        let inner = CreateOrganizationResponse {
            meta: Some(response_meta),
        };
        Ok(Response::new(inner))
    }

    async fn update(
        &self,
        request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<UpdateOrganizationResponse>, Status> {
        let db_token = try_get_token(&request)?;
        let user_id = db_token.try_user_id()?;
        let inner = request.into_inner();
        let org = inner.organization.ok_or_else(required("organization"))?;
        let org_id = org.id.ok_or_else(required("organization.id"))?.try_into()?;
        let update = OrgRequest {
            name: org.name.ok_or_else(required("organization.name"))?,
        };

        match Org::update(org_id, update, &user_id, &self.db).await {
            Ok(_) => {
                let meta = ResponseMeta::from_meta(inner.meta);
                let inner = UpdateOrganizationResponse { meta: Some(meta) };
                Ok(Response::new(inner))
            }
            Err(e) => Err(Status::from(e)),
        }
    }

    async fn delete(
        &self,
        request: Request<DeleteOrganizationRequest>,
    ) -> Result<Response<DeleteOrganizationResponse>, Status> {
        let db_token = try_get_token(&request)?;
        let user_id = db_token.try_user_id()?;
        let inner = request.into_inner();
        let org_id = inner.id.ok_or_else(required("id"))?.try_into()?;

        if !Org::is_member(&user_id, &org_id, &self.db).await? {
            let msg = "User is not member of given organization";
            return Err(Status::permission_denied(msg));
        }
        Org::delete(org_id, &self.db).await?;
        let meta = ResponseMeta::from_meta(inner.meta);
        let inner = DeleteOrganizationResponse { meta: Some(meta) };
        Ok(Response::new(inner))
    }

    async fn members(
        &self,
        request: Request<OrganizationMemberRequest>,
    ) -> Result<Response<OrganizationMemberResponse>, Status> {
        let inner = request.into_inner();
        let meta = inner.meta.ok_or_else(required("meta"))?;
        let org_id = inner.id.ok_or_else(required("id"))?.try_into()?;

        let (limit, offset) = pagination_parameters(meta.pagination.clone())?;
        let users = Org::find_all_member_users_paginated(&org_id, limit, offset, &self.db)
            .await?
            .iter()
            .map(GrpcUiUser::from)
            .collect();
        let inner = OrganizationMemberResponse {
            meta: Some(ResponseMeta::from_meta(meta).with_pagination()),
            users,
        };

        Ok(Response::new(inner))
    }
}
