use crate::grpc::blockjoy_ui::organization_service_server::OrganizationService;
use crate::grpc::blockjoy_ui::{
    CreateOrganizationRequest, CreateOrganizationResponse, DeleteOrganizationRequest,
    DeleteOrganizationResponse, GetOrganizationsRequest, GetOrganizationsResponse, Organization,
    OrganizationMemberRequest, OrganizationMemberResponse, ResponseMeta, UpdateOrganizationRequest,
    UpdateOrganizationResponse, User as GrpcUiUser,
};
use crate::grpc::helpers::pagination_parameters;
use crate::models::{Org, OrgRequest, Token};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

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
        let db_token = request.extensions().get::<Token>().unwrap();
        let user_id = db_token.user_id.unwrap();
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
        let db_token = request.extensions().get::<Token>().unwrap();
        let user_id = db_token.user_id.unwrap();
        let inner = request.into_inner();
        let org_request = OrgRequest {
            name: inner.organization.unwrap().name.unwrap(),
        };

        match Org::create(&org_request, &user_id, &self.db).await {
            Ok(new_org) => {
                let response_meta = ResponseMeta::from_meta(inner.meta).with_message(new_org.id);
                let inner = CreateOrganizationResponse {
                    meta: Some(response_meta),
                };

                Ok(Response::new(inner))
            }
            Err(e) => Err(Status::from(e)),
        }
    }

    async fn update(
        &self,
        request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<UpdateOrganizationResponse>, Status> {
        let db_token = request.extensions().get::<Token>().unwrap();
        let user_id = db_token.user_id.unwrap();
        let inner = request.into_inner();
        let org = inner.organization.unwrap();
        let update = OrgRequest {
            name: org.name.unwrap(),
        };

        match Org::update(Uuid::from(org.id.unwrap()), update, &user_id, &self.db).await {
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
        let db_token = request.extensions().get::<Token>().unwrap();
        let user_id = db_token.user_id.unwrap();
        let inner = request.into_inner();
        let org_id = Uuid::from(inner.id.unwrap());

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
        let meta = inner.meta.unwrap();
        let org_id = Uuid::from(inner.id.unwrap());

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
