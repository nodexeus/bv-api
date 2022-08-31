use crate::grpc::blockjoy_ui::organization_service_server::OrganizationService;
use crate::grpc::blockjoy_ui::{
    response_meta, CreateOrganizationRequest, CreateOrganizationResponse,
    DeleteOrganizationRequest, DeleteOrganizationResponse, GetOrganizationsRequest,
    GetOrganizationsResponse, OrganizationMemberRequest, OrganizationMemberResponse, ResponseMeta,
    UpdateOrganizationRequest, UpdateOrganizationResponse,
};
use crate::models::{Org, OrgRequest, Token};
use crate::server::DbPool;
use tonic::{Request, Response, Status};

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
        _request: Request<GetOrganizationsRequest>,
    ) -> Result<Response<GetOrganizationsResponse>, Status> {
        Err(Status::unimplemented(""))
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
        let new_org = Org::create(&org_request, &user_id, &self.db).await?;
        let response_meta = ResponseMeta {
            status: i32::from(response_meta::Status::Success),
            origin_request_id: inner.meta.unwrap().id,
            messages: vec![new_org.id.to_string()],
            pagination: None,
        };
        let inner = CreateOrganizationResponse {
            meta: Some(response_meta),
        };

        Ok(Response::new(inner))
    }

    async fn update(
        &self,
        _request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<UpdateOrganizationResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn delete(
        &self,
        _request: Request<DeleteOrganizationRequest>,
    ) -> Result<Response<DeleteOrganizationResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn members(
        &self,
        _request: Request<OrganizationMemberRequest>,
    ) -> Result<Response<OrganizationMemberResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}
