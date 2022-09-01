use crate::auth::FindableById;
use crate::grpc::blockjoy_ui::host_service_server::HostService;
use crate::grpc::blockjoy_ui::{
    response_meta, CreateHostRequest, CreateHostResponse, DeleteHostRequest, DeleteHostResponse,
    GetHostsRequest, GetHostsResponse, Host as GrpcHost, UpdateHostRequest, UpdateHostResponse,
};
use crate::grpc::helpers::success_response_meta;
use crate::models::{Host, Token};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct HostServiceImpl {
    db: DbPool,
}

impl HostServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl HostService for HostServiceImpl {
    /// Get host(s) by one of:
    /// - ID
    /// - Organization ID
    /// - Token
    async fn get(
        &self,
        request: Request<GetHostsRequest>,
    ) -> Result<Response<GetHostsResponse>, Status> {
        let inner = request.into_inner();

        match inner.id {
            Some(id) => {
                let response_meta = success_response_meta(
                    response_meta::Status::Success as i32,
                    inner.meta.unwrap().id,
                );
                let host = GrpcHost::from(Host::find_by_id(Uuid::from(id), &self.db).await?);
                let response = GetHostsResponse {
                    meta: Some(response_meta),
                    hosts: vec![host],
                };

                return Ok(Response::new(response));
            }
            None => tracing::debug!("ID not used"),
        }

        match inner.org_id {
            Some(org_id) => {
                let response_meta = success_response_meta(
                    response_meta::Status::Success as i32,
                    inner.meta.unwrap().id,
                );
                let hosts = Host::find_by_org(Uuid::from(org_id), &self.db)
                    .await?
                    .iter()
                    .map(GrpcHost::from)
                    .collect();
                let response = GetHostsResponse {
                    meta: Some(response_meta),
                    hosts,
                };

                return Ok(Response::new(response));
            }
            None => tracing::debug!("Org ID not used"),
        }

        match inner.token {
            Some(token) => {
                let response_meta = success_response_meta(
                    response_meta::Status::Success as i32,
                    inner.meta.unwrap().id,
                );
                let host = GrpcHost::from(Token::get_host_for_token(token, &self.db).await?);
                let response = GetHostsResponse {
                    meta: Some(response_meta),
                    hosts: vec![host],
                };

                return Ok(Response::new(response));
            }
            None => tracing::debug!("Token not used"),
        }

        Err(Status::not_found("None of ID, OrgID, Token was provided"))
    }

    async fn create(
        &self,
        _request: Request<CreateHostRequest>,
    ) -> Result<Response<CreateHostResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn update(
        &self,
        _request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn delete(
        &self,
        _request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}
