use super::blockjoy_ui::ResponseMeta;
use crate::auth::{FindableById, HostAuthToken, JwtToken, TokenType};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::host_service_server::HostService;
use crate::grpc::blockjoy_ui::{
    get_hosts_request, CreateHostRequest, CreateHostResponse, DeleteHostRequest,
    DeleteHostResponse, GetHostsRequest, GetHostsResponse, UpdateHostRequest, UpdateHostResponse,
};
use crate::grpc::helpers::required;
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models::{Host, HostRequest, HostSelectiveUpdate};
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
    /// One of those options need to be there
    async fn get(
        &self,
        request: Request<GetHostsRequest>,
    ) -> Result<Response<GetHostsResponse>, Status> {
        use get_hosts_request::Param;

        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let meta = inner.meta.ok_or_else(required("meta"))?;
        let request_id = meta.id;
        let param = inner.param.ok_or_else(required("param"))?;
        let (hosts, response_meta) = match param {
            Param::Id(id) => (
                vec![Host::find_by_id(
                    Uuid::parse_str(id.as_str()).map_err(ApiError::from)?,
                    &self.db,
                )
                .await?
                .try_into()?],
                ResponseMeta::new(request_id.unwrap_or_default()),
            ),
            Param::Token(token) => {
                let token: HostAuthToken =
                    HostAuthToken::from_encoded(token.as_str(), TokenType::HostAuth, true)?;
                let host = token.try_get_host(&self.db).await?.try_into()?;

                (
                    vec![host],
                    ResponseMeta::new(request_id.unwrap_or_default()),
                )
            }
        };

        if hosts.is_empty() {
            return Err(Status::not_found("No hosts found"));
        }
        let response = GetHostsResponse {
            meta: Some(response_meta),
            hosts,
        };

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn create(
        &self,
        request: Request<CreateHostRequest>,
    ) -> Result<Response<CreateHostResponse>, Status> {
        let inner = request.into_inner();
        let host = inner.host.ok_or_else(required("host"))?;
        let fields: HostRequest = host.try_into()?;

        Host::create(fields, &self.db).await?;
        let response = CreateHostResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
        };

        Ok(Response::new(response))
    }

    async fn update(
        &self,
        request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        let inner = request.into_inner();
        let host = inner.host.ok_or_else(required("host"))?;
        let fields: HostSelectiveUpdate = host.try_into()?;

        Host::update_all(fields, &self.db).await?;
        let response = UpdateHostResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
        };
        Ok(Response::new(response))
    }

    async fn delete(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let inner = request.into_inner();
        let host_id = Uuid::parse_str(inner.id.as_str()).map_err(ApiError::from)?;
        Host::delete(host_id, &self.db).await?;
        let response = DeleteHostResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
        };

        Ok(Response::new(response))
    }
}
