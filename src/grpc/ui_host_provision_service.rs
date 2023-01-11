use super::helpers::required;
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::host_provision_service_server::HostProvisionService;
use crate::grpc::blockjoy_ui::{
    CreateHostProvisionRequest, CreateHostProvisionResponse, GetHostProvisionRequest,
    GetHostProvisionResponse, HostProvision as GrpcHostProvision, ResponseMeta,
};
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models::{HostProvision, HostProvisionRequest};
use crate::server::DbPool;
use anyhow::anyhow;
use std::net::AddrParseError;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct HostProvisionServiceImpl {
    db: DbPool,
}

impl HostProvisionServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl HostProvisionService for HostProvisionServiceImpl {
    async fn get(
        &self,
        request: Request<GetHostProvisionRequest>,
    ) -> Result<Response<GetHostProvisionResponse>, Status> {
        let inner = request.into_inner();
        let host_provision_id = inner.id.ok_or_else(required("id"))?;
        let host_provision = HostProvision::find_by_id(&host_provision_id, &self.db).await?;
        let response = GetHostProvisionResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            host_provisions: vec![GrpcHostProvision::try_from(host_provision)?],
        };
        Ok(Response::new(response))
    }

    async fn create(
        &self,
        request: Request<CreateHostProvisionRequest>,
    ) -> Result<Response<CreateHostProvisionResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let provision = inner
            .host_provision
            .ok_or_else(required("host_provision"))?;
        let req = HostProvisionRequest {
            nodes: None,
            ip_range_from: provision
                .ip_range_from
                .parse()
                .map_err(|err: AddrParseError| ApiError::UnexpectedError(anyhow!(err)))?,
            ip_range_to: provision
                .ip_range_to
                .parse()
                .map_err(|err: AddrParseError| ApiError::UnexpectedError(anyhow!(err)))?,
            ip_gateway: provision
                .ip_gateway
                .parse()
                .map_err(|err: AddrParseError| ApiError::UnexpectedError(anyhow!(err)))?,
        };

        let provision = HostProvision::create(req, &self.db).await?;
        let meta = ResponseMeta::from_meta(inner.meta).with_message(provision.id);
        let response = CreateHostProvisionResponse { meta: Some(meta) };

        Ok(response_with_refresh_token(refresh_token, response)?)
    }
}
