use crate::grpc::blockjoy_ui::host_provision_service_server::HostProvisionService;
use crate::grpc::blockjoy_ui::{
    CreateHostProvisionRequest, CreateHostProvisionResponse, GetHostProvisionRequest,
    GetHostProvisionResponse, HostProvision as GrpcHostProvision, ResponseMeta,
};
use crate::models::{HostProvision, HostProvisionRequest};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::helpers::required;

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
            host_provisions: vec![GrpcHostProvision::from(host_provision)],
        };
        Ok(Response::new(response))
    }

    async fn create(
        &self,
        request: Request<CreateHostProvisionRequest>,
    ) -> Result<Response<CreateHostProvisionResponse>, Status> {
        let inner = request.into_inner();
        let provision = inner.host_provision.unwrap();
        let req = HostProvisionRequest {
            org_id: Uuid::from(provision.org_id.unwrap()),
            nodes: None,
        };

        let provision = HostProvision::create(req, &self.db).await?;
        let meta = ResponseMeta::from_meta(inner.meta).with_message(provision.id);
        let response = CreateHostProvisionResponse { meta: Some(meta) };

        Ok(Response::new(response))
    }
}
