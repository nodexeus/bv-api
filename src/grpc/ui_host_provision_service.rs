use crate::grpc::blockjoy_ui::host_provision_service_server::HostProvisionService;
use crate::grpc::blockjoy_ui::{
    CreateHostProvisionRequest, CreateHostProvisionResponse, GetHostProvisionRequest,
    GetHostProvisionResponse, HostProvision as GrpcHostProvision, ResponseMeta,
};
use crate::models::{HostProvision, HostProvisionRequest};
use crate::server::DbPool;
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

        // The protos were changed so I had to make changes here to keep stuff compiling.
        match HostProvision::find_by_id(inner.id.as_deref().unwrap_or(""), &self.db).await {
            Ok(host_provision) => {
                let response = GetHostProvisionResponse {
                    meta: Some(ResponseMeta::from_meta(inner.meta)),
                    host_provisions: vec![GrpcHostProvision::from(host_provision)],
                };

                Ok(Response::new(response))
            }
            Err(e) => Err(Status::from(e)),
        }
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

        match HostProvision::create(req, &self.db).await {
            Ok(provision) => {
                let meta = ResponseMeta::from_meta(inner.meta).with_message(provision.id);
                let response = CreateHostProvisionResponse { meta: Some(meta) };

                Ok(Response::new(response))
            }
            Err(e) => Err(Status::from(e)),
        }
    }
}
