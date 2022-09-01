use crate::grpc::blockjoy_ui::host_provision_service_server::HostProvisionService;
use crate::grpc::blockjoy_ui::{
    response_meta, CreateHostProvisionRequest, CreateHostProvisionResponse,
    GetHostProvisionRequest, GetHostProvisionResponse, HostProvision as GrpcHostProvision,
};
use crate::grpc::helpers::success_response_meta;
use crate::models::HostProvision;
use crate::server::DbPool;
use tonic::{Request, Response, Status};

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

        match HostProvision::find_by_id(inner.id.as_str(), &self.db).await {
            Ok(host_provision) => {
                let response_meta = success_response_meta(
                    response_meta::Status::Success as i32,
                    inner.meta.unwrap().id,
                );
                let response = GetHostProvisionResponse {
                    meta: Some(response_meta),
                    host_provision: Some(GrpcHostProvision::from(host_provision)),
                };

                Ok(Response::new(response))
            }
            Err(e) => Err(Status::from(e)),
        }
    }

    async fn create(
        &self,
        _request: Request<CreateHostProvisionRequest>,
    ) -> Result<Response<CreateHostProvisionResponse>, Status> {
        todo!()
    }
}
