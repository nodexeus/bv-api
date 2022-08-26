use crate::auth::{FindableById, TokenIdentifyable};
use crate::grpc::blockjoy::hosts_server::Hosts;
use crate::grpc::blockjoy::{
    HostInfoUpdateRequest, HostInfoUpdateResponse, ProvisionHostRequest, ProvisionHostResponse,
    Uuid as GrpcUuid,
};
use crate::grpc::convert::into::IntoData;
use crate::models::{Host, HostProvision, HostSelectiveUpdate};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct HostsServiceImpl {
    db: DbPool,
}

impl HostsServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl Hosts for HostsServiceImpl {
    async fn provision(
        &self,
        request: Request<ProvisionHostRequest>,
    ) -> Result<Response<ProvisionHostResponse>, Status> {
        let inner = request.into_inner();
        let otp = &inner.otp.clone();
        let request_id = inner.request_id.clone();
        let host_provision = HostProvision::claim_by_grpc_provision(otp, inner, &self.db).await;

        match host_provision {
            Ok(host) => {
                let db_token = host.get_token(&self.db).await.unwrap().token;
                let result = ProvisionHostResponse {
                    host_id: Some(GrpcUuid::from(host.id)),
                    token: db_token,
                    messages: vec!["All good".into()],
                    origin_request_id: request_id,
                };

                Ok(Response::new(result))
            }
            Err(e) => Err(Status::not_found(format!(
                "Host provision not found: {:?}",
                e
            ))),
        }
    }

    async fn info_update(
        &self,
        request: Request<HostInfoUpdateRequest>,
    ) -> Result<Response<HostInfoUpdateResponse>, Status> {
        let (request_id, info) = request.into_data();
        let request_host_id = Uuid::from(info.id.clone().unwrap());
        let host = Host::find_by_id(request_host_id, &self.db).await?;

        match Host::update_all(host.id, HostSelectiveUpdate::from(info), &self.db).await {
            Ok(_host) => {
                let result = HostInfoUpdateResponse {
                    messages: vec![],
                    origin_request_id: Some(request_id),
                };

                Ok(Response::new(result))
            }
            Err(e) => Err(Status::not_found(format!(
                "Host {:?} not found. {}",
                request_host_id, e
            ))),
        }
    }
}
