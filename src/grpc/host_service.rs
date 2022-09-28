use super::helpers::{required, try_get_token};
use crate::auth::{FindableById, TokenIdentifyable};
use crate::grpc::blockjoy::hosts_server::Hosts;
use crate::grpc::blockjoy::{
    DeleteHostRequest, DeleteHostResponse, HostInfoUpdateRequest, HostInfoUpdateResponse,
    ProvisionHostRequest, ProvisionHostResponse, Uuid as GrpcUuid,
};
use crate::grpc::convert::into::IntoData;
use crate::models::{Host, HostProvision, HostSelectiveUpdate};
use crate::server::DbPool;
use tonic::{Request, Response, Status};

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
        let host = HostProvision::claim_by_grpc_provision(otp, inner, &self.db)
            .await
            .map_err(|e| Status::not_found(format!("Host provision not found: {e:?}")))?;
        let db_token = host.get_token(&self.db).await?.token;
        let result = ProvisionHostResponse {
            host_id: Some(GrpcUuid::from(host.id)),
            token: db_token,
            messages: vec!["All good".into()],
            origin_request_id: request_id,
        };
        Ok(Response::new(result))
    }

    async fn info_update(
        &self,
        request: Request<HostInfoUpdateRequest>,
    ) -> Result<Response<HostInfoUpdateResponse>, Status> {
        let (request_id, info) = request.into_data()?;
        let request_host_id = info
            .id
            .as_ref()
            .ok_or_else(required("info.id"))?
            .try_into()?;
        let host = Host::find_by_id(request_host_id, &self.db).await?;
        Host::update_all(host.id, HostSelectiveUpdate::from(info), &self.db)
            .await
            .map_err(|e| Status::not_found(format!("Host {request_host_id} not found. {e}")))?;
        let result = HostInfoUpdateResponse {
            messages: vec![],
            origin_request_id: Some(request_id),
        };
        Ok(Response::new(result))
    }

    async fn delete(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let host_token_id = try_get_token(&request)?.host_id;
        let inner = request.into_inner();
        let host_id = inner
            .host_id
            .as_ref()
            .ok_or_else(required("host_id"))?
            .try_into()?;
        if host_token_id != Some(host_id) {
            let msg = format!("Not allowed to delete host '{host_id}'");
            return Err(Status::permission_denied(msg));
        }
        Host::delete(host_id, &self.db).await?;
        let response = DeleteHostResponse {
            messages: vec![],
            origin_request_id: inner.request_id,
        };
        Ok(Response::new(response))
    }
}
