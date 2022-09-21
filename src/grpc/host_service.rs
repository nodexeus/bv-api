use crate::auth::{FindableById, TokenIdentifyable};
use crate::grpc::blockjoy::hosts_server::Hosts;
use crate::grpc::blockjoy::{
    DeleteHostRequest, DeleteHostResponse, HostInfoUpdateRequest, HostInfoUpdateResponse,
    ProvisionHostRequest, ProvisionHostResponse, Uuid as GrpcUuid,
};
use crate::grpc::convert::into::IntoData;
use crate::models::{Host, HostProvision, HostSelectiveUpdate, Token};
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
        let host = HostProvision::claim_by_grpc_provision(otp, inner, &self.db)
            .await
            .map_err(|e| Status::not_found(format!("Host provision not found: {e:?}")))?;
        let db_token = host.get_token(&self.db).await.unwrap().token;
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
        let (request_id, info) = request.into_data();
        let request_host_id = Uuid::from(info.id.clone().unwrap());
        let host = Host::find_by_id(request_host_id, &self.db).await?;
        let _host = Host::update_all(host.id, HostSelectiveUpdate::from(info), &self.db)
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
        let host_token_id = request
            .extensions()
            .get::<Token>()
            .unwrap()
            .host_id
            .unwrap();
        let inner = request.into_inner();
        let host_id = Uuid::from(inner.host_id.unwrap());
        if host_token_id != host_id {
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
