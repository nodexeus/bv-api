use super::blockjoy_ui::{self, ResponseMeta};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::blockchain_service_server::BlockchainService;
use crate::models;
use crate::server::DbPool;

type Result<T, E = tonic::Status> = std::result::Result<T, E>;

pub struct BlockchainServiceImpl {
    db: DbPool,
}

impl BlockchainServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl BlockchainService for BlockchainServiceImpl {
    async fn get(
        &self,
        request: tonic::Request<blockjoy_ui::GetBlockchainRequest>,
    ) -> Result<tonic::Response<blockjoy_ui::GetBlockchainResponse>> {
        let inner = request.into_inner();
        let id = inner
            .id
            .ok_or_else(|| tonic::Status::invalid_argument("The `id` field is required"))?
            .try_into()?;
        let blockchain = models::Blockchain::find_by_id(id, &self.db)
            .await
            .map_err(|_| tonic::Status::not_found("No such blockchain"))?;
        let response = blockjoy_ui::GetBlockchainResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            blockchain: Some(blockchain.try_into()?),
        };
        Ok(tonic::Response::new(response))
    }

    async fn list(
        &self,
        request: tonic::Request<blockjoy_ui::ListBlockchainsRequest>,
    ) -> Result<tonic::Response<blockjoy_ui::ListBlockchainsResponse>> {
        let inner = request.into_inner();
        let blockchains = models::Blockchain::find_all(&self.db).await?;
        let blockchains: Result<Vec<_>, ApiError> =
            blockchains.into_iter().map(|b| b.try_into()).collect();
        let response = blockjoy_ui::ListBlockchainsResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            blockchains: blockchains?,
        };
        Ok(tonic::Response::new(response))
    }
}
