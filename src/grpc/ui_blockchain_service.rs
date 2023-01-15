use super::blockjoy_ui::{self, ResponseMeta};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::blockchain_service_server::BlockchainService;
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::models;

type Result<T, E = tonic::Status> = std::result::Result<T, E>;

pub struct BlockchainServiceImpl {
    db: models::DbPool,
}

impl BlockchainServiceImpl {
    pub fn new(db: models::DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl BlockchainService for BlockchainServiceImpl {
    async fn get(
        &self,
        request: tonic::Request<blockjoy_ui::GetBlockchainRequest>,
    ) -> Result<tonic::Response<blockjoy_ui::GetBlockchainResponse>> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let id = inner.id.parse().map_err(ApiError::from)?;
        let mut tx = self.db.begin().await?;
        let blockchain = models::Blockchain::find_by_id(id, &mut tx)
            .await
            .map_err(|_| tonic::Status::not_found("No such blockchain"))?;
        tx.commit().await?;
        let response = blockjoy_ui::GetBlockchainResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            blockchain: Some(blockchain.try_into()?),
        };
        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn list(
        &self,
        request: tonic::Request<blockjoy_ui::ListBlockchainsRequest>,
    ) -> Result<tonic::Response<blockjoy_ui::ListBlockchainsResponse>> {
        let refresh_token = get_refresh_token(&request);
        let inner = request.into_inner();
        let mut tx = self.db.begin().await?;
        let blockchains = models::Blockchain::find_all(&mut tx).await?;
        tx.commit().await?;
        let blockchains: Result<Vec<_>, ApiError> =
            blockchains.into_iter().map(|b| b.try_into()).collect();
        let response = blockjoy_ui::ListBlockchainsResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            blockchains: blockchains?,
        };

        Ok(response_with_refresh_token(refresh_token, response)?)
    }
}
