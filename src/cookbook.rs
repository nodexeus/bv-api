use crate::auth::key_provider::KeyProvider;
use crate::auth::TokenType;
use crate::cookbook::cookbook_grpc::cook_book_service_client;
use crate::errors::{ApiError, Result as ApiResult};
use anyhow::anyhow;
use derive_getters::Getters;
use tonic::Request;

#[derive(Getters, Clone, Copy)]
pub struct HardwareRequirements {
    pub(crate) vcpu_count: i64,
    pub(crate) mem_size_mb: i64,
    pub(crate) disk_size_gb: i64,
}

#[allow(clippy::derive_partial_eq_without_eq)]
pub mod cookbook_grpc {
    tonic::include_proto!("blockjoy.api.v1.babel");
}

pub async fn get_hw_requirements(
    protocol: String,
    node_type: String,
    node_version: Option<String>,
) -> ApiResult<HardwareRequirements> {
    let id = cookbook_grpc::ConfigIdentifier {
        protocol,
        node_type,
        node_version: node_version.unwrap_or("latest".to_string()),
        status: 1,
    };
    let cb_url = KeyProvider::get_var("COOKBOOK_URL")
        .map_err(ApiError::Key)?
        .to_string();
    let cb_token = base64::encode(
        KeyProvider::get_secret(TokenType::Cookbook)
            .map_err(ApiError::Key)?
            .to_string(),
    );
    let mut client = cook_book_service_client::CookBookServiceClient::connect(cb_url)
        .await
        .map_err(|e| ApiError::UnexpectedError(anyhow!("Can't connect to cookbook: {e}")))?;
    let mut request = Request::new(id);

    request.metadata_mut().insert(
        "authorization",
        cb_token.parse().map_err(|e| {
            ApiError::UnexpectedError(anyhow!("Can't set cookbook auth header: {e}"))
        })?,
    );

    let response = client.requirements(request).await?;
    let inner = response.into_inner();

    Ok(HardwareRequirements {
        vcpu_count: inner.vcpu_count,
        mem_size_mb: inner.mem_size_mb,
        disk_size_gb: inner.disk_size_gb,
    })
}
