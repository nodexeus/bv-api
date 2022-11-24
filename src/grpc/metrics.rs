use crate::auth::{JwtToken, TokenRole, UserAuthToken};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::user_service_server::MetricsService;
use crate::grpc::blockjoy_ui::{
    CreateUserRequest, CreateUserResponse, GetConfigurationRequest, GetConfigurationResponse,
    GetUserRequest, GetUserResponse, ResponseMeta, UpdateUserRequest, UpdateUserResponse,
    UpsertConfigurationRequest, UpsertConfigurationResponse, User as GrpcUser,
};
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::mail::MailClient;
use crate::models::{User, UserRequest};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::helpers::{required, try_get_token};

pub struct MetricsServiceImpl {
    db: DbPool,
}

impl MetricsServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl MetricsService for MetricsServiceImpl {
}
