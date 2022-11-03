use crate::auth::{AuthToken, JwtToken, TokenRole};
use crate::errors::ApiError;
use crate::grpc::blockjoy_ui::user_service_server::UserService;
use crate::grpc::blockjoy_ui::{
    CreateUserRequest, CreateUserResponse, GetConfigurationRequest, GetConfigurationResponse,
    GetUserRequest, GetUserResponse, ResponseMeta, UpdateUserRequest, UpdateUserResponse,
    UpsertConfigurationRequest, UpsertConfigurationResponse, User as GrpcUser,
};
use crate::models::{User, UserRequest};
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::helpers::{required, try_get_token};

pub struct UserServiceImpl {
    db: DbPool,
}

impl UserServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl UserService for UserServiceImpl {
    async fn get(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let token = try_get_token(&request)?;
        let user = token.try_get_user(*token.id(), &self.db).await?;
        let inner = request.into_inner();
        let response = GetUserResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            user: Some(GrpcUser::try_from(user)?),
        };

        Ok(Response::new(response))
    }

    async fn create(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let inner = request.into_inner();
        let user = inner.user.ok_or_else(required("user"))?;
        let user_request = UserRequest {
            email: user.email.ok_or_else(required("email"))?,
            first_name: user.first_name.ok_or_else(required("first_name"))?,
            last_name: user.last_name.ok_or_else(required("last_name"))?,
            password: inner.password,
            password_confirm: inner.password_confirmation,
        };

        let new_user = User::create(user_request, &self.db, Some(TokenRole::User)).await?;
        let meta = ResponseMeta::from_meta(inner.meta).with_message(new_user.id);
        let response = CreateUserResponse { meta: Some(meta) };
        Ok(Response::new(response))
    }

    async fn update(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<UpdateUserResponse>, Status> {
        let token = request
            .extensions()
            .get::<AuthToken>()
            .ok_or_else(required("auth token"))?;
        let user_id = token.try_get_user(*token.id(), &self.db).await?.id;
        let inner = request.into_inner();
        let user = inner.user.ok_or_else(required("user"))?;

        // Check if current user is the same as the one to be updated
        if user_id == Uuid::parse_str(user.id()).map_err(ApiError::from)? {
            let user: GrpcUser = User::update_all(user_id, user.into(), &self.db)
                .await?
                .try_into()?;
            let response_meta = ResponseMeta::from_meta(inner.meta);
            let response = UpdateUserResponse {
                meta: Some(response_meta),
                user: Some(user),
            };

            Ok(Response::new(response))
        } else {
            Err(Status::permission_denied(
                "You are not allowed to update this user",
            ))
        }
    }

    async fn upsert_configuration(
        &self,
        _request: Request<UpsertConfigurationRequest>,
    ) -> Result<Response<UpsertConfigurationResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn get_configuration(
        &self,
        _request: Request<GetConfigurationRequest>,
    ) -> Result<Response<GetConfigurationResponse>, Status> {
        Err(Status::unimplemented(""))
    }
}
