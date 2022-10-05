use crate::auth::{FindableById, TokenIdentifyable};
use crate::grpc::blockjoy_ui::authentication_service_server::AuthenticationService;
use crate::grpc::blockjoy_ui::{
    ApiToken, LoginUserRequest, LoginUserResponse, RefreshTokenRequest, RefreshTokenResponse,
};
use crate::models::{self, Token, User};
use crate::server::DbPool;
use tonic::{Request, Response, Status};

use super::blockjoy_ui::{
    ResetPasswordRequest, ResetPasswordResponse, ResponseMeta, UpdatePasswordRequest,
    UpdatePasswordResponse,
};
use super::helpers::{required, try_get_token};

pub struct AuthenticationServiceImpl {
    db: DbPool,
}

impl AuthenticationServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl AuthenticationService for AuthenticationServiceImpl {
    async fn login(
        &self,
        request: Request<LoginUserRequest>,
    ) -> Result<Response<LoginUserResponse>, Status> {
        let inner = request.into_inner();
        let user = User::login(inner.clone(), &self.db).await?;
        let db_token = user.get_token(&self.db).await?;
        let token = ApiToken {
            value: db_token.token,
        };
        let response = LoginUserResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            token: Some(token),
        };

        Ok(Response::new(response))
    }

    async fn refresh(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        let db_token = try_get_token(&request)?.token;
        let inner = request.into_inner();
        let meta = inner.meta.as_ref().ok_or_else(required("meta"))?;
        let req_token = meta.token.as_ref().ok_or_else(required("meta.token"))?;
        let req_token = req_token.value.as_str();
        let request_id = meta.id.clone();

        if db_token == req_token {
            let new_token = ApiToken {
                value: Token::refresh(&db_token, &self.db).await?.token,
            };
            let response = RefreshTokenResponse {
                meta: Some(ResponseMeta::new(request_id)),
                token: Some(new_token),
            };
            Ok(Response::new(response))
        } else {
            Err(Status::permission_denied("Not allowed to modify token"))
        }
    }

    /// This endpoint triggers the sending of the reset-password email. The actual resetting is
    /// then done through the `update` function.
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordResponse>, Status> {
        let request = request.into_inner();
        // We are going to query the user and send them an email, but when something goes wrong we
        // are not going to return an error. This hides whether or not a user is registered with
        // us to the caller of the api, because this info may be sensitive and this endpoint is not
        // protected by any authentication.
        let user = models::User::find_by_email(&request.email, &self.db).await;
        if let Ok(user) = user {
            let _ = user.email_reset_password(&self.db).await;
        }

        let meta = ResponseMeta::new(String::from(""));
        let response = ResetPasswordResponse { meta: Some(meta) };
        Ok(Response::new(response))
    }

    async fn update_password(
        &self,
        request: tonic::Request<UpdatePasswordRequest>,
    ) -> Result<tonic::Response<UpdatePasswordResponse>, tonic::Status> {
        let db_token = try_get_token(&request)?;
        let user_id = db_token.try_user_id()?;
        let cur_user = models::User::find_by_id(user_id, &self.db).await?;
        let request = request.into_inner();
        let _cur_user = cur_user
            .update_password(&request.password, &self.db)
            .await?;
        let meta = ResponseMeta::from_meta(request.meta);
        let response = UpdatePasswordResponse { meta: Some(meta) };
        Ok(Response::new(response))
    }
}
