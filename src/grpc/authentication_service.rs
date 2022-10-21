use crate::auth::{FindableById, TokenIdentifyable};
use crate::grpc::blockjoy_ui::authentication_service_server::AuthenticationService;
use crate::grpc::blockjoy_ui::{
    ApiToken, ConfirmRegistrationRequest, ConfirmRegistrationResponse, LoginUserRequest,
    LoginUserResponse, RefreshTokenRequest, RefreshTokenResponse, UpdateUiPasswordRequest,
    UpdateUiPasswordResponse,
};
use crate::mail::MailClient;
use crate::models::{Token, User};
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

        if User::is_confirmed(user.id, &self.db).await? {
            let db_token = user.get_token(&self.db).await?;
            let token = ApiToken {
                value: db_token.token,
            };
            let response = LoginUserResponse {
                meta: Some(ResponseMeta::from_meta(inner.meta)),
                token: Some(token),
            };

            Ok(Response::new(response))
        } else {
            Err(Status::unauthenticated(
                "User registration ist not confirmed",
            ))
        }
    }

    async fn confirm(
        &self,
        request: Request<ConfirmRegistrationRequest>,
    ) -> Result<Response<ConfirmRegistrationResponse>, Status> {
        let token = request
            .extensions()
            .get::<Token>()
            .ok_or_else(required("Confirmation token extension"))?
            .clone();
        let user_id = token
            .user_id
            .ok_or_else(required("User ID for registration confirmation"))?;
        let user = User::confirm(user_id, &self.db).await?;
        let response = ConfirmRegistrationResponse {
            meta: Some(ResponseMeta::from_meta(request.into_inner().meta)),
            token: Some(ApiToken {
                value: user.get_token(&self.db).await?.token,
            }),
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
                meta: Some(ResponseMeta::new(request_id.unwrap_or_default())),
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
        let user = User::find_by_email(&request.email, &self.db).await;
        if let Ok(user) = user {
            let _ = user.email_reset_password(&self.db).await;
        }

        let meta = ResponseMeta::new(String::from(""));
        let response = ResetPasswordResponse { meta: Some(meta) };
        Ok(Response::new(response))
    }

    async fn update_password(
        &self,
        request: Request<UpdatePasswordRequest>,
    ) -> Result<Response<UpdatePasswordResponse>, Status> {
        let db_token = try_get_token(&request)?;
        let user_id = db_token.try_user_id()?;
        let cur_user = User::find_by_id(user_id, &self.db).await?;
        let request = request.into_inner();
        let _cur_user = cur_user
            .update_password(&request.password, &self.db)
            .await?;
        let meta = ResponseMeta::from_meta(request.meta);
        let response = UpdatePasswordResponse {
            meta: Some(meta),
            token: Some(ApiToken {
                value: db_token.token,
            }),
        };

        // Send notification mail
        MailClient::new().update_password(&cur_user).await?;

        Ok(Response::new(response))
    }

    async fn update_ui_password(
        &self,
        request: Request<UpdateUiPasswordRequest>,
    ) -> Result<Response<UpdateUiPasswordResponse>, Status> {
        let db_token = try_get_token(&request)?;
        let inner = request.into_inner();
        let user = User::find_by_id(db_token.try_user_id()?, &self.db).await?;

        match user.verify_password(inner.old_pwd.as_str()) {
            Ok(_) => {
                if inner.new_pwd.as_str() == inner.new_pwd_confirmation.as_str() {
                    user.update_password(inner.new_pwd.as_str(), &self.db)
                        .await?;

                    let response = UpdateUiPasswordResponse {
                        meta: None,
                        token: Some(ApiToken {
                            value: db_token.token,
                        }),
                    };

                    // Send notification mail
                    MailClient::new().update_password(&user).await?;

                    Ok(Response::new(response))
                } else {
                    Err(Status::invalid_argument(
                        "Password and password confirmation don't match",
                    ))
                }
            }
            Err(e) => Err(Status::from(e)),
        }
    }
}
