use crate::auth::{FindableById, JwtToken, TokenRole, TokenType, UserAuthToken, UserRefreshToken};
use crate::grpc::blockjoy_ui::authentication_service_server::AuthenticationService;
use crate::grpc::blockjoy_ui::{
    ApiToken, ConfirmRegistrationRequest, ConfirmRegistrationResponse, LoginUserRequest,
    LoginUserResponse, RefreshTokenRequest, RefreshTokenResponse, UpdateUiPasswordRequest,
    UpdateUiPasswordResponse,
};
use crate::grpc::{get_refresh_token, response_with_refresh_token};
use crate::mail::MailClient;
use crate::models::User;
use crate::server::DbPool;
use tonic::metadata::errors::InvalidMetadataValue;
use tonic::{Request, Response, Status};

use super::blockjoy_ui::{
    ResetPasswordRequest, ResetPasswordResponse, ResponseMeta, UpdatePasswordRequest,
    UpdatePasswordResponse,
};
use super::helpers::try_get_token;

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
        let refresh_token = UserRefreshToken::create_token_for::<User>(
            &user,
            TokenType::UserAuth,
            TokenRole::User,
        )?;
        let auth_token =
            UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth, TokenRole::User)?;

        let response = LoginUserResponse {
            meta: Some(ResponseMeta::from_meta(inner.meta)),
            token: Some(ApiToken {
                value: auth_token.to_base64()?,
            }),
        };
        let mut response = Response::new(response);

        if User::is_confirmed(user.id, &self.db).await? {
            let db_token = user.get_token(&self.db).await?;
            let token = ApiToken {
                value: db_token.token,
            };
            let response = LoginUserResponse {
                meta: Some(ResponseMeta::from_meta(inner.meta)),
                token: Some(token),
            };

        response.metadata_mut().insert(
            "set-cookie",
            format!(
                "refresh={}; path=/; expires=Fri, 05 Nov 2022 07:19:40 GMT; HttpOnly; SameSite=None; Secure",
                refresh_token.encode()?,
                // exp,
            )
            .parse().map_err(|e: InvalidMetadataValue| Status::internal(e.to_string()))?
        );

        Ok(response)
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
        _request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        Err(Status::unimplemented("Not necessary anymore"))
    }

    /// This endpoint triggers the sending of the reset-password email. The actual resetting is
    /// then done through the `update` function.
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
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

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn update_password(
        &self,
        request: Request<UpdatePasswordRequest>,
    ) -> Result<Response<UpdatePasswordResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let encoded = token
            .encode()
            .map_err(|e| Status::internal(format!("Token encode error {e:?}")))?;
        let user_id = token.try_get_user(*token.id(), &self.db).await?.id;
        let cur_user = User::find_by_id(user_id, &self.db).await?;
        let request = request.into_inner();
        let _cur_user = cur_user
            .update_password(&request.password, &self.db)
            .await?;
        let meta = ResponseMeta::from_meta(request.meta);
        let response = UpdatePasswordResponse {
            meta: Some(meta),
            token: Some(ApiToken { value: encoded }),
        };

        // Send notification mail
        MailClient::new().update_password(&cur_user).await?;

        Ok(response_with_refresh_token(refresh_token, response)?)
    }

    async fn update_ui_password(
        &self,
        request: Request<UpdateUiPasswordRequest>,
    ) -> Result<Response<UpdateUiPasswordResponse>, Status> {
        let refresh_token = get_refresh_token(&request);
        let token = try_get_token::<_, UserAuthToken>(&request)?;
        let user = token.try_get_user(*token.id(), &self.db).await?;
        let encoded = token
            .encode()
            .map_err(|e| Status::internal(format!("Token encode error {e:?}")))?;
        let inner = request.into_inner();

        match user.verify_password(inner.old_pwd.as_str()) {
            Ok(_) => {
                if inner.new_pwd.as_str() == inner.new_pwd_confirmation.as_str() {
                    user.update_password(inner.new_pwd.as_str(), &self.db)
                        .await?;

                    let response = UpdateUiPasswordResponse {
                        meta: None,
                        token: Some(ApiToken { value: encoded }),
                    };

                    // Send notification mail
                    MailClient::new().update_password(&user).await?;

                    Ok(response_with_refresh_token(refresh_token, response)?)
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
