//! # Authorization layer
//!
//!

use crate::auth::expiration_provider::ExpirationProvider;
use crate::auth::unauthenticated_paths::UnauthenticatedPaths;
use crate::auth::{Authorization, AuthorizationData, AuthorizationState};
use crate::auth::{JwtToken, TokenClaim, TokenType, UserAuthToken, UserRefreshToken};
use futures_util::future::BoxFuture;
use hyper::{Request, Response};
use std::fmt::Debug;
use tonic::body::BoxBody;
use tonic::Status;
use tower_http::auth::AsyncAuthorizeRequest;

use super::AnyToken;

fn unauthorized_response(msg: &str) -> Response<BoxBody> {
    Status::permission_denied(msg).to_http()
}

fn unauthenticated_response(msg: &str) -> Response<BoxBody> {
    Status::unauthenticated(msg).to_http()
}

fn internal_response(msg: &str) -> Response<BoxBody> {
    Status::internal(msg).to_http()
}

#[derive(Clone)]
pub struct AuthorizationService {
    enforcer: Authorization,
}

impl AuthorizationService {
    pub fn new(enforcer: Authorization) -> Self {
        Self { enforcer }
    }

    pub fn is_unauthenticated_request<B: Debug>(&self, request: &Request<B>) -> bool {
        if let Some(unauth_paths) = request.extensions().get::<UnauthenticatedPaths>() {
            unauth_paths.is_unauthenticated(request.uri().path())
        } else {
            tracing::error!(
                "Request {request:?} did not contain `UnauthenicatedPaths` extension! \
                Blockvisor-api is misconfigured!"
            );
            false
        }
    }
}

impl<B> AsyncAuthorizeRequest<B> for AuthorizationService
where
    B: Send + Sync + Debug + 'static,
{
    type RequestBody = B;
    type ResponseBody = BoxBody;
    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        if self.is_unauthenticated_request(&request) {
            tracing::debug!("Request is unauthenticated: {}", request.uri().path());
            return Box::pin(async move { Ok(request) });
        }

        let enforcer = self.enforcer.clone();

        Box::pin(async move {
            let token = AnyToken::from_request(&request)
                .map_err(|_| unauthenticated_response("Missing valid token"))?;
            let cant_parse =
                |e| unauthenticated_response(&format!("Could not extract token: {e:?}"));

            match token {
                AnyToken::UserAuth(mut token) => {
                    // 1. try if token is valid
                    token.encode().map_err(cant_parse)?;

                    // Get refresh token
                    let mut refresh_token = UserRefreshToken::from_request(&request)
                        .map_err(|_| unauthorized_response("Cannot parse refresh token"))?;

                    // 2. test if token is expired
                    if token.has_expired() {
                        // Test if refresh token is valid
                        if !refresh_token.has_expired() {
                            let claim = TokenClaim::new(
                                token.get_id(),
                                ExpirationProvider::expiration(TokenType::UserAuth),
                                TokenType::UserAuth,
                                None,
                            );
                            token = UserAuthToken::new(claim);
                            let claim = TokenClaim::new(
                                token.get_id(),
                                ExpirationProvider::expiration(TokenType::UserRefresh),
                                TokenType::UserRefresh,
                                None,
                            );
                            refresh_token = UserRefreshToken::new(claim);
                        } else {
                            return Err(unauthorized_response("Invalid refresh token"));
                        }
                    }

                    let auth_data = AuthorizationData {
                        subject: token.role().to_string(),
                        object: request.uri().path().to_string(),
                        action: request.method().to_string(),
                    };

                    let result = enforcer
                        .try_authorized(auth_data)
                        .map_err(|e| unauthorized_response(&e.to_string()))?;
                    // Evaluate authorization result
                    match result {
                        AuthorizationState::Authorized => {
                            request.extensions_mut().insert(token);
                            request.headers_mut().insert(
                                "Set-Cookie",
                                format!(
                                    "refresh={}; Expires={}; Secure; HttpOnly",
                                    refresh_token
                                        .encode()
                                        .map_err(|e| internal_response(e.to_string().as_str()))?,
                                    refresh_token.get_expiration(),
                                )
                                .parse()
                                .map_err(|_| {
                                    internal_response("Cannot create refresh token cookie")
                                })?,
                            );

                            Ok(request)
                        }
                        AuthorizationState::Denied => {
                            Err(unauthorized_response("Insufficient privileges"))
                        }
                    }
                }
                _ => Err(unauthorized_response("Invalid token type")),
                /*
                AnyToken::PwdReset(pwd_reset) => pwd_reset.encode().map_err(cant_parse)?,
                AnyToken::RegistrationConfirmation(confirmation) => {
                    confirmation.encode().map_err(cant_parse)?
                }
                 */
            }
        })
    }
}

#[cfg(test)]
mod tests {}
