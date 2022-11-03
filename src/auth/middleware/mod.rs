//! # Authorization layer
//!
//!

use crate::auth::unauthenticated_paths::UnauthenticatedPaths;
use crate::auth::JwtToken;
use crate::auth::{Authorization, AuthorizationData, AuthorizationState};
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
                AnyToken::Auth(token) => {
                    token.encode().map_err(cant_parse)?;

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
                AnyToken::Refresh(refresh) => refresh.encode().map_err(cant_parse)?,
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
