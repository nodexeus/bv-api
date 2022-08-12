//! # gRPC Authorization layer
//!
//!

use crate::auth::JwtToken;
use crate::auth::{Authorization, AuthorizationData, AuthorizationState};
use crate::models::Token;
use crate::server::DbPool;
use futures_util::future::BoxFuture;
use std::convert::TryInto;
use tonic::body::BoxBody;
use tonic::{Request, Status};
use tower_http::auth::AsyncAuthorizeRequest;

fn unauthorized_response() -> Status {
    Status::permission_denied("Insufficient privileges")
}

fn unauthenticated_response() -> Status {
    Status::unauthenticated("Invalid auth token")
}

#[derive(Clone)]
pub struct AuthorizationService {
    enforcer: Authorization,
}

impl AuthorizationService {
    pub fn new(enforcer: Authorization) -> Self {
        Self { enforcer }
    }
}

impl<B> AsyncAuthorizeRequest<B> for AuthorizationService
where
    B: Send + Sync + 'static,
{
    type RequestBody = B;
    type ResponseBody = BoxBody;
    type Future = BoxFuture<'static, Result<Request<B>, Status>>;

    #[allow(unused_mut)]
    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        let enforcer = self.enforcer.clone();

        Box::pin(async move {
            match JwtToken::new_for_grpc_request(&request) {
                Ok(token) => {
                    let db = request
                        .extensions()
                        .get::<DbPool>()
                        .unwrap_or_else(|| panic!("DB extension missing"));
                    let db_token = Token::find_by_token(token.encode().unwrap(), db)
                        .await
                        .unwrap();
                    let auth_data = AuthorizationData {
                        subject: db_token.role.to_string(),
                        object: request.get_ref().into(),
                        action: "POST".into(),
                    };

                    println!("Trying auth data {:?}", auth_data);

                    match enforcer.try_authorized(auth_data) {
                        Ok(result) => {
                            // Evaluate authorization result
                            match result {
                                AuthorizationState::Authorized => {
                                    request.extensions_mut().insert(db_token);

                                    Ok(request)
                                }
                                AuthorizationState::Denied => Err(unauthorized_response()),
                            }
                        }
                        Err(_e) => Err(unauthorized_response()),
                    }
                }
                Err(_e) => Err(unauthenticated_response()),
            }
        })
    }
}

#[cfg(test)]
mod tests {}
