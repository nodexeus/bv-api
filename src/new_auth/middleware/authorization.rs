//! # Authorization layer
//!
//!

use crate::new_auth::auth::{Authorization, AuthorizationData, AuthorizationState};
use crate::new_auth::JwtToken;
use axum::http::Request as HttpRequest;
use std::convert::TryFrom;
use std::task::{Context, Poll};
// use tonic::Request as GrpcRequest;
use crate::server::DbPool;
use tower::{Layer, Service};
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthorizationService<S> {
    inner: S,
    enforcer: Authorization,
}

impl<S> AuthorizationService<S> {
    pub fn new(inner: S, enforcer: Authorization) -> Self {
        Self { inner, enforcer }
    }

    fn get_authorizable<T>(&self, _id: Uuid, _db: DbPool) {
        unimplemented!()
    }
}

impl<S, B> Service<HttpRequest<B>> for AuthorizationService<S>
where
    S: Service<HttpRequest<B>> + Clone + Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest<B>) -> Self::Future {
        match JwtToken::try_from(&req) {
            Ok(_token) => {
                let auth_data = AuthorizationData {
                    subject: "".to_string(),
                    object: req.uri().path().to_string(),
                    action: req.method().to_string(),
                };

                // TODO: Get authorizable

                match self.enforcer.try_authorized(auth_data) {
                    Ok(result) => {
                        // Evaluate authorization result
                        match result {
                            AuthorizationState::Authorized => self.inner.call(req),
                            AuthorizationState::Denied => panic!("Return unauthorized here"),
                        }
                    }
                    Err(_e) => panic!("Return unauthorized here"),
                }
            }
            Err(_e) => panic!("Return FORBIDDEN here"),
        }
    }
}

#[derive(Clone)]
pub struct AuthorizationLayer {
    enforcer: Authorization,
}

impl AuthorizationLayer {
    pub async fn new(enforcer: Authorization) -> Self {
        Self { enforcer }
    }
}

impl<S> Layer<S> for AuthorizationLayer {
    type Service = AuthorizationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService::new(inner, self.enforcer.clone())
    }
}
