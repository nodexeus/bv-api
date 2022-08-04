//! # Authorization layer
//!
//!

use crate::auth::JwtToken;
use crate::auth::{Authorization, AuthorizationData, AuthorizationState};
use crate::models::Token;
use crate::server::DbPool;
use axum::body::{boxed, Body, BoxBody};
use axum::http::Request as HttpRequest;
use axum::http::Response as HttpResponse;
use futures_util::future::BoxFuture;
use http::StatusCode;
use std::convert::TryFrom;
use tower_http::auth::AsyncAuthorizeRequest;

fn unauthorized_response() -> HttpResponse<BoxBody> {
    HttpResponse::builder()
        .status(StatusCode::FORBIDDEN)
        .body(boxed(Body::empty()))
        .unwrap()
}

fn unauthenticated_response() -> HttpResponse<BoxBody> {
    HttpResponse::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(boxed(Body::empty()))
        .unwrap()
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
    type Future = BoxFuture<'static, Result<HttpRequest<B>, HttpResponse<Self::ResponseBody>>>;

    #[allow(unused_mut)]
    fn authorize(&mut self, mut request: HttpRequest<B>) -> Self::Future {
        let enforcer = self.enforcer.clone();

        Box::pin(async move {
            match JwtToken::try_from(&request) {
                Ok(token) => {
                    let db = request
                        .extensions()
                        .get::<DbPool>()
                        .unwrap_or_else(|| panic!("DB extension missing"));
                    let db_token = Token::find_by_token(token.encode().unwrap(), &db)
                        .await
                        .unwrap();
                    let auth_data = AuthorizationData {
                        subject: db_token.role.to_string(),
                        object: request.uri().path().to_string(),
                        action: request.method().to_string(),
                    };

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
/*
#[derive(Clone)]
pub struct AuthorizationService<S> {
    inner: S,
    enforcer: Authorization,
}

impl<S> AuthorizationService<S> {
    pub fn new(inner: S, enforcer: Authorization) -> Self {
        Self { inner, enforcer }
    }

    fn get_authorizable(&self, token_str: String, db: DbPool) -> ApiResult<String> {
        let future = Token::find_by_token(token_str, &db);
        let result = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future);

        match result {
            Ok(token) => Ok(token.role.to_string()),
            Err(e) => Err(e),
        }
    }

    async fn forbidden_response(&self) -> HttpResponse<()> {
        HttpResponse::builder()
            .status(StatusCode::FORBIDDEN)
            .body(())
            .unwrap()
    }

    async fn unauthorized_response(&self) -> HttpResponse<()> {
        HttpResponse::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(())
            .unwrap()
    }
}

impl<S, ReqBody, ResBody> Service<HttpRequest<ReqBody>> for AuthorizationService<S>
where
    S: Service<HttpRequest<ReqBody>, Response = HttpResponse<ResBody>>,
    <S as Service<axum::http::Request<ReqBody>>>::Error: Into<ApiError>,
    // Service<HttpRequest<ReqBody>> + Clone + Send,
    // Response = HttpResponse<ResBody>>,
    //<S as Service<axum::http::Request<ReqBody>>>::Error: Into<ApiError>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest<ReqBody>) -> Self::Future {
        match JwtToken::try_from(&req) {
            Ok(token) => {
                let db = req
                    .extensions()
                    .get::<DbPool>()
                    .unwrap_or_else(|| panic!("DB extension missing"));
                let role = self
                    .get_authorizable(token.encode().unwrap(), db.clone())
                    .unwrap_or_else(|_| "".into());
                let auth_data = AuthorizationData {
                    subject: role,
                    object: req.uri().path().to_string(),
                    action: req.method().to_string(),
                };

                match self.enforcer.try_authorized(auth_data) {
                    Ok(result) => {
                        // Evaluate authorization result
                        match result {
                            AuthorizationState::Authorized => self.inner.call(req),
                            AuthorizationState::Denied => self.unauthorized_response(),
                        }
                    }
                    Err(_e) => self.unauthorized_response(),
                }
            }
            Err(_e) => self.forbidden_response(),
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
 */
