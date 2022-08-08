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
use regex::Regex;
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

fn mask_uuid(input: &str) -> String {
    let regex = Regex::new(
        r#"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}"#,
    )
    .unwrap();

    regex.replacen(input, 0, ":id").to_string()
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
            match JwtToken::new_for_request(&request) {
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
                        object: mask_uuid(request.uri().path()),
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

#[cfg(test)]
mod tests {
    use super::mask_uuid;

    #[test]
    fn should_mask_single_uuids() {
        let uri = "/hosts/a5233b2d-c22b-4dd7-8c8b-48abc8556327/commands/pending";
        let masked = mask_uuid(uri);

        assert_eq!("/hosts/:id/commands/pending", masked);
    }

    #[test]
    fn should_mask_all_uuids() {
        let uri = "/hosts/a5233b2d-c22b-4dd7-8c8b-48abc8556327/commands/58c3f661-9fae-49cf-8851-4bb3b46a6699/pending";
        let masked = mask_uuid(uri);

        assert_eq!("/hosts/:id/commands/:id/pending", masked);
    }
}
