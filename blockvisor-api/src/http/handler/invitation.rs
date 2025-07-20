use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::routing::{self, Router};
use diesel_async::scoped_futures::ScopedFutureExt;
use serde::Deserialize;

use crate::config::Context;
use crate::database::Transaction;
use crate::grpc::{self, api};
use crate::http::params::validation;

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/", routing::post(create))
        .route("/", routing::get(list))
        .route("/{id}/accept", routing::post(accept))
        .route("/{id}/decline", routing::post(decline))
        .route("/{id}/revoke", routing::post(revoke))
        .with_state(context)
}

async fn create(
    State(ctx): State<Arc<Context>>,
    headers: axum::http::header::HeaderMap,
    Json(req): Json<api::InvitationServiceCreateRequest>,
) -> Result<Json<api::InvitationServiceCreateResponse>, super::Error> {
    ctx.write(|write| grpc::invitation::create(req, headers.into(), write).scope_boxed())
        .await
}

/// HTTP query parameters for listing invitations
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationListParams {
    /// Organization ID to filter by
    pub org_id: Option<String>,
    /// Invitee email to filter by
    pub invitee_email: Option<String>,
}

impl InvitationListParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::InvitationServiceListRequest, crate::http::params::ParameterValidationError> {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");

        // Validate org_id if provided
        if let Some(ref org_id) = self.org_id {
            if let Err(e) = validation::validate_uuid(org_id, "org_id") {
                validation_error.add_error(e.parameter, e.error, e.expected);
            }
        }

        // Return validation errors if any
        if !validation_error.is_empty() {
            return Err(validation_error);
        }

        Ok(api::InvitationServiceListRequest {
            org_id: self.org_id,
            invitee_email: self.invitee_email,
            ..Default::default()
        })
    }
}

async fn list(
    State(ctx): State<Arc<Context>>,
    headers: axum::http::header::HeaderMap,
    Query(params): Query<InvitationListParams>,
) -> Result<Json<api::InvitationServiceListResponse>, super::Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(super::Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::invitation::list(req, headers.into(), read).scope_boxed())
        .await
}

async fn accept(
    State(ctx): State<Arc<Context>>,
    headers: axum::http::header::HeaderMap,
    Path((invitation_id,)): Path<(String,)>,
) -> Result<Json<api::InvitationServiceAcceptResponse>, super::Error> {
    let req = api::InvitationServiceAcceptRequest { invitation_id };
    ctx.write(|write| grpc::invitation::accept(req, headers.into(), write).scope_boxed())
        .await
}

async fn decline(
    State(ctx): State<Arc<Context>>,
    headers: axum::http::header::HeaderMap,
    Path((invitation_id,)): Path<(String,)>,
) -> Result<Json<api::InvitationServiceDeclineResponse>, super::Error> {
    let req = api::InvitationServiceDeclineRequest { invitation_id };
    ctx.write(|write| grpc::invitation::decline(req, headers.into(), write).scope_boxed())
        .await
}

async fn revoke(
    State(ctx): State<Arc<Context>>,
    headers: axum::http::header::HeaderMap,
    Path((invitation_id,)): Path<(String,)>,
) -> Result<Json<api::InvitationServiceRevokeResponse>, super::Error> {
    let req = api::InvitationServiceRevokeRequest { invitation_id };
    ctx.write(|write| grpc::invitation::revoke(req, headers.into(), write).scope_boxed())
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[test]
    fn test_invitation_list_params_basic() {
        let query = "org_id=550e8400-e29b-41d4-a716-446655440000&invitee_email=user@example.com";
        let params: InvitationListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert_eq!(params.org_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
        assert_eq!(params.invitee_email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_invitation_list_params_to_grpc_request_success() {
        let params = InvitationListParams {
            org_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            invitee_email: Some("user@example.com".to_string()),
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
        assert_eq!(grpc_req.invitee_email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_invitation_list_params_to_grpc_request_invalid_org_id() {
        let params = InvitationListParams {
            org_id: Some("not-a-uuid".to_string()),
            invitee_email: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "org_id");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_invitation_list_params_optional_fields() {
        let params = InvitationListParams {
            org_id: None,
            invitee_email: Some("user@example.com".to_string()),
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_id, None);
        assert_eq!(grpc_req.invitee_email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_invitation_list_params_empty() {
        let params = InvitationListParams {
            org_id: None,
            invitee_email: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_id, None);
        assert_eq!(grpc_req.invitee_email, None);
    }
}