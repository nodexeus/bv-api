use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::HeaderMap;
use axum::routing::{self, Router};
use diesel_async::scoped_futures::ScopedFutureExt;
use serde::Deserialize;

use crate::config::Context;
use crate::database::Transaction;
use crate::grpc::{self, api, common};
use crate::http::params::validation;

use super::Error;

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/", routing::post(create))
        .route("/{id}", routing::get(get))
        .route("/", routing::get(list))
        .route("/{id}", routing::put(update))
        .route("/{id}", routing::delete(delete))
        .route("/{id}/member", routing::delete(remove_member))
        .route("/{id}/provision-token", routing::get(get_provision_token))
        .route(
            "/{id}/provision-token",
            routing::post(reset_provision_token),
        )
        .route("/{id}/init-card", routing::post(init_card))
        .route("/{id}/payment-methods", routing::get(list_payment_methods))
        .route("/{id}/billing-details", routing::get(billing_details))
        .route("/{id}/address", routing::get(get_address))
        .route("/{id}/address", routing::post(set_address))
        .route("/{id}/address", routing::delete(delete_address))
        .route("/{id}/invoices", routing::get(get_invoices))
        .with_state(context)
}

async fn create(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::OrgServiceCreateRequest>,
) -> Result<Json<api::OrgServiceCreateResponse>, Error> {
    ctx.write(|write| grpc::org::create(req, headers.into(), write).scope_boxed())
        .await
}

async fn get(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceGetResponse>, Error> {
    let req = api::OrgServiceGetRequest { org_id };
    ctx.read(|read| grpc::org::get(req, headers.into(), read).scope_boxed())
        .await
}

/// HTTP query parameters for listing organizations
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgListParams {
    /// Member ID to filter by - only return orgs that this user is a member of
    pub member_id: Option<String>,
    /// If true, only personal orgs are returned, otherwise none are
    pub personal: Option<bool>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// Search query string
    pub search: Option<String>,
}

impl OrgListParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::OrgServiceListRequest, crate::http::params::ParameterValidationError> {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");

        // Validate member_id if provided
        if let Some(ref member_id) = self.member_id {
            if let Err(e) = validation::validate_uuid(member_id, "member_id") {
                validation_error.add_error(e.parameter, e.error, e.expected);
            }
        }

        // Validate limit
        let limit = if let Some(limit) = self.limit {
            match validation::validate_range(limit, 1u64, 1000u64, "limit") {
                Ok(l) => l,
                Err(e) => {
                    validation_error.add_error(e.parameter, e.error, e.expected);
                    50 // default
                }
            }
        } else {
            50 // default
        };

        // Return validation errors if any
        if !validation_error.is_empty() {
            return Err(validation_error);
        }

        Ok(api::OrgServiceListRequest {
            member_id: self.member_id,
            personal: self.personal,
            offset: self.offset.unwrap_or(0),
            limit,
            search: None, // TODO: Implement search parameter parsing
            sort: Vec::new(), // TODO: Implement sort parameter parsing
        })
    }
}

async fn list(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(params): Query<OrgListParams>,
) -> Result<Json<api::OrgServiceListResponse>, Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::org::list(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgServiceUpdateRequest {
    name: Option<String>,
}

async fn update(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(req): Json<OrgServiceUpdateRequest>,
) -> Result<Json<api::OrgServiceUpdateResponse>, Error> {
    let req = api::OrgServiceUpdateRequest {
        org_id,
        name: req.name,
    };
    ctx.write(|write| grpc::org::update(req, headers.into(), write).scope_boxed())
        .await
}

async fn delete(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceDeleteResponse>, Error> {
    let req = api::OrgServiceDeleteRequest { org_id };
    ctx.write(|write| grpc::org::delete(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgServiceRemoveMemberRequest {
    user_id: String,
}

async fn remove_member(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(req): Json<OrgServiceRemoveMemberRequest>,
) -> Result<Json<api::OrgServiceRemoveMemberResponse>, Error> {
    let req = api::OrgServiceRemoveMemberRequest {
        user_id: req.user_id,
        org_id,
    };
    ctx.write(|write| grpc::org::remove_member(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgServiceGetProvisionTokenRequest {
    user_id: String,
}

impl OrgServiceGetProvisionTokenRequest {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self, org_id: String) -> Result<api::OrgServiceGetProvisionTokenRequest, crate::http::params::ParameterValidationError> {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");

        // Validate user_id
        if let Err(e) = validation::validate_uuid(&self.user_id, "user_id") {
            validation_error.add_error(e.parameter, e.error, e.expected);
        }

        // Validate org_id
        if let Err(e) = validation::validate_uuid(&org_id, "org_id") {
            validation_error.add_error(e.parameter, e.error, e.expected);
        }

        // Return validation errors if any
        if !validation_error.is_empty() {
            return Err(validation_error);
        }

        Ok(api::OrgServiceGetProvisionTokenRequest {
            user_id: self.user_id,
            org_id,
        })
    }
}

async fn get_provision_token(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Query(params): Query<OrgServiceGetProvisionTokenRequest>,
) -> Result<Json<api::OrgServiceGetProvisionTokenResponse>, Error> {
    let req = match params.to_grpc_request(org_id) {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::org::get_provision_token(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgServiceResetProvisionTokenRequest {
    user_id: String,
}

async fn reset_provision_token(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(req): Json<OrgServiceResetProvisionTokenRequest>,
) -> Result<Json<api::OrgServiceResetProvisionTokenResponse>, Error> {
    let req = api::OrgServiceResetProvisionTokenRequest {
        user_id: req.user_id,
        org_id,
    };
    ctx.write(|write| grpc::org::reset_provision_token(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgServiceInitCardRequest {
    user_id: String,
}

async fn init_card(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(req): Json<OrgServiceInitCardRequest>,
) -> Result<Json<api::OrgServiceInitCardResponse>, Error> {
    let req = api::OrgServiceInitCardRequest {
        user_id: req.user_id,
        org_id,
    };
    ctx.write(|write| grpc::org::init_card(req, headers.into(), write).scope_boxed())
        .await
}

async fn list_payment_methods(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceListPaymentMethodsResponse>, Error> {
    let req = api::OrgServiceListPaymentMethodsRequest { org_id };
    ctx.read(|read| grpc::org::list_payment_methods(req, headers.into(), read).scope_boxed())
        .await
}

async fn billing_details(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceBillingDetailsResponse>, Error> {
    let req = api::OrgServiceBillingDetailsRequest { org_id };
    ctx.read(|read| grpc::org::billing_details(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_address(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceGetAddressResponse>, Error> {
    let req = api::OrgServiceGetAddressRequest { org_id };
    ctx.read(|read| grpc::org::get_address(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgServiceSetAddressRequest {
    address: common::Address,
}

async fn set_address(
    State(ctx): State<Arc<Context>>,
    headers: axum::http::header::HeaderMap,
    Path((org_id,)): Path<(String,)>,
    Json(req): Json<OrgServiceSetAddressRequest>,
) -> Result<Json<api::OrgServiceSetAddressResponse>, super::Error> {
    let req = api::OrgServiceSetAddressRequest {
        org_id,
        address: Some(req.address),
    };
    ctx.read(|read| grpc::org::set_address(req, headers.into(), read).scope_boxed())
        .await
}

async fn delete_address(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceDeleteAddressResponse>, super::Error> {
    let req = api::OrgServiceDeleteAddressRequest { org_id };
    ctx.read(|read| grpc::org::delete_address(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_invoices(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((org_id,)): Path<(String,)>,
) -> Result<Json<api::OrgServiceGetInvoicesResponse>, super::Error> {
    let req = api::OrgServiceGetInvoicesRequest { org_id };
    ctx.read(|read| grpc::org::get_invoices(req, headers.into(), read).scope_boxed())
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[test]
    fn test_org_list_params_basic() {
        let query = "member_id=550e8400-e29b-41d4-a716-446655440000&personal=true&limit=25";
        let params: OrgListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert_eq!(params.member_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
        assert_eq!(params.personal, Some(true));
        assert_eq!(params.limit, Some(25));
    }

    #[test]
    fn test_org_list_params_to_grpc_request_success() {
        let params = OrgListParams {
            member_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            personal: Some(false),
            offset: Some(5),
            limit: Some(100),
            search: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.member_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
        assert_eq!(grpc_req.personal, Some(false));
        assert_eq!(grpc_req.offset, 5);
        assert_eq!(grpc_req.limit, 100);
    }

    #[test]
    fn test_org_list_params_to_grpc_request_invalid_member_id() {
        let params = OrgListParams {
            member_id: Some("not-a-uuid".to_string()),
            personal: None,
            offset: None,
            limit: None,
            search: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "member_id");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_org_list_params_defaults() {
        let params = OrgListParams {
            member_id: None,
            personal: None,
            offset: None,
            limit: None,
            search: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.member_id, None);
        assert_eq!(grpc_req.personal, None);
        assert_eq!(grpc_req.offset, 0);
        assert_eq!(grpc_req.limit, 50); // default limit
    }

    #[test]
    fn test_org_list_params_limit_validation() {
        let params = OrgListParams {
            member_id: None,
            personal: None,
            offset: None,
            limit: Some(2000), // Over the max limit
            search: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "limit");
        assert!(error.errors[0].error.contains("out of range"));
    }
}