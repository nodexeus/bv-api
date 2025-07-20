use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::HeaderMap;
use axum::routing::{self, Router};
use diesel_async::scoped_futures::ScopedFutureExt;
use serde::Deserialize;

use crate::config::Context;
use crate::database::Transaction;
use crate::grpc::api::protocol_service_get_protocol_request;
use crate::grpc::{self, api};
use crate::http::params::{CommaSeparatedList, validation};

use super::Error;

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/", routing::post(add_protocol))
        .route("/", routing::get(list_protocols))
        .route("/{id}", routing::get(get_protocol))
        .route("/key/{key}", routing::get(get_protocol_by_key))
        .route("/{id}", routing::put(update_protocol))
        .route("/version", routing::post(add_version))
        .route("/version", routing::get(list_versions))
        .route("/version/{id}", routing::put(update_version))
        .route("/latest", routing::get(get_latest))
        .route("/pricing", routing::get(get_pricing))
        .route("/stats", routing::get(get_stats))
        .with_state(context)
}

async fn add_protocol(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::ProtocolServiceAddProtocolRequest>,
) -> Result<Json<api::ProtocolServiceAddProtocolResponse>, Error> {
    ctx.write(|write| grpc::protocol::add_protocol(req, headers.into(), write).scope_boxed())
        .await
}

async fn add_version(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::ProtocolServiceAddVersionRequest>,
) -> Result<Json<api::ProtocolServiceAddVersionResponse>, Error> {
    ctx.write(|write| grpc::protocol::add_version(req, headers.into(), write).scope_boxed())
        .await
}

async fn get_latest(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::ProtocolServiceGetLatestRequest>,
) -> Result<Json<api::ProtocolServiceGetLatestResponse>, Error> {
    ctx.read(|read| grpc::protocol::get_latest(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_pricing(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::ProtocolServiceGetPricingRequest>,
) -> Result<Json<api::ProtocolServiceGetPricingResponse>, Error> {
    ctx.read(|read| grpc::protocol::get_pricing(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolServiceGetProtocolRequest {
    org_id: Option<String>,
}

async fn get_protocol(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((protocol_id,)): Path<(String,)>,
    Query(req): Query<ProtocolServiceGetProtocolRequest>,
) -> Result<Json<api::ProtocolServiceGetProtocolResponse>, Error> {
    let req = api::ProtocolServiceGetProtocolRequest {
        protocol: Some(protocol_service_get_protocol_request::Protocol::ProtocolId(
            protocol_id,
        )),
        org_id: req.org_id,
    };
    ctx.read(|read| grpc::protocol::get_protocol(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_protocol_by_key(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((protocol_key,)): Path<(String,)>,
    Query(req): Query<ProtocolServiceGetProtocolRequest>,
) -> Result<Json<api::ProtocolServiceGetProtocolResponse>, Error> {
    let req = api::ProtocolServiceGetProtocolRequest {
        protocol: Some(protocol_service_get_protocol_request::Protocol::ProtocolKey(protocol_key)),
        org_id: req.org_id,
    };
    ctx.read(|read| grpc::protocol::get_protocol(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_stats(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::ProtocolServiceGetStatsRequest>,
) -> Result<Json<api::ProtocolServiceGetStatsResponse>, Error> {
    ctx.read(|read| grpc::protocol::get_stats(req, headers.into(), read).scope_boxed())
        .await
}

/// HTTP query parameters for listing protocols
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolListParams {
    /// Organization IDs to filter by (supports both singular and plural forms)
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// Search query string
    pub search: Option<String>,
}

impl ProtocolListParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::ProtocolServiceListProtocolsRequest, crate::http::params::ParameterValidationError> {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");

        // Validate org_ids
        let org_ids = if let Some(org_ids) = self.org_ids {
            match validation::validate_uuid_list(&org_ids.0, "org_ids") {
                Ok(_) => org_ids.0,
                Err(e) => {
                    validation_error.add_error(e.parameter, e.error, e.expected);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

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

        Ok(api::ProtocolServiceListProtocolsRequest {
            org_ids,
            offset: self.offset.unwrap_or(0),
            limit,
            search: None, // TODO: Implement search parameter parsing
            sort: Vec::new(), // TODO: Implement sort parameter parsing
        })
    }
}

async fn list_protocols(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(params): Query<ProtocolListParams>,
) -> Result<Json<api::ProtocolServiceListProtocolsResponse>, Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::protocol::list_protocols(req, headers.into(), read).scope_boxed())
        .await
}

async fn list_versions(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::ProtocolServiceListVersionsRequest>,
) -> Result<Json<api::ProtocolServiceListVersionsResponse>, Error> {
    ctx.read(|read| grpc::protocol::list_versions(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolServiceUpdateProtocolRequest {
    name: Option<String>,
    description: Option<String>,
    visibility: Option<i32>,
}

async fn update_protocol(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((protocol_id,)): Path<(String,)>,
    Query(req): Query<ProtocolServiceUpdateProtocolRequest>,
) -> Result<Json<api::ProtocolServiceUpdateProtocolResponse>, Error> {
    let req = api::ProtocolServiceUpdateProtocolRequest {
        protocol_id,
        name: req.name,
        description: req.description,
        visibility: req.visibility,
    };
    ctx.write(|write| grpc::protocol::update_protocol(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolServiceUpdateVersionRequest {
    sku_code: Option<String>,
    description: Option<String>,
    visibility: Option<i32>,
}

async fn update_version(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((protocol_version_id,)): Path<(String,)>,
    Query(req): Query<ProtocolServiceUpdateVersionRequest>,
) -> Result<Json<api::ProtocolServiceUpdateVersionResponse>, Error> {
    let req = api::ProtocolServiceUpdateVersionRequest {
        protocol_version_id,
        sku_code: req.sku_code,
        description: req.description,
        visibility: req.visibility,
    };
    ctx.write(|write| grpc::protocol::update_version(req, headers.into(), write).scope_boxed())
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[test]
    fn test_protocol_list_params_single_org_id() {
        let query = "org_id=550e8400-e29b-41d4-a716-446655440000&limit=15";
        let params: ProtocolListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(params.limit, Some(15));
    }

    #[test]
    fn test_protocol_list_params_plural_org_ids() {
        let query = "org_ids=550e8400-e29b-41d4-a716-446655440000,6ba7b810-9dad-11d1-80b4-00c04fd430c8&offset=5";
        let params: ProtocolListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec![
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        ]);
        assert_eq!(params.offset, Some(5));
    }

    #[test]
    fn test_protocol_list_params_to_grpc_request_success() {
        let params = ProtocolListParams {
            org_ids: Some(CommaSeparatedList(vec!["550e8400-e29b-41d4-a716-446655440000".to_string()])),
            offset: Some(20),
            limit: Some(75),
            search: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_ids, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(grpc_req.offset, 20);
        assert_eq!(grpc_req.limit, 75);
    }

    #[test]
    fn test_protocol_list_params_to_grpc_request_invalid_uuid() {
        let params = ProtocolListParams {
            org_ids: Some(CommaSeparatedList(vec!["invalid-uuid".to_string()])),
            offset: None,
            limit: None,
            search: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "org_ids");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_protocol_list_params_defaults() {
        let params = ProtocolListParams {
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_ids, Vec::<String>::new());
        assert_eq!(grpc_req.offset, 0);
        assert_eq!(grpc_req.limit, 50); // default limit
    }

    #[test]
    fn test_protocol_list_params_limit_validation() {
        let params = ProtocolListParams {
            org_ids: None,
            offset: None,
            limit: Some(1500), // Over the max limit
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