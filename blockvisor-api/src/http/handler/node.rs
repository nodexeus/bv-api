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
use crate::http::params::{CommaSeparatedList, validation};

use super::Error;

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/{id}", routing::get(get))
        .route("/", routing::get(list))
        .route("/", routing::post(create))
        .route("/{id}/report", routing::post(report_error))
        .route("/status", routing::post(report_status))
        .route("/config", routing::put(update_config))
        .route("/image", routing::put(upgrade_image))
        .route("/{id}/start", routing::put(start))
        .route("/{id}/stop", routing::put(stop))
        .route("/{id}/restart", routing::put(restart))
        .route("/{id}", routing::delete(delete))
        .with_state(context)
}

async fn create(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceCreateRequest>,
) -> Result<Json<api::NodeServiceCreateResponse>, Error> {
    ctx.write(|write| grpc::node::create(req, headers.into(), write).scope_boxed())
        .await
}

async fn get(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(req): Query<api::NodeServiceGetRequest>,
) -> Result<Json<api::NodeServiceGetResponse>, Error> {
    ctx.read(|read| grpc::node::get(req, headers.into(), read).scope_boxed())
        .await
}

async fn list(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(params): Query<NodeListParams>,
) -> Result<Json<api::NodeServiceListResponse>, Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::node::list(req, headers.into(), read).scope_boxed())
        .await
}

/// HTTP query parameters for listing nodes
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeListParams {
    /// Organization IDs to filter by (supports both singular and plural forms)
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// Search query string
    pub search: Option<String>,
    /// Protocol IDs to filter by
    pub protocol_ids: Option<CommaSeparatedList<String>>,
    /// Semantic versions to filter by
    pub semantic_versions: Option<CommaSeparatedList<String>>,
    /// Host IDs to filter by
    #[serde(alias = "host_id")]
    pub host_ids: Option<CommaSeparatedList<String>>,
    /// User IDs to filter by
    #[serde(alias = "user_id")]
    pub user_ids: Option<CommaSeparatedList<String>>,
    /// IP addresses to filter by
    pub ip_addresses: Option<CommaSeparatedList<String>>,
    /// Node states to filter by
    pub node_states: Option<CommaSeparatedList<String>>,
    /// Next states to filter by
    pub next_states: Option<CommaSeparatedList<String>>,
}

impl NodeListParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::NodeServiceListRequest, crate::http::params::ParameterValidationError> {
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

        // Validate host_ids
        let host_ids = if let Some(host_ids) = self.host_ids {
            match validation::validate_uuid_list(&host_ids.0, "host_ids") {
                Ok(_) => host_ids.0,
                Err(e) => {
                    validation_error.add_error(e.parameter, e.error, e.expected);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // Validate user_ids
        let user_ids = if let Some(user_ids) = self.user_ids {
            match validation::validate_uuid_list(&user_ids.0, "user_ids") {
                Ok(_) => user_ids.0,
                Err(e) => {
                    validation_error.add_error(e.parameter, e.error, e.expected);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // Validate node_states and convert to gRPC enum integers
        let node_states = if let Some(node_states) = self.node_states {
            let mut validated_states = Vec::new();
            for state in &node_states.0 {
                if let Err(e) = validation::validate_node_state(state, "node_states") {
                    validation_error.add_error(e.parameter, e.error, e.expected);
                } else {
                    // Convert string to gRPC enum integer
                    let enum_value = match state.as_str() {
                        "starting" => common::NodeState::Starting as i32,
                        "running" => common::NodeState::Running as i32,
                        "stopped" => common::NodeState::Stopped as i32,
                        "failed" => common::NodeState::Failed as i32,
                        "upgrading" => common::NodeState::Upgrading as i32,
                        "deleting" => common::NodeState::Deleting as i32,
                        "deleted" => common::NodeState::Deleted as i32,
                        _ => common::NodeState::Unspecified as i32, // This shouldn't happen due to validation
                    };
                    validated_states.push(enum_value);
                }
            }
            validated_states
        } else {
            Vec::new()
        };

        // Validate next_states and convert to gRPC enum integers
        let next_states = if let Some(next_states) = self.next_states {
            let mut validated_states = Vec::new();
            for state in &next_states.0 {
                // Next states are: stopping, deleting, upgrading
                let allowed_next_states = ["stopping", "deleting", "upgrading"];
                if let Err(e) = validation::validate_enum(state, &allowed_next_states, "next_states") {
                    validation_error.add_error(e.parameter, e.error, e.expected);
                } else {
                    // Convert string to gRPC enum integer
                    let enum_value = match state.as_str() {
                        "stopping" => common::NextState::Stopping as i32,
                        "deleting" => common::NextState::Deleting as i32,
                        "upgrading" => common::NextState::Upgrading as i32,
                        _ => common::NextState::Unspecified as i32, // This shouldn't happen due to validation
                    };
                    validated_states.push(enum_value);
                }
            }
            validated_states
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

        Ok(api::NodeServiceListRequest {
            org_ids,
            offset: self.offset.unwrap_or(0),
            limit,
            search: None, // TODO: Implement search parameter parsing
            sort: Vec::new(), // TODO: Implement sort parameter parsing
            protocol_ids: self.protocol_ids.map(|p| p.0).unwrap_or_default(),
            version_keys: Vec::new(), // TODO: Implement version_keys parsing
            semantic_versions: self.semantic_versions.map(|s| s.0).unwrap_or_default(),
            host_ids,
            user_ids,
            ip_addresses: self.ip_addresses.map(|i| i.0).unwrap_or_default(),
            node_states,
            next_states,
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeServiceReportErrorRequest {
    created_by: common::Resource,
    message: String,
}

async fn report_error(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((node_id,)): Path<(String,)>,
    Json(req): Json<NodeServiceReportErrorRequest>,
) -> Result<Json<api::NodeServiceReportErrorResponse>, Error> {
    let req = api::NodeServiceReportErrorRequest {
        node_id,
        created_by: Some(req.created_by),
        message: req.message,
    };
    ctx.write(|write| grpc::node::report_error(req, headers.into(), write).scope_boxed())
        .await
}

async fn report_status(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceReportStatusRequest>,
) -> Result<Json<api::NodeServiceReportStatusResponse>, Error> {
    ctx.write(|write| grpc::node::report_status(req, headers.into(), write).scope_boxed())
        .await
}

async fn update_config(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceUpdateConfigRequest>,
) -> Result<Json<api::NodeServiceUpdateConfigResponse>, Error> {
    ctx.write(|write| grpc::node::update_config(req, headers.into(), write).scope_boxed())
        .await
}

async fn upgrade_image(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceUpgradeImageRequest>,
) -> Result<Json<api::NodeServiceUpgradeImageResponse>, Error> {
    ctx.write(|write| grpc::node::upgrade_image(req, headers.into(), write).scope_boxed())
        .await
}

async fn start(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceStartRequest>,
) -> Result<Json<api::NodeServiceStartResponse>, Error> {
    ctx.write(|write| grpc::node::start(req, headers.into(), write).scope_boxed())
        .await
}

async fn stop(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceStopRequest>,
) -> Result<Json<api::NodeServiceStopResponse>, Error> {
    ctx.write(|write| grpc::node::stop(req, headers.into(), write).scope_boxed())
        .await
}

async fn restart(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceRestartRequest>,
) -> Result<Json<api::NodeServiceRestartResponse>, Error> {
    ctx.write(|write| grpc::node::restart(req, headers.into(), write).scope_boxed())
        .await
}

async fn delete(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::NodeServiceDeleteRequest>,
) -> Result<Json<api::NodeServiceDeleteResponse>, Error> {
    ctx.write(|write| grpc::node::delete(req, headers.into(), write).scope_boxed())
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[test]
    fn test_node_list_params_single_org_id() {
        let query = "org_id=550e8400-e29b-41d4-a716-446655440000&limit=10";
        let params: NodeListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(params.limit, Some(10));
    }

    #[test]
    fn test_node_list_params_plural_org_ids() {
        let query = "org_ids=550e8400-e29b-41d4-a716-446655440000,6ba7b810-9dad-11d1-80b4-00c04fd430c8&limit=20";
        let params: NodeListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec![
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        ]);
        assert_eq!(params.limit, Some(20));
    }

    #[test]
    fn test_node_list_params_to_grpc_request_success() {
        let params = NodeListParams {
            org_ids: Some(CommaSeparatedList(vec!["550e8400-e29b-41d4-a716-446655440000".to_string()])),
            offset: Some(10),
            limit: Some(50),
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: None,
            next_states: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_ids, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(grpc_req.offset, 10);
        assert_eq!(grpc_req.limit, 50);
    }

    #[test]
    fn test_node_list_params_to_grpc_request_invalid_uuid() {
        let params = NodeListParams {
            org_ids: Some(CommaSeparatedList(vec!["not-a-uuid".to_string()])),
            offset: None,
            limit: None,
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: None,
            next_states: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "org_ids");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_node_list_params_to_grpc_request_limit_out_of_range() {
        let params = NodeListParams {
            org_ids: None,
            offset: None,
            limit: Some(2000), // Over the max limit of 1000
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: None,
            next_states: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "limit");
        assert!(error.errors[0].error.contains("out of range"));
    }

    #[test]
    fn test_node_list_params_defaults() {
        let params = NodeListParams {
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: None,
            next_states: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_ids, Vec::<String>::new());
        assert_eq!(grpc_req.offset, 0);
        assert_eq!(grpc_req.limit, 50); // default limit
    }

    #[test]
    fn test_node_list_params_valid_node_states() {
        let params = NodeListParams {
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: Some(CommaSeparatedList(vec!["running".to_string(), "stopped".to_string()])),
            next_states: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.node_states, vec![
            common::NodeState::Running as i32, 
            common::NodeState::Stopped as i32
        ]);
    }

    #[test]
    fn test_node_list_params_invalid_node_states() {
        let params = NodeListParams {
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: Some(CommaSeparatedList(vec!["invalid_state".to_string()])),
            next_states: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "node_states");
        assert!(error.errors[0].error.contains("Invalid value"));
        assert!(error.errors[0].expected.contains("starting, running, stopped"));
    }

    #[test]
    fn test_node_list_params_valid_next_states() {
        let params = NodeListParams {
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: None,
            next_states: Some(CommaSeparatedList(vec!["stopping".to_string(), "upgrading".to_string()])),
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.next_states, vec![
            common::NextState::Stopping as i32, 
            common::NextState::Upgrading as i32
        ]);
    }

    #[test]
    fn test_node_list_params_invalid_next_states() {
        let params = NodeListParams {
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
            protocol_ids: None,
            semantic_versions: None,
            host_ids: None,
            user_ids: None,
            ip_addresses: None,
            node_states: None,
            next_states: Some(CommaSeparatedList(vec!["invalid_next_state".to_string()])),
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "next_states");
        assert!(error.errors[0].error.contains("Invalid value"));
        assert!(error.errors[0].expected.contains("stopping, deleting, upgrading"));
    }
}