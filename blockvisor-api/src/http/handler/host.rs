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
        .route("/", routing::post(create_host))
        .route("/region", routing::post(create_region))
        .route("/{id}", routing::get(get_host))
        .route("/region/{id}", routing::get(get_region))
        .route("/", routing::get(list_hosts))
        .route("/regions", routing::get(list_regions))
        .route("/{id}/nodes", routing::get(list_host_nodes))
        .route("/{id}", routing::put(update_host))
        .route("/region/{id}", routing::put(update_region))
        .route("/{id}", routing::delete(delete_host))
        .route("/{id}/start", routing::put(start))
        .route("/{id}/stop", routing::put(stop))
        .route("/{id}/restart", routing::put(restart))
        .with_state(context)
}

async fn create_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::HostServiceCreateHostRequest>,
) -> Result<Json<api::HostServiceCreateHostResponse>, Error> {
    ctx.write(|write| grpc::host::create_host(req, headers.into(), write).scope_boxed())
        .await
}

async fn create_region(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::HostServiceCreateRegionRequest>,
) -> Result<Json<api::HostServiceCreateRegionResponse>, Error> {
    ctx.write(|write| grpc::host::create_region(req, headers.into(), write).scope_boxed())
        .await
}

async fn get_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceGetHostResponse>, Error> {
    let req = api::HostServiceGetHostRequest { host_id };
    ctx.read(|read| grpc::host::get_host(req, headers.into(), read).scope_boxed())
        .await
}

async fn get_region(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((region_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceGetRegionResponse>, Error> {
    let req = api::HostServiceGetRegionRequest {
        region: Some(api::host_service_get_region_request::Region::RegionId(
            region_id,
        )),
    };
    ctx.read(|read| grpc::host::get_region(req, headers.into(), read).scope_boxed())
        .await
}

/// HTTP query parameters for listing hosts
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostListParams {
    /// Organization IDs to filter by (supports both singular and plural forms)
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    /// Blockvisor versions to filter by
    pub bv_versions: Option<CommaSeparatedList<String>>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// Search query string
    pub search: Option<String>,
}

impl HostListParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::HostServiceListHostsRequest, crate::http::params::ParameterValidationError> {
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

        Ok(api::HostServiceListHostsRequest {
            org_ids,
            bv_versions: self.bv_versions.map(|v| v.0).unwrap_or_default(),
            offset: self.offset.unwrap_or(0),
            limit,
            search: None, // TODO: Implement search parameter parsing
            sort: Vec::new(), // TODO: Implement sort parameter parsing
        })
    }
}

/// HTTP query parameters for listing regions
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostListRegionsParams {
    /// Image ID to list regions for
    pub image_id: String,
    /// Organization ID for private hosts, images or protocols
    pub org_id: Option<String>,
}

impl HostListRegionsParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::HostServiceListRegionsRequest, crate::http::params::ParameterValidationError> {
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

        Ok(api::HostServiceListRegionsRequest {
            image_id: self.image_id,
            org_id: self.org_id,
        })
    }
}

/// HTTP query parameters for listing nodes on a specific host
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNodesParams {
    /// Node states to filter by
    pub node_states: Option<CommaSeparatedList<String>>,
    /// Next states to filter by
    pub next_states: Option<CommaSeparatedList<String>>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// IP addresses to filter by
    pub ip_addresses: Option<CommaSeparatedList<String>>,
}

impl HostNodesParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self, host_id: String) -> Result<api::NodeServiceListRequest, crate::http::params::ParameterValidationError> {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");

        // Validate host_id
        if let Err(e) = validation::validate_uuid(&host_id, "host_id") {
            validation_error.add_error(e.parameter, e.error, e.expected);
        }

        // Validate and convert node_states
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

        // Validate and convert next_states
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
            // For authorization to work properly, we need to let the gRPC service
            // handle the org_ids filtering based on the user's permissions
            org_ids: Vec::new(),
            host_ids: vec![host_id], // Filter by specific host
            offset: self.offset.unwrap_or(0),
            limit,
            node_states,
            next_states,
            ip_addresses: self.ip_addresses.map(|i| i.0).unwrap_or_default(),
            // Set other fields to defaults
            protocol_ids: Vec::new(),
            semantic_versions: Vec::new(),
            user_ids: Vec::new(),
            search: None,
            sort: Vec::new(),
            version_keys: Vec::new(),
        })
    }


}

async fn list_hosts(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(params): Query<HostListParams>,
) -> Result<Json<api::HostServiceListHostsResponse>, Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::host::list_hosts(req, headers.into(), read).scope_boxed())
        .await
}

async fn list_host_nodes(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
    Query(params): Query<HostNodesParams>,
) -> Result<Json<api::NodeServiceListResponse>, Error> {
    // First validate the host_id format before proceeding
    if let Err(_) = uuid::Uuid::parse_str(&host_id) {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");
        validation_error.add_error(
            "host_id", 
            format!("Invalid UUID format: '{}'", host_id), 
            "Valid UUID string (e.g., '550e8400-e29b-41d4-a716-446655440000')"
        );
        return Err(Error::new(
            validation_error.to_json(),
            hyper::StatusCode::BAD_REQUEST,
        ));
    }

    let req = match params.to_grpc_request(host_id.clone()) {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    // Use the existing node list gRPC service which handles authorization properly
    // The gRPC service will filter results based on user permissions, so we don't need
    // to handle authorization errors differently - empty results are valid for hosts
    // the user can't access or hosts that don't exist
    ctx.read(|read| grpc::node::list(req, headers.into(), read).scope_boxed())
        .await
}

async fn list_regions(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(params): Query<HostListRegionsParams>,
) -> Result<Json<api::HostServiceListRegionsResponse>, Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::host::list_regions(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostServiceUpdateHostRequest {
    network_name: Option<String>,
    display_name: Option<String>,
    region_id: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    bv_version: Option<String>,
    cpu_cores: Option<u64>,
    memory_bytes: Option<u64>,
    disk_bytes: Option<u64>,
    schedule_type: Option<i32>,
    update_tags: Option<common::UpdateTags>,
    cost: Option<common::BillingAmount>,
}

async fn update_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
    Json(req): Json<HostServiceUpdateHostRequest>,
) -> Result<Json<api::HostServiceUpdateHostResponse>, Error> {
    let req = api::HostServiceUpdateHostRequest {
        host_id,
        network_name: req.network_name,
        display_name: req.display_name,
        region_id: req.region_id,
        os: req.os,
        os_version: req.os_version,
        bv_version: req.bv_version,
        cpu_cores: req.cpu_cores,
        memory_bytes: req.memory_bytes,
        disk_bytes: req.disk_bytes,
        schedule_type: req.schedule_type,
        update_tags: req.update_tags,
        cost: req.cost,
    };
    ctx.write(|write| grpc::host::update_host(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostServiceUpdateRegionRequest {
    display_name: Option<String>,
    sku_code: Option<String>,
}

async fn update_region(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((region_id,)): Path<(String,)>,
    Json(req): Json<HostServiceUpdateRegionRequest>,
) -> Result<Json<api::HostServiceUpdateRegionResponse>, Error> {
    let req = api::HostServiceUpdateRegionRequest {
        region_id,
        display_name: req.display_name,
        sku_code: req.sku_code,
    };
    ctx.write(|write| grpc::host::update_region(req, headers.into(), write).scope_boxed())
        .await
}

async fn delete_host(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceDeleteHostResponse>, Error> {
    let req = api::HostServiceDeleteHostRequest { host_id };
    ctx.write(|write| grpc::host::delete_host(req, headers.into(), write).scope_boxed())
        .await
}

async fn start(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceStartResponse>, Error> {
    let req = api::HostServiceStartRequest { host_id };
    ctx.write(|write| grpc::host::start(req, headers.into(), write).scope_boxed())
        .await
}

async fn stop(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceStopResponse>, Error> {
    let req = api::HostServiceStopRequest { host_id };
    ctx.write(|write| grpc::host::stop(req, headers.into(), write).scope_boxed())
        .await
}

async fn restart(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
) -> Result<Json<api::HostServiceRestartResponse>, Error> {
    let req = api::HostServiceRestartRequest { host_id };
    ctx.write(|write| grpc::host::restart(req, headers.into(), write).scope_boxed())
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[test]
    fn test_host_list_params_single_org_id() {
        let query = "org_id=550e8400-e29b-41d4-a716-446655440000&limit=10";
        let params: HostListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(params.limit, Some(10));
    }

    #[test]
    fn test_host_list_params_plural_org_ids() {
        let query = "org_ids=550e8400-e29b-41d4-a716-446655440000,6ba7b810-9dad-11d1-80b4-00c04fd430c8&limit=20";
        let params: HostListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec![
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        ]);
        assert_eq!(params.limit, Some(20));
    }

    #[test]
    fn test_host_list_params_to_grpc_request_success() {
        let params = HostListParams {
            org_ids: Some(CommaSeparatedList(vec!["550e8400-e29b-41d4-a716-446655440000".to_string()])),
            bv_versions: Some(CommaSeparatedList(vec!["1.0.0".to_string()])),
            offset: Some(10),
            limit: Some(50),
            search: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.org_ids, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(grpc_req.bv_versions, vec!["1.0.0"]);
        assert_eq!(grpc_req.offset, 10);
        assert_eq!(grpc_req.limit, 50);
    }

    #[test]
    fn test_host_list_params_to_grpc_request_invalid_uuid() {
        let params = HostListParams {
            org_ids: Some(CommaSeparatedList(vec!["not-a-uuid".to_string()])),
            bv_versions: None,
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
    fn test_host_list_regions_params_success() {
        let query = "image_id=img123&org_id=550e8400-e29b-41d4-a716-446655440000";
        let params: HostListRegionsParams = serde_urlencoded::from_str(query).unwrap();
        
        assert_eq!(params.image_id, "img123");
        assert_eq!(params.org_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
    }

    #[test]
    fn test_host_list_regions_params_to_grpc_request_success() {
        let params = HostListRegionsParams {
            image_id: "img123".to_string(),
            org_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.image_id, "img123");
        assert_eq!(grpc_req.org_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
    }

    #[test]
    fn test_host_list_regions_params_invalid_org_id() {
        let params = HostListRegionsParams {
            image_id: "img123".to_string(),
            org_id: Some("not-a-uuid".to_string()),
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "org_id");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_host_nodes_params_basic() {
        let query = "node_states=running,stopped&limit=25&offset=10";
        let params: HostNodesParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.node_states.is_some());
        assert_eq!(params.node_states.unwrap().0, vec!["running", "stopped"]);
        assert_eq!(params.limit, Some(25));
        assert_eq!(params.offset, Some(10));
    }

    #[test]
    fn test_host_nodes_params_to_grpc_request_success() {
        let params = HostNodesParams {
            node_states: Some(CommaSeparatedList(vec!["running".to_string(), "stopped".to_string()])),
            next_states: None,
            offset: Some(5),
            limit: Some(100),
            ip_addresses: None,
        };

        let host_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        let grpc_req = params.to_grpc_request(host_id.clone()).unwrap();
        
        assert_eq!(grpc_req.host_ids, vec![host_id]);
        assert_eq!(grpc_req.offset, 5);
        assert_eq!(grpc_req.limit, 100);
        assert_eq!(grpc_req.node_states, vec![
            common::NodeState::Running as i32,
            common::NodeState::Stopped as i32
        ]);
    }

    #[test]
    fn test_host_nodes_params_invalid_host_id() {
        let params = HostNodesParams {
            node_states: None,
            next_states: None,
            offset: None,
            limit: None,
            ip_addresses: None,
        };

        let result = params.to_grpc_request("not-a-uuid".to_string());
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "host_id");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_host_nodes_params_invalid_node_states() {
        let params = HostNodesParams {
            node_states: Some(CommaSeparatedList(vec!["invalid_state".to_string()])),
            next_states: None,
            offset: None,
            limit: None,
            ip_addresses: None,
        };

        let host_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        let result = params.to_grpc_request(host_id);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "node_states");
        assert!(error.errors[0].error.contains("Invalid value"));
    }

    #[test]
    fn test_host_nodes_params_valid_next_states() {
        let params = HostNodesParams {
            node_states: None,
            next_states: Some(CommaSeparatedList(vec!["stopping".to_string(), "upgrading".to_string()])),
            offset: None,
            limit: None,
            ip_addresses: None,
        };

        let host_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        let grpc_req = params.to_grpc_request(host_id).unwrap();
        
        assert_eq!(grpc_req.next_states, vec![
            common::NextState::Stopping as i32,
            common::NextState::Upgrading as i32
        ]);
    }

    #[test]
    fn test_host_nodes_params_limit_validation() {
        let params = HostNodesParams {
            node_states: None,
            next_states: None,
            offset: None,
            limit: Some(2000), // Over the max limit
            ip_addresses: None,
        };

        let host_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        let result = params.to_grpc_request(host_id);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "limit");
        assert!(error.errors[0].error.contains("out of range"));
    }

    #[test]
    fn test_host_nodes_params_defaults() {
        let params = HostNodesParams {
            node_states: None,
            next_states: None,
            offset: None,
            limit: None,
            ip_addresses: None,
        };

        let host_id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        let grpc_req = params.to_grpc_request(host_id.clone()).unwrap();
        
        assert_eq!(grpc_req.host_ids, vec![host_id]);
        assert_eq!(grpc_req.offset, 0);
        assert_eq!(grpc_req.limit, 50); // default limit
        assert_eq!(grpc_req.node_states, Vec::<i32>::new());
        assert_eq!(grpc_req.next_states, Vec::<i32>::new());
    }
}