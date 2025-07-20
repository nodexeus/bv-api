use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header::HeaderMap;
use axum::routing::{self, Router};
use diesel_async::scoped_futures::ScopedFutureExt;
use serde::Deserialize;

use crate::config::Context;
use crate::database::Transaction;
use crate::grpc::{self, api};
use crate::http::params::{CommaSeparatedList, validation};

use super::Error;

pub fn router<S>(context: Arc<Context>) -> Router<S>
where
    S: Clone + Send + Sync,
{
    Router::new()
        .route("/", routing::post(create))
        .route("/{user_id}", routing::get(get))
        .route("/", routing::get(list))
        .route("/", routing::put(update))
        .route("/{user_id}", routing::delete(delete))
        .route("/{user_id}/settings", routing::get(get_settings))
        .route("/{user_id}/settings", routing::put(update_settings))
        .route("/{user_id}/settings", routing::delete(delete_settings))
        .with_state(context)
}

async fn create(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::UserServiceCreateRequest>,
) -> Result<Json<api::UserServiceCreateResponse>, Error> {
    ctx.write(|write| grpc::user::create(req, headers.into(), write).scope_boxed())
        .await
}

async fn get(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((user_id,)): Path<(String,)>,
) -> Result<Json<api::UserServiceGetResponse>, Error> {
    let req = api::UserServiceGetRequest { user_id };
    ctx.read(|read| grpc::user::get(req, headers.into(), read).scope_boxed())
        .await
}

/// HTTP query parameters for listing users
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserListParams {
    /// User IDs to filter by (supports both singular and plural forms)
    #[serde(alias = "user_id")]
    pub user_ids: Option<CommaSeparatedList<String>>,
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

impl UserListParams {
    /// Validate parameters and convert to gRPC request
    fn to_grpc_request(self) -> Result<api::UserServiceListRequest, crate::http::params::ParameterValidationError> {
        let mut validation_error = crate::http::params::ParameterValidationError::new("Invalid query parameters");

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

        Ok(api::UserServiceListRequest {
            user_ids,
            org_ids,
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
    Query(params): Query<UserListParams>,
) -> Result<Json<api::UserServiceListResponse>, Error> {
    let req = match params.to_grpc_request() {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    ctx.read(|read| grpc::user::list(req, headers.into(), read).scope_boxed())
        .await
}

async fn update(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Json(req): Json<api::UserServiceUpdateRequest>,
) -> Result<Json<api::UserServiceUpdateResponse>, Error> {
    ctx.write(|write| grpc::user::update(req, headers.into(), write).scope_boxed())
        .await
}

async fn delete(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((user_id,)): Path<(String,)>,
) -> Result<Json<api::UserServiceDeleteResponse>, Error> {
    let req = api::UserServiceDeleteRequest { user_id };
    ctx.write(|write| grpc::user::delete(req, headers.into(), write).scope_boxed())
        .await
}

async fn get_settings(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((user_id,)): Path<(String,)>,
) -> Result<Json<api::UserServiceGetSettingsResponse>, Error> {
    let req = api::UserServiceGetSettingsRequest { user_id };
    ctx.read(|read| grpc::user::get_settings(req, headers.into(), read).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UserServiceUpdateSettingsRequest {
    key: String,
    value: String,
}

async fn update_settings(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((user_id,)): Path<(String,)>,
    Json(req): Json<UserServiceUpdateSettingsRequest>,
) -> Result<Json<api::UserServiceUpdateSettingsResponse>, Error> {
    let req = api::UserServiceUpdateSettingsRequest {
        user_id,
        key: req.key,
        value: req.value.as_bytes().to_vec(),
    };
    ctx.write(|write| grpc::user::update_settings(req, headers.into(), write).scope_boxed())
        .await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UserServiceDeleteSettingsRequest {
    key: String,
}

async fn delete_settings(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((user_id,)): Path<(String,)>,
    Json(req): Json<UserServiceDeleteSettingsRequest>,
) -> Result<Json<api::UserServiceDeleteSettingsResponse>, Error> {
    let req = api::UserServiceDeleteSettingsRequest {
        user_id,
        key: req.key,
    };
    ctx.write(|write| grpc::user::delete_settings(req, headers.into(), write).scope_boxed())
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[test]
    fn test_user_list_params_single_user_id() {
        let query = "user_id=550e8400-e29b-41d4-a716-446655440000&limit=10";
        let params: UserListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.user_ids.is_some());
        assert_eq!(params.user_ids.unwrap().0, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(params.limit, Some(10));
    }

    #[test]
    fn test_user_list_params_plural_user_ids() {
        let query = "user_ids=550e8400-e29b-41d4-a716-446655440000,6ba7b810-9dad-11d1-80b4-00c04fd430c8&limit=20";
        let params: UserListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.user_ids.is_some());
        assert_eq!(params.user_ids.unwrap().0, vec![
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        ]);
        assert_eq!(params.limit, Some(20));
    }

    #[test]
    fn test_user_list_params_to_grpc_request_success() {
        let params = UserListParams {
            user_ids: Some(CommaSeparatedList(vec!["550e8400-e29b-41d4-a716-446655440000".to_string()])),
            org_ids: Some(CommaSeparatedList(vec!["6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string()])),
            offset: Some(10),
            limit: Some(50),
            search: None,
        };

        let grpc_req = params.to_grpc_request().unwrap();
        assert_eq!(grpc_req.user_ids, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert_eq!(grpc_req.org_ids, vec!["6ba7b810-9dad-11d1-80b4-00c04fd430c8"]);
        assert_eq!(grpc_req.offset, 10);
        assert_eq!(grpc_req.limit, 50);
    }

    #[test]
    fn test_user_list_params_to_grpc_request_invalid_uuid() {
        let params = UserListParams {
            user_ids: Some(CommaSeparatedList(vec!["not-a-uuid".to_string()])),
            org_ids: None,
            offset: None,
            limit: None,
            search: None,
        };

        let result = params.to_grpc_request();
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(error.errors[0].parameter, "user_ids");
        assert!(error.errors[0].error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_user_list_params_mixed_singular_plural() {
        let query = "user_id=550e8400-e29b-41d4-a716-446655440000&org_ids=6ba7b810-9dad-11d1-80b4-00c04fd430c8,7ca8c920-aead-22e2-91c5-11d15fe541d9";
        let params: UserListParams = serde_urlencoded::from_str(query).unwrap();
        
        assert!(params.user_ids.is_some());
        assert_eq!(params.user_ids.unwrap().0, vec!["550e8400-e29b-41d4-a716-446655440000"]);
        assert!(params.org_ids.is_some());
        assert_eq!(params.org_ids.unwrap().0, vec![
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "7ca8c920-aead-22e2-91c5-11d15fe541d9"
        ]);
    }
}