use crate::errors::Result as ApiResult;
use crate::models::{HostCreateRequest, HostProvision, HostProvisionRequest};
use crate::server::DbPool;
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use http::StatusCode;

pub async fn create_host_provision(
    Extension(db): Extension<DbPool>,
    Json(req): Json<HostProvisionRequest>,
) -> ApiResult<impl IntoResponse> {
    //TODO: Verify user is member of group

    let host_provision = HostProvision::create(req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn get_host_provision(
    Extension(db): Extension<DbPool>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let host_provision = HostProvision::find_by_id(&id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn claim_host_provision(
    Extension(db): Extension<DbPool>,
    Path(id): Path<String>,
    Json(req): Json<HostCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let host_provision = HostProvision::claim(&id, req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}
