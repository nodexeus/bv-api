use crate::auth::FindableById;
use crate::errors::Result as ApiResult;
use crate::http::handlers::QueryParams;
use crate::models::{
    Command, CommandRequest, Host, HostCreateRequest, HostSelectiveUpdate, HostStatusRequest, Token,
};
use crate::server::DbPool;
use axum::extract::{Path, Query};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use http::StatusCode;
use serde_json::json;
use uuid::Uuid;

// Can pass ?token= to get a host by token
pub async fn list_hosts(
    Extension(db): Extension<DbPool>,
    params: Query<QueryParams>,
) -> ApiResult<impl IntoResponse> {
    if let Some(token) = params.token.clone() {
        let host = Token::get_host_for_token(token, db.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    } else {
        let host = Host::find_all(db.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    }
}

pub async fn create_host(
    Extension(db): Extension<DbPool>,
    Json(host): Json<HostCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::create(host.into(), db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn update_host(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(host): Json<HostSelectiveUpdate>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::update_all(id, host, &db).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn get_host(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::find_by_id(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn delete_host(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    //TODO: Major security issue here and with all host checks
    // since we opening up hosts to self service we need to validate
    // host token can delete only itself.

    let rows = Host::delete(id, &db).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", rows)),
    ))
}

pub async fn update_host_status(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(host): Json<HostStatusRequest>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::update_status(id, host, &db).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn get_host_by_token(
    Extension(db): Extension<DbPool>,
    Path(token): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let host = Token::get_host_for_token(token, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

// Nested commands

pub async fn list_commands(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let commands = Command::find_all_by_host(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(commands)))
}

pub async fn list_pending_commands(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let commands = Command::find_pending_by_host(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(commands)))
}

pub async fn create_command(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(command): Json<CommandRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::create(id, command, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}
