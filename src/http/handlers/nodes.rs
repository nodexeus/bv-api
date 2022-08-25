//! TODO: DELETE ME after moving necessary to gRPC

use crate::errors::Result as ApiResult;
use crate::models::{Node, NodeCreateRequest, NodeInfo};
use crate::server::DbPool;
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use http::StatusCode;
use uuid::Uuid;

pub async fn get_node(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let node = Node::find_by_id(&id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn create_node(
    Extension(db): Extension<DbPool>,
    Json(req): Json<NodeCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let node = Node::create(&req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn update_node_info(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<NodeInfo>,
) -> ApiResult<impl IntoResponse> {
    let node = Node::update_info(&id, &req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}
