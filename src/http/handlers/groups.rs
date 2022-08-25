//! TODO: DELETE ME after moving necessary to gRPC

use crate::errors::Result as ApiResult;
use crate::models::NodeGroup;
use crate::server::DbPool;
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use http::StatusCode;
use uuid::Uuid;

pub async fn list_node_groups(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let groups = NodeGroup::find_all(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(groups)))
}

pub async fn get_node_group(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let node_group = NodeGroup::find_by_id(db.as_ref(), id).await?;
    Ok((StatusCode::OK, Json(node_group)))
}
