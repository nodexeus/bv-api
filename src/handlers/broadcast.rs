use crate::errors;
use crate::models::*;
use crate::server::DbPool;
use axum::extract::{Extension, Json, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use errors::Result as ApiResult;
use uuid::Uuid;

pub async fn list_org_broadcast_filters(
    Extension(db): Extension<DbPool>,
    Path(org_id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_org_access(&org_id, db.as_ref()).await?;

    let filters = BroadcastFilter::find_all_by_org_id(&org_id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(filters)))
}

pub async fn create_broadcast_filter(
    Extension(db): Extension<DbPool>,
    Json(req): Json<BroadcastFilterRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_org_access(&req.org_id, db.as_ref()).await?;
    dbg!("auth passed!!!!");
    let filter = BroadcastFilter::create(&req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(filter)))
}
