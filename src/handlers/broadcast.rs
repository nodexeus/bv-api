use crate::errors;
use crate::models::*;
use crate::server::DbPool;
use axum::extract::{Extension, Json, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use errors::Result as ApiResult;
use uuid::Uuid;

pub async fn create_broadcast_filter(
    Extension(db): Extension<DbPool>,
    Json(req): Json<BroadcastFilterRequest>,
) -> ApiResult<impl IntoResponse> {
    let filter = BroadcastFilter::create(&req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(filter)))
}

pub async fn list_org_broadcast_filters(
    Extension(db): Extension<DbPool>,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let filters = BroadcastFilter::find_all_by_org_id(&org_id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(filters)))
}

pub async fn get_broadcast_filter(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let filter = BroadcastFilter::find_by_id(&id, db.as_ref()).await?;

    Ok((StatusCode::OK, Json(filter)))
}

pub async fn update_broadcast_filter(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(mut req): Json<BroadcastFilterRequest>,
) -> ApiResult<impl IntoResponse> {
    let filter = BroadcastFilter::find_by_id(&id, db.as_ref()).await?;

    req.org_id = filter.org_id;

    let filter = BroadcastFilter::update(&id, &req, db.as_ref()).await?;

    Ok((StatusCode::OK, Json(filter)))
}

pub async fn delete_broadcast_filter(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _ = BroadcastFilter::delete(&id, db.as_ref()).await?;

    Ok(StatusCode::OK)
}
