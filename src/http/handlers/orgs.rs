//! TODO: DELETE ME after moving necessary to gRPC

use crate::errors::{ApiError, Result as ApiResult};
use crate::models::{Org, OrgRequest, OrgRole, Token};
use crate::server::DbPool;
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use http::StatusCode;
use uuid::Uuid;

pub async fn create_org(
    Extension(db): Extension<DbPool>,
    Json(req): Json<OrgRequest>,
    Extension(token): Extension<Token>,
) -> ApiResult<impl IntoResponse> {
    let org = Org::create(&req, &token.user_id.unwrap(), db.as_ref()).await?;
    Ok((StatusCode::OK, Json(org)))
}

pub async fn get_org(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Extension(token): Extension<Token>,
) -> ApiResult<impl IntoResponse> {
    let org = Org::find_by_user(&id, &token.user_id.unwrap(), db.as_ref()).await?;
    Ok((StatusCode::OK, Json(org)))
}

pub async fn delete_org(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Extension(token): Extension<Token>,
) -> ApiResult<impl IntoResponse> {
    if Org::find_org_user(&token.user_id.unwrap(), &id, db.as_ref())
        .await?
        .role
        == OrgRole::Member
    {
        return Err(ApiError::InsufficientPermissionsError);
    }
    let result = Org::delete(id, db.as_ref()).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", result)),
    ))
}

pub async fn update_org(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<OrgRequest>,
    Extension(token): Extension<Token>,
) -> ApiResult<impl IntoResponse> {
    if Org::find_org_user(&token.user_id.unwrap(), &id, db.as_ref())
        .await?
        .role
        == OrgRole::Member
    {
        return Err(ApiError::InsufficientPermissionsError);
    }
    let org = Org::update(id, req, &token.user_id.unwrap(), db.as_ref()).await?;
    Ok((StatusCode::OK, Json(org)))
}

pub async fn get_org_members(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Extension(token): Extension<Token>,
) -> ApiResult<impl IntoResponse> {
    let _ = Org::find_org_user(&token.user_id.unwrap(), &id, db.as_ref()).await?;
    let org = Org::find_all_members(&id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(org)))
}
