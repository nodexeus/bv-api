//! TODO: DELETE ME after moving necessary to gRPC

use crate::auth::FindableById;
use crate::errors::{ApiError, Result as ApiResult};
use crate::models::{
    validator::Validator, validator::ValidatorStakeRequest, Invoice, Org, Payment, Reward, User,
    UserRequest,
};
use crate::server::DbPool;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use http::StatusCode;
use hyper::Body;
use uuid::Uuid;

pub async fn create_user(
    Extension(db): Extension<DbPool>,
    Json(user): Json<UserRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::create(user, db.as_ref(), None).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn users_summary(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let users = User::find_all_summary(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(users)))
}

pub async fn user_summary(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let summary = User::find_summary_by_user(db.as_ref(), user_id).await?;
    Ok((StatusCode::OK, Json(summary)))
}

pub async fn user_payments(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let payments = Payment::find_all_by_user(db.as_ref(), user_id).await?;
    Ok((StatusCode::OK, Json(payments)))
}

pub async fn list_user_orgs(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let orgs = Org::find_all_by_user(&id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(orgs)))
}

pub async fn get_reward_summary(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let total = Reward::summary_by_user(db.as_ref(), &id).await?;
    Ok((StatusCode::OK, Json(total)))
}

pub async fn list_validators_by_user(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let mut validators = Validator::find_all_by_user(user_id, db.as_ref()).await?;
    validators.iter_mut().for_each(|v| v.swarm_key = None);
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_invoices(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let invoices = Invoice::find_all_by_user(db.as_ref(), &user_id).await?;
    Ok((StatusCode::OK, Json(invoices)))
}

pub async fn stake_validator(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<ValidatorStakeRequest>,
) -> ApiResult<impl IntoResponse> {
    let count = req.count;
    let user = User::find_by_id(user_id, db.as_ref()).await?;
    let validators = Validator::stake(db.as_ref(), &user, count).await?;

    Ok((StatusCode::OK, Json(validators)))
}

pub async fn users_staking_export(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let export = Validator::list_staking_export(&user_id, db.as_ref()).await?;
    let export = serde_json::to_string(&export).map_err(|e| ApiError::UnexpectedError(e.into()))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Disposition",
            "attachment; filename=validators.json",
        )
        .body(Body::from(export))
        .map_err(|e| ApiError::UnexpectedError(e.into())))
}
