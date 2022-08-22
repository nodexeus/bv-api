//! TODO: DELETE ME after moving necessary to gRPC

use crate::errors::Result as ApiResult;
use crate::models::validator::{
    StakeStatus, Validator, ValidatorDetail, ValidatorIdentityRequest, ValidatorPenaltyRequest,
    ValidatorStatus, ValidatorStatusRequest,
};
use crate::server::DbPool;
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use http::StatusCode;
use uuid::Uuid;

pub async fn migrate_validator(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let val = Validator::migrate(db.as_ref(), id).await?;
    Ok((StatusCode::OK, Json(val)))
}

pub async fn list_validators(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let validators = Validator::find_all(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_validators_staking(
    Extension(db): Extension<DbPool>,
) -> ApiResult<impl IntoResponse> {
    let validators = Validator::find_all_by_stake_status(StakeStatus::Staking, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_validators_consensus(
    Extension(db): Extension<DbPool>,
) -> ApiResult<impl IntoResponse> {
    let validators = Validator::find_all_by_status(ValidatorStatus::Consensus, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_validators_attention(
    Extension(db): Extension<DbPool>,
) -> ApiResult<impl IntoResponse> {
    let validators = ValidatorDetail::list_needs_attention(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn validator_inventory_count(
    Extension(db): Extension<DbPool>,
) -> ApiResult<impl IntoResponse> {
    let count = Validator::inventory_count(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(count)))
}

pub async fn get_validator(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let validator = Validator::find_by_id(id, &db).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_status(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(validator): Json<ValidatorStatusRequest>,
) -> ApiResult<impl IntoResponse> {
    let validator = Validator::update_status(id, validator, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_stake_status(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(status): Json<StakeStatus>,
) -> ApiResult<impl IntoResponse> {
    let validator = Validator::update_stake_status(id, status, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_owner_address(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(owner_address): Json<String>,
) -> ApiResult<impl IntoResponse> {
    let validator = Validator::update_owner_address(id, Some(owner_address), db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_penalty(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(penalty): Json<ValidatorPenaltyRequest>,
) -> ApiResult<impl IntoResponse> {
    let validator = Validator::update_penalty(id, penalty, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_identity(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(validator): Json<ValidatorIdentityRequest>,
) -> ApiResult<impl IntoResponse> {
    //TODO: Validator host has access to validator

    let validator = Validator::update_identity(id, validator, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}
