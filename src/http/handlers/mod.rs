use crate::auth::TokenIdentifyable;
use crate::errors;
use crate::errors::ApiError;
use crate::server::DbPool;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Json, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use errors::Result as ApiResult;
use qrcode_generator;
use qrcode_generator::QrCodeEcc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

mod broadcast;
mod commands;
mod groups;
mod host_provisions;
mod hosts;
mod nodes;
mod orgs;
mod users;
mod validators;

pub use broadcast::*;
pub use commands::*;
pub use groups::*;
pub use host_provisions::*;
pub use hosts::*;
pub use nodes::*;
pub use orgs::*;
pub use users::*;
pub use validators::*;

use crate::models::*;
pub use broadcast::*;

#[derive(Deserialize)]
pub struct QueryParams {
    token: Option<String>,
}

pub async fn reset_pwd(
    Extension(db): Extension<DbPool>,
    Json(req): Json<PasswordResetRequest>,
) -> impl IntoResponse {
    let _ = User::email_reset_password(db.as_ref(), req).await;
    (
        StatusCode::OK,
        Json("An email with reset instructions has been sent."),
    )
}

pub async fn update_pwd(
    Extension(db): Extension<DbPool>,
    Json(req): Json<PwdResetInfo>,
) -> ApiResult<impl IntoResponse> {
    let user = User::reset_password(db.as_ref(), &req).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn login(
    Extension(db): Extension<DbPool>,
    Json(login): Json<UserLoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::login(login, db.as_ref()).await?;
    let token = user.get_token(db.as_ref()).await?;
    let login = UserLogin {
        id: user.id,
        email: user.email,
        fee_bps: user.fee_bps,
        staking_quota: user.staking_quota,
        token: token.to_base64(),
    };

    Ok((StatusCode::OK, Json(login)))
}

pub async fn refresh(
    Extension(db): Extension<DbPool>,
    Json(req): Json<UserRefreshRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::refresh(req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn whoami(
    Extension(db): Extension<DbPool>,
    Extension(token): Extension<Token>,
) -> ApiResult<impl IntoResponse> {
    match token.user_id {
        Some(_) => {
            let user = Token::get_user_for_token(token.token, &db).await.unwrap();
            return Ok((StatusCode::OK, Json(json!(user))));
        }
        _ => tracing::debug!("No user assigned for token"),
    }

    match token.host_id {
        Some(_) => {
            let host = Token::get_host_for_token(token.token, &db).await.unwrap();
            return Ok((StatusCode::OK, Json(json!(host))));
        }
        _ => tracing::debug!("No host assigned for token"),
    }

    Ok((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!("No resource assigned to token")),
    ))
}

pub async fn get_block_height(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let info = Info::get_info(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(info.block_height)))
}

pub async fn get_block_info(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let info = Info::get_info(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(info)))
}

pub async fn update_block_info(
    Extension(db): Extension<DbPool>,
    Json(info): Json<InfoRequest>,
) -> ApiResult<impl IntoResponse> {
    let info = Info::update_info(db.as_ref(), &info).await?;
    Ok((StatusCode::OK, Json(info)))
}

pub async fn list_payments_due(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let payments_due = Invoice::find_all_payments_due(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(payments_due)))
}

pub async fn list_pay_addresses(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let addresses = User::find_all_pay_address(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(addresses)))
}

pub async fn create_rewards(
    Extension(db): Extension<DbPool>,
    Json(rewards): Json<Vec<RewardRequest>>,
) -> ApiResult<impl IntoResponse> {
    Reward::create(db.as_ref(), &rewards).await?;
    Ok((StatusCode::OK, Json("no content")))
}

pub async fn create_payments(
    Extension(db): Extension<DbPool>,
    Json(payments): Json<Vec<Payment>>,
) -> ApiResult<impl IntoResponse> {
    Payment::create(db.as_ref(), &payments).await?;
    Ok((StatusCode::OK, Json("no content")))
}

pub async fn update_command_response(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(response): Json<CommandResponseRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::update_response(id, response, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn get_qr(
    Extension(db): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let qr_data = User::get_qr_by_id(db.as_ref(), user_id).await?;
    let png: Vec<u8> = qrcode_generator::to_png_to_vec(qr_data, QrCodeEcc::Low, 1024).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/png")
        .body(Body::from(Bytes::from(png)))
        .map_err(|e| ApiError::UnexpectedError(e.into())))
}

pub async fn list_blockchains(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let blockchains = Blockchain::find_all(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(blockchains)))
}
