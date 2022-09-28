use crate::server::DbPool;
use axum::extract::{Extension, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// Health handler used indicating system status
/// Returns empty message (assuming all is working properly).
/// DB extension is passed in to check DB status
pub async fn health(Extension(db): Extension<DbPool>) -> impl IntoResponse {
    if db.is_closed() {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json("DB connection is closed"),
        )
    } else {
        (StatusCode::OK, Json(""))
    }
}

/* TODO: DELETE ME after moving necessary to gRPC */
/*
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
    let png: Vec<u8> = qrcode_generator::to_png_to_vec(qr_data, QrCodeEcc::Low, 1024).expect("Commented out code heheh");

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
*/
/*************/
