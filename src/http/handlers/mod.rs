use crate::auth::{JwtToken, TokenType, UserAuthToken, UserRefreshToken};
use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy_ui::LoginUserRequest;
use crate::http::HttpLoginUserRequest;
use crate::models::{User, UserSelectiveUpdate};
use crate::server::DbPool;
use anyhow::anyhow;
use axum::extract::{Extension, Json};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{TimeZone, Utc};

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

/// 1. Create JWT login token
/// 2. Create JWT refresh token
/// 3. Save refresh token on user/host
/// 4. Return tokens
///     a. Refresh token as HTTP only cookie
///     b. Login token inside the body
pub async fn login(
    Extension(db): Extension<DbPool>,
    Json(req): Json<HttpLoginUserRequest>,
) -> ApiResult<Response<Json<String>>> {
    let login_req = LoginUserRequest {
        meta: None,
        email: req.email,
        password: req.pwd,
    };
    let user = User::login(login_req, &db).await?;
    let token = UserAuthToken::create_token_for::<User>(&user, TokenType::UserAuth)?;
    let refresh_token = UserRefreshToken::create_token_for::<User>(&user, TokenType::UserRefresh)?;

    // TODO: Update user with refresh token
    let fields = UserSelectiveUpdate {
        first_name: None,
        last_name: None,
        fee_bps: None,
        staking_quota: None,
        refresh_token: Some(refresh_token.encode()?),
    };
    User::update_all(user.id, fields, &db).await?;

    let exp = *refresh_token.exp();
    let exp = Utc.timestamp(exp, 0).to_string();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(
            "Set-Cookie",
            format!(
                "refresh={}; Expires={}; Secure; HttpOnly",
                refresh_token.encode()?,
                exp,
            ),
        )
        .body(Json(token.encode()?))
        .map_err(|e| ApiError::UnexpectedError(anyhow!("Error creating response cookie: {e:?}")))?;

    Ok(response)
}

/// @see `login`
pub async fn claim_host_provision() -> impl IntoResponse {
    (StatusCode::OK, Json(""))
}

/// Recreate JWT login/refresh tokens, @see `login`
pub async fn refresh() -> impl IntoResponse {
    (StatusCode::OK, Json(""))
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
