use crate::errors;
use crate::errors::ApiError;
use crate::models::*;
use crate::server::DbPool;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Json, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use errors::Result as ApiResult;
use log::debug;
use qrcode_generator;
use qrcode_generator::QrCodeEcc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct QueryParams {
    token: Option<String>,
}

pub async fn reset_pwd(
    Extension(db_pool): Extension<DbPool>,
    Json(req): Json<PasswordResetRequest>,
) -> impl IntoResponse {
    let _ = User::email_reset_password(db_pool.as_ref(), req).await;
    (
        StatusCode::OK,
        Json("An email with reset instructions has been sent."),
    )
}

pub async fn update_pwd(
    Extension(db_pool): Extension<DbPool>,
    Json(req): Json<PwdResetInfo>,
) -> ApiResult<impl IntoResponse> {
    let user = User::reset_password(db_pool.as_ref(), &req).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn login(
    Extension(db_pool): Extension<DbPool>,
    Json(login): Json<UserLoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::login(login, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn refresh(
    Extension(db_pool): Extension<DbPool>,
    Json(req): Json<UserRefreshRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::refresh(req, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn whoami(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if auth.is_user() {
        let user = auth.get_user(db_pool.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(user))))
    } else {
        let host = auth.get_host(db_pool.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    }
}

pub async fn get_block_height(
    Extension(db_pool): Extension<DbPool>,
) -> ApiResult<impl IntoResponse> {
    let info = Info::get_info(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(info.block_height)))
}

pub async fn get_block_info(Extension(db_pool): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let info = Info::get_info(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(info)))
}

pub async fn update_block_info(
    Extension(db_pool): Extension<DbPool>,
    Json(info): Json<InfoRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;

    let info = Info::update_info(db_pool.as_ref(), &info).await?;
    Ok((StatusCode::OK, Json(info)))
}

pub async fn list_node_groups(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;
    let groups = NodeGroup::find_all(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(groups)))
}

pub async fn get_node_group(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;
    let node_group = NodeGroup::find_by_id(db_pool.as_ref(), id).await?;
    Ok((StatusCode::OK, Json(node_group)))
}

pub async fn get_node(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    //TODO refactor this for owner/org
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }
    let node = Node::find_by_id(&id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn create_node(
    Extension(db_pool): Extension<DbPool>,
    Json(req): Json<NodeCreateRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    //todo refactor correctly
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }
    let node = Node::create(&req, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn update_node_info(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<NodeInfo>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    //todo refactor correctly
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }
    let node = Node::update_info(&id, &req, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn create_user(
    Extension(db_pool): Extension<DbPool>,
    Json(user): Json<UserRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::create(user, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(user)))
}

pub async fn users_summary(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;
    let users = User::find_all_summary(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(users)))
}

pub async fn user_summary(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_user_access(user_id)?;
    let summary = User::find_summary_by_user(db_pool.as_ref(), user_id).await?;
    Ok((StatusCode::OK, Json(summary)))
}

pub async fn user_payments(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_user_access(user_id)?;
    let payments = Payment::find_all_by_user(db_pool.as_ref(), user_id).await?;
    Ok((StatusCode::OK, Json(payments)))
}

pub async fn list_user_orgs(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_user_access(id)?;

    let orgs = Org::find_all_by_user(&id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(orgs)))
}

// Can pass ?token= to get a host by token
pub async fn list_hosts(
    Extension(db_pool): Extension<DbPool>,
    params: Query<QueryParams>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_service() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    if let Some(token) = params.token.clone() {
        let host = Host::find_by_token(&token, db_pool.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    } else {
        let host = Host::find_all(db_pool.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    }
}

pub async fn get_host_by_token(
    Extension(db_pool): Extension<DbPool>,
    Path(token): Path<String>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host = Host::find_by_token(&token, &db_pool).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn get_host(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host = Host::find_by_id(id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn create_host(
    Extension(db_pool): Extension<DbPool>,
    Json(host): Json<HostCreateRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host = Host::create(host.into(), db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn update_host(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(host): Json<HostRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host = Host::update(id, host, &db_pool).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn update_host_status(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(host): Json<HostStatusRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_host_access(id, db_pool.as_ref()).await?;

    let host = Host::update_status(id, host, &db_pool).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn delete_host(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;

    let rows = Host::delete(id, &db_pool).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", rows)),
    ))
}

pub async fn get_host_provision(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<String>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    //TODO better security
    if !auth.is_admin() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host_provision = HostProvision::find_by_id(&id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn create_host_provision(
    Extension(db_pool): Extension<DbPool>,
    Json(req): Json<HostProvisionRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    //TODO: Verify user is member of group
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host_provision = HostProvision::create(req, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn claim_host_provision(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<String>,
    Json(req): Json<HostCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let host_provision = HostProvision::claim(&id, req, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn migrate_validator(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;

    let val = Validator::migrate(db_pool.as_ref(), id).await?;
    Ok((StatusCode::OK, Json(val)))
}

pub async fn list_validators(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_service() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validators = Validator::find_all(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_validators_staking(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;

    let validators =
        Validator::find_all_by_stake_status(StakeStatus::Staking, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_validators_consensus(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;

    let validators =
        Validator::find_all_by_status(ValidatorStatus::Consensus, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn list_validators_attention(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_admin()?;

    let validators = ValidatorDetail::list_needs_attention(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validators)))
}

pub async fn validator_inventory_count(
    Extension(db_pool): Extension<DbPool>,
    _auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let count = Validator::inventory_count(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(count)))
}

pub async fn users_staking_export(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let export = Validator::list_staking_export(&user_id, db_pool.as_ref()).await?;
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

pub async fn list_validators_by_user(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if auth.is_admin() || auth.try_user_access(user_id)? {
        let mut validators = Validator::find_all_by_user(user_id, db_pool.as_ref()).await?;
        if auth.is_user() {
            //users should get swarmkey
            validators.iter_mut().for_each(|v| v.swarm_key = None);
        }
        Ok((StatusCode::OK, Json(validators)))
    } else {
        Err(ApiError::InsufficientPermissionsError)
    }
}

pub async fn list_invoices(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if auth.is_admin() || auth.try_user_access(user_id)? {
        let invoices = Invoice::find_all_by_user(db_pool.as_ref(), &user_id).await?;
        Ok((StatusCode::OK, Json(invoices)))
    } else {
        Err(ApiError::InsufficientPermissionsError)
    }
}

pub async fn list_payments_due(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;

    let payments_due = Invoice::find_all_payments_due(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(payments_due)))
}

pub async fn list_pay_addresses(
    Extension(db_pool): Extension<DbPool>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;

    let addresses = User::find_all_pay_address(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(addresses)))
}

pub async fn stake_validator(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<ValidatorStakeRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if auth.is_admin() || auth.try_user_access(user_id)? {
        let count = req.count;
        let user = User::find_by_id(user_id, db_pool.as_ref()).await?;
        let validators = Validator::stake(db_pool.as_ref(), &user, count).await?;

        Ok((StatusCode::OK, Json(validators)))
    } else {
        Err(ApiError::InsufficientPermissionsError)
    }
}

pub async fn get_validator(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && auth.is_user() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator = Validator::find_by_id(id, &db_pool).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_status(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(validator): Json<ValidatorStatusRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if auth.is_user() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator = Validator::update_status(id, validator, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_stake_status(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(status): Json<StakeStatus>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() && !auth.is_service() {
        debug!(
            "update_validator_stake_status:Invalid Permissions {:?}",
            auth
        );
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator = Validator::update_stake_status(id, status, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_owner_address(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(owner_address): Json<String>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() && !auth.is_service() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator =
        Validator::update_owner_address(id, Some(owner_address), db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_penalty(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(penalty): Json<ValidatorPenaltyRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;

    let validator = Validator::update_penalty(id, penalty, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn update_validator_identity(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(validator): Json<ValidatorIdentityRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_host()?;

    //TODO: Validator host has access to validator

    let validator = Validator::update_identity(id, validator, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(validator)))
}

pub async fn get_reward_summary(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_user_access(id)?;
    let total = Reward::summary_by_user(db_pool.as_ref(), &id).await?;
    Ok((StatusCode::OK, Json(total)))
}

pub async fn create_rewards(
    Extension(db_pool): Extension<DbPool>,
    Json(rewards): Json<Vec<RewardRequest>>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;
    Reward::create(db_pool.as_ref(), &rewards).await?;
    Ok((StatusCode::OK, Json("no content")))
}

pub async fn create_payments(
    Extension(db_pool): Extension<DbPool>,
    Json(payments): Json<Vec<Payment>>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    let _ = auth.try_service()?;
    Payment::create(db_pool.as_ref(), &payments).await?;
    Ok((StatusCode::OK, Json("no content")))
}

pub async fn get_command(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::find_by_id(id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn list_commands(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let commands = Command::find_all_by_host(id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(commands)))
}

pub async fn list_pending_commands(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let commands = Command::find_pending_by_host(id, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(commands)))
}

pub async fn create_command(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(command): Json<CommandRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::create(id, command, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn update_command_response(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(response): Json<CommandResponseRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::update_response(id, response, db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn delete_command(
    Extension(db_pool): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let result = Command::delete(id, &db_pool).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", result)),
    ))
}

pub async fn get_qr(
    Extension(db_pool): Extension<DbPool>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let qr_data = User::get_qr_by_id(db_pool.as_ref(), user_id).await?;
    let png: Vec<u8> = qrcode_generator::to_png_to_vec(qr_data, QrCodeEcc::Low, 1024).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/png")
        .body(Body::from(Bytes::from(png)))
        .map_err(|e| ApiError::UnexpectedError(e.into())))
}

pub async fn list_blockchains(
    Extension(db_pool): Extension<DbPool>,
) -> ApiResult<impl IntoResponse> {
    let blockchains = Blockchain::find_all(db_pool.as_ref()).await?;
    Ok((StatusCode::OK, Json(blockchains)))
}
