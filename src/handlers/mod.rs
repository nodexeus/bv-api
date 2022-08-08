use crate::auth::{FindableById, TokenIdentifyable};
use crate::errors;
use crate::errors::ApiError;
use crate::models::*;
use crate::server::DbPool;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Json, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use errors::Result as ApiResult;
use qrcode_generator;
use qrcode_generator::QrCodeEcc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

mod broadcast;
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

pub async fn get_node(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let node = Node::find_by_id(&id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn create_node(
    Extension(db): Extension<DbPool>,
    Json(req): Json<NodeCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let node = Node::create(&req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn update_node_info(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<NodeInfo>,
) -> ApiResult<impl IntoResponse> {
    let node = Node::update_info(&id, &req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(node)))
}

pub async fn create_user(
    Extension(db): Extension<DbPool>,
    Json(user): Json<UserRequest>,
) -> ApiResult<impl IntoResponse> {
    let user = User::create(user, db.as_ref()).await?;
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

// Can pass ?token= to get a host by token
pub async fn list_hosts(
    Extension(db): Extension<DbPool>,
    params: Query<QueryParams>,
) -> ApiResult<impl IntoResponse> {
    if let Some(token) = params.token.clone() {
        let host = Token::get_host_for_token(token, db.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    } else {
        let host = Host::find_all(db.as_ref()).await?;
        Ok((StatusCode::OK, Json(json!(host))))
    }
}

pub async fn get_host_by_token(
    Extension(db): Extension<DbPool>,
    Path(token): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let host = Token::get_host_for_token(token, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn get_host(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::find_by_id(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn create_host(
    Extension(db): Extension<DbPool>,
    Json(host): Json<HostCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::create(host.into(), db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn update_host(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(host): Json<HostSelectiveUpdate>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::update_all(id, host, &db).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn update_host_status(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(host): Json<HostStatusRequest>,
) -> ApiResult<impl IntoResponse> {
    let host = Host::update_status(id, host, &db).await?;
    Ok((StatusCode::OK, Json(host)))
}

pub async fn delete_host(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    //TODO: Major security issue here and with all host checks
    // since we opening up hosts to self service we need to validate
    // host token can delete only itself.

    let rows = Host::delete(id, &db).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", rows)),
    ))
}

pub async fn get_host_provision(
    Extension(db): Extension<DbPool>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let host_provision = HostProvision::find_by_id(&id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn create_host_provision(
    Extension(db): Extension<DbPool>,
    Json(req): Json<HostProvisionRequest>,
) -> ApiResult<impl IntoResponse> {
    //TODO: Verify user is member of group

    let host_provision = HostProvision::create(req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

pub async fn claim_host_provision(
    Extension(db): Extension<DbPool>,
    Path(id): Path<String>,
    Json(req): Json<HostCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    let host_provision = HostProvision::claim(&id, req, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(host_provision)))
}

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

pub async fn list_payments_due(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let payments_due = Invoice::find_all_payments_due(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(payments_due)))
}

pub async fn list_pay_addresses(Extension(db): Extension<DbPool>) -> ApiResult<impl IntoResponse> {
    let addresses = User::find_all_pay_address(db.as_ref()).await?;
    Ok((StatusCode::OK, Json(addresses)))
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

pub async fn get_reward_summary(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let total = Reward::summary_by_user(db.as_ref(), &id).await?;
    Ok((StatusCode::OK, Json(total)))
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

pub async fn get_command(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::find_by_id(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn list_commands(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let commands = Command::find_all_by_host(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(commands)))
}

pub async fn list_pending_commands(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let commands = Command::find_pending_by_host(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(commands)))
}

pub async fn create_command(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(command): Json<CommandRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::create(id, command, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn update_command_response(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
    Json(response): Json<CommandResponseRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::update_response(id, response, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn delete_command(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let result = Command::delete(id, &db).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", result)),
    ))
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
