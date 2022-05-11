use crate::errors::ApiError;
use crate::models::*;
use crate::{auth, errors};
use anyhow::anyhow;
use axum::async_trait;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, FromRequest, Json, Path, Query, RequestParts};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use errors::Result as ApiResult;
use log::{debug, warn};
use qrcode_generator;
use qrcode_generator::QrCodeEcc;
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

type DbPool = Arc<PgPool>;

#[derive(Deserialize)]
pub struct QueryParams {
    token: Option<String>,
}

#[async_trait]
impl<B> FromRequest<B> for Authentication
where
    B: Send,
{
    type Rejection = ApiError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        if let Some(token) = req
            .headers()
            .get("Authorization")
            .and_then(|hv| hv.to_str().ok())
            .and_then(|hv| {
                let words = hv.split("Bearer").collect::<Vec<&str>>();
                let token = words.get(1).map(|w| w.trim());
                token.map(Cow::Borrowed)
            })
        {
            let api_service_secret =
                std::env::var("API_SERVICE_SECRET").unwrap_or_else(|_| "".into());
            let is_service_token = !api_service_secret.is_empty() && token == api_service_secret;

            if token.starts_with("eyJ") {
                debug!("JWT Auth in Bearer.");
                if let Ok(auth::JwtValidationStatus::Valid(auth_data)) =
                    auth::validate_jwt(token.as_ref())
                {
                    if let Ok(role) = UserRole::from_str(&auth_data.user_role) {
                        return Ok(Self::User(UserAuthInfo {
                            id: auth_data.user_id,
                            role,
                        }));
                    }
                }
            } else if is_service_token {
                debug!("Service Auth in Bearer.");
                return Ok(Self::Service(token.as_ref().to_string()));
            } else {
                debug!("Host Auth in Bearer.");
                return Ok(Self::Host(token.as_ref().to_string()));
            };
        };

        warn!(
            "Invalid token auth: {:?} - {:?}",
            req.headers().get("Authorization"),
            req.uri().path()
        );
        Err(ApiError::InvalidAuthentication(anyhow!(
            "invalid authentication credentials"
        )))
    }
}

pub async fn start() -> anyhow::Result<()> {
    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    let db_max_conn: u32 = std::env::var("DB_MAX_CONN")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .unwrap();
    let db_min_conn: u32 = std::env::var("DB_MIN_CONN")
        .unwrap_or_else(|_| "2".to_string())
        .parse()
        .unwrap();

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, port);

    let db_pool = PgPoolOptions::new()
        .max_connections(db_max_conn)
        .min_connections(db_min_conn)
        .max_lifetime(Some(Duration::from_secs(60 * 60 * 24)))
        .idle_timeout(Some(Duration::from_secs(60 * 2)))
        .connect(&db_url)
        .await
        .expect("Could not create db connection pool.");

    let app = Router::new()
        .route("/reset", post(reset_pwd))
        .route("/reset", put(update_pwd))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/whoami", get(whoami))
        .route("/block_height", get(get_block_height))
        .route("/block_info", get(get_block_info))
        .route("/block_info", put(update_block_info))
        .route("/users", post(create_user))
        .route("/users/summary", get(users_summary))
        .route("/users/:user_id/summary", get(user_summary))
        .route("/users/:user_id/payments", get(user_payments))
        .route("/hosts", get(list_hosts))
        .route("/hosts/token/:token", get(get_host_by_token))
        .route("/hosts/:id", get(get_host))
        .route("/hosts", post(create_host))
        .route("/hosts/:id", put(update_host))
        .route("/hosts/:id/status", put(update_host_status))
        .route("/hosts/:id", delete(delete_host))
        .route("/host_provisions", post(create_host_provision))
        .route("/validators/:id/migrate", post(migrate_validator))
        .route("/validators", get(list_validators))
        .route("/validators/staking", get(list_validators_staking))
        .route("/validators/consensus", get(list_validators_consensus))
        .route(
            "/validators/needs_attention",
            get(list_validators_attention),
        )
        .route(
            "/validators/inventory/count",
            get(validator_inventory_count),
        )
        .route(
            "/users/:user_id/validators/staking/export",
            get(users_staking_export),
        )
        .route("/users/:user_id/validators", get(list_validators_by_user))
        .route("/users/:user_id/invoices", get(list_invoices))
        .route("/payments_due", get(list_payments_due))
        .route("/pay_adresses", get(list_pay_addresses))
        .route("/users/:user_id/validators", post(stake_validator))
        .route("/validators/:id", get(get_validator))
        .route("/validators/:id/status", put(update_validator_status))
        .route(
            "/validators/:id/stake_status",
            put(update_validator_stake_status),
        )
        .route(
            "/validators/:id/owner_address",
            put(update_validator_owner_address),
        )
        .route("/validators/:id/penalty", put(update_validator_penalty))
        .route("/validators/:id/identity", put(update_validator_identity))
        .route("/users/:user_id/rewards/summary", get(get_reward_summary))
        .route("/rewards", post(create_rewards))
        .route("/payments", post(create_payments))
        .route("/commands/:id", get(get_command))
        .route("/hosts/:id/commands", get(list_commands))
        .route("/hosts/:id/commands/pending", get(list_pending_commands))
        .route("/hosts/:id/commands", post(create_command))
        .route("/commands/:id/response", put(update_command_response))
        .route("/command/:id", delete(delete_command))
        .route("/qr/:user_id", get(get_qr))
        .route("/groups/nodes", get(list_node_groups))
        .route("/groups/nodes/:id", get(get_node_group))
        .layer(
            CorsLayer::new()
                .allow_headers(Any)
                .allow_methods(Any)
                .allow_origin(Any),
        )
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(Extension(Arc::new(db_pool)));

    Ok(axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?)
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

pub async fn create_host_provision(
    Extension(db_pool): Extension<DbPool>,
    Json(req): Json<HostProvisionRequest>,
    auth: Authentication,
) -> ApiResult<impl IntoResponse> {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host_provision = HostProvision::create(req, db_pool.as_ref()).await?;
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
