use crate::errors::ApiError;
use crate::models::*;
use crate::{auth, errors};
use actix_cors::Cors;
use actix_web::{
    delete, dev, get, middleware, post, put, web, App, FromRequest, HttpRequest, HttpResponse,
    HttpServer,
};
use anyhow::anyhow;
use futures_util::future::{err, ok, Ready};
use log::{debug, warn};
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::borrow::Cow;
use std::str::FromStr;
use uuid::Uuid;

type ApiResponse = errors::Result<HttpResponse>;

type DbPool = web::Data<PgPool>;

#[derive(Deserialize)]
struct QueryParams {
    token: Option<String>,
}

impl FromRequest for Authentication {
    type Error = errors::ApiError;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        if let Some(token) = req
            .headers()
            .get("Authorization")
            .and_then(|hv| hv.to_str().ok())
            .and_then(|hv| {
                let words = hv.split("Bearer").collect::<Vec<&str>>();
                let token = words.get(1).map(|w| w.trim());
                token.map(|t| Cow::Borrowed(t))
            })
        {
            let api_service_secret = std::env::var("API_SERVICE_SECRET").unwrap_or("".into());
            let is_service_token = api_service_secret != "" && token == api_service_secret;

            if token.starts_with("eyJ") {
                debug!("JWT Auth in Bearer.");
                if let Ok(auth::JwtValidationStatus::Valid(auth_data)) =
                    auth::validate_jwt(token.as_ref())
                {
                    if let Ok(role) = UserRole::from_str(&auth_data.user_role) {
                        return ok(Self::User(UserAuthInfo {
                            id: auth_data.user_id,
                            role: role,
                        }));
                    }
                }
            } else if is_service_token {
                debug!("Service Auth in Bearer.");
                return ok(Self::Service(token.as_ref().to_string()));
            } else {
                debug!("Host Auth in Bearer.");
                return ok(Self::Host(token.as_ref().to_string()));
            };
        };

        warn!(
            "Invalid token auth: {:?}",
            req.headers().get("Authorizatoin")
        );
        err(Self::Error::InvalidAuthentication(anyhow!(
            "invalid authentication credentials"
        )))
    }
}

pub async fn start() -> anyhow::Result<()> {
    let db_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");
    let db_max_conn = std::env::var("DB_MAX_CONN")
        .unwrap_or("10".to_string())
        .parse()
        .unwrap();
    let port = std::env::var("PORT").unwrap_or("8080".to_string());
    let bind_ip = std::env::var("BIND_IP").unwrap_or("0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_ip, port);

    let db_pool = PgPoolOptions::new()
        .max_connections(db_max_conn)
        .connect(&db_url)
        .await
        .expect("Could not create db connection pool.");

    Ok(HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .allow_any_origin()
            .supports_credentials();

        App::new()
            .data(db_pool.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .service(create_command)
            .service(get_reward_summary)
            .service(create_host)
            .service(create_user)
            .service(delete_command)
            .service(delete_host)
            .service(list_validators_staking)
            .service(list_commands)
            .service(list_hosts)
            .service(list_pending_commands)
            .service(list_validators)
            .service(list_validators_by_user)
            .service(login)
            .service(refresh)
            .service(stake_validator)
            .service(update_block_height)
            .service(update_command_response)
            .service(update_host)
            .service(update_host_status)
            .service(update_validator_identity)
            .service(update_validator_status)
            .service(update_validator_stake_status)
            .service(update_validator_owner_address)
            .service(validator_inventory_count)
            .service(whoami)
            .service(get_block_height)
            .service(get_command)
            .service(get_host)
            .service(get_host_by_token)
            .service(get_validator)
            .service(create_rewards)
    })
    .bind(&addr)?
    .run()
    .await?)
}

#[post("/login")]
async fn login(db_pool: DbPool, login: web::Json<UserLoginRequest>) -> ApiResponse {
    let user = User::login(login.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(user))
}

#[post("/refresh")]
async fn refresh(db_pool: DbPool, req: web::Json<UserRefreshRequest>) -> ApiResponse {
    let user = User::refresh(req.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(user))
}

#[get("/whoami")]
async fn whoami(db_pool: DbPool, auth: Authentication) -> ApiResponse {
    if auth.is_user() {
        let user = auth.get_user(db_pool.as_ref()).await?;
        return Ok(HttpResponse::Ok().json(user));
    } else {
        let host = auth.get_host(db_pool.as_ref()).await?;
        return Ok(HttpResponse::Ok().json(host));
    }
}

#[get("/block_height")]
async fn get_block_height(db_pool: DbPool, _auth: Authentication) -> ApiResponse {
    let info = Info::get_info(db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(info.block_height))
}

#[put("/block_height")]
async fn update_block_height(
    db_pool: DbPool,
    height: web::Json<i64>,
    auth: Authentication,
) -> ApiResponse {
    let _ = auth.try_service()?;

    let info = Info::update_info(
        db_pool.as_ref(),
        &Info {
            block_height: height.into_inner(),
        },
    )
    .await?;
    Ok(HttpResponse::Ok().json(info.block_height))
}

#[post("/users")]
async fn create_user(db_pool: DbPool, user: web::Json<UserRequest>) -> ApiResponse {
    let user = User::create(user.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(user))
}

// Can pass ?token= to get a host by token
#[get("/hosts")]
async fn list_hosts(
    db_pool: DbPool,
    params: web::Query<QueryParams>,
    auth: Authentication,
) -> ApiResponse {
    let _ = auth.try_admin()?;

    if let Some(token) = params.token.clone() {
        let host = Host::find_by_token(&token, db_pool.get_ref()).await?;
        Ok(HttpResponse::Ok().json(host))
    } else {
        let host = Host::find_all(db_pool.get_ref()).await?;
        Ok(HttpResponse::Ok().json(host))
    }
}

#[get("/hosts/token/{token}")]
async fn get_host_by_token(
    db_pool: DbPool,
    token: web::Path<String>,
    auth: Authentication,
) -> ApiResponse {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let host = Host::find_by_token(&token.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[get("/hosts/{id}")]
async fn get_host(db_pool: DbPool, id: web::Path<Uuid>, auth: Authentication) -> ApiResponse {
    if !auth.is_admin() && !auth.is_host() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let id = id.into_inner();
    let host = Host::find_by_id(id, db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[post("/hosts")]
async fn create_host(
    db_pool: DbPool,
    host: web::Json<HostCreateRequest>,
    auth: Authentication,
) -> ApiResponse {
    let _ = auth.try_admin()?;

    let host = host.into_inner().into();

    let host = Host::create(host, db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[put("/hosts/{id}")]
async fn update_host(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    host: web::Json<HostRequest>,
    auth: Authentication,
) -> ApiResponse {
    let _ = auth.try_admin()?;

    let host = Host::update(id.into_inner(), host.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[put("/hosts/{id}/status")]
async fn update_host_status(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    host: web::Json<HostStatusRequest>,
    auth: Authentication,
) -> ApiResponse {
    let id = id.into_inner();

    let _ = auth.try_host_access(id, db_pool.as_ref()).await?;

    let host = Host::update_status(id, host.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(host))
}

#[delete("/hosts/{id}")]
async fn delete_host(db_pool: DbPool, id: web::Path<Uuid>, auth: Authentication) -> ApiResponse {
    let _ = auth.try_admin()?;

    let rows = Host::delete(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(format!("Successfully deleted {} record(s).", rows)))
}

#[get("/validators")]
async fn list_validators(db_pool: DbPool, auth: Authentication) -> ApiResponse {
    if !auth.is_admin() && !auth.is_service() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validators = Validator::find_all(db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(validators))
}

#[get("/validators/staking")]
async fn list_validators_staking(db_pool: DbPool, auth: Authentication) -> ApiResponse {
    let _ = auth.try_service()?;

    let validators =
        Validator::find_all_by_stake_status(StakeStatus::Staking, db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(validators))
}

#[get("/validators/inventory/count")]
async fn validator_inventory_count(db_pool: DbPool, _auth: Authentication) -> ApiResponse {
    let count = Validator::inventory_count(db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(count))
}

#[get("/users/{id}/validators")]
async fn list_validators_by_user(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    auth: Authentication,
) -> ApiResponse {
    let id = id.into_inner();

    if auth.is_admin() || auth.try_user_access(id)? {
        let mut validators = Validator::find_all_by_user(id, db_pool.get_ref()).await?;
        if auth.is_user() {
            //users should get swarmkey
            validators.iter_mut().for_each(|v| v.swarm_key = None);
        }
        Ok(HttpResponse::Ok().json(validators))
    } else {
        Err(ApiError::InsufficientPermissionsError)
    }
}

#[post("/users/{id}/validators")]
async fn stake_validator(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    req: web::Json<ValidatorStakeRequest>,
    auth: Authentication,
) -> ApiResponse {
    let id = id.into_inner();

    if auth.is_admin() || auth.try_user_access(id)? {
        let count = req.into_inner().count;
        let user = User::find_by_id(id, db_pool.as_ref()).await?;
        let validators = Validator::stake(db_pool.as_ref(), &user, count).await?;

        Ok(HttpResponse::Ok().json(validators))
    } else {
        Err(ApiError::InsufficientPermissionsError)
    }
}

#[get("/validators/{id}")]
async fn get_validator(db_pool: DbPool, id: web::Path<Uuid>, auth: Authentication) -> ApiResponse {
    if auth.is_user() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator = Validator::find_by_id(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[put("/validators/{id}/status")]
async fn update_validator_status(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    validator: web::Json<ValidatorStatusRequest>,
    auth: Authentication,
) -> ApiResponse {
    if auth.is_user() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator =
        Validator::update_status(id.into_inner(), validator.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[put("/validators/{id}/stake_status")]
async fn update_validator_stake_status(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    status: web::Json<StakeStatus>,
    auth: Authentication,
) -> ApiResponse {
    if !auth.is_admin() && !auth.is_host() && !auth.is_service() {
        debug!(
            "update_validator_stake_status:Invalid Permissions {:?}",
            auth
        );
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator =
        Validator::update_stake_status(id.into_inner(), status.into_inner(), db_pool.as_ref())
            .await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[put("/validators/{id}/owner_address")]
async fn update_validator_owner_address(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    owner_address: web::Json<String>,
    auth: Authentication,
) -> ApiResponse {
    if !auth.is_admin() && !auth.is_host() && !auth.is_service() {
        return Err(ApiError::InsufficientPermissionsError);
    }

    let validator = Validator::update_owner_address(
        id.into_inner(),
        Some(owner_address.into_inner()),
        db_pool.as_ref(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[put("/validators/{id}/identity")]
async fn update_validator_identity(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    validator: web::Json<ValidatorIdentityRequest>,
    auth: Authentication,
) -> ApiResponse {
    let id = id.into_inner();

    let _ = auth.try_host_access(id, db_pool.get_ref());

    let validator =
        Validator::update_identity(id, validator.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(validator))
}

#[get("/users/{id}/rewards/summary")]
async fn get_reward_summary(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    auth: Authentication,
) -> ApiResponse {
    let id = id.into_inner();

    let _ = auth.try_user_access(id);
    let total = Reward::summary_by_user(db_pool.as_ref(), &id).await?;
    Ok(HttpResponse::Ok().json(total))
}

#[post("/rewards")]
async fn create_rewards(
    db_pool: DbPool,
    rewards: web::Json<Vec<RewardRequest>>,
    auth: Authentication,
) -> ApiResponse {
    let _ = auth.try_service();
    Reward::create(db_pool.as_ref(), &rewards.into_inner()).await?;
    Ok(HttpResponse::Ok().json("no content"))
}

#[get("/commands/{id}")]
async fn get_command(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let command = Command::find_by_id(id.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(command))
}

#[get("/hosts/(host_id}/commands")]
async fn list_commands(db_pool: DbPool, host_id: web::Path<Uuid>) -> ApiResponse {
    let commands = Command::find_all_by_host(host_id.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(commands))
}

#[get("/hosts/(host_id}/commands/pending")]
async fn list_pending_commands(db_pool: DbPool, host_id: web::Path<Uuid>) -> ApiResponse {
    let commands = Command::find_pending_by_host(host_id.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(commands))
}

#[post("/hosts/{host_id}/commands")]
async fn create_command(
    db_pool: DbPool,
    host_id: web::Path<Uuid>,
    command: web::Json<CommandRequest>,
) -> ApiResponse {
    let command =
        Command::create(host_id.into_inner(), command.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(command))
}

#[put("/commands/{id}/response")]
async fn update_command_response(
    db_pool: DbPool,
    id: web::Path<Uuid>,
    response: web::Json<CommandResponseRequest>,
) -> ApiResponse {
    let command =
        Command::update_response(id.into_inner(), response.into_inner(), db_pool.as_ref()).await?;
    Ok(HttpResponse::Ok().json(command))
}

#[delete("/command/{id}")]
async fn delete_command(db_pool: DbPool, id: web::Path<Uuid>) -> ApiResponse {
    let result = Command::delete(id.into_inner(), db_pool.get_ref()).await?;
    Ok(HttpResponse::Ok().json(format!("Successfully deleted {} record(s).", result)))
}
