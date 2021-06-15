use crate::auth;
use crate::errors::{ApiError, Result};
use angry_purple_tiger::AnimalName;
use anyhow::anyhow;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use chrono::{DateTime, NaiveDate, Utc};
use log::warn;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, PgConnection};
use sqlx::{FromRow, PgPool, Row};
use std::convert::From;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use validator::Validate;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_conn_status", rename_all = "snake_case")]
pub enum ConnectionStatus {
    Online,
    Offline,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_validator_status", rename_all = "snake_case")]
pub enum ValidatorStatus {
    Provisioning,
    Syncing,
    Upgrading,
    Synced,
    Consensus,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_stake_status", rename_all = "snake_case")]
pub enum StakeStatus {
    Available,
    Staking,
    Staked,
    Delinquent,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_host_cmd", rename_all = "snake_case")]
pub enum HostCmd {
    RestartMiner,
    RestartJail,
    GetMinerName,
    GetBlockHeight,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_user_role", rename_all = "snake_case")]
pub enum UserRole {
    User,
    Host,
    Admin,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Host => write!(f, "host"),
            Self::User => write!(f, "user"),
        }
    }
}

impl FromStr for UserRole {
    type Err = ApiError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "admin" => Ok(Self::Admin),
            "host" => Ok(Self::Host),
            _ => Ok(Self::User),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserAuthInfo {
    pub id: Uuid,
    pub role: UserRole,
}

pub type AuthToken = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Authentication {
    User(UserAuthInfo),
    Host(AuthToken),
    Service(AuthToken),
}

impl Authentication {
    pub fn is_user(&self) -> bool {
        match self {
            Self::User(_) => true,
            _ => false,
        }
    }

    pub fn is_host(&self) -> bool {
        match self {
            Self::Host(_) => true,
            _ => false,
        }
    }

    pub fn is_admin(&self) -> bool {
        match self {
            Self::User(u) if u.role == UserRole::Admin => true,
            _ => false,
        }
    }

    pub fn is_service(&self) -> bool {
        match self {
            Self::Service(_) => true,
            _ => false,
        }
    }

    /// Returns an error if not an admin
    pub fn try_admin(&self) -> Result<bool> {
        if self.is_admin() {
            Ok(true)
        } else {
            Err(ApiError::InsufficientPermissionsError)
        }
    }

    /// Returns an error if not an host
    pub fn try_host(&self) -> Result<bool> {
        if self.is_host() {
            Ok(true)
        } else {
            Err(ApiError::InsufficientPermissionsError)
        }
    }

    /// Returns an error if not an admin
    pub fn try_service(&self) -> Result<bool> {
        if self.is_service() {
            Ok(true)
        } else {
            Err(ApiError::InsufficientPermissionsError)
        }
    }

    /// Returns an error if user doesn't have access
    pub fn try_user_access(&self, user_id: Uuid) -> Result<bool> {
        match self {
            Self::User(u) if u.id == user_id => Ok(true),
            _ => Err(ApiError::InsufficientPermissionsError),
        }
    }

    /// Returns an error if user doesn't have access
    pub async fn try_host_access(&self, host_id: Uuid, pool: &PgPool) -> Result<bool> {
        if self.is_host() {
            let host = self.get_host(pool).await?;
            if host.id == host_id {
                return Ok(true);
            }
        }

        Err(ApiError::InsufficientPermissionsError)
    }

    pub async fn get_user(&self, pool: &PgPool) -> Result<User> {
        match self {
            Self::User(u) => User::find_by_id(u.id, pool).await,
            _ => Err(anyhow!("Authentication is not a user.").into()),
        }
    }

    pub async fn get_host(&self, pool: &PgPool) -> Result<Host> {
        match self {
            Self::Host(token) => Host::find_by_token(token, pool).await,
            _ => Err(anyhow!("Autentication is not a host.").into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub hashword: String,
    pub role: UserRole,
    #[serde(skip_serializing)]
    pub salt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub fee_bps: i64,
    pub staking_quota: i64,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn verify_password(&self, password: &str) -> Result<()> {
        let argon2 = Argon2::default();
        let parsed_hash = argon2.hash_password_simple(password.as_bytes(), &self.salt)?;

        if let Some(output) = parsed_hash.hash {
            if self.hashword == output.to_string() {
                return Ok(());
            }
        }

        Err(ApiError::InvalidAuthentication(anyhow!(
            "Inavlid email or password."
        )))
    }

    pub fn set_jwt(&mut self) -> Result<Self> {
        let auth_data = auth::AuthData {
            user_id: self.id,
            user_role: self.role.to_string(),
        };

        self.token = Some(auth::create_jwt(&auth_data)?);
        Ok(self.to_owned())
    }

    pub async fn can_stake(&self, pool: &PgPool, count: i64) -> Result<bool> {
        Ok(self.staking_quota >= (self.staking_count(pool).await? + count))
    }

    /// Returns the number of validators in "Staking"
    pub async fn staking_count(&self, pool: &PgPool) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM validators where user_id = $1 AND stake_status = $2",
        )
        .bind(self.id)
        .bind(StakeStatus::Staking)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    pub async fn find_all(pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>("SELECT * FROM users")
            .fetch_all(pool)
            .await
            .map_err(ApiError::from)
    }

    /// Gets a summary list of all users
    pub async fn find_all_summary(pool: &PgPool) -> Result<Vec<UserSummary>> {
        sqlx::query_as::<_, UserSummary>(
            r##"
                SELECT 
                    users.id, 
                    email,
                    staking_quota,
                    fee_bps,
                    (SELECT count(*) from validators where validators.user_id=users.id) as validator_count,
                    COALESCE((SELECT sum(rewards.amount) from rewards where rewards.user_id=users.id), 0) as rewards_total
                FROM
                    users
                ORDER BY
                    validator_count, users.email
            "##
        )
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_by_email(email: &str, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM users WHERE LOWER(email) = LOWER($1) limit 1")
            .bind(email)
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_by_refresh(refresh: &str, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM users WHERE refresh = $1 limit 1")
            .bind(refresh)
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM users WHERE id = $1 limit 1")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn create(user: UserRequest, pool: &PgPool) -> Result<Self> {
        let _ = user
            .validate()
            .map_err(|e| ApiError::ValidationError(e.to_string()))?;

        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        if let Some(hashword) = argon2
            .hash_password_simple(user.password.as_bytes(), salt.as_str())?
            .hash
        {
            return sqlx::query_as::<_, Self>(
                "INSERT INTO users (email, hashword, salt) values (LOWER($1),$2,$3) RETURNING *",
            )
            .bind(user.email)
            .bind(hashword.to_string())
            .bind(salt.as_str())
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)?
            .set_jwt();
        }

        Err(ApiError::ValidationError("Invalid password.".to_string()))
    }

    pub async fn login(login: UserLoginRequest, pool: &PgPool) -> Result<Self> {
        let mut user = Self::find_by_email(&login.email, pool)
            .await
            .map_err(|_e| {
                ApiError::InvalidAuthentication(anyhow!("Email or password is invalid."))
            })?;
        let _ = user.verify_password(&login.password)?;

        user.set_jwt()
    }

    pub async fn refresh(req: UserRefreshRequest, pool: &PgPool) -> Result<User> {
        let mut user = Self::find_by_refresh(&req.refresh, pool).await?;
        Ok(user.set_jwt()?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserSummary {
    pub id: Uuid,
    pub email: String,
    pub staking_quota: i64,
    pub fee_bps: i64,
    pub validator_count: i64,
    pub rewards_total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UserRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8), must_match = "password_confirm")]
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UserLoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

impl UserLoginRequest {
    pub async fn is_valid(&self, pool: &PgPool) -> Result<bool> {
        let user = User::find_by_email(&self.email, pool).await?;

        Ok(user.verify_password(&self.password).is_ok())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRefreshRequest {
    pub refresh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
    pub ip_addr: String,
    pub val_ip_addrs: String,
    pub token: String,
    pub status: ConnectionStatus,
    pub validators: Option<Vec<Validator>>,
    pub created_at: DateTime<Utc>,
}

impl From<PgRow> for Host {
    fn from(row: PgRow) -> Self {
        Host {
            id: row.try_get("id").expect("Couldn't try_get id for host."),
            name: row
                .try_get("name")
                .expect("Couldn't try_get name for host."),
            version: row
                .try_get("version")
                .expect("Couldn't try_get version for host."),
            location: row
                .try_get("location")
                .expect("Couldn't try_get location for host."),
            ip_addr: row
                .try_get("ip_addr")
                .expect("Couldn't try_get ip_addr for host."),
            val_ip_addrs: row
                .try_get("val_ip_addrs")
                .expect("Couldn't try_get val_ip_addrs for host."),
            token: row
                .try_get("token")
                .expect("Couldn't try_get token for host."),
            status: row
                .try_get("status")
                .expect("Couldn't try_get status for host."),
            validators: None,
            created_at: row
                .try_get("created_at")
                .expect("Couldn't try_get created_at for host."),
        }
    }
}

impl Host {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query("SELECT * FROM hosts")
            .map(|row: PgRow| Self::from(row))
            .fetch_all(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Self> {
        let mut host = sqlx::query("SELECT * FROM hosts WHERE id = $1")
            .bind(id)
            .map(|row: PgRow| Self::from(row))
            .fetch_one(pool)
            .await?;

        // Add Validators list
        host.validators = Some(Validator::find_all_by_host(host.id, pool).await?);

        Ok(host)
    }

    pub async fn find_by_token(token: &str, pool: &PgPool) -> Result<Self> {
        let mut host = sqlx::query("SELECT * FROM hosts WHERE token = $1")
            .bind(token)
            .map(|row: PgRow| Self::from(row))
            .fetch_one(pool)
            .await?;

        // Add Validators list
        host.validators = Some(Validator::find_all_by_host(host.id, pool).await?);

        Ok(host)
    }

    pub async fn create(host: HostRequest, pool: &PgPool) -> Result<Self> {
        let mut tx = pool.begin().await?;
        let mut host = sqlx::query("INSERT INTO hosts (name, version, location, ip_addr, val_ip_addrs, token, status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *")
        .bind(host.name)
        .bind(host.version)
        .bind(host.location)
        .bind(host.ip_addr)
        .bind(host.val_ip_addrs)
        .bind(host.token)
        .bind(host.status)
        .map(|row: PgRow| {
            Self::from(row)
        })
        .fetch_one(&mut tx)
        .await?;

        let mut vals: Vec<Validator> = vec![];

        // Create and add validators
        for ip in host.validator_ips() {
            let val = ValidatorRequest {
                name: petname::petname(2, "_"),
                version: None,
                ip_addr: ip.to_owned(),
                host_id: host.id,
                user_id: None,
                address: None,
                swarm_key: None,
                block_height: None,
                stake_status: StakeStatus::Available,
                status: ValidatorStatus::Provisioning,
                tenure_penalty: 0.0,
                dkg_penalty: 0.0,
                performance_penalty: 0.0,
                total_penalty: 0.0,
            };

            let val = Validator::create_tx(val, &mut tx).await?;
            vals.push(val.to_owned());
        }

        host.validators = Some(vals);

        tx.commit().await?;

        Ok(host)
    }

    pub async fn update(id: Uuid, host: HostRequest, pool: &PgPool) -> Result<Self> {
        let mut tx = pool.begin().await.unwrap();
        let host = sqlx::query(
            r#"UPDATE hosts SET name = $1, version = $2, location = $3, ip_addr = $4, token = $5, status = $6  WHERE id = $7 RETURNING *"#
        )
        .bind(host.name)
        .bind(host.version)
        .bind(host.location)
        .bind(host.ip_addr)
        .bind(host.token)
        .bind(host.status)
        .bind(id)
        .map(|row: PgRow| {
            Self::from(row)
        })
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await.unwrap();
        Ok(host)
    }

    pub async fn update_status(id: Uuid, host: HostStatusRequest, pool: &PgPool) -> Result<Self> {
        let mut tx = pool.begin().await.unwrap();
        let host =
            sqlx::query(r#"UPDATE hosts SET version = $1, status = $2  WHERE id = $3 RETURNING *"#)
                .bind(host.version)
                .bind(host.status)
                .bind(id)
                .map(|row: PgRow| Self::from(row))
                .fetch_one(&mut tx)
                .await?;

        tx.commit().await.unwrap();
        Ok(host)
    }

    pub async fn delete(id: Uuid, pool: &PgPool) -> Result<u64> {
        let mut tx = pool.begin().await?;
        let deleted = sqlx::query("DELETE FROM hosts WHERE id = $1")
            .bind(id)
            .execute(&mut tx)
            .await?;

        tx.commit().await?;
        Ok(deleted.rows_affected())
    }

    pub fn new_token() -> String {
        Uuid::new_v4()
            .to_simple()
            .encode_lower(&mut Uuid::encode_buffer())
            .to_string()
    }

    pub fn validator_ips(&self) -> Vec<String> {
        self.val_ip_addrs
            .split(",")
            .map(|ip| ip.trim().to_string())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRequest {
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
    pub ip_addr: String,
    pub val_ip_addrs: String,
    pub token: String,
    pub status: ConnectionStatus,
}

impl From<HostCreateRequest> for HostRequest {
    fn from(host: HostCreateRequest) -> Self {
        Self {
            name: host.name,
            version: host.version,
            location: host.location,
            ip_addr: host.ip_addr,
            val_ip_addrs: host.val_ip_addrs,
            token: Host::new_token(),
            status: ConnectionStatus::Offline,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCreateRequest {
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
    pub ip_addr: String,
    pub val_ip_addrs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStatusRequest {
    pub version: Option<String>,
    pub status: ConnectionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Command {
    pub id: Uuid,
    pub host_id: Uuid,
    pub cmd: HostCmd,
    pub sub_cmd: Option<String>,
    pub response: Option<String>,
    pub exit_status: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl Command {
    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM commands where id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_all_by_host(host_id: Uuid, pool: &PgPool) -> Result<Vec<Command>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM commands where host_id = $1 ORDER BY created_at DESC",
        )
        .bind(host_id)
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_pending_by_host(host_id: Uuid, pool: &PgPool) -> Result<Vec<Command>> {
        sqlx::query_as::<_, Self>("SELECT * FROM commands where host_id = $1 AND completed_at IS NULL ORDER BY created_at_DESC")
        .bind(host_id)
        .fetch_all(pool)
            .await.map_err(ApiError::from)
    }

    pub async fn create(host_id: Uuid, command: CommandRequest, pool: &PgPool) -> Result<Command> {
        sqlx::query_as::<_, Self>(
            "INSERT INTO commands (host_id, cmd, sub_cmd) VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(host_id)
        .bind(command.cmd)
        .bind(command.sub_cmd)
        .fetch_one(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn update_response(
        id: Uuid,
        response: CommandResponseRequest,
        pool: &PgPool,
    ) -> Result<Command> {
        sqlx::query_as::<_, Self>("UPDATE commands SET response = $1, exit_status = $2, completed_at = now() WHERE id = $3 RETURNING *")
        .bind(response.response)
        .bind(response.exit_status)
        .bind(id)
        .fetch_one(pool)
        .await.map_err(ApiError::from)
    }

    pub async fn delete(id: Uuid, pool: &PgPool) -> Result<u64> {
        let mut tx = pool.begin().await?;
        let deleted = sqlx::query("DELETE FROM commands WHERE id = $1")
            .bind(id)
            .execute(&mut tx)
            .await?;

        tx.commit().await?;
        Ok(deleted.rows_affected())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub cmd: HostCmd,
    pub sub_cmd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponseRequest {
    pub response: Option<String>,
    pub exit_status: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Validator {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub ip_addr: String,
    pub host_id: Uuid,
    pub user_id: Option<Uuid>,
    pub owner_address: Option<String>,
    pub address: Option<String>,
    pub address_name: Option<String>,
    pub swarm_key: Option<String>,
    pub block_height: Option<i64>,
    pub stake_status: StakeStatus,
    pub staking_height: Option<i64>,
    pub status: ValidatorStatus,
    pub tenure_penalty: f64,
    pub dkg_penalty: f64,
    pub performance_penalty: f64,
    pub total_penalty: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Validator {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>("SELECT * FROM validators")
            .fetch_all(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_all_by_host(host_id: Uuid, pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM validators WHERE host_id = $1 order by status, name",
        )
        .bind(host_id)
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_all_by_user(user_id: Uuid, pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM validators WHERE user_id = $1 order by status, name",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM validators WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_all_by_stake_status(
        stake_status: StakeStatus,
        pool: &PgPool,
    ) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM validators WHERE stake_status = $1 order by status, name",
        )
        .bind(stake_status)
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn create_tx(validator: ValidatorRequest, tx: &mut PgConnection) -> Result<Self> {
        let validator = sqlx::query_as::<_, Self>("INSERT INTO validators (name, version, ip_addr, host_id, user_id, address, swarm_key, block_height, stake_status, status, tenure_penalty, dkg_penalty, performance_penalty, total_penalty) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *")
        .bind(validator.name)
        .bind(validator.version)
        .bind(validator.ip_addr)
        .bind(validator.host_id)
        .bind(validator.user_id)
        .bind(validator.address)
        .bind(validator.swarm_key)
        .bind(validator.block_height)
        .bind(validator.stake_status)
        .bind(validator.status)
        .bind(validator.tenure_penalty)
        .bind(validator.dkg_penalty)
        .bind(validator.performance_penalty)
        .bind(validator.total_penalty)
        .fetch_one(tx)
        .await?;

        Ok(validator)
    }

    pub async fn update_status(
        id: Uuid,
        validator: ValidatorStatusRequest,
        pool: &PgPool,
    ) -> Result<Self> {
        let mut tx = pool.begin().await.unwrap();
        let validator = sqlx::query_as::<_, Self>(
            r#"UPDATE validators SET version=$1, block_height=$2, status=$3, tenure_penalty=$4, dkg_penalty=$5, performance_penalty=$6, total_penalty=$7, updated_at=now()  WHERE id = $8 RETURNING *"#
        )
        .bind(validator.version)
        .bind(validator.block_height)
        .bind(validator.status)
        .bind(validator.tenure_penalty)
        .bind(validator.dkg_penalty)
        .bind(validator.performance_penalty)
        .bind(validator.total_penalty)
        .bind(id)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await.unwrap();
        Ok(validator)
    }

    pub async fn update_stake_status(id: Uuid, status: StakeStatus, pool: &PgPool) -> Result<Self> {
        let query = match status {
            StakeStatus::Available => {
                r#"UPDATE validators SET stake_status=$1, owner_address=NULL, user_id=NULL, staking_height=NULL, updated_at=now()  WHERE id = $2 RETURNING *"#
            }
            StakeStatus::Staking => {
                r#"UPDATE validators SET stake_status=$1, staking_height=(SELECT block_height FROM info LIMIT 1), updated_at=now() WHERE id = $2 RETURNING *"#
            }
            _ => {
                r#"UPDATE validators SET stake_status=$1, staking_height=NULL, updated_at=now()  WHERE id = $2 RETURNING *"#
            }
        };

        Ok(sqlx::query_as::<_, Self>(query)
            .bind(status)
            .bind(id)
            .fetch_one(pool)
            .await?)
    }

    pub async fn update_owner_address(
        id: Uuid,
        owner_address: Option<String>,
        pool: &PgPool,
    ) -> Result<Self> {
        let mut tx = pool.begin().await.unwrap();
        let validator = sqlx::query_as::<_, Self>(
            r#"UPDATE validators SET owner_address=$1, updated_at=now()  WHERE id = $2 RETURNING *"#,
        )
        .bind(owner_address)
        .bind(id)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await.unwrap();
        Ok(validator)
    }

    pub async fn update_identity(
        id: Uuid,
        validator: ValidatorIdentityRequest,
        pool: &PgPool,
    ) -> Result<Self> {
        let mut address_name = None;
        if let Some(val_addr) = &validator.address {
            address_name = match val_addr.parse::<AnimalName>() {
                Ok(name) => Some(name.to_string()),
                Err(_) => None,
            }
        };

        let mut tx = pool.begin().await.unwrap();
        let validator = sqlx::query_as::<_, Self>(
            r#"UPDATE validators SET version=$1, address=$2, swarm_key=$3, address_name=$4, updated_at=now() WHERE id = $5 RETURNING *"#
        )
        .bind(validator.version)
        .bind(validator.address)
        .bind(validator.swarm_key)
        .bind(address_name)
        .bind(id)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await.unwrap();
        Ok(validator)
    }

    pub async fn inventory_count(pool: &PgPool) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) AS available FROM validators where status = $1 and stake_status = $2",
        )
        .bind(ValidatorStatus::Synced)
        .bind(StakeStatus::Available)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    pub async fn stake(pool: &PgPool, user: &User, count: i64) -> Result<Vec<Validator>> {
        if user.can_stake(pool, count).await? {
            return sqlx::query_as::<_, Self>(
                r#"
            WITH inv AS (
                SELECT id FROM validators
                WHERE status = $1 AND stake_status = $2
                LIMIT $3
            ) 
            UPDATE validators SET 
                user_id = $4, 
                stake_status = $5,
                staking_height = (SELECT block_height FROM info LIMIT 1)
            FROM inv
            WHERE validators.id = inv.id
            RETURNING *"#,
            )
            .bind(ValidatorStatus::Synced)
            .bind(StakeStatus::Available)
            .bind(count)
            .bind(user.id)
            .bind(StakeStatus::Staking)
            .fetch_all(pool)
            .await
            .map_err(ApiError::from);
        }

        Err(ApiError::ValidationError(
            "User's staking quota over limit.".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRequest {
    pub name: String,
    pub version: Option<String>,
    pub ip_addr: String,
    pub host_id: Uuid,
    pub user_id: Option<Uuid>,
    pub address: Option<String>,
    pub swarm_key: Option<String>,
    pub block_height: Option<i64>,
    pub stake_status: StakeStatus,
    pub status: ValidatorStatus,
    pub tenure_penalty: f64,
    pub dkg_penalty: f64,
    pub performance_penalty: f64,
    pub total_penalty: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusRequest {
    pub version: Option<String>,
    pub block_height: Option<i64>,
    pub status: ValidatorStatus,
    pub tenure_penalty: f64,
    pub dkg_penalty: f64,
    pub performance_penalty: f64,
    pub total_penalty: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorIdentityRequest {
    pub version: Option<String>,
    pub address: Option<String>,
    pub swarm_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStakeRequest {
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reward {
    pub id: Uuid,
    pub block: i64,
    pub hash: String,
    pub txn_time: DateTime<Utc>,
    pub validator_id: Uuid,
    pub user_id: Option<Uuid>,
    pub account: String,
    pub validator: String,
    pub amount: i64,
    pub created_at: DateTime<Utc>,
}

impl Reward {
    pub async fn summary_by_user(pool: &PgPool, user_id: &Uuid) -> Result<RewardSummary> {
        let row: RewardSummary = sqlx::query_as(
            r##"SELECT 
                        COALESCE(SUM(amount) FILTER (WHERE txn_time BETWEEN now() - '30 day'::interval AND now()), 0)::BIGINT as last_30,
                        COALESCE(SUM(amount) FILTER (WHERE txn_time BETWEEN now() - '14 day'::interval AND now()), 0)::BIGINT as last_14,
                        COALESCE(SUM(amount) FILTER (WHERE txn_time BETWEEN now() - '7 day'::interval AND now()), 0)::BIGINT as last_7,
                        COALESCE(SUM(amount) FILTER (WHERE txn_time BETWEEN now() - '1 day'::interval AND now()), 0)::BIGINT as last_1,
                        COALESCE(SUM(amount), 0)::BIGINT as total
                    FROM rewards 
                    WHERE user_id=$1"##
            )
            .bind(user_id)
            .fetch_one(pool)
            .await?;

        Ok(row)
    }

    pub async fn create(pool: &PgPool, rewards: &Vec<RewardRequest>) -> Result<()> {
        for reward in rewards {
            let res = sqlx::query("INSERT INTO rewards (block, hash, txn_time, validator_id, user_id, account, validator, amount) values ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&reward.block)
            .bind(&reward.hash)
            .bind(&reward.txn_time)
            .bind(&reward.validator_id)
            .bind(&reward.user_id)
            .bind(&reward.account)
            .bind(&reward.validator)
            .bind(&reward.amount)
            .execute(pool)
            .await;

            if let Err(e) = res {
                warn!("Creating rewards (duplicate violations expected): {}", e);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardRequest {
    pub block: i64,
    pub hash: String,
    pub txn_time: DateTime<Utc>,
    pub validator_id: Uuid,
    pub user_id: Option<Uuid>,
    pub account: String,
    pub validator: String,
    pub amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RewardSummary {
    pub total: i64,
    pub last_30: i64,
    pub last_14: i64,
    pub last_7: i64,
    pub last_1: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Info {
    pub block_height: i64,
}

impl Info {
    pub async fn update_info(pool: &PgPool, info: &Info) -> Result<Info> {
        sqlx::query_as::<_, Info>(
            "UPDATE info SET block_height = $1 WHERE block_height <> $1 RETURNING *",
        )
        .bind(info.block_height)
        .fetch_one(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn get_info(pool: &PgPool) -> Result<Info> {
        sqlx::query_as::<_, Info>("SELECT * FROM info LIMIT 1")
            .fetch_one(pool)
            .await
            .map_err(ApiError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Bill {
    pub user_id: Uuid,
    pub date: NaiveDate,
    pub amount: i64,
}

impl Bill {
    pub async fn find_all_by_user(pool: &PgPool, user_id: &Uuid) -> Result<Vec<Bill>> {
        sqlx::query_as::<_, Bill>(
            r##"SELECT
                        user_id, 
                        EXTRACT(ISOYEAR FROM txn_time) AS year, 
                        EXTRACT(WEEK FROM txn_time) AS week, 
                        TO_DATE(CONCAT(EXTRACT(ISOYEAR FROM txn_time), 
                        EXTRACT(WEEK FROM txn_time)), 'IYYYIW') AS date, 
                        (SUM(amount) * (users.fee_bps::DECIMAL / 10000))::BIGINT AS amount 
                    FROM 
                        rewards
                    INNER JOIN
                        users
                    ON
                        users.id = rewards.user_id
                    WHERE
                        user_id = $1
                    GROUP BY 
                        user_id,
                        fee_bps, 
                        year, 
                        week 
                    ORDER BY 
                        date DESC
                    "##,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }
}
