use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Result, Row};
use sqlx::{postgres::PgRow, PgConnection};
use std::convert::From;
use uuid::Uuid;
use validator::{Validate, ValidationError};

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

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub hashword: String,
    pub salt: String,
}

impl User {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>("SELECT * FROM users")
            .fetch_all(pool)
            .await
    }

    pub async fn find_by_email(email: Uuid, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM users WHERE email = $1 limit 1",
        )
        .bind(email)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM users WHERE id = $1 limit 1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
    }

}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UserRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8), must_match = "password_confirm")]
    pub password: String,
    pub password_confirm: String,
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
                stake_status: StakeStatus::Available,
                status: ValidatorStatus::Provisioning,
                score: 0,
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
        //TODO: disable until we can figure out how best to handle
        //.bind(host.val_ip_addr_start)
        //.bind(host.val_count)
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
            .map(|ip| {
                ip.trim().to_string()
            })
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
pub struct Validator {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub ip_addr: String,
    pub host_id: Uuid,
    pub user_id: Option<Uuid>,
    pub address: Option<String>,
    pub swarm_key: Option<Vec<u8>>,
    pub stake_status: StakeStatus,
    pub status: ValidatorStatus,
    pub score: i64,
    pub created_at: DateTime<Utc>,
}

impl Validator {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>("SELECT * FROM validators")
            .fetch_all(pool)
            .await
    }

    pub async fn find_all_by_host(host_id: Uuid, pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM validators WHERE host_id = $1 order by status, name",
        )
        .bind(host_id)
        .fetch_all(pool)
        .await
    }

    pub async fn find_all_by_user(user_id: Uuid, pool: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM validators WHERE user_id = $1 order by status, name",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM validators WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
    }

    pub async fn create_tx(validator: ValidatorRequest, tx: &mut PgConnection) -> Result<Self> {
        let validator = sqlx::query_as::<_, Self>("INSERT INTO validators (name, version, ip_addr, host_id, user_id, address, swarm_key, stake_status, status, score) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *")
        .bind(validator.name)
        .bind(validator.version)
        .bind(validator.ip_addr)
        .bind(validator.host_id)
        .bind(validator.user_id)
        .bind(validator.address)
        .bind(validator.swarm_key)
        .bind(validator.stake_status)
        .bind(validator.status)
        .bind(validator.score)
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
            r#"UPDATE validators SET version=$1, stake_status=$2, status=$3, score=$4  WHERE id = $5 RETURNING *"#
        )
        .bind(validator.version)
        .bind(validator.stake_status)
        .bind(validator.status)
        .bind(validator.score)
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
        let mut tx = pool.begin().await.unwrap();
        let validator = sqlx::query_as::<_, Self>(
            r#"UPDATE validators SET version=$1, address=$2, swarm_key=$3 WHERE id = $4 RETURNING *"#
        )
        .bind(validator.version)
        .bind(validator.address)
        .bind(validator.swarm_key)
        .bind(id)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await.unwrap();
        Ok(validator)
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
    pub swarm_key: Option<Vec<u8>>,
    pub stake_status: StakeStatus,
    pub status: ValidatorStatus,
    pub score: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusRequest {
    pub version: Option<String>,
    pub stake_status: StakeStatus,
    pub status: ValidatorStatus,
    pub score: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorIdentityRequest {
    pub version: Option<String>,
    pub address: Option<String>,
    pub swarm_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reward {
    pub id: Uuid,
    pub block: i64,
    pub transaction_hash: String,
    pub time: i64,
    pub validator_id: Uuid,
    pub account: String,
    pub amount: i64,
}
