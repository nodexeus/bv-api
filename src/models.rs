use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Result};
use uuid::Uuid;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub hashword: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Host {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
    pub ip_addr: IpNetwork,
    pub val_ip_addr_start: IpNetwork,
    pub val_count: i32,
    pub token: String,
    pub status: ConnectionStatus,
    pub created_at: time::PrimitiveDateTime,
}

impl Host {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Host>> {
        sqlx::query_as::<_, Host>("SELECT * FROM hosts")
            .fetch_all(pool)
            .await
    }

    pub async fn find_by_id(id: Uuid, pool: &PgPool) -> Result<Host> {
        sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
    }

    pub async fn find_by_token(token: String, pool: &PgPool) -> Result<Host> {
        sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE token = $1")
            .bind(token)
            .fetch_one(pool)
            .await
    }

    pub async fn create(host: HostRequest, pool: &PgPool) -> Result<Host> {
        let mut tx = pool.begin().await?;
        let host = sqlx::query_as::<_, Host>("INSERT INTO hosts (name, version, location, ip_addr, val_ip_addr_start, val_count, token, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *")
        .bind(host.name)
        .bind(host.version)
        .bind(host.location)
        .bind(host.ip_addr)
        .bind(host.val_ip_addr_start)
        .bind(host.val_count)
        .bind(host.token)
        .bind(host.status)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await?;

        Ok(host)
    }

    pub async fn update(id: Uuid, host: HostRequest, pool: &PgPool) -> Result<Host> {
        let mut tx = pool.begin().await.unwrap();
        let host = sqlx::query_as::<_, Host>(
            r#"UPDATE hosts SET name = $1, version = $2, location = $3, ip_addr = $4, val_ip_addr_start = $5, val_count = $6, token = $7, status = $8  WHERE id = $9 RETURNING *"#
        )
        .bind(host.name)
        .bind(host.version)
        .bind(host.location)
        .bind(host.ip_addr)
        .bind(host.val_ip_addr_start)
        .bind(host.val_count)
        .bind(host.token)
        .bind(host.status)
        .bind(id)
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRequest {
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
    pub ip_addr: IpNetwork,
    pub val_ip_addr_start: IpNetwork,
    pub val_count: i32,
    pub token: String,
    pub status: ConnectionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub host_id: Uuid,
    pub user_id: Uuid,
    pub address: String,
    pub swarm_key: Vec<u8>,
    pub is_staked: bool,
    pub is_consensus: bool,
    pub is_enabled: bool,
    pub status: Option<String>,
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
