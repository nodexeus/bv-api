use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Result};
use uuid::Uuid;
use ipnetwork::IpNetwork;

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
    pub locatoin: Option<String>,
    pub ip_addr: IpNetwork,
    pub ip_addrs: String,
    pub token: String,
    pub status: ConnectionStatus,
    pub created_at: time::PrimitiveDateTime,
}

impl Host {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Host>> {
        sqlx::query_as::<_, Host> ("SELECT * FROM hosts")
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
        unimplemented!()
    }

    pub async fn create(host: HostRequest, pool: &PgPool) -> Result<Host> {
        let mut tx = pool.begin().await?;
        let host = sqlx::query_as::<_, Host>("INSERT INTO hosts (name, location, ip_addr, ip_addrs, token, status) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *")
        .bind(host.name)
        .bind(host.location)
        .bind(host.ip_addr)
        .bind(host.ip_addrs)
        .bind(host.token)
        .bind(host.status)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await?;
        
        Ok(host)
    }

    pub async fn delete(id: Uuid, pool: &PgPool) -> Result<()> {
        let mut tx = pool.begin().await?;
        let _deleted = sqlx::query("DELETE FROM hosts WHERE id = $1")
            .bind(id)
            .execute(&mut tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRequest {
    pub name: String,
    pub location: Option<String>,
    pub ip_addr: String,
    pub ip_addrs: String,
    pub token: String,
    pub status: ConnectionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub id: Uuid,
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
