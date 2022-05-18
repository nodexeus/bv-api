use crate::errors::{ApiError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BroadcastFilter {
    id: Uuid,
    blockchain_id: Uuid,
    org_id: Uuid,
    name: String,
    addresses: Option<String>,
    callback_url: String,
    auth_token: String,
    txn_types: String,
    is_active: bool,
    last_processed_height: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl BroadcastFilter {
    pub async fn create(req: &BroadcastFilterRequest, pool: &PgPool) -> Result<Self> {
        //TODO: Validate Org/user
        sqlx::query_as::<_, Self>(
            r##"
            INSERT INTO filters
                (blockchain_id, org_id, name, addresses, callback_url, auth_token, txn_types, is_active)
            VALUES
                ($1,$2,$3,$4,$5,$6,$7,$8)
            RETURNING *
            "##)
        .bind(&req.blockchain_id)
        .bind(&req.org_id)
        .bind(&req.name)
        .bind(&req.addresses)
        .bind(&req.callback_url)
        .bind(&req.auth_token)
        .bind(&req.txn_types)
        .bind(&req.is_active)
        .fetch_one(pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn update(id: &Uuid, req: &BroadcastFilterRequest, pool: &PgPool) -> Result<Self> {
        //TODO: Validate Org/user
        sqlx::query_as::<_, Self>(
            r##"
            UPDATE filters
                SET blockchain_id=$1, org_id=$2, name=$3, addresses=$4, callback_url=$5, auth_token=$6, txn_types=$7, is_active=$8
            WHERE
                id=$9
            RETURNING *
            "##)
        .bind(&req.blockchain_id)
        .bind(&req.org_id)
        .bind(&req.name)
        .bind(&req.addresses)
        .bind(&req.callback_url)
        .bind(&req.auth_token)
        .bind(&req.txn_types)
        .bind(&req.is_active)
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(ApiError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastFilterRequest {
    blockchain_id: Uuid,
    org_id: Uuid,
    name: String,
    addresses: Option<String>,
    callback_url: String,
    auth_token: String,
    txn_types: String,
    is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BroadcastLog {
    id: Uuid,
    blockchain_id: Uuid,
    org_id: Uuid,
    broadcast_filter_id: Uuid,
    address_count: i64,
    txn_count: i64,
    event_type: String,
    event_msg: Option<String>,
    created_at: DateTime<Utc>,
}
