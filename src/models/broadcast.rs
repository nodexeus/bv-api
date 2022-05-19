use crate::errors::{ApiError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BroadcastFilter {
    pub id: Uuid,
    pub blockchain_id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub addresses: Option<String>,
    pub callback_url: String,
    pub auth_token: String,
    pub txn_types: String,
    pub is_active: bool,
    pub last_processed_height: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BroadcastFilter {
    pub async fn find_by_id(id: &Uuid, db: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM broadcast_filters where id = $1")
            .bind(&id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_all_by_org_id(id: &Uuid, db: &PgPool) -> Result<Vec<Self>> {
        sqlx::query_as::<_, Self>("SELECT * FROM broadcast_filters where org_id = $1")
            .bind(&id)
            .fetch_all(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn create(req: &BroadcastFilterRequest, db: &PgPool) -> Result<Self> {
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
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn update(id: &Uuid, req: &BroadcastFilterRequest, db: &PgPool) -> Result<Self> {
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
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastFilterRequest {
    pub blockchain_id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub addresses: Option<String>,
    pub callback_url: String,
    pub auth_token: String,
    pub txn_types: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BroadcastLog {
    pub id: Uuid,
    pub blockchain_id: Uuid,
    pub org_id: Uuid,
    pub broadcast_filter_id: Uuid,
    pub address_count: i64,
    pub txn_count: i64,
    pub event_type: String,
    pub event_msg: Option<String>,
    pub created_at: DateTime<Utc>,
}
