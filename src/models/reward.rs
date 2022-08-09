use crate::errors::Result;
use chrono::{DateTime, Utc};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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
    pub async fn summary_by_user(db: &PgPool, user_id: &Uuid) -> Result<RewardSummary> {
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
            .fetch_one(db)
            .await?;

        Ok(row)
    }

    pub async fn create(db: &PgPool, rewards: &[RewardRequest]) -> Result<()> {
        for reward in rewards {
            if reward.amount < 1 {
                error!("Reward has zero amount. {:?}", reward);
            }
            let res = sqlx::query("INSERT INTO rewards (block, hash, txn_time, validator_id, user_id, account, validator, amount) values ($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(&reward.block)
                .bind(&reward.hash)
                .bind(&reward.txn_time)
                .bind(&reward.validator_id)
                .bind(&reward.user_id)
                .bind(&reward.account)
                .bind(&reward.validator)
                .bind(&reward.amount)
                .execute(db)
                .await;

            if let Err(e) = res {
                debug!("Creating rewards (duplicate violations expected): {}", e);
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
