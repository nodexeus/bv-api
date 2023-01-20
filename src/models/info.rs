use crate::errors::{ApiError, Result};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::convert::From;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct InfoRequest {
    pub block_height: i64,
    /// Divide by 100000000 to get USD value
    pub oracle_price: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Info {
    pub block_height: i64,
    pub staked_count: i64,
    /// Divide by 100000000 to get USD value
    pub oracle_price: i64,
    pub total_rewards: i64,
}

impl Info {
    pub async fn update_info(info: &InfoRequest, tx: &mut super::DbTrx<'_>) -> Result<Info> {
        sqlx::query_as(
            "UPDATE info
            SET
                block_height = $1,
                oracle_price = $2,
                total_rewards = COALESCE((SELECT SUM(amount) FROM rewards), 0),
                staked_count = (SELECT count(*) FROM validators where stake_status = 'staked')
            WHERE block_height <> $1
            RETURNING *",
        )
        .bind(info.block_height)
        .bind(info.oracle_price)
        .fetch_one(tx)
        .await
        .map_err(ApiError::from)
    }

    pub async fn get_info(db: &mut sqlx::PgConnection) -> Result<Info> {
        sqlx::query_as("SELECT * FROM info LIMIT 1")
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }
}
