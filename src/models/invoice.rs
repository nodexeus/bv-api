use crate::errors::{ApiError, Result};
use crate::models::payment::PaymentDue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Invoice {
    pub id: i32,
    pub user_id: Uuid,
    pub pay_address: String,
    pub earnings: i64,
    pub fee_bps: i64,
    pub amount: i64,
    pub validators_count: i64,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub is_paid: bool,
}

impl Invoice {
    pub async fn find_all_by_user(
        user_id: &Uuid,
        db: impl sqlx::PgExecutor<'_>,
    ) -> Result<Vec<Invoice>> {
        sqlx::query_as(
            r##"SELECT
                        invoices.*,
                        users.pay_address
                    FROM
                        invoices
                    INNER JOIN
                        users on users.id = invoices.user_id
                    WHERE
                        user_id = $1 
                    ORDER BY 
                        ends_at DESC
                    "##,
        )
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(ApiError::from)
    }

    /// Gets all wallets addresses with a due amount.
    pub async fn find_all_payments_due(db: impl sqlx::PgExecutor<'_>) -> Result<Vec<PaymentDue>> {
        sqlx::query_as("SELECT users.pay_address, sum(amount), min(ends_at) FROM invoices INNER JOIN users on users.id = invoices.user_id WHERE is_paid = false GROUP BY address")
            .fetch_all(db)
            .await
            .map_err(ApiError::from)
    }
}
