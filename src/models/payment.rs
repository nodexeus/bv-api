use crate::errors::Result;
use chrono::{DateTime, Utc};
use log::debug;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Payment {
    pub hash: String,
    pub user_id: Uuid,
    pub block: i64,
    pub payer: String,
    pub payee: String,
    pub amount: i64,
    pub oracle_price: i64,
    pub created_at: Option<DateTime<Utc>>,
}

impl Payment {
    pub async fn create(payments: &[Payment], tx: &mut super::DbTrx<'_>) -> Result<()> {
        for payment in payments {
            let res = sqlx::query(
                r##"
                INSERT INTO payments (
                    hash,
                    user_id,
                    block, 
                    payer,
                    payee,
                    amount,
                    oracle_price
                ) values ($1,$2,$3,$4,$5,$6,$7)"##,
            )
            .bind(payment.block)
            .bind(payment.user_id)
            .bind(&payment.hash)
            .bind(&payment.payer)
            .bind(&payment.payee)
            .bind(payment.amount)
            .bind(payment.oracle_price)
            .execute(&mut *tx)
            .await;

            if let Err(e) = res {
                debug!("Creating payments (duplicate violations expected): {}", e);
            }
        }

        Ok(())
    }

    pub async fn find_all_by_user(
        user_id: Uuid,
        db: &mut sqlx::PgConnection,
    ) -> Result<Vec<Payment>> {
        Ok(sqlx::query_as::<_, Payment>(
            "SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(db)
        .await?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentDue {
    pub pay_address: String,
    pub amount: i64,
    pub due_date: DateTime<Utc>,
}
