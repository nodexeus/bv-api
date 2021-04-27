use crate::models::*;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

impl Host {
    pub async fn find_by_id(_id: Uuid, _pool: &PgPool) -> Result<Host> {
        unimplemented!()
    }
}
