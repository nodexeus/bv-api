use crate::errors::ApiError;
use crate::errors::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_token_role", rename_all = "snake_case")]
pub enum TokenRole {
    Admin,
    Guest,
    Service,
    User,
}

impl ToString for TokenRole {
    fn to_string(&self) -> String {
        match self {
            TokenRole::Admin => "admin".into(),
            TokenRole::Guest => "guest".into(),
            TokenRole::Service => "service".into(),
            TokenRole::User => "user".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Token {
    pub token: String,
    pub host_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub role: TokenRole,
}

impl Token {
    pub async fn find_by_token(token_str: String, db: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM tokens where token = $1")
            .bind(token_str)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }
}
