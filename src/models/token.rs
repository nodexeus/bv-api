use crate::auth::{JwtToken, TokenHolderType};
use crate::errors::ApiError;
use crate::errors::Result;
use crate::models::{Host, Node, User, Validator};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::env;
use std::ops::Add;
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
    pub async fn refresh(jwt_token: JwtToken, db: &PgPool) -> Result<Self> {
        // delete and get old one
        match sqlx::query_as::<_, Self>("delete from tokens where token = $1 returning *")
            .bind(jwt_token.encode().unwrap())
            .fetch_one(db)
            .await
        {
            // return new one
            Ok(old_token) => {
                // create new token
                Self::create_token(
                    old_token.user_id.unwrap(),
                    old_token.role,
                    db,
                    jwt_token.token_holder(),
                )
                .await
            }
            Err(e) => Err(ApiError::NotFoundError(e)),
        }
    }

    pub async fn create_token(
        id: Uuid,
        role: TokenRole,
        db: &PgPool,
        holder_type: &TokenHolderType,
    ) -> Result<Self> {
        let expiration = Self::get_expiration(Self::get_expiration_period());
        let jwt_token = JwtToken::new(id, expiration.timestamp() as usize, TokenHolderType::Host);
        let id_field = match holder_type {
            TokenHolderType::User => "user_id",
            TokenHolderType::Host => "host_id",
        };

        sqlx::query_as::<_, Self>(&*format!(
            "insert into tokens (token, {}, expires_at, role) values ($1, $2, $3, $4)",
            id_field
        ))
        .bind(jwt_token.encode().unwrap())
        .bind(id)
        .bind(expiration)
        .bind(role)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_by_token(token_str: String, db: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM tokens where token = $1")
            .bind(token_str)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn get_user_for_token(token_str: String, db: &PgPool) -> Result<User> {
        sqlx::query_as::<_, User>(
            "select u.* from tokens t right join users u on t.user_id = u.id where t.token = $1",
        )
        .bind(token_str)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn get_host_for_token(token_str: String, db: &PgPool) -> Result<Host> {
        let mut host = sqlx::query(
            "select h.* from tokens t right join hosts u on t.host_id = h.id where t.token = $1",
        )
        .bind(token_str)
        .map(Host::from)
        .fetch_one(db)
        .await?;

        // Add Validators list
        host.validators = Some(Validator::find_all_by_host(host.id, db).await?);
        host.nodes = Some(Node::find_all_by_host(host.id, db).await?);

        Ok(host)
    }

    fn get_expiration(duration_days: i64) -> DateTime<Utc> {
        let start = Utc::now();

        start.add(Duration::days(duration_days))
    }

    fn get_expiration_period() -> i64 {
        env::var("TOKEN_EXPIRATION_DAYS")
            .unwrap_or("1".into())
            .parse()
            .unwrap()
    }
}
