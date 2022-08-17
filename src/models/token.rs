use crate::auth::{JwtToken, TokenHolderType, TokenIdentifyable};
use crate::errors::ApiError;
use crate::errors::Result;
use crate::models::{host::Host, node::Node, user::User, validator::Validator};
use anyhow::anyhow;
use base64::encode as base64_encode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::env;
use std::ops::Add;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
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
    pub id: Uuid,
    pub token: String,
    pub host_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub role: TokenRole,
}

impl ToString for Token {
    fn to_string(&self) -> String {
        self.token.clone()
    }
}

impl Token {
    pub fn to_base64(&self) -> String {
        base64_encode(&self.token)
    }

    pub async fn get<T: TokenIdentifyable>(resource_id: Uuid, db: &PgPool) -> Result<Self> {
        let id_field = match T::get_holder_type() {
            TokenHolderType::User => "user_id",
            TokenHolderType::Host => "host_id",
        };

        sqlx::query_as::<_, Self>(&*format!("select * from tokens where {} = $1", id_field))
            .bind(resource_id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn delete(id: Uuid, db: &PgPool) -> Result<Self> {
        let mut tx = db.begin().await?;

        let token = sqlx::query_as::<_, Self>("DELETE FROM tokens WHERE id = $1 RETURNING *")
            .bind(id)
            .fetch_one(&mut tx)
            .await
            .map_err(ApiError::from)?;

        match tx.commit().await {
            Ok(_) => Ok(token),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn refresh(token_str: String, db: &PgPool) -> Result<Self> {
        // 1. Get the old token
        let old_token = sqlx::query_as::<_, Self>("SELECT * FROM tokens WHERE token = $1")
            .bind(token_str)
            .fetch_one(db)
            .await?;

        match old_token.host_id {
            Some(host_id) => {
                // Create new token
                let new_token =
                    Token::create(host_id, old_token.role, db, TokenHolderType::Host).await?;

                return match Host::set_token(new_token.id, host_id, db).await {
                    Ok(_host) => {
                        // delete old token
                        match Token::delete(old_token.id, db).await {
                            Ok(new_token) => Ok(new_token),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                };
            }
            None => tracing::debug!("old token has no host ID"),
        }

        match old_token.user_id {
            Some(user_id) => {
                // Create new token
                let new_token =
                    Token::create(user_id, old_token.role, db, TokenHolderType::User).await?;

                return match User::set_token(new_token.id, user_id, db).await {
                    Ok(_user) => {
                        // delete old token
                        match Token::delete(old_token.id, db).await {
                            Ok(new_token) => Ok(new_token),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                };
            }
            None => tracing::debug!("old token has no user ID"),
        }

        Err(ApiError::UnexpectedError(anyhow!(
            "Neither host nor user ID set on token, can't refresh"
        )))
    }

    pub async fn create_for<T: TokenIdentifyable>(
        resource: &T,
        role: TokenRole,
        db: &PgPool,
    ) -> Result<Self> {
        let token = Token::create(resource.get_id(), role, db, T::get_holder_type()).await?;

        match T::set_token(token.id, resource.get_id(), db).await {
            Ok(_) => Ok(token),
            Err(e) => Err(e),
        }
    }

    /// TODO: refactor me
    pub async fn create(
        resource_id: Uuid,
        role: TokenRole,
        db: &PgPool,
        holder_type: TokenHolderType,
    ) -> Result<Self> {
        let expiration = Self::get_expiration(Self::get_expiration_period(holder_type));
        let jwt_token = JwtToken::new(resource_id, expiration.timestamp(), holder_type);
        let token_str = jwt_token.encode().unwrap();
        let id_field = match holder_type {
            TokenHolderType::User => "user_id",
            TokenHolderType::Host => "host_id",
        };

        let mut tx = db.begin().await?;
        let token = sqlx::query_as::<_, Self>(&*format!(
            "INSERT INTO tokens (token, {}, expires_at, role) VALUES ($1, $2, $3, $4) RETURNING *",
            id_field
        ))
        .bind(token_str)
        .bind(resource_id)
        .bind(expiration)
        .bind(role)
        .fetch_one(&mut tx)
        .await
        .map_err(ApiError::from)
        .unwrap();

        tx.commit().await?;

        match holder_type {
            TokenHolderType::User => match User::set_token(token.id, resource_id, db).await {
                Ok(_user) => Ok(token),
                Err(e) => Err(e),
            },
            TokenHolderType::Host => match Host::set_token(token.id, resource_id, db).await {
                Ok(_host) => Ok(token),
                Err(e) => Err(e),
            },
        }
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
            "select h.* from tokens t right join hosts h on t.host_id = h.id where t.token = $1",
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

    fn get_expiration_period(holder_type: TokenHolderType) -> i64 {
        let name = match holder_type {
            TokenHolderType::User => "TOKEN_EXPIRATION_DAYS_USER",
            TokenHolderType::Host => "TOKEN_EXPIRATION_DAYS_HOST",
        };

        env::var(name)
            .unwrap_or_else(|_| "1".into())
            .parse()
            .unwrap()
    }
}
