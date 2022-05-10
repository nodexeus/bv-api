use crate::errors::{ApiError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, PgConnection};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_org_role", rename_all = "snake_case")]
pub enum OrgRole {
    Admin,
    Owner,
    Member,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Org {
    id: Uuid,
    name: String,
    is_personal: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct OrgUsers {
    org_id: Uuid,
    user_id: Uuid,
    role: OrgRole,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}
