use crate::errors::{ApiError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_org_role", rename_all = "snake_case")]
pub enum OrgRole {
    Admin,
    Owner,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub is_personal: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Org {
    pub async fn find_all_by_user_id(id: &Uuid, pool: &PgPool) -> Result<Vec<Org>> {
        sqlx::query_as::<_, Self>(
            r##"
            SELECT 
                orgs.* 
            FROM 
                orgs 
            INNER JOIN 
                orgs_users 
            ON 
                orgs.id = orgs_users.org_id 
            WHERE 
                orgs_users.user_id = $1
            ORDER BY
                lower(orgs.name)
            "##,
        )
        .bind(&id)
        .fetch_all(pool)
        .await
        .map_err(ApiError::from)
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct OrgUser {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: OrgRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
