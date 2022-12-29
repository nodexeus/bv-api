use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy_ui::Invitation as GrpcInvitation;
use crate::grpc::helpers::required;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Invitation {
    pub(crate) token: String,
    pub(crate) created_by_id: Uuid,
    pub(crate) created_for_org_id: Uuid,
    pub(crate) invitee_email: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) accepted_at: DateTime<Utc>,
    pub(crate) declined_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

impl Invitation {
    pub async fn get_by_token(token: String, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as("SELECT * FROM invitations where token = $1 and expires_at > now()")
            .bind(token)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn create(invitation: &GrpcInvitation, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as(
            r#"INSERT INTO invitations
                (token, created_by_user, created_for_org, invitee_email, expires_at) 
                values 
                ($1,$2,false)
                RETURNING *"#,
        )
        .bind(token)
        .bind(invitation.created_by_id.into())
        .bind(invitation.created_for_org_id.into())
        .bind(invitation.invitee_email.into())
        .bind(expiration)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }
}
