use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy_ui::Invitation as GrpcInvitation;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Invitation {
    pub(crate) id: Uuid,
    pub(crate) created_by_id: Uuid,
    pub(crate) created_for_org_id: Uuid,
    pub(crate) invitee_email: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) accepted_at: DateTime<Utc>,
    pub(crate) declined_at: DateTime<Utc>,
}

impl Invitation {
    pub async fn get_by_token(token: String, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as("SELECT * FROM invitations where token = $1")
            .bind(token)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn create(invitation: &GrpcInvitation, db: &PgPool) -> ApiResult<Self> {
        let creator_id = Uuid::from_slice(
            invitation
                .created_by_id
                .as_ref()
                .ok_or_else(|| ApiError::UnexpectedError(anyhow!("Creator ID required")))?
                .as_bytes(),
        )?;
        let org_id = Uuid::from_slice(
            invitation
                .created_for_org_id
                .as_ref()
                .ok_or_else(|| ApiError::UnexpectedError(anyhow!("Org ID required")))?
                .as_bytes(),
        )?;

        sqlx::query_as(
            r#"INSERT INTO invitations
                (created_by_user, created_for_org, invitee_email)
                values 
                ($1,$2,false)
                RETURNING *"#,
        )
        .bind(creator_id)
        .bind(org_id)
        .bind(
            invitation
                .invitee_email
                .as_ref()
                .ok_or_else(|| ApiError::UnexpectedError(anyhow!("Invitee email required")))?,
        )
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }
}
