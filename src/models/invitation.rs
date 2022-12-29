use crate::auth::FindableById;
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

#[tonic::async_trait]
impl FindableById for Invitation {
    async fn find_by_id(id: Uuid, db: &PgPool) -> ApiResult<Self>
    where
        Self: Sized,
    {
        sqlx::query_as("select * from invitations where id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }
}

impl Invitation {
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

    pub async fn pending(org_id: Uuid, db: &PgPool) -> ApiResult<Vec<Self>> {
        sqlx::query_as(
            r#"select * from invitations 
                    where created_for_org_id = $1 and accepted_at is null and declined_at is null"#,
        )
        .bind(org_id)
        .fetch_all(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn received(email: String, db: &PgPool) -> ApiResult<Vec<Self>> {
        sqlx::query_as(
            r#"select * from invitations 
                    where invitee_email = $1 and accepted_at is null and declined_at is null"#,
        )
        .bind(email)
        .fetch_all(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn accept(id: Uuid, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as("update invitations set accepted_at = now() where id = $1 returning *")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn decline(id: Uuid, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as("update invitations set declined_at = now() where id = $1 returning *")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn revoke(id: Uuid, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as("delete from invitations where id = $1 returning *")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }
}
