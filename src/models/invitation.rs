use crate::auth::FindableById;
use crate::errors::{ApiError, Result as ApiResult};
use crate::grpc::blockjoy_ui::Invitation as GrpcInvitation;
use crate::models::{Org, User};
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use derive_getters::Getters;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow, Getters)]
pub struct Invitation {
    pub(crate) id: Uuid,
    pub(crate) created_by_user: Uuid,
    pub(crate) created_by_user_name: String,
    pub(crate) created_for_org: Uuid,
    pub(crate) created_for_org_name: String,
    pub(crate) invitee_email: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) accepted_at: Option<DateTime<Utc>>,
    pub(crate) declined_at: Option<DateTime<Utc>>,
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
    pub async fn find_by_creator_for_email(
        creator_id: Uuid,
        invitee_email: String,
        db: &PgPool,
    ) -> ApiResult<Self> {
        sqlx::query_as(
            r#"select * from invitations 
                    where created_by_user = $1 and invitee_email = $2 and accepted_at is null and declined_at is null"#,
        )
            .bind(creator_id)
            .bind(invitee_email)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn create(invitation: &GrpcInvitation, db: &PgPool) -> ApiResult<Self> {
        let creator_id = Uuid::from_str(
            invitation
                .created_by_id
                .as_ref()
                .unwrap_or(&String::new())
                .as_str(),
        )
        .map_err(|e| ApiError::UnexpectedError(anyhow!("Creator ID required: {e}")))?;
        let creator = User::find_by_id(creator_id, db).await?;
        let org_id = Uuid::from_str(
            invitation
                .created_for_org_id
                .as_ref()
                .unwrap_or(&String::new())
                .as_str(),
        )
        .map_err(|e| ApiError::UnexpectedError(anyhow!("Org ID required: {e}")))?;
        let for_org = Org::find_by_id(org_id, db).await?;
        let email = invitation
            .invitee_email
            .as_ref()
            .ok_or_else(|| ApiError::UnexpectedError(anyhow!("Invitee email required")))?;

        sqlx::query_as(
            r#"INSERT INTO invitations
                (created_by_user, created_for_org, invitee_email, created_by_user_name, created_for_org_name)
                values 
                ($1,$2,$3,$4,$5)
                RETURNING *"#,
        )
        .bind(creator_id)
        .bind(org_id)
        .bind(email)
        .bind(format!("{} {} ({})", creator.first_name, creator.last_name, creator.email))
        .bind(for_org.name)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn pending(org_id: Uuid, db: &PgPool) -> ApiResult<Vec<Self>> {
        sqlx::query_as(
            r#"select * from invitations 
                    where created_for_org = $1 and accepted_at is null and declined_at is null"#,
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
