use crate::errors::{ApiError, Result};
use crate::grpc::blockjoy::CommandInfo;
use crate::models::UpdateInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::convert::From;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_host_cmd", rename_all = "snake_case")]
pub enum HostCmd {
    CreateNode,
    RestartNode,
    KillNode,
    ShutdownNode,
    DeleteNode,
    UpdateNode,
    MigrateNode,
    GetNodeVersion,
    GetBVSVersion,
    CreateBVS,
    UpdateBVS,
    RestartBVS,
    RemoveBVS,
    StopBVS,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Command {
    pub id: Uuid,
    pub host_id: Uuid,
    pub cmd: HostCmd,
    pub sub_cmd: Option<String>,
    pub response: Option<String>,
    pub exit_status: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub resource_id: Uuid,
}

impl Command {
    pub async fn find_by_id(id: Uuid, db: &PgPool) -> Result<Self> {
        sqlx::query_as::<_, Self>("SELECT * FROM commands where id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_all_by_host(host_id: Uuid, db: &PgPool) -> Result<Vec<Command>> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM commands where host_id = $1 ORDER BY created_at DESC",
        )
        .bind(host_id)
        .fetch_all(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_pending_by_host(host_id: Uuid, db: &PgPool) -> Result<Vec<Command>> {
        sqlx::query_as::<_, Self>("SELECT * FROM commands where host_id = $1 AND completed_at IS NULL ORDER BY created_at DESC")
            .bind(host_id)
            .fetch_all(db)
            .await.map_err(ApiError::from)
    }

    pub async fn create(host_id: Uuid, command: CommandRequest, db: &PgPool) -> Result<Command> {
        sqlx::query_as::<_, Self>(
            "INSERT INTO commands (host_id, cmd, sub_cmd, resource_id) VALUES ($1, $2, $3, $4) RETURNING *",
        )
        .bind(host_id)
        .bind(command.cmd)
        .bind(command.sub_cmd)
        .bind(command.resource_id)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn update_response(
        id: Uuid,
        response: CommandResponseRequest,
        db: &PgPool,
    ) -> Result<Command> {
        sqlx::query_as::<_, Self>("UPDATE commands SET response = $1, exit_status = $2, completed_at = now() WHERE id = $3 RETURNING *")
            .bind(response.response)
            .bind(response.exit_status)
            .bind(id)
            .fetch_one(db)
            .await.map_err(ApiError::from)
    }

    pub async fn delete(id: Uuid, db: &PgPool) -> Result<u64> {
        let mut tx = db.begin().await?;
        let deleted = sqlx::query("DELETE FROM commands WHERE id = $1")
            .bind(id)
            .execute(&mut tx)
            .await?;

        tx.commit().await?;
        Ok(deleted.rows_affected())
    }
}

#[tonic::async_trait]
impl UpdateInfo<CommandInfo, Command> for Command {
    async fn update_info(info: CommandInfo, db: &sqlx::PgPool) -> Result<Command> {
        let id = Uuid::from(info.id.unwrap());
        let mut tx = db.begin().await?;
        let cmd = sqlx::query_as::<_, Command>(
            r##"UPDATE hosts SET
                         response = COALESCE($1, response),
                         exit_status = COALESCE($2, exit_status),
                WHERE id = $2
                RETURNING *
            "##,
        )
        .bind(info.response)
        .bind(info.exit_code)
        .bind(id)
        .fetch_one(&mut tx)
        .await?;

        tx.commit().await?;

        Ok(cmd)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub cmd: HostCmd,
    pub sub_cmd: Option<String>,
    pub resource_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponseRequest {
    pub response: Option<String>,
    pub exit_status: Option<i32>,
}
