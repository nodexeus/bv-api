use crate::auth::FindableById;
use crate::errors::{ApiError, Result as ApiResult};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

pub struct CreateNodeKeyFileRequest {
    name: String,
    content: String,
    node_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct NodeKeyFile {
    id: Uuid,
    name: String,
    content: String,
    node_id: Uuid,
}

impl NodeKeyFile {
    pub async fn create(req: CreateNodeKeyFileRequest, db: &PgPool) -> ApiResult<Self> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO node_key_files 
                (name, content, node_id)
            VALUES
                ($1, $2, $3)
            RETURNING *
        "#,
        )
        .bind(req.name)
        .bind(req.content)
        .bind(req.node_id)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }

    pub async fn find_by_node(node_id: Uuid, db: &PgPool) -> ApiResult<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM node_key_files WHERE node_id = $1
        "#,
        )
        .bind(node_id)
        .fetch_all(db)
        .await
        .map_err(ApiError::from)
    }
}

#[tonic::async_trait]
impl FindableById for NodeKeyFile {
    async fn find_by_id(id: Uuid, db: &PgPool) -> ApiResult<Self>
    where
        Self: Sized,
    {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM node_key_files WHERE id = $1
        "#,
        )
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(ApiError::from)
    }
}
