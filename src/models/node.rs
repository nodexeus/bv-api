use super::Validator;
use crate::errors::{ApiError, Result};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_node_status", rename_all = "snake_case")]
pub enum NodeType {
    Api,
    Node,
    Oracle,
    Relay,
    Validator,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "enum_node_status", rename_all = "snake_case")]
pub enum NodeStatus {
    Available,
    Broadcasting,
    Cancelled,
    Consensus,
    Creating,
    Delegating,
    Delinquent,
    Disabled,
    Earning,
    Electing,
    Elected,
    Exporting,
    Ingesting,
    Installing,
    Migrating,
    Mining,
    Minting,
    Processing,
    Relaying,
    Removed,
    Removing,
    Running,
    Snapshoting,
    Staked,
    Staking,
    Started,
    Starting,
    Stopped,
    Stopping,
    Synced,
    Syncing,
    Upgrading,
    Validating,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Node {
    id: Uuid,
    org_id: Uuid,
    host_id: Uuid,
    name: Option<String>,
    groups: Option<String>,
    version: Option<String>,
    ip_addr: Option<String>,
    chain_type: String,
    node_type: NodeType,
    address: Option<String>,
    wallet_address: Option<String>,
    block_height: Option<i64>,
    node_data: Option<serde_json::Value>,
    created_at: Uuid,
    updated_at: Uuid,
    status: NodeStatus,
    is_online: bool,
}
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct NodeGroup {
    id: Uuid,
    name: String,
    node_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nodes: Option<Vec<Validator>>,
}

impl NodeGroup {
    pub async fn find_all(pool: &PgPool) -> Result<Vec<NodeGroup>> {
        sqlx::query("SELECT user_id as id, users.email as name, count(*) as node_count, null as nodes FROM validators INNER JOIN users on users.id = validators.user_id  GROUP BY user_id, users.email ORDER BY users.email DESC")
            .map(Self::from)
            .fetch_all(pool)
            .await
            .map_err(ApiError::from)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<NodeGroup> {
        let validators = Validator::find_all_by_user(id, pool).await?;
        let name = validators.first().unwrap().name.clone();
        Ok(NodeGroup {
            id,
            name,
            node_count: validators.len() as i64,
            nodes: Some(validators),
        })
    }
}

impl From<PgRow> for NodeGroup {
    fn from(row: PgRow) -> Self {
        NodeGroup {
            id: row
                .try_get("id")
                .expect("Couldn't try_get id for node_group."),
            name: row
                .try_get("name")
                .expect("Couldn't try_get name node_group."),
            node_count: row
                .try_get("node_count")
                .expect("Couldn't try_get node_count node_group."),
            nodes: None,
        }
    }
}
