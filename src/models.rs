use crate::schema::{hosts, rewards, users, validators};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Insertable)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub hashword: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Insertable)]
pub struct Host {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewHost {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Insertable)]
pub struct Validator {
    pub id: Uuid,
    pub host_id: Uuid,
    pub user_id: Uuid,
    pub address: String,
    pub swarm: String,
    pub is_staked: bool,
    pub is_consensus: bool,
    pub is_enabled: bool,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Insertable)]
pub struct Reward {
    pub id: Uuid,
    pub block: i64,
    pub transaction_hash: String,
    pub time: i64,
    pub validator_id: Uuid,
    pub account: String,
    pub amount: i64,
}
