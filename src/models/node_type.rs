use serde::{Deserialize, Serialize};
use sqlx::postgres::PgHasArrayType;

pub enum NodeTypeKey {
    Unknown = 0,
    Miner = 1,
    Etl = 2,
    Validator = 3,
    Api = 4,
    Oracle = 5,
    Relay = 6,
    Execution = 7,
    Beacon = 8,
    MevBoost = 9,
    Node = 10,
    FullNode = 11,
    LightNode = 12,
}

impl From<NodeTypeKey> for i32 {
    fn from(id: NodeTypeKey) -> Self {
        match id {
            NodeTypeKey::Unknown => 0,
            NodeTypeKey::Miner => 1,
            NodeTypeKey::Etl => 2,
            NodeTypeKey::Validator => 3,
            NodeTypeKey::Api => 4,
            NodeTypeKey::Oracle => 5,
            NodeTypeKey::Relay => 6,
            NodeTypeKey::Execution => 7,
            NodeTypeKey::Beacon => 8,
            NodeTypeKey::MevBoost => 9,
            NodeTypeKey::Node => 10,
            NodeTypeKey::FullNode => 11,
            NodeTypeKey::LightNode => 12,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTypeProperty {
    name: String,
    label: String,
    default: Option<String>,
    r#type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeType {
    id: i32,
    properties: Option<Vec<NodeTypeProperty>>,
}

impl PgHasArrayType for NodeType {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("JSONB[]")
    }
}

impl From<String> for NodeType {
    fn from(json: String) -> Self {
        serde_json::from_str::<Self>(json.as_str()).unwrap()
    }
}

impl NodeTypeProperty {
    pub fn to_json(&self) -> String {
        format!(
            "{{ \"name\": \"{}\", \"label\": \"{}\", \"default\": \"{}\", \"type:\": \"{}\" }}",
            self.name.clone(),
            self.label.clone(),
            self.default.clone().unwrap(),
            self.r#type.clone()
        )
    }
}

impl NodeType {
    pub fn to_json(&self) -> String {
        format!(
            "{{ \"id\": {}, \"properties\": [{}] }}",
            self.id,
            self.properties
                .clone()
                .ok_or("")
                .unwrap()
                .iter()
                .map(|p| { p.to_json() })
                .collect::<String>()
        )
    }

    pub fn special_type(id: NodeTypeKey) -> Self {
        Self {
            id: id.into(),
            properties: Some(vec![]),
        }
    }
}
