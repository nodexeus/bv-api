use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTypeProperty {
    name: String,
    label: String,
    default: Option<String>,
    r#type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct NodeType {
    name: String,
    properties: Option<Vec<NodeTypeProperty>>,
}
