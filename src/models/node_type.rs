use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct NodeTypeProperty {
    name: String,
    label: String,
    default: Option<String>,
    r#type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct NodeType {
    id: i32,
    properties: Option<Vec<NodeTypeProperty>>,
}

impl NodeTypeProperty {
    pub fn to_json(&self) -> String {
        format!(
            "{{ \"name\": \"{}\", \"label\": \"{}\", \"default\": \"{}\", \"type:\": \"{}\" }}",
            self.name,
            self.label,
            self.default.unwrap(),
            self.r#type
        )
    }
}

impl NodeType {
    pub fn to_json(&self) -> String {
        format!(
            "{{ \"id\": {}, \"properties\": [{}] }}",
            self.id,
            // self.properties.unwrap().iter().map(|p| { p.to_json() }).collect().join(',')
            self.properties
                .ok_or("")
                .unwrap()
                .iter()
                .map(|p| { p.to_json() })
                .collect::<String>()
        )
    }
}
