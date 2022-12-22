use derive_getters::Getters;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgHasArrayType;

use crate::models::NodeTypeKey;
use crate::{errors::ApiError, grpc::helpers::required};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Getters)]
pub struct NodePropertyValue {
    name: String,
    label: String,
    description: String,
    ui_type: String,
    disabled: bool,
    required: bool,
    value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeProperties {
    id: i32,
    properties: Option<Vec<NodePropertyValue>>,
}

impl PgHasArrayType for NodeProperties {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("JSONB[]")
    }
}

impl TryFrom<String> for NodeProperties {
    type Error = ApiError;

    fn try_from(json: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&json).map_err(Into::into)
    }
}

impl NodePropertyValue {
    pub fn to_json(&self) -> Result<String, ApiError> {
        let json_str = format!(
            "{{ \"name\": \"{}\", \"ui_type\": \"{}\", \"default\": \"{}\", \"disabled:\": \"{}\", \"required\": \"{}\" }}",
            self.name,
            self.ui_type,
            self.default.as_ref().ok_or_else(required("default"))?,
            self.disabled,
            self.required,
        );
        Ok(json_str)
    }
}

impl NodeProperties {
    pub fn to_json(&self) -> Result<String, ApiError> {
        let empty = Vec::new();
        let props: Result<String, ApiError> = self
            .properties
            .as_ref()
            .unwrap_or(&empty)
            .iter()
            .map(|p| p.to_json())
            .collect();
        // TODO: Replace this hack
        let props = props?.replace("}{", "},{");
        let json_str = format!("{{ \"id\": {}, \"properties\": [{}] }}", self.id, props);
        Ok(json_str)
    }

    pub fn special_type(id: NodeTypeKey) -> Self {
        Self {
            id: id.into(),
            properties: Some(vec![]),
        }
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }

    pub fn get_properties(&self) -> Option<&[NodePropertyValue]> {
        self.properties.as_deref()
    }
}
