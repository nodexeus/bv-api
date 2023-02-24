use serde::Deserialize;

#[derive(Deserialize)]
pub struct MqttAuthRequest {
    pub username: String,
}

#[derive(Deserialize, Eq, PartialEq)]
pub enum MqttOperationType {
    Publish,
    Subscribe,
}

#[derive(Deserialize)]
pub struct MqttAclRequest {
    pub operation: MqttOperationType,
    pub username: String,
    pub topic: String,
}
