use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
pub struct IpAddress {
    id: Uuid,
    ip: IpAddr,
    host_provision_id: Option<String>,
    host_id: Option<Uuid>,
    is_assigned: bool,
}
