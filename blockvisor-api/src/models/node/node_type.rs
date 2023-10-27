use std::fmt;
use std::str::FromStr;

use derive_more::{AsRef, Deref, Display, From, Into};
use diesel_derive_enum::DbEnum;
use diesel_derive_newtype::DieselNewType;
use displaydoc::Display as DisplayDoc;
use semver::Version;
use thiserror::Error;
use tonic::Status;

use crate::grpc::api;
use crate::models::schema::sql_types;

#[derive(Debug, DisplayDoc, Error)]
pub enum Error {
    /// Failed to parse semantic Version: {0}
    ParseVersion(semver::Error),
    /// Unknown NodeType: {0}
    UnknownNodeType(String),
    /// Unknown NodeType value: {0}
    UnknownNodeTypeValue(i32),
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            UnknownNodeType(_) | UnknownNodeTypeValue(_) => Status::internal("Internal error."),
            ParseVersion(_) => Status::invalid_argument("version"),
        }
    }
}

#[derive(Clone, Debug, Display, DieselNewType, AsRef, Deref, From, Into)]
pub struct NodeNetwork(String);

#[derive(Clone, Debug, Display, DieselNewType, AsRef, Deref, From, Into)]
pub struct NodeVersion(String);

impl NodeVersion {
    pub fn new(version: &str) -> Result<Self, Error> {
        version
            .parse::<Version>()
            .map(|version| Self(version.to_string().to_lowercase()))
            .map_err(Error::ParseVersion)
    }

    pub fn semver(&self) -> Result<Version, Error> {
        self.0.parse().map_err(Error::ParseVersion)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, DbEnum)]
#[ExistingTypePath = "sql_types::EnumNodeType"]
pub enum NodeType {
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

impl From<api::NodeType> for NodeType {
    fn from(api: api::NodeType) -> Self {
        match api {
            api::NodeType::Unspecified => NodeType::Unknown,
            api::NodeType::Miner => NodeType::Miner,
            api::NodeType::Etl => NodeType::Etl,
            api::NodeType::Validator => NodeType::Validator,
            api::NodeType::Api => NodeType::Api,
            api::NodeType::Oracle => NodeType::Oracle,
            api::NodeType::Relay => NodeType::Relay,
            api::NodeType::Execution => NodeType::Execution,
            api::NodeType::Beacon => NodeType::Beacon,
            api::NodeType::Mevboost => NodeType::MevBoost,
            api::NodeType::Node => NodeType::Node,
            api::NodeType::Fullnode => NodeType::FullNode,
            api::NodeType::Lightnode => NodeType::LightNode,
        }
    }
}

impl From<NodeType> for api::NodeType {
    fn from(ty: NodeType) -> Self {
        match ty {
            NodeType::Unknown => api::NodeType::Unspecified,
            NodeType::Miner => api::NodeType::Miner,
            NodeType::Etl => api::NodeType::Etl,
            NodeType::Validator => api::NodeType::Validator,
            NodeType::Api => api::NodeType::Api,
            NodeType::Oracle => api::NodeType::Oracle,
            NodeType::Relay => api::NodeType::Relay,
            NodeType::Execution => api::NodeType::Execution,
            NodeType::Beacon => api::NodeType::Beacon,
            NodeType::MevBoost => api::NodeType::Mevboost,
            NodeType::Node => api::NodeType::Node,
            NodeType::FullNode => api::NodeType::Fullnode,
            NodeType::LightNode => api::NodeType::Lightnode,
        }
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "Unknown",
            Self::Miner => "Miner",
            Self::Etl => "ETL",
            Self::Validator => "Validator",
            Self::Api => "API",
            Self::Oracle => "Oracle",
            Self::Relay => "Relay",
            Self::Execution => "Execution",
            Self::Beacon => "Beacon",
            Self::MevBoost => "MEVBoost",
            Self::Node => "Node",
            Self::FullNode => "FullNode",
            Self::LightNode => "LightNode",
        };
        write!(f, "{s}")
    }
}

impl FromStr for NodeType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unknown" => Ok(Self::Unknown),
            "miner" => Ok(Self::Miner),
            "etl" => Ok(Self::Etl),
            "validator" => Ok(Self::Validator),
            "api" => Ok(Self::Api),
            "oracle" => Ok(Self::Oracle),
            "relay" => Ok(Self::Relay),
            "execution" => Ok(Self::Execution),
            "beacon" => Ok(Self::Beacon),
            "mevboost" => Ok(Self::MevBoost),
            "node" => Ok(Self::Node),
            "fullnode" => Ok(Self::FullNode),
            "lightnode" => Ok(Self::LightNode),
            _ => Err(Error::UnknownNodeType(s.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_valid_string_for_value() {
        assert_eq!(NodeType::Unknown.to_string(), "Unknown");
        assert_eq!(NodeType::Miner.to_string(), "Miner");
        assert_eq!(NodeType::Etl.to_string(), "ETL");
        assert_eq!(NodeType::Validator.to_string(), "Validator");
        assert_eq!(NodeType::Api.to_string(), "API");
        assert_eq!(NodeType::Oracle.to_string(), "Oracle");
        assert_eq!(NodeType::Relay.to_string(), "Relay");
        assert_eq!(NodeType::Execution.to_string(), "Execution");
        assert_eq!(NodeType::Beacon.to_string(), "Beacon");
        assert_eq!(NodeType::MevBoost.to_string(), "MEVBoost");
        assert_eq!(NodeType::Node.to_string(), "Node");
        assert_eq!(NodeType::FullNode.to_string(), "FullNode");
        assert_eq!(NodeType::LightNode.to_string(), "LightNode");
    }
}
