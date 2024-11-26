//! This module contains models for interacting with database tables.

use diesel::{deserialize, expression, pg, serialize, sql_types};

pub mod address;
pub use address::{Address, AddressId};

pub mod api_key;
pub use api_key::ApiKey;

pub mod command;
pub use command::{Command, CommandId, CommandType};

pub mod host;
pub use host::Host;

pub mod image;
pub use image::{Image, ImageId};

pub mod invitation;
pub use invitation::{Invitation, InvitationId};

pub mod ip_address;
pub use ip_address::IpAddress;

pub mod node;
pub use node::Node;

pub mod org;
pub use org::Org;

pub mod paginate;
pub use paginate::Paginate;

pub mod rbac;

pub mod region;
pub use region::{Region, RegionId};

#[allow(clippy::wildcard_imports)]
pub mod schema;

pub mod protocol;
pub use protocol::{Protocol, ProtocolId, ProtocolVersion, VersionId};

pub mod token;
pub use token::Token;

pub mod user;
pub use user::User;

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    expression::AsExpression,
    deserialize::FromSqlRow,
)]
#[diesel(sql_type = sql_types::Jsonb)]
pub struct Amount {
    pub amount: i64,
    pub currency: Currency,
    pub period: Period,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Currency {
    Usd,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Monthly,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
enum AmountError {
    /// Failed to parse cost `{1}`: {0}
    Parse(serde_json::Error, serde_json::Value),
}

impl deserialize::FromSql<sql_types::Jsonb, pg::Pg> for Amount {
    fn from_sql(value: pg::PgValue<'_>) -> deserialize::Result<Self> {
        let value: serde_json::Value =
            deserialize::FromSql::<sql_types::Jsonb, pg::Pg>::from_sql(value)?;
        Ok(serde_json::from_value(value.clone()).map_err(|e| AmountError::Parse(e, value))?)
    }
}

impl serialize::ToSql<sql_types::Jsonb, pg::Pg> for Amount {
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, pg::Pg>) -> serialize::Result {
        let value = serde_json::to_value(self)?;
        <serde_json::Value as serialize::ToSql<sql_types::Jsonb, pg::Pg>>::to_sql(
            &value,
            &mut out.reborrow(),
        )
    }
}
