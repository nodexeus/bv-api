//! This module contains the code related to database tables. Each table is represented by one or
//! more models, which are structs that have a field for the columns of the queries that they
//! interact with. There may exist multiple models for a given table, for example models that are
//! used for updating rows often do not contain all of the columns, whereas models that are used
//! for selecting usually do.

pub mod api_key;
pub use api_key::ApiKey;

pub mod blockchain;
pub use blockchain::{Blockchain, BlockchainId};

pub mod command;
pub use command::{Command, CommandId, CommandType};

pub mod host;
pub use host::{Host, HostType};

pub mod invitation;
pub use invitation::{Invitation, InvitationId};

pub mod ip_address;
pub use ip_address::IpAddress;

pub mod node;
pub use node::{Node, NodeType};

pub mod org;
pub use org::Org;

pub mod paginate;
pub use paginate::Paginate;

pub mod rbac;

pub mod region;
pub use region::{Region, RegionId};

#[allow(clippy::wildcard_imports)]
pub mod schema;

pub mod subscription;
pub use subscription::{Subscription, SubscriptionId};

pub mod token;
pub use token::Token;

pub mod user;
pub use user::User;

use diesel::{sql_function, sql_types};

sql_function!(fn lower(x: sql_types::Text) -> sql_types::Text);
sql_function!(fn string_to_array(version: sql_types::Text, split: sql_types::Text) -> sql_types::Array<diesel::sql_types::Text>);
sql_function!(fn text(version: sql_types::Uuid) -> sql_types::Text);
