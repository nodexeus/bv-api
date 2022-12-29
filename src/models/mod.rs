mod blockchain;
mod broadcast;
mod command;
mod host;
mod info;
mod invoice;
mod node;
mod org;
mod payment;
mod reward;
mod user;
// needs to be brought into namespace like this because of
// name ambiguities with another crate
mod blacklist_token;
mod invitation;
mod ip_address;
mod node_key_file;
mod node_property_value;
mod node_type;
pub mod validator;

use crate::errors::Result as ApiResult;
pub use blacklist_token::*;
pub use blockchain::*;
pub use broadcast::*;
pub use command::*;
pub use host::*;
pub use info::*;
pub use invitation::*;
pub use invoice::*;
pub use ip_address::*;
pub use node::*;
pub use node_key_file::*;
pub use node_property_value::*;
pub use node_type::*;
pub use org::*;
pub use payment::*;
pub use reward::*;
pub use user::*;

pub const STAKE_QUOTA_DEFAULT: i64 = 5;
pub const FEE_BPS_DEFAULT: i64 = 300;

type PgQuery<'a> = sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments>;

#[tonic::async_trait]
pub trait UpdateInfo<T, R> {
    async fn update_info(info: T, db: &sqlx::PgPool) -> ApiResult<R>;
}
