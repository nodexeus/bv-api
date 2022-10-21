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
mod token;
mod user;
// needs to be brought into namespace like this because of
// name ambiguities with another crate
mod ip_address;
mod node_type;
pub mod validator;

use crate::errors::Result as ApiResult;
pub use blockchain::*;
pub use broadcast::*;
pub use command::*;
pub use host::*;
pub use info::*;
pub use invoice::*;
pub use ip_address::*;
pub use node::*;
pub use node_type::*;
pub use org::*;
pub use payment::*;
pub use reward::*;
pub use token::*;
pub use user::*;

pub const STAKE_QUOTA_DEFAULT: i64 = 5;
pub const FEE_BPS_DEFAULT: i64 = 300;

#[tonic::async_trait]
pub trait UpdateInfo<T, R> {
    async fn update_info(info: T, db: &sqlx::PgPool) -> ApiResult<R>;
}
