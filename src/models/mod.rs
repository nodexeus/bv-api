//! This module contains the code related to database tables. Each table is represented by one or
//! more models, which are structs that have a field for the columns of the queries that they
//! interact with. There may exist multiple models for a given table, for example models that are
//! used for updating rows often do not contain all of the columns, whereas models that are used
//! for selecting usually do.

/// This is the name of the environment variable that is used to retrieve the database url. It is
/// exported as a constant to prevent typos.
pub const DATABASE_URL: &str = "DATABASE_URL";

mod blacklist_token;
mod blockchain;
mod command;
mod host;
mod invitation;
mod ip_address;
mod node;
mod node_key_file;
mod node_log;
mod node_scheduler;
mod node_type;
mod org;
pub mod schema;
mod user;

use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};
use diesel_async::scoped_futures::{ScopedBoxFuture, ScopedFutureExt};
use diesel_async::{AsyncConnection, AsyncPgConnection};
use std::cmp;

pub use blacklist_token::*;
pub use blockchain::*;
pub use command::*;
pub use host::*;
pub use invitation::*;
pub use ip_address::*;
pub use node::*;
pub use node_key_file::*;
pub use node_log::*;
pub use node_scheduler::*;
pub use node_type::*;
pub use org::*;
pub use user::*;

diesel::sql_function!(fn lower(x: diesel::sql_types::Text) -> diesel::sql_types::Text);
diesel::sql_function!(fn string_to_array(version: diesel::sql_types::Text, split: diesel::sql_types::Text) -> diesel::sql_types::Array<diesel::sql_types::Text>);

/// Our wrapper type for a ref counted postgres pool. We use a wrapper type because the functions
/// `begin` and `conn` return a `Result<_, sqlx::Error>`. From our controllers we must return a
/// `Result<_, tonic::Status>`, but there is no `impl From<sqlx::Error> for tonic::Status`, nor can
/// we create one. This means that we cannot use the `?`-operator in our controllers when we
/// retrieve a connection or when we begin a transaction. Since we do this in virtually every
/// controller, it is worth creating this wrapper type that also has the functions `begin` and
/// `conn`, but altered such that they return a `Result<_, error::Error>`. With this Err-variant
/// we _can_ use the `?`-operator in our controllers.
#[derive(Debug, Clone)]
pub struct DbPool {
    pool: Pool<diesel_async::AsyncPgConnection>,
}

impl DbPool {
    pub fn new(pool: Pool<diesel_async::AsyncPgConnection>) -> Self {
        Self { pool }
    }

    pub async fn trx<'a, F, T>(&self, f: F) -> Result<T, tonic::Status>
    where
        F: for<'r> FnOnce(
                &'r mut diesel_async::AsyncPgConnection,
            ) -> ScopedBoxFuture<'a, 'r, crate::Result<T>>
            + Send
            + 'a,
        T: Send + 'a,
    {
        let res = self
            .pool
            .get()
            .await
            .map_err(crate::Error::from)?
            .transaction(|c| f(c).scope_boxed())
            .await?;
        Ok(res)
    }

    /// Returns a database connection that is not in a transition state. Use this for read-only
    /// endpoints.
    pub async fn conn(&self) -> crate::Result<PooledConnection<'_, AsyncPgConnection>> {
        Ok(self.pool.get().await?)
    }

    pub fn is_closed(&self) -> bool {
        self.pool.state().connections == 0
    }
}

fn semver_cmp(s1: &str, s2: &str) -> Option<cmp::Ordering> {
    s1.split('.')
        .zip(s2.split('.'))
        .filter_map(|(s1, s2)| cmp_str(s1, s2))
        .next()
}

fn cmp_str(s1: &str, s2: &str) -> Option<cmp::Ordering> {
    let take_nums = |s: &str| s.chars().take_while(|c| c.is_numeric()).collect::<String>();
    let parse_nums = |s: String| s.parse().ok();
    parse_nums(take_nums(s1))
        .and_then(|n1: i64| parse_nums(take_nums(s2)).map(move |n2| (n1, n2)))
        .map(|(n1, n2)| n1.cmp(&n2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmp::Ordering::*;

    #[test]
    fn test_semver_cmp() {
        assert_eq!(semver_cmp("1.2.3", "1.2.3"), Some(Equal));
        assert_eq!(semver_cmp("3.2.3", "1.2.3"), Some(Greater));
        assert_eq!(semver_cmp("1.2.3", "3.2.3"), Some(Less));
        assert_eq!(semver_cmp("1.2.3-beta", "1.2.3"), Some(Equal));
        assert_eq!(semver_cmp("1.2.3-beta3", "1.2.3.4"), Some(Equal));
        assert_eq!(semver_cmp("1.2-beta.3", "1.2"), Some(Equal));
    }

    #[test]
    fn test_cmp_str() {
        assert_eq!(cmp_str("1", "1"), Some(Equal));
        assert_eq!(cmp_str("1", "2"), Some(Less));
        assert_eq!(cmp_str("3", "2"), Some(Greater));
        assert_eq!(cmp_str("3-beta", "2"), Some(Greater));
        assert_eq!(cmp_str("3", "2-beta"), Some(Greater));
    }
}
