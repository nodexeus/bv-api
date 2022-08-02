pub mod auth;
pub mod jwt_token;
pub mod middleware;

pub use jwt_token::*;

#[macro_export]
macro_rules! is_owned_by {
    ($r:expr => $o:expr, using $d:expr) => {{
        match $r.is_owned_by($o, $d).await {
            OwnershipState::Owned => true,
            OwnershipState::NotOwned => false,
        }
    }};

    ($r:expr => $o:expr) => {{
        match $r.is_owned_by($o, ()).await {
            OwnershipState::Owned => true,
            OwnershipState::NotOwned => false,
        }
    }};
}

/// Implement for all objects that shall be used for authorization
pub trait Authorizable {
    fn get_role(&self) -> String;
}

/// Define possible ownership states
#[derive(PartialEq, Eq)]
pub enum OwnershipState {
    Owned,
    NotOwned,
}

/// Implement for all objects that shall be able to test, if it's "owned" (i.e. has a FK constraint
/// in the DB) by given resource
#[axum::async_trait]
pub trait Owned<T, D> {
    async fn is_owned_by(&self, resource: T, db: D) -> OwnershipState
    where
        D: 'static;
}
