pub mod jwt_token;
pub mod middleware;

pub use jwt_token::*;

use crate::errors::Result as ApiResult;
use casbin::prelude::*;
use sqlx::PgPool;
use std::env;
use std::env::VarError;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use uuid::Uuid;

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

#[axum::async_trait]
pub trait FindableById: Send + Sync + 'static {
    async fn find_by_id(id: Uuid, db: &PgPool) -> ApiResult<Self>
    where
        Self: Sized;
}

#[axum::async_trait]
pub trait TokenIdentifyable: Send + Sync + 'static {
    async fn set_token(token_id: Uuid, resource_id: Uuid, db: &PgPool) -> ApiResult<Self>
    where
        Self: Sized;
}

pub type AuthorizationResult = std::result::Result<AuthorizationState, AuthorizationError>;
pub type InitResult = std::result::Result<Authorization, AuthorizationError>;

/// Restrict possible authorization results
pub enum AuthorizationState {
    Authorized,
    Denied,
}

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Generic Casbin Error: `{0:?}`")]
    CasbinError(#[from] casbin::error::Error),

    #[error("Insufficient privileges error: `{0:?}`")]
    InsufficientPriviliges(#[from] casbin::error::PolicyError),

    #[error("Malformed request error: `{0:?}`")]
    MalformedRequest(#[from] casbin::error::RequestError),

    #[error("Malformed or missing env vars error: `{0:?}`")]
    MissingEnv(#[from] VarError),

    #[error("Enforcer locked")]
    LockedError,
}

/// Holds all data needed for authorization
#[derive(Debug, Clone)]
pub struct AuthorizationData {
    pub(crate) subject: String,
    pub(crate) object: String,
    pub(crate) action: String,
}

impl AuthorizationData {
    pub fn new(subject: String, object: String, action: String) -> Self {
        Self {
            subject,
            object,
            action,
        }
    }
}

/// Convert auth data into 3-tuple needed by Enforcer::enforce
impl From<AuthorizationData> for (String, String, String) {
    fn from(auth_data: AuthorizationData) -> Self {
        (auth_data.subject, auth_data.object, auth_data.action)
    }
}

/// Authorization namespace
/// Implements a simple ACL based authorization solution.
/// Users must belong to a group, the authorization will be tested
/// against that group
#[derive(Clone)]
pub struct Authorization {
    // Enforcer is not thread safe, need to protect it with RwLock
    // @see https://github.com/casbin/casbin-rs/blob/master/README.md
    enforcer: Arc<RwLock<Enforcer>>,
}

impl Authorization {
    /// Creates a new Authorization object using configuration as defined in
    /// env vars ***CASBIN_MODEL*** and ***CASBIN_POLICIES***
    pub async fn new() -> InitResult {
        let model = env::var("CASBIN_MODEL").expect("Couldn't load auth model");
        let policies = env::var("CASBIN_POLICIES").expect("Couldn't load auth policies");

        match Enforcer::new(
            Authorization::string_to_static_str(model),
            Authorization::string_to_static_str(policies),
        )
        .await
        {
            Ok(enforcer) => Ok(Self {
                enforcer: Arc::new(RwLock::new(enforcer)),
            }),
            Err(e) => Err(AuthorizationError::CasbinError(e)),
        }
    }

    /// Test if subject is allowed to perform given action on object
    ///
    /// Param: ***subject*** The user object. _NOTE_: Must provide a role!
    ///
    /// Param: ***object*** Either the HTTP path or the gRPC method
    ///
    /// Param: ***action*** The intended action (CRUD)
    pub fn try_authorized(&self, auth_data: AuthorizationData) -> AuthorizationResult {
        match self.enforcer.try_read() {
            Ok(enforcer) => match enforcer.enforce::<(String, String, String)>(auth_data.into()) {
                Ok(authorized) => {
                    if authorized {
                        Ok(AuthorizationState::Authorized)
                    } else {
                        Ok(AuthorizationState::Denied)
                    }
                }
                Err(e) => Err(AuthorizationError::CasbinError(e)),
            },
            Err(_) => Err(AuthorizationError::LockedError),
        }
    }

    /// Helper for converting a String to &'static str
    fn string_to_static_str(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }
}
