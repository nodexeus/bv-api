//! Actual authorization happens here

use casbin::prelude::*;
use std::env;
use std::env::VarError;
use std::sync::{Arc, RwLock};
use thiserror::Error;

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
