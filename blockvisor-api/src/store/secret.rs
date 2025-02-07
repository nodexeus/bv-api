use std::sync::Arc;

use derive_more::{Deref, Display, Into};
use displaydoc::Display as DisplayDoc;
use thiserror::Error;

use crate::auth::resource::Resource;
use crate::config::secret::Config;
use crate::grpc::Status;
use crate::util::LOWER_KEBAB_CASE;

#[derive(Debug, DisplayDoc, Error)]
pub enum Error {
    /// SecretKey is not lower-kebab-case: {0}
    SecretKeyChars(String),
    /// SecretKey length `{0}` must be at least 6 characters.
    SecretKeyLen(usize),
    /// Secret functionality is currently unimplemented.
    Unimplemented,
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        use Error::*;
        match err {
            SecretKeyChars(_) | SecretKeyLen(_) => Status::invalid_argument("secret_key"),
            Unimplemented => Status::internal("Unimplemented."),
        }
    }
}

#[derive(Clone, Debug, Display, PartialEq, Eq, Deref, Into)]
pub struct SecretKey(String);

impl SecretKey {
    pub fn new(key: String) -> Result<Self, Error> {
        if key.len() < 6 {
            Err(Error::SecretKeyLen(key.len()))
        } else if !key.chars().all(|c| LOWER_KEBAB_CASE.contains(c)) {
            Err(Error::SecretKeyChars(key))
        } else {
            Ok(SecretKey(key))
        }
    }
}

pub struct Secret {
    config: Arc<Config>,
}

impl Secret {
    pub const fn new(config: Arc<Config>) -> Self {
        Secret { config }
    }

    pub fn get(&self, _resource: Resource, key: &SecretKey) -> Result<Vec<u8>, Error> {
        match key.0.as_ref() {
            "cloudflare-cert-key" => Ok(self.config.cloudflare_cert_key.clone().into_bytes()),
            "grafana-prometheus-key" => Ok(self.config.grafana_prometheus_key.clone().into_bytes()),
            "grafana-basic-auth-key" => Ok(self.config.grafana_basic_auth_key.clone().into_bytes()),
            _ => Err(Error::Unimplemented),
        }
    }

    pub const fn put(
        &self,
        _resource: Resource,
        _key: &SecretKey,
        _value: &[u8],
    ) -> Result<(), Error> {
        Err(Error::Unimplemented)
    }
}
