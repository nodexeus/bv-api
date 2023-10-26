use derive_more::FromStr;
use displaydoc::Display;
use serde::Deserialize;
use thiserror::Error;

use super::provider::{self, Provider};
use super::Redacted;

const CHARGEBEE_SECRET_VAR: &str = "CHARGEBEE_SECRET";
const CHARGEBEE_SECRET_ENTRY: &str = "chargebee.secret";

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to find {CHARGEBEE_SECRET_ENTRY:?}: {0}
    SecretMissing(provider::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub secret: Secret,
}

#[derive(Debug, FromStr, Deserialize)]
pub struct Secret(Redacted<String>);

impl PartialEq<String> for Secret {
    fn eq(&self, other: &String) -> bool {
        self.0.eq(other)
    }
}

impl TryFrom<&Provider> for Config {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        let secret = provider
            .read(CHARGEBEE_SECRET_VAR, CHARGEBEE_SECRET_ENTRY)
            .map_err(Error::SecretMissing)?;

        Ok(Config { secret })
    }
}
