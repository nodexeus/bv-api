use displaydoc::Display;
use serde::Deserialize;
use thiserror::Error;

use super::provider::{self, Provider};

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
    pub secret: String,
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
