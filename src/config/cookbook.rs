use derive_more::{Deref, FromStr};
use displaydoc::Display;
use serde::Deserialize;
use thiserror::Error;
use tonic::metadata::{errors, AsciiMetadataValue};
use url::Url;

use super::provider::{self, Provider};
use super::Redacted;

const URL_VAR: &str = "COOKBOOK_URL";
const URL_ENTRY: &str = "cookbook.url";
const TOKEN_VAR: &str = "COOKBOOK_TOKEN";
const TOKEN_ENTRY: &str = "cookbook.token";

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to create authorization header: {0}
    AuthHeader(errors::InvalidMetadataValue),
    /// Failed to parse ${URL_ENTRY:?}: {0}
    ParseUrl(provider::Error),
    /// Failed to parse ${TOKEN_ENTRY:?}: {0}
    ParseToken(provider::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub url: Url,
    pub token: Token,
}

impl TryFrom<&Provider> for Config {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        Ok(Config {
            url: provider.read(URL_VAR, URL_ENTRY).map_err(Error::ParseUrl)?,
            token: provider
                .read(TOKEN_VAR, TOKEN_ENTRY)
                .map_err(Error::ParseToken)?,
        })
    }
}

#[derive(Debug, Deref, Deserialize, FromStr)]
#[deref(forward)]
pub struct Token(Redacted<String>);

impl Token {
    pub fn auth_header(&self) -> Result<AsciiMetadataValue, Error> {
        let bearer = format!("Bearer {}", base64::encode(self.as_bytes()));
        bearer.try_into().map_err(Error::AuthHeader)
    }
}
