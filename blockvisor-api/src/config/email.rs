use derive_more::{Deref, FromStr};
use displaydoc::Display;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use super::provider::{self, Provider};
use super::Redacted;

const TEMPLATE_DIR_VAR: &str = "EMAIL_TEMPLATE_DIR";
const TEMPLATE_DIR_ENTRY: &str = "email.template_dir";
const SENDGRID_API_KEY_VAR: &str = "SENDGRID_API_KEY";
const SENDGRID_API_KEY_ENTRY: &str = "email.sendgrid_api_key";
const UI_BASE_URL_VAR: &str = "UI_BASE_URL";
const UI_BASE_URL_ENTRY: &str = "email.ui_base_url";

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to parse {SENDGRID_API_KEY_ENTRY:?}: {0}
    ParseSendgridApiKey(provider::Error),
    /// Failed to parse {UI_BASE_URL_ENTRY:?}: {0}
    ParseUiBaseUrl(provider::Error),
}

#[derive(Debug, Default, Deref, Deserialize, FromStr)]
#[deref(forward)]
pub struct SendgridApiKey(Redacted<String>);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub template_dir: String,
    pub sendgrid_api_key: SendgridApiKey,
    pub ui_base_url: Url,
}

impl TryFrom<&Provider> for Config {
    type Error = Error;

    fn try_from(provider: &Provider) -> Result<Self, Self::Error> {
        Ok(Config {
            template_dir: provider
                .read_or_default(TEMPLATE_DIR_VAR, TEMPLATE_DIR_ENTRY)
                .map_err(Error::ParseSendgridApiKey)?,
            sendgrid_api_key: provider
                .read_or_default(SENDGRID_API_KEY_VAR, SENDGRID_API_KEY_ENTRY)
                .map_err(Error::ParseSendgridApiKey)?,
            ui_base_url: provider
                .read(UI_BASE_URL_VAR, UI_BASE_URL_ENTRY)
                .map_err(Error::ParseUiBaseUrl)?,
        })
    }
}
