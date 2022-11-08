use crate::auth::TokenType;
use anyhow::anyhow;
use derive_getters::Getters;
use thiserror::Error;

pub type KeyProviderResult = Result<KeyValue, KeyProviderError>;

#[derive(Error, Debug)]
pub enum KeyProviderError {
    #[error("Key is empty")]
    Empty,
    #[error("Env var couldn't be loaded: {0}")]
    DotenvError(#[from] dotenv::Error),
    #[error("Unexpected error: {0}")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Getters)]
pub struct KeyValue {
    value: String,
}

impl KeyValue {
    pub fn new(value: String) -> Self {
        Self { value }
    }
}

pub struct KeyProvider;

impl KeyProvider {
    pub fn get_secret(token_type: TokenType) -> KeyProviderResult {
        let key = match token_type {
            TokenType::UserAuth => Self::get_env_value("JWT_SECRET"),
            TokenType::UserRefresh => Self::get_env_value("REFRESH_SECRET"),
            TokenType::HostAuth => Self::get_env_value("JWT_SECRET"),
            TokenType::HostRefresh => Self::get_env_value("REFRESH_SECRET"),
            TokenType::RegistrationConfirmation => Self::get_env_value("CONFIRMATION_SECRET"),
            TokenType::PwdReset => Self::get_env_value("PWD_RESET_SECRET"),
        };

        let key = key?;

        if key.value.is_empty() {
            Err(KeyProviderError::Empty)
        } else {
            Ok(key)
        }
    }

    fn get_env_value(name: &str) -> KeyProviderResult {
        std::env::var(name)
            .map(KeyValue::new)
            .map_err(|e| KeyProviderError::UnexpectedError(anyhow!(e)))
    }
}
