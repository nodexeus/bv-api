use crate::auth::TokenType;
use derive_getters::Getters;
use thiserror::Error;

pub type KeyProviderResult = Result<KeyValue, KeyProviderError>;

#[derive(Error, Debug)]
pub enum KeyProviderError {
    #[error("Key is empty")]
    Empty,
    #[error("Env var couldn't be loaded: {0}")]
    DotenvError(#[from] dotenv::Error),
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
            TokenType::Login => Self::get_auth_secret(),
            TokenType::RegistrationConfirmation => Self::get_registration_confirmation_secret(),
            TokenType::PwdReset => Self::get_pwd_reset_secret(),
            TokenType::Refresh => Self::get_refresh_secret(),
        };

        match key {
            Ok(key) => {
                if key.value.is_empty() {
                    Err(KeyProviderError::Empty)
                } else {
                    Ok(key)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn get_auth_secret() -> KeyProviderResult {
        dotenv::var("JWT_SECRET")
            .map(KeyValue::new)
            .map_err(KeyProviderError::from)
    }

    fn get_pwd_reset_secret() -> KeyProviderResult {
        dotenv::var("PWD_RESET_SECRET")
            .map(KeyValue::new)
            .map_err(KeyProviderError::from)
    }

    fn get_registration_confirmation_secret() -> KeyProviderResult {
        dotenv::var("CONFIRMATION_SECRET")
            .map(KeyValue::new)
            .map_err(KeyProviderError::from)
    }

    fn get_refresh_secret() -> KeyProviderResult {
        dotenv::var("REFRESH_SECRET")
            .map(KeyValue::new)
            .map_err(KeyProviderError::from)
    }
}
