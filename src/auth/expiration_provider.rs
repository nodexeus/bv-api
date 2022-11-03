use crate::auth::{TokenHolderType, TokenType};
use crate::errors::{ApiError, Result as ApiResult};
use anyhow::anyhow;

pub struct ExpirationProvider;

impl ExpirationProvider {
    pub fn expiration(holder_type: TokenHolderType, token_type: TokenType) -> i64 {
        let value = match (holder_type, token_type) {
            (TokenHolderType::User, TokenType::Login) => {
                Self::get_expiration_from_dotenv("TOKEN_EXPIRATION_DAYS_USER")
            }
            (TokenHolderType::User, TokenType::Refresh) => {
                Self::get_expiration_from_dotenv("REFRESH_TOKEN_EXPIRATION_DAYS_USER")
            }
            (TokenHolderType::User, TokenType::PwdReset) => {
                Self::get_expiration_from_dotenv("PWD_RESET_TOKEN_EXPIRATION_DAYS_USER")
            }
            (TokenHolderType::User, TokenType::RegistrationConfirmation) => {
                Self::get_expiration_from_dotenv("REGISTRATION_CONFIRMATION_DAYS_USER")
            }
            (TokenHolderType::Host, TokenType::Login) => {
                Self::get_expiration_from_dotenv("TOKEN_EXPIRATION_DAYS_HOST")
            }
            (TokenHolderType::Host, TokenType::Refresh) => {
                Self::get_expiration_from_dotenv("REFRESH_EXPIRATION_DAYS_HOST")
            }
            (TokenHolderType::Host, TokenType::PwdReset) => Err(ApiError::UnexpectedError(
                anyhow!("Invalid type/holder combination for token expiration"),
            )),
            (TokenHolderType::Host, TokenType::RegistrationConfirmation) => {
                Err(ApiError::UnexpectedError(anyhow!(
                    "Invalid type/holder combination for token expiration"
                )))
            }
        };

        value.unwrap_or(0)
    }

    fn get_expiration_from_dotenv(key: &str) -> ApiResult<i64> {
        dotenv::var(key)
            .map_err(ApiError::EnvError)?
            .parse::<i64>()
            .map_err(|e| ApiError::UnexpectedError(anyhow!("Couldn't parse env var value: {e:?}")))
    }
}
