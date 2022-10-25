use crate::auth::{JwtToken, TokenClaim};
use std::env;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RegistrationConfirmationToken {
    id: uuid::Uuid,
    exp: i64,
    holder_type: super::TokenHolderType,
    token_type: super::TokenType,
}

impl JwtToken for RegistrationConfirmationToken {
    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            holder_type: claim.holder_type,
            token_type: claim.token_type,
        }
    }

    fn token_holder(&self) -> super::TokenHolderType {
        self.holder_type
    }

    /// Get PWD_RESET_SECRET from env vars.
    fn get_secret() -> crate::auth::TokenResult<String> {
        match env::var("PWD_RESET_SECRET") {
            Ok(s) if s.is_empty() => panic!("`PWD_RESET_SECRET` parameter is empty"),
            Ok(secret) => Ok(secret),
            Err(e) => Err(super::TokenError::EnvVar(e)),
        }
    }
}
