use crate::auth::{from_encoded, JwtToken, OnetimeToken, TokenClaim, TokenResult, TokenType};
use crate::server::DbPool;
use std::str::FromStr;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RegistrationConfirmationToken {
    id: uuid::Uuid,
    exp: i64,
    holder_type: super::TokenHolderType,
    token_type: TokenType,
}

impl JwtToken for RegistrationConfirmationToken {
    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            holder_type: claim.holder_type,
            token_type: TokenType::RegistrationConfirmation,
        }
    }

    fn token_holder(&self) -> super::TokenHolderType {
        self.holder_type
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

#[tonic::async_trait]
impl OnetimeToken for RegistrationConfirmationToken {
    async fn blacklist(&self, _db: DbPool) -> TokenResult<bool> {
        Ok(true)
    }
}

impl FromStr for RegistrationConfirmationToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        from_encoded::<RegistrationConfirmationToken>(encoded, TokenType::RegistrationConfirmation)
    }
}

impl super::Identifier for RegistrationConfirmationToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
