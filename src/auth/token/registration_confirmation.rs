use crate::auth::{Blacklisted, JwtToken, TokenClaim, TokenResult, TokenRole, TokenType};
use crate::models::BlacklistToken;
use crate::server::DbPool;
use derive_getters::Getters;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct RegistrationConfirmationToken {
    id: Uuid,
    exp: i64,
    token_type: TokenType,
    role: TokenRole,
}

impl JwtToken for RegistrationConfirmationToken {
    fn get_expiration(&self) -> i64 {
        self.exp
    }

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn try_new(claim: TokenClaim) -> TokenResult<Self> {
        Ok(Self {
            id: claim.id,
            exp: claim.exp,
            token_type: TokenType::RegistrationConfirmation,
            role: claim.role,
        })
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

#[tonic::async_trait]
impl Blacklisted for RegistrationConfirmationToken {
    async fn blacklist(&self, db: DbPool) -> TokenResult<bool> {
        Ok(BlacklistToken::create(self.encode()?, self.token_type, &db)
            .await
            .is_ok())
    }

    async fn is_blacklisted(&self, token: String, db: DbPool) -> TokenResult<bool> {
        Ok(BlacklistToken::is_listed(token, &db).await.is_ok())
    }
}

impl FromStr for RegistrationConfirmationToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        RegistrationConfirmationToken::from_encoded(
            encoded,
            TokenType::RegistrationConfirmation,
            true,
        )
    }
}
