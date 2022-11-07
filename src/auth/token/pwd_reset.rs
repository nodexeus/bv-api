use super::JwtToken;
use crate::auth::{from_encoded, OnetimeToken, TokenClaim, TokenResult, TokenType};
use crate::errors::Result;
use crate::server::DbPool;
use std::str;
use std::str::FromStr;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct PwdResetToken {
    id: uuid::Uuid,
    exp: i64,
    token_type: TokenType,
}

impl JwtToken for PwdResetToken {
    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            token_type: TokenType::PwdReset,
        }
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

#[tonic::async_trait]
impl OnetimeToken for PwdResetToken {
    async fn blacklist(&self, _db: DbPool) -> TokenResult<bool> {
        Ok(true)
    }
}

impl FromStr for PwdResetToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        from_encoded::<PwdResetToken>(encoded, TokenType::PwdReset)
    }
}

impl super::Identifier for PwdResetToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
