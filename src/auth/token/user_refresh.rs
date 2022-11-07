use crate::auth::{from_encoded, JwtToken, TokenClaim, TokenType};
use derive_getters::Getters;
use std::str::FromStr;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct UserRefreshToken {
    id: uuid::Uuid,
    exp: i64,
    token_type: TokenType,
}

impl JwtToken for UserRefreshToken {
    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            token_type: TokenType::UserRefresh,
        }
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

impl FromStr for UserRefreshToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        from_encoded::<UserRefreshToken>(encoded, TokenType::UserRefresh)
    }
}

impl super::Identifier for UserRefreshToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
