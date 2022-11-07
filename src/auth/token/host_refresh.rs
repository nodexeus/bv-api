use crate::auth::{from_encoded, JwtToken, TokenClaim, TokenType};
use derive_getters::Getters;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct HostRefreshToken {
    id: uuid::Uuid,
    exp: i64,
    token_type: TokenType,
}

impl JwtToken for HostRefreshToken {
    fn get_expiration(&self) -> i64 {
        self.exp
    }

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            token_type: TokenType::HostRefresh,
        }
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

impl FromStr for HostRefreshToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        from_encoded::<HostRefreshToken>(encoded, TokenType::HostRefresh)
    }
}

impl super::Identifier for HostRefreshToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
