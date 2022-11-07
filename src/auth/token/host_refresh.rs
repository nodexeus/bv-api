use crate::auth::{from_encoded, JwtToken, TokenClaim, TokenType};
use chrono::Utc;
use derive_getters::Getters;
use std::str::FromStr;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct HostRefreshToken {
    id: uuid::Uuid,
    exp: i64,
    token_type: TokenType,
}

impl JwtToken for HostRefreshToken {
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

    fn has_expired(&self) -> bool {
        let now = Utc::now().timestamp();

        now > self.exp
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
