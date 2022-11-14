use crate::auth::{JwtToken, TokenClaim, TokenResult, TokenRole, TokenType};
use crate::errors::Result;
use derive_getters::Getters;
use std::str;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Getters)]
pub struct HostAuthToken {
    id: Uuid,
    exp: i64,
    token_type: TokenType,
    role: TokenRole,
}

#[tonic::async_trait]
impl JwtToken for HostAuthToken {
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
            token_type: TokenType::HostAuth,
            role: claim.role,
        })
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

impl FromStr for HostAuthToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        HostAuthToken::from_encoded(encoded, TokenType::HostAuth, false)
    }
}
