use super::JwtToken;
use crate::auth::{from_encoded, TokenClaim, TokenRole, TokenType};
use crate::errors::Result;
use derive_getters::Getters;
use std::str;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct AuthToken {
    id: Uuid,
    exp: i64,
    holder_type: super::TokenHolderType,
    token_type: TokenType,
    role: TokenRole,
}

#[tonic::async_trait]
impl JwtToken for AuthToken {
    fn new(claim: TokenClaim) -> Self {
        let data = claim.data.unwrap_or_default();
        let def = &"user".to_string();
        let role = TokenRole::from_str(data.get("role").unwrap_or(def))
            .unwrap_or(TokenRole::User);

        Self {
            id: claim.id,
            exp: claim.exp,
            holder_type: claim.holder_type,
            token_type: TokenType::Login,
            role,
        }
    }

    fn token_holder(&self) -> super::TokenHolderType {
        self.holder_type
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

impl FromStr for AuthToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        from_encoded::<AuthToken>(encoded, TokenType::Login)
    }
}

impl super::Identifier for AuthToken {
    fn get_id(&self) -> Uuid {
        self.id
    }
}
