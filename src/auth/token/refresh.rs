use crate::auth::key_provider::KeyProvider;
use crate::auth::{JwtToken, TokenClaim, TokenType};
use jsonwebtoken as jwt;
use std::str::FromStr;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RefreshToken {
    id: uuid::Uuid,
    exp: i64,
    holder_type: super::TokenHolderType,
    token_type: TokenType,
}

impl JwtToken for RefreshToken {
    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            holder_type: claim.holder_type,
            token_type: TokenType::Refresh,
        }
    }

    fn token_holder(&self) -> super::TokenHolderType {
        self.holder_type
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

impl FromStr for RefreshToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let key = KeyProvider::get_secret(TokenType::Refresh)?;
        let secret = key.value();
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS512);

        validation.validate_exp = true;

        match jwt::decode(
            encoded,
            &jwt::DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            Ok(token) => Ok(token.claims),
            Err(e) => Err(super::TokenError::EnDeCoding(e)),
        }
    }
}

impl super::Identifier for RefreshToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
