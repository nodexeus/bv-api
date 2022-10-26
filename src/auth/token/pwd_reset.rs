use super::JwtToken;
use crate::auth::key_provider::KeyProvider;
use crate::auth::{OnetimeToken, TokenClaim, TokenResult, TokenType};
use crate::server::DbPool;
use jsonwebtoken as jwt;
use std::str;
use std::str::FromStr;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct PwdResetToken {
    id: uuid::Uuid,
    exp: i64,
    holder_type: super::TokenHolderType,
    token_type: TokenType,
}

impl JwtToken for PwdResetToken {
    fn new(claim: TokenClaim) -> Self {
        Self {
            id: claim.id,
            exp: claim.exp,
            holder_type: claim.holder_type,
            token_type: TokenType::PwdReset,
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
impl OnetimeToken for PwdResetToken {
    async fn blacklist(&self, _db: DbPool) -> TokenResult<bool> {
        Ok(true)
    }
}

impl FromStr for PwdResetToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let key = KeyProvider::get_secret(TokenType::PwdReset)?;
        let secret = key.value();
        let validation = jwt::Validation::new(jwt::Algorithm::HS512);
        let key = jwt::DecodingKey::from_secret(secret.as_bytes());

        match jwt::decode(encoded, &key, &validation) {
            Ok(token) => Ok(token.claims),
            Err(e) => Err(super::TokenError::EnDeCoding(e)),
        }
    }
}

impl super::Identifier for PwdResetToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
