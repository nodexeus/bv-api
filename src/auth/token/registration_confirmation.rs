use crate::auth::{
    Blacklisted, JwtToken, TokenClaim, TokenError, TokenResult, TokenRole, TokenType,
};
use crate::models;
use anyhow::anyhow;
use diesel_async::AsyncPgConnection;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RegistrationConfirmationToken {
    pub id: Uuid,
    exp: i64,
    token_type: TokenType,
    pub role: TokenRole,
    email: String,
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
            email: claim
                .data
                .ok_or_else(|| TokenError::Invitation(anyhow!("Invalid claim")))?
                .get("email")
                .ok_or_else(|| TokenError::Invitation(anyhow!("Invitee email can't be empty")))?
                .to_string(),
        })
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

#[tonic::async_trait]
impl Blacklisted for RegistrationConfirmationToken {
    async fn blacklist(&self, conn: &mut diesel_async::AsyncPgConnection) -> TokenResult<bool> {
        let tkn = models::BlacklistToken {
            token: self.encode()?,
            token_type: self.token_type.into(),
        };
        Ok(tkn.create(conn).await.is_ok())
    }

    async fn is_blacklisted(
        &self,
        token: String,
        conn: &mut AsyncPgConnection,
    ) -> TokenResult<bool> {
        Ok(models::BlacklistToken::is_listed(token, conn).await.is_ok())
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
