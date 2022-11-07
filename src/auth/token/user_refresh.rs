use crate::auth::{JwtToken, TokenClaim, TokenError, TokenResult, TokenType};
use axum::http::Request as HttpRequest;
use derive_getters::Getters;
use std::str::FromStr;
use tonic::Status;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct UserRefreshToken {
    id: uuid::Uuid,
    exp: i64,
    token_type: TokenType,
}

impl JwtToken for UserRefreshToken {
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
            token_type: TokenType::UserRefresh,
        }
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }

    fn from_request<B>(request: &HttpRequest<B>) -> TokenResult<Self>
    where
        Self: FromStr<Err = TokenError>,
    {
        request
            .headers()
            .get("cookie")
            .map(|hv| {
                hv.to_str()
                    .map_err(|_| Status::unauthenticated("Couldn't read refresh token"))
                    .unwrap_or_default()
            })
            .map(|hv| hv.split("refresh=").nth(1).unwrap_or_default())
            .unwrap_or_default()
            .parse()
    }
}

impl FromStr for UserRefreshToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        UserRefreshToken::from_encoded::<UserRefreshToken>(encoded, TokenType::UserRefresh, true)
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::expiration_provider::ExpirationProvider;
    use crate::auth::{JwtToken, TokenClaim, TokenType, UserRefreshToken};
    use uuid::Uuid;

    #[test]
    fn can_create_token() -> anyhow::Result<()> {
        let claim = TokenClaim::new(
            Uuid::new_v4(),
            ExpirationProvider::expiration(TokenType::UserRefresh),
            TokenType::UserRefresh,
            None,
        );
        let encoded = UserRefreshToken::new(claim).encode()?;

        println!("Encoded token: {encoded:?}");
        assert!(encoded.starts_with("ey"));

        Ok(())
    }

    #[test]
    fn can_decode_token() -> anyhow::Result<()> {
        let user_id = Uuid::new_v4();
        let claim = TokenClaim::new(
            user_id,
            ExpirationProvider::expiration(TokenType::UserRefresh),
            TokenType::UserRefresh,
            None,
        );
        let encoded = UserRefreshToken::new(claim).encode()?;

        println!("Encoded token: {encoded:?}");
        assert!(encoded.starts_with("ey"));

        let token = UserRefreshToken::from_encoded::<UserRefreshToken>(
            encoded.as_str(),
            TokenType::UserRefresh,
            true,
        );

        assert!(token.is_ok());
        assert_eq!(token.unwrap().id, user_id);

        Ok(())
    }
}
