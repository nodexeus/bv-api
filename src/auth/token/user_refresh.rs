use crate::auth::{from_encoded, JwtToken, TokenClaim, TokenError, TokenResult, TokenType};
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
        from_encoded::<UserRefreshToken>(encoded, TokenType::UserRefresh)
    }
}

impl super::Identifier for UserRefreshToken {
    fn get_id(&self) -> uuid::Uuid {
        self.id
    }
}
