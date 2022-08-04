use axum::http::header::AUTHORIZATION;
use axum::http::Request as HttpRequest;
use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::env::VarError;
use thiserror::Error;
use uuid::Uuid;

pub type TokenResult<T> = Result<T, TokenError>;

pub trait Identifier {
    fn get_id(&self) -> Uuid;
}

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token is empty")]
    Empty,
    #[error("Token has expired")]
    Expired,
    #[error("Token couldn't be decoded: {0:?}")]
    EnDeCoding(#[from] JwtError),
    #[error("Env var not defined: {0:?}")]
    EnvVar(#[from] VarError),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenHolderType {
    Host,
    User,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtToken {
    id: Uuid,
    exp: usize,
    holder_type: TokenHolderType,
}

impl JwtToken {
    pub fn new(id: Uuid, exp: usize, holder_type: TokenHolderType) -> Self {
        Self {
            id,
            exp,
            holder_type,
        }
    }

    pub fn token_holder(&self) -> &TokenHolderType {
        &self.holder_type
    }

    /// Decode JWT token string and create a JwtToken instance out of it
    pub fn decode(encoded: &str) -> TokenResult<JwtToken> {
        let secret = Self::get_secret()?;
        let mut validation = Validation::new(Algorithm::HS512);

        validation.validate_exp = true;

        match decode::<JwtToken>(
            &encoded,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
            Ok(token) => Ok(token.claims),
            Err(e) => Err(TokenError::EnDeCoding(e)),
        }
    }

    /// Encode this instance to a JWT token string
    pub fn encode(&self) -> TokenResult<String> {
        let secret = Self::get_secret()?;
        let header = Header::new(Algorithm::HS512);

        match encode(&header, self, &EncodingKey::from_secret(secret.as_ref())) {
            Ok(token_str) => Ok(token_str),
            Err(e) => Err(TokenError::EnDeCoding(e)),
        }
    }

    /// Get JWT_SECRET from env vars
    fn get_secret() -> TokenResult<String> {
        match env::var("JWT_SECRET") {
            Ok(secret) => {
                assert!(!secret.is_empty());

                Ok(secret)
            }
            Err(e) => Err(TokenError::EnvVar(e)),
        }
    }
}

impl Identifier for JwtToken {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl<B> TryFrom<&HttpRequest<B>> for JwtToken {
    type Error = TokenError;

    /// TODO: token must be base64 encoded, decode before using it
    fn try_from(request: &HttpRequest<B>) -> Result<Self, Self::Error> {
        let token = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|hv| hv.to_str().ok())
            .unwrap_or("");

        JwtToken::decode(token)
    }
}
