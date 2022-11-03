use anyhow::anyhow;
use axum::http::Request as HttpRequest;
use base64::DecodeError;
use http::header::AUTHORIZATION;
use jsonwebtoken as jwt;
use jsonwebtoken::errors::Error as JwtError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::Utf8Error;
use std::{env::VarError, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

mod auth;
mod pwd_reset;
mod refresh;
mod registration_confirmation;

use crate::auth::expiration_provider::ExpirationProvider;
use crate::auth::key_provider::{KeyProvider, KeyProviderError};
use crate::auth::{FindableById, Identifiable};
use crate::errors::{ApiError, Result as ApiResult};
use crate::models::{Host, User};
use crate::server::DbPool;
pub use {
    auth::AuthToken, pwd_reset::PwdResetToken, refresh::*,
    registration_confirmation::RegistrationConfirmationToken,
};

pub type TokenResult<T> = Result<T, TokenError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenRole {
    Admin,
    Guest,
    Service,
    User,
    PwdReset,
}

impl ToString for TokenRole {
    fn to_string(&self) -> String {
        match self {
            TokenRole::Admin => "admin".into(),
            TokenRole::Guest => "guest".into(),
            TokenRole::Service => "service".into(),
            TokenRole::User => "user".into(),
            TokenRole::PwdReset => "pwd_reset".into(),
        }
    }
}

impl FromStr for TokenRole {
    type Err = ApiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(TokenRole::User),
            "service" => Ok(TokenRole::Service),
            "guest" => Ok(TokenRole::Guest),
            "admin" => Ok(TokenRole::Admin),
            "pwd_reset" => Ok(TokenRole::PwdReset),
            _ => Err(ApiError::UnexpectedError(anyhow!("Unknown role"))),
        }
    }
}

pub trait Identifier {
    fn get_id(&self) -> Uuid;
}

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token is empty")]
    Empty,
    #[error("Token is incorrectly formatted")]
    Invalid,
    #[error("Token has expired")]
    Expired,
    #[error("Token couldn't be decoded: {0:?}")]
    EnDeCoding(#[from] JwtError),
    #[error("Env var not defined: {0:?}")]
    EnvVar(#[from] VarError),
    #[error("UTF-8 error: {0:?}")]
    Utf8(#[from] Utf8Error),
    #[error("JWT decoding error: {0:?}")]
    JwtDecoding(#[from] DecodeError),
    #[error("Provided key is invalid: {0:?}")]
    KeyError(#[from] KeyProviderError),
}

/// The type of token we are dealing with. We have various different types of token and they convey
/// various different permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "token_type", rename_all = "snake_case")]
pub enum TokenType {
    /// This is a "normal" login token obtained by sending the login credentials to
    /// `AuthenticationService.Login`.
    Login,
    /// This is a dedicated refresh token. It can be used after the login token has expired to
    /// obtain a new refresh and login token pair.
    Refresh,
    /// This is a password reset token. It is issued as a part of the password forgot/reset email
    /// and may be used _only_ to reset the user's password.
    PwdReset,
    /// This is the token used for confirming a new users registration
    RegistrationConfirmation,
}

impl ToString for TokenType {
    fn to_string(&self) -> String {
        match self {
            Self::Login => "login".to_string(),
            Self::Refresh => "refresh".to_string(),
            Self::PwdReset => "pwd_reset".to_string(),
            Self::RegistrationConfirmation => "registration_confirmation".to_string(),
        }
    }
}

/// The claims of the tokens. Each claim is a key-value pair
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaim {
    id: Uuid,
    exp: i64,
    holder_type: TokenHolderType,
    token_type: TokenType,
    data: Option<HashMap<String, String>>,
}

impl TokenClaim {
    pub fn new(
        id: Uuid,
        exp: i64,
        holder_type: TokenHolderType,
        token_type: TokenType,
        data: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            id,
            exp,
            holder_type,
            token_type,
            data,
        }
    }
}

/// The type of entity that is granted some permission through this token.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum TokenHolderType {
    /// This means that the token authenticates a host machine.
    Host,
    /// This means that the token authenticates a user of our web console.
    User,
}

impl TokenHolderType {
    pub fn id_field(&self) -> &'static str {
        match self {
            Self::User => "user_id",
            Self::Host => "host_id",
        }
    }
}

#[tonic::async_trait]
pub trait JwtToken: Sized + serde::Serialize {
    fn new(claim: TokenClaim) -> Self;

    fn token_holder(&self) -> TokenHolderType;

    fn token_type(&self) -> TokenType;

    /// Encode this instance to a JWT token string
    fn encode(&self) -> TokenResult<String> {
        let key = KeyProvider::get_secret(self.token_type())?;
        let secret = key.value();
        let header = jwt::Header::new(jwt::Algorithm::HS512);
        let key = jwt::EncodingKey::from_secret(secret.as_ref());
        jwt::encode(&header, self, &key).map_err(TokenError::EnDeCoding)
    }

    /// Extract the JWT from given request
    fn from_request<B>(request: &HttpRequest<B>) -> TokenResult<Self>
    where
        Self: FromStr<Err = TokenError>,
    {
        extract_token(request).and_then(|s| Self::from_str(&s))
    }

    /// Try to retrieve user for given token
    async fn try_get_user(&self, id: Uuid, db: &DbPool) -> ApiResult<User> {
        match (self.token_holder(), self.token_type()) {
            (TokenHolderType::User, TokenType::Login) => User::find_by_id(id, db).await,
            (TokenHolderType::User, TokenType::Refresh) => User::find_by_id(id, db).await,
            (TokenHolderType::User, TokenType::RegistrationConfirmation) => {
                User::find_by_id(id, db).await
            }
            (TokenHolderType::User, TokenType::PwdReset) => User::find_by_id(id, db).await,
            _ => Err(ApiError::UnexpectedError(anyhow!(
                "Cannot retrieve host from token of type {} for User",
                self.token_type().to_string()
            ))),
        }
    }

    fn to_base64(&self) -> ApiResult<String> {
        Ok(base64::encode(self.encode()?))
    }

    /// Try to retrieve host for given token
    async fn try_get_host(&self, id: Uuid, db: &DbPool) -> ApiResult<Host> {
        match (self.token_holder(), self.token_type()) {
            (TokenHolderType::Host, TokenType::Login) => Host::find_by_id(id, db).await,
            (TokenHolderType::Host, TokenType::Refresh) => Host::find_by_id(id, db).await,
            _ => Err(ApiError::UnexpectedError(anyhow!(
                "Cannot retrieve host from token of type {} for Host",
                self.token_type().to_string()
            ))),
        }
    }

    /// Create token for given resource
    fn create_token_for<T: Identifiable>(
        resource: &T,
        holder_type: TokenHolderType,
        token_type: TokenType,
    ) -> TokenResult<Self> {
        let claim = TokenClaim::new(
            resource.get_id(),
            ExpirationProvider::expiration(holder_type, token_type),
            holder_type,
            token_type,
            None,
        );

        Ok(Self::new(claim))
    }
}

#[derive(serde::Deserialize)]
struct UnknownToken {
    token_type: TokenType,
}

/// A token whose `token_type` is not known.
pub enum AnyToken {
    Auth(AuthToken),
    PwdReset(PwdResetToken),
    Refresh(RefreshToken),
    RegistrationConfirmation(RegistrationConfirmationToken),
}

impl AnyToken {
    /// Deduces the correct of the token and then decodes the token according to that type.
    pub fn from_request<B>(req: &HttpRequest<B>) -> TokenResult<AnyToken> {
        use AnyToken::*;

        let token = extract_token(req)?;
        let payload = token.split('.').nth(1).ok_or(TokenError::Invalid)?;
        let decoded = base64::decode(payload).or(Err(TokenError::Invalid))?;
        let json: UnknownToken = serde_json::from_slice(&decoded).or(Err(TokenError::Invalid))?;
        let token = match json.token_type {
            TokenType::Login => Auth(AuthToken::from_str(&token)?),
            TokenType::Refresh => Refresh(RefreshToken::from_str(&token)?),
            TokenType::PwdReset => PwdReset(PwdResetToken::from_str(&token)?),
            TokenType::RegistrationConfirmation => {
                RegistrationConfirmation(RegistrationConfirmationToken::from_str(&token)?)
            }
        };

        Ok(token)
    }
}

fn extract_token<B>(req: &HttpRequest<B>) -> TokenResult<String> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|hv| hv.strip_prefix("Bearer"))
        .map(|tkn| tkn.trim())
        .unwrap_or("");
    let clear_token = base64::decode(token)?;
    let token = std::str::from_utf8(&clear_token)?;
    Ok(token.to_owned())
}

/// Indicates the impl token is subject to be blacklisted once used
#[tonic::async_trait]
pub trait OnetimeToken {
    /// Method needs to be called after validation and use
    async fn blacklist(&self, db: DbPool) -> TokenResult<bool>;
}

/// Decode token from encoded value
pub fn from_encoded<T: JwtToken + DeserializeOwned>(
    encoded: &str,
    token_type: TokenType,
) -> Result<T, TokenError> {
    let key = KeyProvider::get_secret(token_type)?;
    let secret = key.value();
    let mut validation = jwt::Validation::new(jwt::Algorithm::HS512);

    validation.validate_exp = true;

    match jwt::decode::<T>(
        encoded,
        &jwt::DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(token) => Ok(token.claims),
        Err(e) => Err(TokenError::EnDeCoding(e)),
    }
}
