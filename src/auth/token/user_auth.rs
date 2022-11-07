use super::JwtToken;
use crate::auth::{from_encoded, TokenClaim, TokenRole, TokenType};
use crate::errors::Result;
use derive_getters::Getters;
use std::str;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct UserAuthToken {
    id: Uuid,
    exp: i64,
    token_type: TokenType,
    role: TokenRole,
}

#[tonic::async_trait]
impl JwtToken for UserAuthToken {
    fn get_expiration(&self) -> i64 {
        self.exp
    }

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn new(claim: TokenClaim) -> Self {
        let data = claim.data.unwrap_or_default();
        let def = &"user".to_string();
        let role = TokenRole::from_str(data.get("role").unwrap_or(def)).unwrap_or(TokenRole::User);

        Self {
            id: claim.id,
            exp: claim.exp,
            token_type: TokenType::UserAuth,
            role,
        }
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

impl FromStr for UserAuthToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        from_encoded::<UserAuthToken>(encoded, TokenType::UserAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::TokenClaim;
    use super::UserAuthToken;
    use crate::auth::{JwtToken, TokenType};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn returns_true_for_expired_token() {
        let id = Uuid::new_v4();
        let exp = Utc::now().timestamp() - 60000;
        let claim = TokenClaim::new(id, exp, TokenType::UserAuth, None);
        let token = UserAuthToken::new(claim);

        assert!(token.has_expired());
    }

    #[test]
    fn returns_false_for_not_expired_token() {
        let id = Uuid::new_v4();
        let exp = Utc::now().timestamp() + 60000;
        let claim = TokenClaim::new(id, exp, TokenType::UserAuth, None);
        let token = UserAuthToken::new(claim);

        assert!(!token.has_expired());
    }
}
