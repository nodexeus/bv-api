use crate::auth::{Blacklisted, JwtToken, TokenClaim, TokenResult, TokenRole, TokenType};
use crate::errors::Result;
use crate::grpc::blockjoy_ui::Invitation as GrpcInvitation;
use crate::grpc::helpers::required;
use crate::models::BlacklistToken;
use crate::server::DbPool;
use derive_getters::Getters;
use std::collections::HashMap;
use std::str;
use std::str::FromStr;
use uuid::Uuid;

/// The claims of the token to be stored (encrypted) on the client side.
#[derive(Debug, serde::Deserialize, serde::Serialize, Getters)]
pub struct InvitationToken {
    exp: i64,
    token_type: TokenType,
    role: TokenRole,
    email: String,
}

impl InvitationToken {
    pub fn create_for_invitation(invitation: &GrpcInvitation) -> TokenResult<Self> {
        let mut data: HashMap<String, String> = HashMap::new();

        data.insert(
            "invitee_email".into(),
            invitation
                .invitee_email
                .ok_or_else(required("invitee_email"))?,
        );

        let claim = TokenClaim::new(
            Uuid::new_v4(),
            3,
            TokenType::Invitation,
            TokenRole::OrgMember,
            data,
        );

        Self::try_new(claim)
    }
}

impl JwtToken for InvitationToken {
    fn get_expiration(&self) -> i64 {
        self.exp
    }

    fn get_id(&self) -> Uuid {
        todo!()
    }

    fn try_new(claim: TokenClaim) -> TokenResult<Self> {
        Ok(Self {
            exp: claim.exp,
            token_type: claim.token_type,
            role: claim.role,
            email: claim
                .data
                .ok_or_else(|| required("invitee_email"))?
                .get("invitee_email")
                .ok_or_else(|| required("invitee_email"))?
                .to_string(),
        })
    }

    fn token_type(&self) -> TokenType {
        self.token_type
    }
}

#[tonic::async_trait]
impl Blacklisted for InvitationToken {
    async fn blacklist(&self, db: DbPool) -> TokenResult<bool> {
        Ok(BlacklistToken::create(self.encode()?, self.token_type, &db)
            .await
            .is_ok())
    }

    async fn is_blacklisted(&self, token: String, db: DbPool) -> TokenResult<bool> {
        Ok(BlacklistToken::is_listed(token, &db).await.is_ok())
    }
}

impl FromStr for InvitationToken {
    type Err = super::TokenError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        InvitationToken::from_encoded(encoded, TokenType::Invitation, true)
    }
}
