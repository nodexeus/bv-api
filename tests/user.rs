mod setup;

use api::auth::{JwtToken, TokenClaim, TokenType, UserAuthToken, UserRefreshToken};
use api::models::{User, UserSelectiveUpdate};
use chrono::Utc;
use setup::setup;
use test_macros::*;

#[before(call = "setup")]
#[tokio::test]
async fn can_verify_and_refresh_auth_token() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() + 60000,
        TokenType::UserRefresh,
        None,
    );
    let refresh_token = UserRefreshToken::new(claim);
    let fields = UserSelectiveUpdate {
        refresh_token: Some(refresh_token.encode()?),
        ..Default::default()
    };
    let user = User::update_all(refresh_token.get_id(), fields, &db.pool).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        None,
    );
    let auth_token = UserAuthToken::new(claim);

    assert!(
        User::verify_and_refresh_auth_token(auth_token, refresh_token, &db.pool)
            .await
            .is_ok()
    );

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn cannot_verify_and_refresh_wo_valid_refresh_token() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 60000,
        TokenType::UserRefresh,
        None,
    );
    let refresh_token = UserRefreshToken::new(claim);
    let fields = UserSelectiveUpdate {
        refresh_token: Some(refresh_token.encode()?),
        ..Default::default()
    };
    let user = User::update_all(refresh_token.get_id(), fields, &db.pool).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        None,
    );
    let auth_token = UserAuthToken::new(claim);

    assert!(
        User::verify_and_refresh_auth_token(auth_token, refresh_token, &db.pool)
            .await
            .is_err()
    );

    Ok(())
}
