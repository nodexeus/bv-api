mod setup;

use anyhow::anyhow;
use api::models::User;
use setup::setup;
use test_macros::before;

#[before(call = "setup")]
#[tokio::test]
async fn can_confirm_unconfirmed_user() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let user = User::confirm(user.id, &db.pool).await?;

    assert!(user.confirmed_at.is_some());

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn cannot_confirm_confirmed_user() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let user = User::confirm(user.id, &db.pool).await?;

    assert!(user.confirmed_at.is_some());

    match User::confirm(user.id, &db.pool).await {
        Ok(_) => Err(anyhow!("Already confirmed user confirmed again")),
        Err(_) => Ok(()),
    }
}

#[before(call = "setup")]
#[tokio::test]
async fn can_check_if_user_confirmed() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let user = User::confirm(user.id, &db.pool).await?;

    assert!(user.confirmed_at.is_some());
    assert!(User::is_confirmed(user.id, &db.pool).await?);
use api::auth::{JwtToken, TokenClaim, TokenRole, TokenType, UserAuthToken, UserRefreshToken};
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
        TokenRole::User,
        None,
    );
    let refresh_token = UserRefreshToken::try_new(claim)?;
    let fields = UserSelectiveUpdate {
        refresh_token: Some(refresh_token.encode()?),
        ..Default::default()
    };
    let user = User::update_all(refresh_token.get_id(), fields, &db.pool).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        TokenRole::User,
        None,
    );
    let auth_token = UserAuthToken::try_new(claim)?;

    assert!(
        User::verify_and_refresh_auth_token(auth_token, refresh_token, &db.pool)
            .await
            .is_ok()
    );

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn returns_false_for_unconfirmed_user_at_check_if_user_confirmed() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;

    assert!(user.confirmed_at.is_none());
    assert!(!User::is_confirmed(user.id, &db.pool).await?);
async fn cannot_verify_and_refresh_wo_valid_refresh_token() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 60000,
        TokenType::UserRefresh,
        TokenRole::User,
        None,
    );
    let refresh_token = UserRefreshToken::try_new(claim)?;
    let fields = UserSelectiveUpdate {
        refresh_token: Some(refresh_token.encode()?),
        ..Default::default()
    };
    let user = User::update_all(refresh_token.get_id(), fields, &db.pool).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        TokenRole::User,
        None,
    );
    let auth_token = UserAuthToken::try_new(claim)?;

    assert!(
        User::verify_and_refresh_auth_token(auth_token, refresh_token, &db.pool)
            .await
            .is_err()
    );

    Ok(())
}
