mod setup;

use anyhow::anyhow;
use api::auth::{JwtToken, TokenClaim, TokenRole, TokenType, UserAuthToken, UserRefreshToken};
use api::models::{User, UserSelectiveUpdate};
use chrono::Utc;

#[tokio::test]
async fn can_verify_and_refresh_auth_token() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() + 60000,
        TokenType::UserRefresh,
        TokenRole::User,
        None,
    );
    let refresh = UserRefreshToken::try_new(claim)?;
    let fields = UserSelectiveUpdate {
        refresh_token: Some(refresh.encode()?),
        ..Default::default()
    };
    let user = User::update_all(refresh.get_id(), fields, tester.pool()).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        TokenRole::User,
        None,
    );
    let auth = UserAuthToken::try_new(claim)?;

    User::verify_and_refresh_auth_token(auth, refresh, tester.pool())
        .await
        .unwrap();
    Ok(())
}

#[tokio::test]
async fn cannot_verify_and_refresh_wo_valid_refresh_token() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
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
    let user = User::update_all(refresh_token.get_id(), fields, tester.pool()).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        TokenRole::User,
        None,
    );
    let auth_token = UserAuthToken::try_new(claim)?;

    User::verify_and_refresh_auth_token(auth_token, refresh_token, tester.pool())
        .await
        .unwrap_err();

    Ok(())
}

#[tokio::test]
async fn can_confirm_unconfirmed_user() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let user = User::confirm(user.id, tester.pool()).await?;

    user.confirmed_at.unwrap();

    Ok(())
}

#[tokio::test]
async fn cannot_confirm_confirmed_user() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let user = User::confirm(user.id, tester.pool()).await?;

    assert!(user.confirmed_at.is_some());

    match User::confirm(user.id, tester.pool()).await {
        Ok(_) => Err(anyhow!("Already confirmed user confirmed again")),
        Err(_) => Ok(()),
    }
}

#[tokio::test]
async fn can_check_if_user_confirmed() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let user = User::confirm(user.id, tester.pool()).await?;

    assert!(user.confirmed_at.is_some());
    assert!(User::is_confirmed(user.id, tester.pool()).await?);

    Ok(())
}

#[tokio::test]
async fn returns_false_for_unconfirmed_user_at_check_if_user_confirmed() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());
    assert!(!User::is_confirmed(user.id, tester.pool()).await?);

    Ok(())
}
