mod setup;

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
    let mut tx = tester.begin().await;
    let user = User::update_all(refresh.get_id(), fields, &mut tx).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        TokenRole::User,
        None,
    );
    let auth = UserAuthToken::try_new(claim)?;

    User::verify_and_refresh_auth_token(auth, refresh, &mut tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
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
    let mut tx = tester.begin().await;
    let user = User::update_all(refresh_token.get_id(), fields, &mut tx).await?;
    let claim = TokenClaim::new(
        user.id,
        Utc::now().timestamp() - 1,
        TokenType::UserAuth,
        TokenRole::User,
        None,
    );
    let auth_token = UserAuthToken::try_new(claim)?;

    User::verify_and_refresh_auth_token(auth_token, refresh_token, &mut tx)
        .await
        .unwrap_err();
    tx.commit().await.unwrap();

    Ok(())
}

#[tokio::test]
async fn can_confirm_unconfirmed_user() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let mut tx = tester.begin().await;
    let user = User::confirm(user.id, &mut tx).await?;
    tx.commit().await.unwrap();

    user.confirmed_at.unwrap();

    Ok(())
}

#[tokio::test]
async fn cannot_confirm_confirmed_user() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let mut tx = tester.begin().await;
    let user = User::confirm(user.id, &mut tx).await?;

    assert!(user.confirmed_at.is_some());

    User::confirm(user.id, &mut tx)
        .await
        .expect_err("Already confirmed user confirmed again");
    tx.commit().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn can_check_if_user_confirmed() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());

    let mut tx = tester.begin().await;
    let user = User::confirm(user.id, &mut tx).await?;

    assert!(user.confirmed_at.is_some());
    assert!(User::is_confirmed(user.id, &mut tx).await?);

    Ok(())
}

#[tokio::test]
async fn returns_false_for_unconfirmed_user_at_check_if_user_confirmed() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;

    assert!(user.confirmed_at.is_none());
    let mut tx = tester.begin().await;
    assert!(!User::is_confirmed(user.id, &mut tx).await?);
    tx.commit().await.unwrap();

    Ok(())
}
