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

    Ok(())
}

#[before(call = "setup")]
#[tokio::test]
async fn returns_false_for_unconfirmed_user_at_check_if_user_confirmed() -> anyhow::Result<()> {
    let db = _before_values.await;
    let user = db.admin_user().await;

    assert!(user.confirmed_at.is_none());
    assert!(!User::is_confirmed(user.id, &db.pool).await?);

    Ok(())
}
