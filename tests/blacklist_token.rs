mod setup;

use api::auth::TokenType;
use api::models::BlacklistToken;
use setup::setup;
use test_macros::*;

#[before(call = "setup")]
#[tokio::test]
async fn can_blacklist_any_token() -> anyhow::Result<()> {
    let db = _before_values.await;
    let token = "some-fancy-token".to_string();
    let blt = BlacklistToken::create(token.clone(), TokenType::Login, &db.pool).await?;

    assert_eq!(blt.token, token);

    Ok(())
}
