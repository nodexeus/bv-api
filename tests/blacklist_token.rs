mod setup;

use api::auth::TokenType;
use api::models::BlacklistToken;
use setup::setup;
use test_macros::*;

#[before(call = "setup")]
#[tokio::test]
async fn can_blacklist_any_token() {
    let db = _before_values.await;
    let token = "some-fancy-token".to_string();
    let blt = BlacklistToken::create(token.clone(), TokenType::UserAuth, &db.pool)
        .await
        .unwrap();

    assert_eq!(blt.token, token);
}
