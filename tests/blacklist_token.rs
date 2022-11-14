mod setup;

use api::auth::TokenType;
use api::models::BlacklistToken;

#[tokio::test]
async fn can_blacklist_any_token() {
    let tester = setup::Tester::new().await;
    let token = "some-fancy-token".to_string();
    let blt = BlacklistToken::create(token.clone(), TokenType::UserAuth, tester.pool())
        .await
        .unwrap();

    assert_eq!(blt.token, token);
}
