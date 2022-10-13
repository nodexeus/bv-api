mod setup;

use api::auth::{AuthToken, JwtToken, TokenHolderType, TokenIdentifyable};
use api::models::Token;
use std::thread::sleep;
use std::time::Duration;

#[tokio::test]
async fn can_create_host_token() {
    let db = api::TestDb::setup().await;
    let host = db.test_host().await;
    let token = host.get_token(&db.pool).await.unwrap();
    let token_str = AuthToken::new(host.id, token.expires_at.timestamp(), TokenHolderType::Host)
        .encode()
        .unwrap();

    assert_eq!(token.token, token_str);
}

#[tokio::test]
async fn can_refresh_host_token() {
    let db = api::TestDb::setup().await;
    let host = db.test_host().await;
    let token = host.get_token(&db.pool).await.unwrap();

    // sleep 1 sec so the expiration REALLY changes
    sleep(Duration::from_secs(1));

    match Token::refresh(&token.token, &db.pool).await {
        Ok(_) => println!("All good"),
        Err(e) => panic!("error at refresh: {}", e),
    }
}

#[tokio::test]
async fn can_create_user_token() {
    let db = api::TestDb::setup().await;
    let user = db.admin_user().await;
    let token = user.get_token(&db.pool).await.unwrap();
    let token_str = AuthToken::new(user.id, token.expires_at.timestamp(), TokenHolderType::User)
        .encode()
        .unwrap();

    assert_eq!(token.token, token_str);
}

#[tokio::test]
async fn can_refresh_user_token() {
    let db = api::TestDb::setup().await;
    let user = db.admin_user().await;
    let token = user.get_token(&db.pool).await.unwrap();

    // sleep 1 sec so the expiration REALLY changes
    sleep(Duration::from_secs(1));

    match Token::refresh(&token.token, &db.pool).await {
        Ok(_) => println!("All good"),
        Err(e) => panic!("error at refresh: {}", e),
    }
}
