mod setup;

use crate::setup::get_admin_user;
use api::auth::{JwtToken, TokenHolderType, TokenIdentifyable};
use api::models::{Host, Token, TokenRole, User};
use setup::{get_test_host, setup};
use test_macros::*;

#[before(call = "setup")]
#[tokio::test]
async fn can_create_host_token() {
    let db = _before_values.await;
    let host = get_test_host(&db).await;
    let token = Token::create(host.id, TokenRole::Admin, &db, TokenHolderType::Host)
        .await
        .unwrap();
    let host = Host::set_token(token.id, host.id, &db).await.unwrap();
    let token_str = JwtToken::new(host.id, token.expires_at.timestamp(), TokenHolderType::Host)
        .encode()
        .unwrap();

    assert_eq!(token.token, token_str);
}

#[before(call = "setup")]
#[tokio::test]
async fn can_refresh_host_token() {
    let db = _before_values.await;
    let host = get_test_host(&db).await;
    let token = Token::create(host.id, TokenRole::Admin, &db, TokenHolderType::Host)
        .await
        .unwrap();

    match Token::refresh(token.token, &db).await {
        Ok(_) => println!("All good"),
        Err(e) => panic!("error at refresh: {}", e),
    }
}

#[before(call = "setup")]
#[tokio::test]
async fn can_create_user_token() {
    let db = _before_values.await;
    let user = get_admin_user(&db).await;
    let token = Token::create(user.id, TokenRole::Admin, &db, TokenHolderType::User)
        .await
        .unwrap();
    let user = User::set_token(token.id, user.id, &db).await.unwrap();
    let token_str = JwtToken::new(user.id, token.expires_at.timestamp(), TokenHolderType::User)
        .encode()
        .unwrap();

    assert_eq!(token.token, token_str);
}

#[before(call = "setup")]
#[tokio::test]
async fn can_refresh_user_token() {
    let db = _before_values.await;
    let user = get_admin_user(&db).await;
    let token = Token::create(user.id, TokenRole::Admin, &db, TokenHolderType::User)
        .await
        .unwrap();

    match Token::refresh(token.token, &db).await {
        Ok(_) => println!("All good"),
        Err(e) => panic!("error at refresh: {}", e),
    }
}
