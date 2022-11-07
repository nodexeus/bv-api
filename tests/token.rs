use api::auth::token::*;
use axum::http::header::AUTHORIZATION;
use axum::http::Request;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use test_macros::*;
use uuid::Uuid;

struct TestData {
    pub(crate) now: i64,
}

fn setup() -> TestData {
    let start = SystemTime::now();

    TestData {
        now: start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64,
    }
}

#[before(call = "setup")]
#[test]
fn should_encode_token() -> anyhow::Result<()> {
    let test_secret = "123456";
    temp_env::with_var("JWT_SECRET", Some(test_secret), || {
        let id = Uuid::new_v4();
        let claim = TokenClaim::new(id, 123123, TokenHolderType::User, TokenType::Login, None);
        let token = UserAuthToken::new(claim);
        let header = Header::new(Algorithm::HS512);

        match jsonwebtoken::encode(
            &header,
            &token,
            &EncodingKey::from_secret(test_secret.as_ref()),
        ) {
            Ok(token_str) => assert_eq!(token_str, token.encode().unwrap()),
            Err(e) => panic!("encoding failed: {}", e),
        }

        Ok(())
    })
}

#[before(call = "setup")]
#[test]
fn should_decode_valid_token() -> anyhow::Result<()> {
    let test_secret = "123456";
    temp_env::with_var("JWT_SECRET", Some(test_secret), || {
        let id = Uuid::new_v4();
        let claim = TokenClaim::new(
            id,
            _before_values.now,
            TokenHolderType::User,
            TokenType::Login,
            None,
        );
        let token = UserAuthToken::new(claim);
        let token_str = token.encode().unwrap();
        let mut validation = Validation::new(Algorithm::HS512);

        validation.validate_exp = true;

        match jsonwebtoken::decode::<UserAuthToken>(
            token_str.as_str(),
            &DecodingKey::from_secret(test_secret.as_bytes()),
            &validation,
        ) {
            Ok(decoded_data) => assert_eq!(decoded_data.claims.get_id(), id),
            Err(e) => panic!("decoding failed: {}", e),
        }

        Ok(())
    })
}

#[before(call = "setup")]
#[test]
fn should_panic_on_decode_expired_token() {
    let test_secret = "123456";
    temp_env::with_var("JWT_SECRET", Some(test_secret), || {
        let id = Uuid::new_v4();
        let claim = TokenClaim::new(id, 123123, TokenHolderType::User, TokenType::Login, None);
        let token = UserAuthToken::new(claim);
        let token_str = token.encode().unwrap();
        let mut validation = Validation::new(Algorithm::HS512);

        validation.validate_exp = true;

        match jsonwebtoken::decode::<UserAuthToken>(
            token_str.as_str(),
            &DecodingKey::from_secret(test_secret.as_bytes()),
            &validation,
        ) {
            Err(e) => assert_eq!(format!("{}", e), "ExpiredSignature"),
            // assert_eq!(e.into_kind().type_name(), jsonwebtoken::errors::ErrorKind::ExpiredSignature),
            _ => panic!("it worked, but it shouldn't"),
        };
    });
}

#[before(call = "setup")]
#[test]
#[should_panic]
fn should_panic_with_invalid_token() {
    let request = Request::builder()
        .uri("/")
        .method("GET")
        .header(AUTHORIZATION, "some-token")
        .body(())
        .unwrap();
    let _ = UserAuthToken::from_request(&request).unwrap();
}

#[before(call = "setup")]
#[test]
fn should_not_work_with_empty_token() {
    let request = Request::builder()
        .uri("/")
        .method("GET")
        .header(AUTHORIZATION, "")
        .body(())
        .unwrap();

    assert!(UserAuthToken::from_request(&request).is_err());
}

#[before(call = "setup")]
#[test]
fn should_get_valid_token() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let id = Uuid::new_v4();
    let exp = _before_values.now + 60 * 60 * 24;
    let claim = TokenClaim::new(id, exp, TokenHolderType::User, TokenType::Login, None);
    let token = UserAuthToken::new(claim);
    let encoded = base64::encode(token.encode().unwrap());
    let request = Request::builder()
        .header(AUTHORIZATION, format!("Bearer {}", encoded))
        .uri("/")
        .method("GET")
        .body(())?;
    let token = UserAuthToken::from_request(&request).unwrap();

    assert_eq!(token.get_id(), id);

    Ok(())
}

#[test]
#[should_panic]
fn should_panic_encode_without_secret_in_envs() {
    temp_env::with_var_unset("JWT_SECRET", || {
        let claim = TokenClaim::new(
            Uuid::new_v4(),
            123123123,
            TokenHolderType::User,
            TokenType::Login,
            None,
        );
        UserAuthToken::new(claim).encode().unwrap()
    });
}

#[test]
fn should_not_decode_without_secret_in_envs() {
    assert!(UserAuthToken::from_str("asf.asdfasdfasdfasdfsadfasdfasdf.asdfasfasdf").is_err());
}

#[test]
#[should_panic]
fn should_panic_on_encode_with_empty_secret_in_envs() {
    temp_env::with_var("JWT_SECRET", Some(""), || {
        let claim = TokenClaim::new(
            Uuid::new_v4(),
            123123123,
            TokenHolderType::User,
            TokenType::Login,
            None,
        );
        let token = UserAuthToken::new(claim);

        assert!(token.encode().is_err());
    });
}

#[test]
#[should_panic]
fn should_panic_on_decode_with_empty_secret_in_envs() {
    temp_env::with_var("JWT_SECRET", Some(""), || {
        assert!(UserAuthToken::from_str("asf.asdfasdfasdfasdfsadfasdfasdf.asdfasfasdf").is_err());
    });
}
