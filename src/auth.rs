use crate::errors::{ApiError, Result};
use anyhow::anyhow;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const JWT_SECRET: &'static str = "?G'A$jNW<$6x(PdFP?4VdRvmotIV^^";

pub struct AuthData {
    pub user_id: uuid::Uuid,
    pub user_role: String,
}

pub enum JwtValidationStatus {
    Valid(AuthData),
    Expired(AuthData),
    Invalid,
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub fn create_jwt(data: &AuthData) -> Result<String> {
    let exp = Utc::now()
        .checked_add_signed(chrono::Duration::days(1))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: data.user_id.to_string(),
        role: data.user_role.clone(),
        exp: exp as usize,
    };

    let header = Header::new(Algorithm::HS512);
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )?)
}

pub fn validate_jwt(jwt: &str) -> Result<JwtValidationStatus> {
    let validation = Validation {
        leeway: 60,
        validate_exp: false,
        algorithms: vec![Algorithm::HS512],
        ..Default::default()
    };

    let result = match decode::<Claims>(
        &jwt,
        &DecodingKey::from_secret(&jwt_secret().as_bytes()),
        &validation,
    ) {
        Ok(decoded) => {
            let user_id = Uuid::parse_str(&decoded.claims.sub)
                .map_err(|_| ApiError::from(anyhow!("Error parsing uuid from JWT sub")))?;
            let user_role = decoded.claims.role;

            let auth_data = AuthData { user_id, user_role };

            // Check Expiration
            let exp = decoded.claims.exp;
            let now = get_current_timestamp();
            if (exp as u64) < now - 60 {
                JwtValidationStatus::Expired(auth_data)
            } else {
                JwtValidationStatus::Valid(auth_data)
            }
        }

        Err(_) => JwtValidationStatus::Invalid,
    };

    Ok(result)
}

fn jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or(JWT_SECRET.to_string())
}

fn get_current_timestamp() -> u64 {
    let start = SystemTime::now();
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
