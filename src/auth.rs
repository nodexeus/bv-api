use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use uuid::Uuid;
use chrono::Utc;
use crate::errors;
use anyhow::anyhow;
use std::env;

const JWT_SECRET: &'static str = "?G'A$jNW<$6x(PdFP?4VdRvmotIV^^";

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub fn create_jwt(uuid: Uuid, role: &str) -> errors::Result<String> {

    let secret = env::var("JWT_SECRET").unwrap_or(JWT_SECRET.to_string());

    let exp = Utc::now()
    .checked_add_signed(chrono::Duration::seconds(5*60))
    .expect("valid timestamp")
    .timestamp();

    let claims = Claims {
        sub: uuid.to_string(),
        role: role.to_string(),
        exp: exp as usize,
    };

    let header = Header::new(Algorithm::HS512);
    //todo: Fix this secret code
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(|_| errors::ApiError::UnexpectedError(anyhow!("Error encoding JWT")))
}