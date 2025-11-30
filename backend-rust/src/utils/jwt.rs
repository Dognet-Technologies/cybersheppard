// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - JWT Utilities
// ============================================================================

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,           // User ID
    pub username: String,   // Username
    pub role: String,       // User role
    pub exp: i64,          // Expiration timestamp
    pub iat: i64,          // Issued at timestamp
    pub token_type: String, // "access" or "refresh"
}

#[derive(Debug)]
pub enum JwtError {
    InvalidToken,
    ExpiredToken,
    MissingSecret,
    EncodingError,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::InvalidToken => write!(f, "Invalid token"),
            JwtError::ExpiredToken => write!(f, "Token has expired"),
            JwtError::MissingSecret => write!(f, "JWT secret not configured"),
            JwtError::EncodingError => write!(f, "Failed to encode token"),
        }
    }
}

impl std::error::Error for JwtError {}

/// Generate an access token (15 minutes validity)
pub fn generate_access_token(
    user_id: i32,
    username: &str,
    role: &str,
) -> Result<String, JwtError> {
    let secret = env::var("JWT_SECRET").map_err(|_| JwtError::MissingSecret)?;

    let now = Utc::now();
    let expiration = now + Duration::minutes(15);

    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        role: role.to_string(),
        exp: expiration.timestamp(),
        iat: now.timestamp(),
        token_type: "access".to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| JwtError::EncodingError)
}

/// Generate a refresh token (7 days validity)
pub fn generate_refresh_token(
    user_id: i32,
    username: &str,
    role: &str,
) -> Result<String, JwtError> {
    let secret = env::var("JWT_REFRESH_SECRET").map_err(|_| JwtError::MissingSecret)?;

    let now = Utc::now();
    let expiration = now + Duration::days(7);

    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        role: role.to_string(),
        exp: expiration.timestamp(),
        iat: now.timestamp(),
        token_type: "refresh".to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| JwtError::EncodingError)
}

/// Validate and decode an access token
pub fn validate_access_token(token: &str) -> Result<Claims, JwtError> {
    let secret = env::var("JWT_SECRET").map_err(|_| JwtError::MissingSecret)?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        if e.to_string().contains("ExpiredSignature") {
            JwtError::ExpiredToken
        } else {
            JwtError::InvalidToken
        }
    })?;

    if token_data.claims.token_type != "access" {
        return Err(JwtError::InvalidToken);
    }

    Ok(token_data.claims)
}

/// Validate and decode a refresh token
pub fn validate_refresh_token(token: &str) -> Result<Claims, JwtError> {
    let secret = env::var("JWT_REFRESH_SECRET").map_err(|_| JwtError::MissingSecret)?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        if e.to_string().contains("ExpiredSignature") {
            JwtError::ExpiredToken
        } else {
            JwtError::InvalidToken
        }
    })?;

    if token_data.claims.token_type != "refresh" {
        return Err(JwtError::InvalidToken);
    }

    Ok(token_data.claims)
}

/// Extract token from Authorization header (Bearer token)
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    if auth_header.starts_with("Bearer ") {
        Some(auth_header[7..].to_string())
    } else {
        None
    }
}
