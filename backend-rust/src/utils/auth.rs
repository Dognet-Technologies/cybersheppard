// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Authentication Utilities
// ============================================================================

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

#[derive(Debug)]
pub enum PasswordError {
    HashingFailed,
    VerificationFailed,
    InvalidHash,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::HashingFailed => write!(f, "Failed to hash password"),
            PasswordError::VerificationFailed => write!(f, "Password verification failed"),
            PasswordError::InvalidHash => write!(f, "Invalid password hash format"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError::HashingFailed)
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHash)?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long".to_string());
    }

    if password.len() > 128 {
        return Err("Password must not exceed 128 characters".to_string());
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_uppercase {
        return Err("Password must contain at least one uppercase letter".to_string());
    }

    if !has_lowercase {
        return Err("Password must contain at least one lowercase letter".to_string());
    }

    if !has_digit {
        return Err("Password must contain at least one digit".to_string());
    }

    if !has_special {
        return Err("Password must contain at least one special character".to_string());
    }

    Ok(())
}

/// Validate email format (basic check)
pub fn validate_email(email: &str) -> bool {
    email.contains('@') && email.contains('.') && email.len() >= 5
}

/// Validate username format
pub fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 {
        return Err("Username must be at least 3 characters long".to_string());
    }

    if username.len() > 32 {
        return Err("Username must not exceed 32 characters".to_string());
    }

    let is_valid = username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-');

    if !is_valid {
        return Err("Username can only contain alphanumeric characters, underscores, and hyphens".to_string());
    }

    Ok(())
}
