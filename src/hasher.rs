use bcrypt::DEFAULT_COST;
use sha2::{Digest, Sha256};

use crate::error::AuthError;

/// Validates and makes a hash of the provided string using bcrypt
pub(crate) fn bcrypt_hash(source_str: &str) -> Result<String, AuthError> {
    let res = bcrypt::hash(source_str, DEFAULT_COST)?;

    Ok(res)
}

/// Checks if provided string's hash is equal to provided hash using bcrypt
pub(crate) fn bcrypt_verify(source_str: &str, hash: &str) -> Result<bool, AuthError> {
    let res = bcrypt::verify(source_str, hash)?;

    Ok(res)
}

/// Creates sha256 hash from source string
pub(crate) fn sha256_hash(source_str: &str) -> String {
    let mut hasher = Sha256::new();

    hasher.update(source_str.as_bytes());
    let hash_result = hasher.finalize();

    hex::encode(hash_result)
}

/// Checks if provided string's hash is equal to provided hash using sha256
pub(crate) fn sha256_verify(source_str: &str, hash: &str) -> bool {
    let source_hash = sha256_hash(source_str);

    source_hash == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcrypt_verify_0_valid_password_0_true() {
        // Arrange
        let password = "1qaz@WSX3edc";
        let hash = bcrypt_hash(password).unwrap();

        // Act
        let verify_result = bcrypt_verify(password, &hash);

        // Assert
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap())
    }

    #[test]
    fn bcrypt_verify_0_invalid_password_0_false() {
        // Arrange
        let password = "1qaz@WSX3edc";
        let hash = bcrypt_hash(password).unwrap();
        let invalid_password = "1qaz2wsx#EDC";

        // Act
        let verify_result = bcrypt_verify(invalid_password, &hash);

        // Assert
        assert!(verify_result.is_ok());
        assert!(!verify_result.unwrap())
    }
}