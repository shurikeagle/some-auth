use std::fmt;

use bcrypt::BcryptError;

/// Errors connected to auth mechanisms
#[derive(Debug)]
pub enum AuthError {
    /// Auth problem connected with some internal error
    Internal(String),
    /// Validation error in auth' domain
    ValidationError(String),
    /// Provided username is unavailable
    UsernameUnavailable,
    /// Invalid credentials. 
    /// This module returns such error in most cases when there are some problems with user validation 
    /// to provide less information for potential intruder
    InvalidCredentials,
    /// Error connected with `UserRepository`
    AuthRepositoryError(String),
    /// User with not found. Inner string represents info about user
    UserNotFound(String)
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Internal(err) => write!(f, "Auth internal error: {err}"),
            AuthError::ValidationError(err) => write!(f, "Auth validation error: {err}"),
            AuthError::UsernameUnavailable => write!(f, "Provided username is unavailable"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::AuthRepositoryError(err) => write!(f, "Auth repository error: {err}"),
            AuthError::UserNotFound(username) => write!(f, "Couldn't find user {username}"),
        }
    }
}

impl From<BcryptError> for AuthError {
    fn from(error: BcryptError) -> Self {
        AuthError::Internal(error.to_string())
    }
}