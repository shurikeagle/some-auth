use std::fmt;

use chrono::{Duration, TimeDelta, Utc};
use jsonwebtoken::{decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// Access-Refresh token pair
#[derive(Serialize)]
pub struct TokenPair {
    pub access: String,
    pub refresh: String
}

impl fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenPair")
            .field("access", &"***")
            .field("refresh", &"***")
            .finish()
    }
}

/// Jwt settings for [`UserService`] configuration
pub struct JwtTokenSettings {
    pub access_tokens_secret: String,
    pub access_tokens_lifetime: TimeDelta,
    pub refresh_tokens_secret: String,
    pub refresh_tokens_lifetime: TimeDelta
}

/// Token's claims
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    pub(crate) sub: String,
    pub(crate) exp: usize,
    pub(crate) roles: Vec<String>
}

pub(crate) fn generate_token(user_id: i32, roles: &Vec<String>, alg: Algorithm, expiration: Duration, key: &[u8]) -> Result<String, AuthError> {
    let exp = Utc::now()
        .checked_add_signed(expiration)
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        roles: roles.iter().map(|s| s.to_string()).collect()
    };

    encode(&Header::new(alg), &claims, &EncodingKey::from_secret(key))
        .map_err(|err| AuthError::Internal(format!("couldn't generate jwt: {err}")))
}

pub(crate) fn decode_token(token: &str, alg: Algorithm, key: &[u8]) -> Result<TokenData<Claims>, AuthError> {
    const BEARER_START: &str = "Bearer ";
    let token = token.strip_prefix(BEARER_START).unwrap_or(token);

    decode::<Claims>(&token, &DecodingKey::from_secret(&key), &Validation::new(alg))
        .map_err(|err| {
            match err.kind() {                
                ErrorKind::ExpiredSignature => AuthError::Unathorized,
                _ => AuthError::InvalidCredentials,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_test() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd";
        let user_id = 1;
        let user_roles = vec!["admin".to_string(), "adm".to_string()];

        // Act
        let generate_token_res = generate_token(user_id, &user_roles, Algorithm::HS256, TimeDelta::seconds(10), key.as_bytes());

        // Arrange
        assert!(generate_token_res.is_ok());
        assert_ne!("", generate_token_res.unwrap())
    }

    #[test]
    fn decode_token_test() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let user_roles = vec!["admin".to_string(), "adm".to_string()];
        let token = generate_token(user_id, &user_roles, Algorithm::HS256, TimeDelta::seconds(10), key).unwrap();

        // Act
        let decoded_token = decode_token(&token, Algorithm::HS256, key);
        
        // Arrange
        assert!(decoded_token.is_ok());
        let decoded_token = decoded_token.unwrap();
        assert_eq!("1", decoded_token.claims.sub);
        assert!(decoded_token.claims.roles.iter().any(|r| r == "admin"));
        assert!(decoded_token.claims.roles.iter().any(|r| r == "adm"));
    }

    #[test]
    fn decode_token_with_bearer_test() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let user_roles = vec!["admin".to_string(), "adm".to_string()];
        let token = format!("Bearer {}", generate_token(user_id, &user_roles, Algorithm::HS256, TimeDelta::seconds(10), key).unwrap());

        // Act
        let decoded_token = decode_token(&token, Algorithm::HS256, key);
        
        // Arrange
        assert!(decoded_token.is_ok());
        let decoded_token = decoded_token.unwrap();
        assert_eq!("1", decoded_token.claims.sub);
        assert!(decoded_token.claims.roles.iter().any(|r| r == "admin"));
        assert!(decoded_token.claims.roles.iter().any(|r| r == "adm"));
    }

    #[test]
    fn decode_token_0_expired_token_0_invalid() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let token = generate_token(user_id, &vec![], Algorithm::HS256, TimeDelta::minutes(-2), key).unwrap();

        // Act
        let decoded_token = decode_token(&token, Algorithm::HS256, key);
        
        // Arrange
        assert!(decoded_token.is_err());
        assert!(decoded_token.unwrap_err().to_string().contains("Unathorized"))
    }

    #[test]
    fn decode_token_0_spoofed_token_0_invalid() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let token = generate_token(user_id, &vec![], Algorithm::HS256, TimeDelta::seconds(10), key).unwrap();
        // {"sub":"2","iat":1718955601}
        let spoofed_part = "eyJzdWIiOiIyIiwiaWF0IjoxNzE4OTU1NjAxfQ";

        // Act
        let token_parts: Vec<_> = token.split('.').collect();
        let spoofed_token = format!("{}.{}.{}", token_parts[0], spoofed_part, token_parts[2]);
        let decoded_token = decode_token(&spoofed_token, Algorithm::HS256, key);

        // Arrange
        assert!(decoded_token.is_err());
        assert!(decoded_token.unwrap_err().to_string().contains("Invalid credentials"))
    }
}