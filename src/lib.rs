use std::{fmt, sync::Arc};

use async_trait::async_trait;
use bcrypt::{BcryptError, DEFAULT_COST};
use chrono::{DateTime, Duration, TimeDelta, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// User in auth context
pub trait AuthUser {
    /// Creates new user
    /// (implement validation in  validation requires in implementation)
    fn new(username: String, pwd_hash: String) -> Self;

    /// for mapping purposes
    fn existing(id: i32, username: String, pwd_hash: String, blocked: bool, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self;

    /// Validates if provided username meets the minimum requirements
    fn validate_username(username: &str) -> Result<(), AuthError>;
    /// Validates if provided password meets the minimum requirements
    fn validate_password(password: &str) -> Result<(), AuthError>;

    // getters
    fn id(&self) -> i32;
    fn username(&self) -> &str;
    fn pwd_hash(&self) -> &str;
    fn blocked(&self) -> bool;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;

    // setters
    fn set_pwd_hash(&mut self, value: String);
    fn set_updated_at(&mut self, value: DateTime<Utc>);
    fn set_blocked(&mut self, value: bool);
}

/// Auth repository which is used in `UserService`
#[async_trait]
pub trait AuthRepository<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    /// returns created id
    async fn add_user(&self, user: &TAuthUser) -> Result<i32, String>;
    async fn update_user(&self, user: &TAuthUser) -> Result<(), String>;
    async fn get_user(&self, id: i32) -> Result<Option<TAuthUser>, String>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<TAuthUser>, String>;
    async fn update_user_refresh_token(&self, user_id: i32, token_hash: &str, time_updated: DateTime<Utc>) -> Result<(), String>;
    /// returns token's hash
    async fn get_user_refresh_token(&self, user_id: i32) -> Result<Option<String>, String>;
}

/// Provides access logic for `TAuthUser`
pub struct UserService<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    settings: UserServiceSettings,
    repository: Arc<dyn AuthRepository<TAuthUser> + Sync + Send>
}

/// Access-Refresh token pair
#[derive(Serialize)]
pub struct TokenPair {
    pub access: String,
    pub refresh: String
}

/// Settings for `UserService`` configuration
pub struct UserServiceSettings {
    pub access_tokens_secret: String,
    pub access_tokens_lifetime: TimeDelta,
    pub refresh_tokens_secret: String,
    pub refresh_tokens_lifetime: TimeDelta
}

/// Builder to configure and build `UserService`
pub struct UserServiceBuilder<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    settings: Option<UserServiceSettings>,
    repository: Option<Arc<dyn AuthRepository<TAuthUser> + Sync + Send>>
}

pub fn default_builder() -> UserServiceBuilder<User> {
    builder()
}

/// Creates builder to configure and build `UserService`.
/// See also `AuthUser`
pub fn builder<TAuthUser: AuthUser + fmt::Debug + Send + Sync>() -> UserServiceBuilder<TAuthUser> {
    UserServiceBuilder {
        settings: None,
        repository: None
    }
}

impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> UserServiceBuilder<TAuthUser> {
    /// Sets the settings which will be used in `UserService`
    pub fn configure(mut self, settings: UserServiceSettings) -> Self {
        self.settings = Some(settings);

        self
    }

    /// Sets the repository which will be used in `UserService`
    pub fn use_repository(mut self, repository: Arc<dyn AuthRepository<TAuthUser> + Sync + Send>) -> Self {
        self.repository = Some(repository);

        self
    }

    /// Builds `UserService`. Returns error, if there are some validation problems or some of the required dependencies are not configured
    pub fn build(self) -> Result<UserService<TAuthUser>, &'static str> {
        if self.settings.is_none() {
            return Err("User service settings can't be empty");
        }

        if self.repository.is_none() {
            return Err("User service repository can't be empty");
        }

        // TODO: Additional validation of settings (positive exp times, not empty secrets, etc)

        Ok(UserService {
            settings: self.settings.unwrap(),
            repository: self.repository.unwrap()
        })
    }
}

//TODO: Tests
impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> UserService<TAuthUser> {
    /// Creates new user and returns created id
    pub async fn create_user(&self, username: String, password: String) -> Result<i32, AuthError> {
        if let Some(_) = self.repository.get_user_by_username(&username).await.map_err(|err| AuthError::AuthRepositoryError(err))? {
            return Err(AuthError::UsernameUnavailable)
        }

        User::validate_username(&username)?;

        User::validate_password(&password)?;

        let pwd_hash = EncryptionService::bcrypt_hash(&password)?;

        let user = TAuthUser::new(username, pwd_hash);

        self.repository.add_user(&user).await.map_err(|err| AuthError::AuthRepositoryError(err))
    }

    /// Updates password for user with provided access_token
    pub async fn update_own_password(&self, access_token: &str, old_password: &str, password: String) -> Result<(), AuthError> {
        let decoded_token = JwtService::decode_token(access_token, self.settings.access_tokens_secret.as_bytes())?;

        let user_id: i32 = decoded_token.claims.sub.parse().map_err(|_| AuthError::InvalidCredentials)?;

        let mut user = self.repository.get_user(user_id)
            .await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.blocked() {
            return Err(AuthError::InvalidCredentials);
        }

        let check_old_pwd_res = EncryptionService::bcrypt_verify(old_password, user.pwd_hash())?;
        if !check_old_pwd_res {
            return Err(AuthError::InvalidCredentials);
        }

        User::validate_password(&password)?;

        let new_pwd_hash = EncryptionService::bcrypt_hash(&password)?;

        user.set_pwd_hash(new_pwd_hash);
        user.set_updated_at(Utc::now());

        _ = self.repository.update_user_refresh_token(user_id, "",Utc::now()).await;
        
        self.repository.update_user(&user).await.map_err(|err| AuthError::AuthRepositoryError(err))
    }

    /// Blocks user with provided username
    pub async fn block_user(&self, username: &str) -> Result<(), AuthError> {
        let mut user = self.repository.get_user_by_username(username).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::UserNotFound(username.to_string()))?;

        user.set_blocked(true);
        user.set_updated_at(Utc::now());


        self.repository.update_user(&user).await.map_err(|err| AuthError::AuthRepositoryError(err))?;

        self.repository.update_user_refresh_token(user.id(), "",Utc::now()).await
            .map_err(|err| AuthError::AuthRepositoryError(format!("User {username} was blocked, but refresh token wasn't cleared in repository: {err}")))
    }

    /// Generates `TokenPair` (refresh and access tokens) by credentials
    pub async fn generate_tokens(&self, username: &str, password: &str) -> Result<TokenPair, AuthError> {
        let user = self.repository.get_user_by_username(username).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.blocked() {
            return Err(AuthError::InvalidCredentials);
        }

        let check_pwd_res = EncryptionService::bcrypt_verify(password, user.pwd_hash())?;
        if !check_pwd_res {
            return Err(AuthError::InvalidCredentials);
        }

        let token_pair = self.generate_token_pair(user.id())?;

        self.update_hashed_refresh_in_repo(user.id(), &token_pair.refresh).await?;

        Ok(token_pair)
    }

    /// Refreshes `TokenPair` by refresh token
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let decoded_token = JwtService::decode_token(refresh_token, self.settings.refresh_tokens_secret.as_bytes())?;

        let user_id: i32 = decoded_token.claims.sub.parse().map_err(|_| AuthError::InvalidCredentials)?;
        let user = self.repository.get_user(user_id).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.blocked() {
            return Err(AuthError::InvalidCredentials);
        }

        // Ensure that token is actual
        let stored_token_hash = self.repository.get_user_refresh_token(user_id).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;
        if !EncryptionService::sha256_verify(refresh_token, &stored_token_hash) {
            // if something's wrong, revoke old refresh token from repository too
            _ = self.repository.update_user_refresh_token(user_id, "",Utc::now()).await;

            return Err(AuthError::InvalidCredentials);
        }

        let token_pair = self.generate_token_pair(user_id)?;

        self.update_hashed_refresh_in_repo(user_id, &token_pair.refresh).await?;

        Ok(token_pair)
    }

    fn generate_token_pair(&self, user_id: i32) -> Result<TokenPair, AuthError> {
        let refresh_token = JwtService::generate_token(
            user_id,
            self.settings.refresh_tokens_lifetime,
            self.settings.refresh_tokens_secret.as_bytes())?;

        let access_token = JwtService::generate_token(
            user_id,
            self.settings.access_tokens_lifetime,
            self.settings.access_tokens_secret.as_bytes())?;

        Ok(TokenPair {
            access: access_token,
            refresh: refresh_token
        })
    }

    async fn update_hashed_refresh_in_repo(&self, user_id: i32, refresh_token: &str) -> Result<(), AuthError> {
        let refresh_token_hash = EncryptionService::sha256_hash(&refresh_token);
        
        Ok(self.repository.update_user_refresh_token(user_id, &refresh_token_hash,Utc::now()).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?)
    }
}

/// Default implementation of `AuthUser`
pub struct User {
    id: i32,
    username: String,
    pwd_hash: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    blocked: bool
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwilioSenderConfig")
            .field("account", &self.id)
            .field("sender_number", &self.username)
            .field("pwd_hash", &"***").finish()
    }
}

impl AuthUser for User {
    fn new(username: String, pwd_hash: String) -> Self {
        let now: DateTime<Utc> = Utc::now();

        User {
            id: 0,
            username,
            pwd_hash,
            blocked: false,
            created_at: now,
            updated_at: now
        }
    }

    fn existing(id: i32, username: String, pwd_hash: String, blocked: bool, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        User {
            id,
            username,
            pwd_hash,
            blocked,
            created_at,
            updated_at
        }
    }

    fn validate_username(username: &str) -> Result<(), AuthError> {
        const USERNAME_REQS: &str = 
            "username must be at least 5 characters, a combination of latin letters and numbers with one letter at least";

        let length_check = username.len() >= 5;
        let valid_chars_check = Regex::new(r"^[a-zA-Z0-9]+$").unwrap().is_match(username);
        let contains_letter_check = Regex::new(r"[a-zA-Z]").unwrap().is_match(username);

        if !(length_check && valid_chars_check && contains_letter_check) {
            return Err(AuthError::ValidationError(USERNAME_REQS.to_string()))
        }

        Ok(())
    }

    fn validate_password(password: &str) -> Result<(), AuthError> {
        const PWD_REQS: &str = 
            "password must be at least 12 characters, a combination of latin uppercase and lowercase letters, numbers, and special symbols";

        let length_check = password.len() >= 12;
        let digit_check = Regex::new(r"\d").unwrap().is_match(password);
        let uppercase_check = Regex::new(r"[A-Z]").unwrap().is_match(password);
        let lowercase_check = Regex::new(r"[a-z]").unwrap().is_match(password);
        let special_char_check = Regex::new(r#"[!@#$%^&*(),.?\":{}|<>]"#).unwrap().is_match(password);
    
        if !(length_check && digit_check && uppercase_check && lowercase_check && special_char_check) {
            return Err(AuthError::ValidationError(PWD_REQS.to_string()))
        }

        Ok(())
    }

    fn id(&self) -> i32 { self.id }
    fn username(&self) -> &str { &self.username }
    fn pwd_hash(&self) -> &str { &self.pwd_hash }
    fn blocked(&self) -> bool { self.blocked }
    fn created_at(&self) -> DateTime<Utc> { self.created_at }
    fn updated_at(&self) -> DateTime<Utc> { self.updated_at }
    
    fn set_pwd_hash(&mut self, value: String) { self.pwd_hash = value; }    
    fn set_updated_at(&mut self, value: DateTime<Utc>) { self.updated_at = value; }    
    fn set_blocked(&mut self, value: bool) { self.blocked = value; }
}

/// Provides encryption operations
struct EncryptionService;

// TODO: Check all returns with '?' and handle some of them to avoid details in errors
// Log these details instead
impl EncryptionService {
    /// Validates and makes a hash of the provided string using bcrypt
    fn bcrypt_hash(source_str: &str) -> Result<String, AuthError> {
        let res = bcrypt::hash(source_str, DEFAULT_COST)?;

        Ok(res)
    }
    
    /// Checks if provided string's hash is equal to provided hash 
    fn bcrypt_verify(source_str: &str, hash: &str) -> Result<bool, AuthError> {
        match bcrypt::verify(source_str, hash) {
            Ok(res) => Ok(res),
            Err(err) => Err(err.into()),
        }
    }

    fn sha256_hash(source_str: &str) -> String {
        let mut hasher = Sha256::new();

        hasher.update(source_str.as_bytes());
        let hash_result = hasher.finalize();

        hex::encode(hash_result)
    }

    fn sha256_verify(source_str: &str, hash: &str) -> bool {
        let source_hash = EncryptionService::sha256_hash(source_str);

        source_hash == hash
    }
}

/// Token's claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize
}

/// Provides JWT operations
struct JwtService;

// alg HS256
impl JwtService {
    fn generate_token(user_id: i32, expiration: Duration, key: &[u8]) -> Result<String, AuthError> {

        let exp = Utc::now()
            .checked_add_signed(expiration)
            .unwrap()
            .timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            exp
        };

        encode(&Header::default(), &claims, &EncodingKey::from_secret(key))
            .map_err(|err| AuthError::Internal(format!("couldn't generate jwt: {err}")))
    }

    fn decode_token(token: &str, key: &[u8]) -> Result<TokenData<Claims>, AuthError> {
        decode::<Claims>(&token, &DecodingKey::from_secret(&key), &Validation::default())
            .map_err(|_| AuthError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    #[test]
    fn validate_username_0_with_letters_and_numbers_0_ok() {
        let username = "u1s2e3r";

        let res = User::validate_username(username);

        assert!(res.is_ok())
    }

    #[test]
    fn validate_username_0_only_letters_0_ok() {
        let username = "userr";

        let res = User::validate_username(username);

        assert!(res.is_ok())
    }

    #[test]
    fn validate_username_0_only_numbers_0_err() {
        let username = "12345";

        let res = User::validate_username(username);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_username_0_too_short_0_err() {
        let username = "user";

        let res = User::validate_username(username);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_username_0_non_latin_0_err() {
        let username = "ユーザー";

        let res = User::validate_username(username);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_all_requirements_0_ok() {
        let password = "1qaz@WSX3edc";

        let res = User::validate_password(password);

        assert!(res.is_ok())
    }

    #[test]
    fn validate_password_0_no_special_simbols_0_err() {
        let password = "1qaz2WSX3edc";

        let res = User::validate_password(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_no_digits_0_err() {
        let password = "!qaz@WSX#edc";

        let res = User::validate_password(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_no_uppercases_0_err() {
        let password = "1qaz@wsx#edc";

        let res = User::validate_password(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_no_lowercases_0_err() {
        let password = "1QAZ@WSX3EDC";

        let res = User::validate_password(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_too_short_0_err() {
        let password = "1qaz@WSX";

        let res = User::validate_password(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn bcrypt_verify_0_valid_password_0_true() {
        // Arrange
        let password = "1qaz@WSX3edc";
        let hash = EncryptionService::bcrypt_hash(password).unwrap();

        // Act
        let verify_result = EncryptionService::bcrypt_verify(password, &hash);

        // Assert
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap())
    }

    #[test]
    fn bcrypt_verify_0_invalid_password_0_false() {
        // Arrange
        let password = "1qaz@WSX3edc";
        let hash = EncryptionService::bcrypt_hash(password).unwrap();
        let invalid_password = "1qaz2wsx#EDC";

        // Act
        let verify_result = EncryptionService::bcrypt_verify(invalid_password, &hash);

        // Assert
        assert!(verify_result.is_ok());
        assert!(!verify_result.unwrap())
    }

    #[test]
    fn generate_token_test() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd";
        let user_id = 1;

        // Act
        let generate_token_res = JwtService::generate_token(user_id, TimeDelta::seconds(10), key.as_bytes());

        // Arrange
        assert!(generate_token_res.is_ok());
        assert_ne!("", generate_token_res.unwrap())
    }

    #[test]
    fn decode_token_test() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let token = JwtService::generate_token(user_id, TimeDelta::seconds(10), key).unwrap();

        // Act
        let decoded_token = JwtService::decode_token(&token, key);
        
        // Arrange
        assert!(decoded_token.is_ok());
        assert_eq!("1", decoded_token.unwrap().claims.sub);
    }

    #[test]
    fn decode_token_0_expired_token_0_invalid() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let token = JwtService::generate_token(user_id, TimeDelta::minutes(-2), key).unwrap();

        // Act
        let decoded_token = JwtService::decode_token(&token, key);
        
        // Arrange
        assert!(decoded_token.is_err());
        assert!(decoded_token.unwrap_err().to_string().contains("Invalid credentials"))
    }

    #[test]
    fn decode_token_0_spoofed_token_0_invalid() {
        // Arrange
        let key = "m4HsuPraSekretp455W00rd".as_bytes();
        let user_id = 1;
        let token = JwtService::generate_token(user_id, TimeDelta::seconds(10), key).unwrap();
        // {"sub":"2","iat":1718955601}
        let spoofed_part = "eyJzdWIiOiIyIiwiaWF0IjoxNzE4OTU1NjAxfQ";

        // Act
        let token_parts: Vec<_> = token.split('.').collect();
        let spoofed_token = format!("{}.{}.{}", token_parts[0], spoofed_part, token_parts[2]);
        let decoded_token = JwtService::decode_token(&spoofed_token, key);

        // Arrange
        assert!(decoded_token.is_err());
        assert!(decoded_token.unwrap_err().to_string().contains("Invalid credentials"))
    }
}