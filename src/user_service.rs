use std::{fmt, sync::Arc};

use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::Algorithm;
use regex::Regex;

use crate::{error::AuthError, hasher, jwt::{self, JwtTokenSettings, TokenPair}, repository::AuthRepository};

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

/// Provides access logic for specified [`AuthUser`]
pub struct UserService<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    jwt_algorithm: Algorithm,
    jwt_token_settings: JwtTokenSettings,
    repository: Arc<dyn AuthRepository<TAuthUser> + Sync + Send>
}

//TODO: Tests
impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> UserService<TAuthUser> {
    /// Creates new user and returns created id
    pub async fn create_user(&self, username: String, password: String) -> Result<i32, AuthError> {
        if let Some(_) = self.repository.get_user_by_username(&username).await.map_err(|err| AuthError::AuthRepositoryError(err))? {
            return Err(AuthError::UsernameUnavailable)
        }

        TAuthUser::validate_username(&username)?;

        TAuthUser::validate_password(&password)?;

        let pwd_hash = hasher::bcrypt_hash(&password)?;

        let user = TAuthUser::new(username, pwd_hash);

        self.repository.add_user(&user).await.map_err(|err| AuthError::AuthRepositoryError(err))
    }

    /// Updates password for user with provided `access_token`
    pub async fn update_own_password(&self, access_token: &str, old_password: &str, password: String) -> Result<(), AuthError> {
        let decoded_token = jwt::decode_token(
            access_token,
            self.jwt_algorithm,
            self.jwt_token_settings.access_tokens_secret.as_bytes())?;

        let user_id: i32 = decoded_token.claims.sub.parse().map_err(|_| AuthError::InvalidCredentials)?;

        let mut user = self.repository.get_user(user_id)
            .await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.blocked() {
            return Err(AuthError::InvalidCredentials);
        }

        let check_old_pwd_res = hasher::bcrypt_verify(old_password, user.pwd_hash())?;
        if !check_old_pwd_res {
            return Err(AuthError::InvalidCredentials);
        }

        TAuthUser::validate_password(&password)?;

        let new_pwd_hash = hasher::bcrypt_hash(&password)?;

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

    /// Generates [`TokenPair`] (refresh and access tokens) by credentials
    pub async fn generate_tokens(&self, username: &str, password: &str) -> Result<TokenPair, AuthError> {
        let user = self.repository.get_user_by_username(username).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.blocked() {
            return Err(AuthError::InvalidCredentials);
        }

        let check_pwd_res = hasher::bcrypt_verify(password, user.pwd_hash())?;
        if !check_pwd_res {
            return Err(AuthError::InvalidCredentials);
        }

        let token_pair = self.generate_token_pair(user.id())?;

        self.update_hashed_refresh_in_repo(user.id(), &token_pair.refresh).await?;

        Ok(token_pair)
    }

    /// Refreshes [`TokenPair`] by refresh token
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let decoded_token = jwt::decode_token(
            refresh_token,
            self.jwt_algorithm,
            self.jwt_token_settings.refresh_tokens_secret.as_bytes())?;

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
        if !hasher::sha256_verify(refresh_token, &stored_token_hash) {
            // if something's wrong, revoke old refresh token from repository too
            _ = self.repository.update_user_refresh_token(user_id, "",Utc::now()).await;

            return Err(AuthError::InvalidCredentials);
        }

        let token_pair = self.generate_token_pair(user_id)?;

        self.update_hashed_refresh_in_repo(user_id, &token_pair.refresh).await?;

        Ok(token_pair)
    }

    fn generate_token_pair(&self, user_id: i32) -> Result<TokenPair, AuthError> {
        let refresh_token = jwt::generate_token(
            user_id,
            self.jwt_algorithm,
            self.jwt_token_settings.refresh_tokens_lifetime,
            self.jwt_token_settings.refresh_tokens_secret.as_bytes())?;

        let access_token = jwt::generate_token(
            user_id,
            self.jwt_algorithm,
            self.jwt_token_settings.access_tokens_lifetime,
            self.jwt_token_settings.access_tokens_secret.as_bytes())?;

        Ok(TokenPair {
            access: access_token,
            refresh: refresh_token
        })
    }

    async fn update_hashed_refresh_in_repo(&self, user_id: i32, refresh_token: &str) -> Result<(), AuthError> {
        let refresh_token_hash = hasher::sha256_hash(&refresh_token);
        
        Ok(self.repository.update_user_refresh_token(user_id, &refresh_token_hash,Utc::now()).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?)
    }
}

/// Builder to configure and build [`UserService`]
pub struct UserServiceBuilder<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    jwt_algorithm: Option<Algorithm>,
    jwt_token_settings: Option<JwtTokenSettings>,
    repository: Option<Arc<dyn AuthRepository<TAuthUser> + Sync + Send>>
}

/// Creates default builder with the following configuration:
/// + Default [`User`] model
/// + JWT algorithm: [`Algorithm::HS256`]
pub fn default_builder() -> UserServiceBuilder<User> {
    builder().set_jwt_algorithm(Algorithm::HS256)
}

/// Creates builder to configure and build [`UserService`].
/// See also [`AuthUser`]
pub fn builder<TAuthUser: AuthUser + fmt::Debug + Send + Sync>() -> UserServiceBuilder<TAuthUser> {
    UserServiceBuilder {
        jwt_algorithm: None,
        jwt_token_settings: None,
        repository: None
    }
}

impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> UserServiceBuilder<TAuthUser> {
    /// Sets jwt algorithm which will be used in [`UserService`]
    /// 
    /// Note that only HMAC (HS256, HS384, HS512) algorithms are supported now
    pub fn set_jwt_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.jwt_algorithm = Some(algorithm);

        self
    }

    /// Sets jwt token settings which will be used in [`UserService`]
    /// 
    /// Note that access and refresh token secrets are expected as raw string regardless of the chosen jwt algorithm
    pub fn configure_jwt(mut self, jwt_token_settings: JwtTokenSettings) -> Self {
        self.jwt_token_settings = Some(jwt_token_settings);

        self
    }

    /// Sets the repository which will be used in [`UserService`]
    pub fn use_repository(mut self, repository: Arc<dyn AuthRepository<TAuthUser> + Sync + Send>) -> Self {
        self.repository = Some(repository);

        self
    }

    /// Builds [`UserService`] 
    /// 
    /// Returns error, if there are some validation problems or some of the required dependencies are not configured
    pub fn build(self) -> Result<UserService<TAuthUser>, &'static str> {        
        let jwt_token_settings = self.jwt_token_settings.ok_or("User service jwt settings can't be empty")?;
        
        if jwt_token_settings.access_tokens_secret == "" || jwt_token_settings.refresh_tokens_secret == "" {
            return Err("Access and refresh token secrets can't be empty")
        }

        if jwt_token_settings.access_tokens_lifetime <= TimeDelta::zero() || jwt_token_settings.refresh_tokens_lifetime <= TimeDelta::zero() {
            return Err("Access and refresh token lifetimes must be positive")
        }

        let jwt_alg: Algorithm = self.jwt_algorithm.ok_or("JWT algorithm must be set")?;
        if jwt_alg != Algorithm::HS256 && jwt_alg != Algorithm::HS384 && jwt_alg != Algorithm::HS512 {
            return Err("Only HMAC (HS256, HS384, HS512) algorithms are supported now")
        }

        Ok(UserService {
            jwt_algorithm: self.jwt_algorithm.ok_or("JWT algorithm must be set")?,
            jwt_token_settings,
            repository: self.repository.ok_or("User service repository can't be empty")?
        })
    }
}

/// Default implementation of [`AuthUser`]
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

#[cfg(test)]
mod tests {    
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
}