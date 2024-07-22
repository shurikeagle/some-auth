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
#[derive(Clone)]
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
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("pwd_hash", &"***")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("blocked", &self.blocked)
            .finish()
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
    use std::{thread::sleep, time::Duration};

    use mockall::predicate;

    use crate::repository::MockAuthRepository;

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

    #[tokio::test]
    async fn create_user_test() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let res = user_service.create_user(AVAILABLE_USERNAME.to_string(), "1qaz@WSX3edc".to_string()).await;

        //Assert
        assert!(res.is_ok());
        assert_eq!(1, res.unwrap())
    }

    #[tokio::test]
    async fn create_user_0_existing_usernaime_0_returns_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let res = user_service.create_user(EXISTING_USERNAME.to_string(), "1qaz@WSX3edc".to_string()).await;

        //Assert
        assert!(res.is_err());
        assert_eq!(AuthError::UsernameUnavailable.to_string(), res.unwrap_err().to_string());
    }

    #[tokio::test]
    async fn create_user_0_non_valid_username_or_password_validation_0_returns_err() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let bad_username = user_service.create_user("usr".to_string(), "1qaz@WSX3edc".to_string()).await;
        let bad_pwd = user_service.create_user(AVAILABLE_USERNAME.to_string(), "1qaz".to_string()).await;

        //Assert
        assert!(bad_username.is_err());
        assert!(bad_pwd.is_err());
        match bad_username.unwrap_err() {
            AuthError::ValidationError(msg) => assert!(msg.contains("username")),
            _ => panic!("Error is not ValidationError")
        };
        match bad_pwd.unwrap_err() {
            AuthError::ValidationError(msg) => assert!(msg.contains("password")),
            _ => panic!("Error is not ValidationError")
        };
    }

    #[tokio::test]
    async fn update_own_password_test() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let user = get_existing_user(false);
        let token_pair = user_service.generate_token_pair(user.id).unwrap();

        // Act
        let res = user_service.update_own_password(&token_pair.access, "123", "1qaz@WSX3edc".to_string()).await;

        //Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn update_own_password_0_invalid_password_0_returns_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let token_pair = user_service.generate_token_pair(0).unwrap();

        // Act
        let res = user_service.update_own_password(&token_pair.access, "321", "1qaz@WSX3edc".to_string()).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        }
    }

    #[tokio::test]
    async fn update_own_password_0_blocked_user_0_returns_error() {
        // Arrange
        let user_service = build_user_service(true, "".to_string());
        let token_pair = user_service.generate_token_pair(0).unwrap();

        // Act
        let res = user_service.update_own_password(&token_pair.access, "123", "1qaz@WSX3edc".to_string()).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        }
    }

    #[tokio::test]
    async fn update_own_password_0_weak_password_0_returns_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let token_pair = user_service.generate_token_pair(0).unwrap();

        // Act
        let res = user_service.update_own_password(&token_pair.access, "123", "321".to_string()).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::ValidationError(msg) => assert!(msg.contains("password")),
            _ => panic!("Error is not ValidationError")
        };
    }

    #[tokio::test]
    async fn block_user_test() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let res = user_service.block_user(EXISTING_USERNAME).await;

        //Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn block_user_0_non_existent_user_0_returns_not_found_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let res = user_service.block_user("somename").await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::UserNotFound(msg) => assert!(msg.contains("somename")),
            _ => panic!("Error is not UserNotFound")
        };
    }

    #[tokio::test]
    async fn generate_tokens_test() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let user = get_existing_user(false);

        // Act
        let res = user_service.generate_tokens(&user.username, "123").await;

        //Assert
        assert!(res.is_ok());
        let token_pair = res.unwrap();
        assert!(token_pair.access != "");
        assert!(token_pair.refresh != "");
    }

    #[tokio::test]
    async fn generate_tokens_0_invalid_password_0_returns_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let user = get_existing_user(false);

        // Act
        let res = user_service.generate_tokens(&user.username, "321").await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        };
    }

    #[tokio::test]
    async fn generate_tokens_0_blocked_user_0_returns_error() {
        // Arrange
        let user_service = build_user_service(true, "".to_string());
        let user = get_existing_user(true);

        // Act
        let res = user_service.generate_tokens(&user.username, "123").await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        };
    }

    #[tokio::test]
    async fn refresh_tokens_test() {
        // Arrange
        let user = get_existing_user(false);
        let refresh_token = get_user_refresh_token(user.id);
        let user_service = build_user_service(false, refresh_token.clone());

        // Act
        let res = user_service.refresh_tokens(&refresh_token).await;

        //Assert
        assert!(res.is_ok());
        let token_pair = res.unwrap();
        assert!(token_pair.access != "");
        assert!(token_pair.refresh != "");
    }

    #[tokio::test]
    async fn refresh_tokens_0_non_existent_user_0_returns_invalid_credentials() {
        // Arrange
        let user = get_existing_user(false);
        let refresh_token = get_user_refresh_token(user.id);
        let refresh_token_non_existent_user = get_user_refresh_token(42);
        let user_service = build_user_service(false, refresh_token.clone());

        // Act
        let res = user_service.refresh_tokens(&refresh_token_non_existent_user).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        };
    }

    #[tokio::test]
    async fn refresh_tokens_0_blocked_user_0_returns_invalid_credentials() {
        // Arrange
        let user = get_existing_user(true);
        let refresh_token = get_user_refresh_token(user.id);
        let user_service = build_user_service(true, refresh_token.clone());

        // Act
        let res = user_service.refresh_tokens(&refresh_token).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        };
    }

    #[tokio::test]
    async fn refresh_tokens_0_unactual_token_0_returns_invalid_credentials() {
        // Arrange
        let user = get_existing_user(false);
        let refresh_token = get_user_refresh_token(user.id);
        sleep(Duration::from_secs(1));
        let new_refresh_token = get_user_refresh_token(user.id);
        let user_service = build_user_service(false, new_refresh_token);

        // Act
        let res = user_service.refresh_tokens(&refresh_token).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        };
    }

    const EXISTING_USERNAME: &str = "existing";
    const AVAILABLE_USERNAME: &str = "admin";

    fn build_user_service(blocked_user: bool, user_refresh_token: String) -> UserService<User> {
        let existing_user = get_existing_user(blocked_user);
        let existing_user_clone = existing_user.clone();
        let existing_username = existing_user.username.clone();

        let builder = default_builder()
            .configure_jwt(JwtTokenSettings {
                access_tokens_lifetime: TimeDelta::minutes(5),
                refresh_tokens_lifetime: TimeDelta::days(7),
                access_tokens_secret: "Sup$rS4ccrettt".to_string(),
                refresh_tokens_secret: "AnotherSup$rS4ccrettt".to_string(),
            });

            
        let mut repository_mock = MockAuthRepository::new();

        repository_mock
            .expect_get_user_by_username()
            .with(predicate::function(move |name| name == existing_username))
            .returning(move |_| Ok(Some(existing_user.clone())));
        repository_mock
            .expect_get_user_by_username()
            .with(predicate::always())
            .returning(move |_| Ok(None));

        repository_mock
            .expect_get_user()
            .with(predicate::always())
            .returning(move |_| Ok(Some(existing_user_clone.clone())));

        repository_mock
            .expect_add_user()
            .with(predicate::always())
            .returning(move |_| Ok(1));

        repository_mock
            .expect_update_user()
            .with(predicate::always())
            .returning(move |_| Ok(()));

        repository_mock
            .expect_update_user_refresh_token()
            .with(predicate::always(), predicate::always(), predicate::always())
            .returning(move |_, _, _| Ok(()));

        repository_mock
            .expect_get_user_refresh_token()
            .with(predicate::always())
            .returning(move |_| Ok(Some(hasher::sha256_hash(&user_refresh_token))));

        builder.use_repository(Arc::new(repository_mock)).build().unwrap()
    }

    fn get_existing_user(blocked: bool) -> User {
        let now = Utc::now();

        User {
            id: 0,
            username: EXISTING_USERNAME.to_string(),
            pwd_hash: hasher::bcrypt_hash("123").unwrap(),
            created_at: now,
            updated_at: now,
            blocked
        }
    }

    fn get_user_refresh_token(user_id: i32) -> String {
        jwt::generate_token(
            user_id,
            Algorithm::HS256,
            TimeDelta::days(7),
            "AnotherSup$rS4ccrettt".as_bytes())
            .unwrap()
    }
}