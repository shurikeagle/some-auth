use std::{fmt, sync::Arc};

use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::Algorithm;
use regex::Regex;

use crate::{error::AuthError, hasher, jwt::{self, JwtTokenSettings, TokenPair}, repository::AuthRepository};

/// Provides access logic for specified [`AuthUser`]
pub struct UserService<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    jwt_algorithm: Algorithm,
    jwt_token_settings: JwtTokenSettings,
    cred_validator: CredentialValidator,
    repository: Arc<dyn AuthRepository<TAuthUser> + Sync + Send>
}

impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> UserService<TAuthUser> {
    /// Creates new user and returns created id
    pub async fn create_user(&self, username: String, password: String, admin: bool) -> Result<i32, AuthError> {
        if let Some(_) = self.repository.get_user_by_username(&username).await.map_err(|err| AuthError::AuthRepositoryError(err))? {
            return Err(AuthError::UsernameUnavailable)
        }

        (self.cred_validator.validate_username)(&username)?;
        (self.cred_validator.validate_password)(&password)?;

        let pwd_hash = hasher::bcrypt_hash(&password)?;

        let user = TAuthUser::new(username, pwd_hash, admin);

        self.repository.add_user(&user).await.map_err(|err| AuthError::AuthRepositoryError(err))
    }

    /// Updates password for user with provided `access_token`
    pub async fn update_own_password(&self, access_token: &str, old_password: &str, new_password: String) -> Result<(), AuthError> {
        let mut user = self.get_authenticated_user(access_token, false).await?;

        let check_old_pwd_res = hasher::bcrypt_verify(old_password, user.pwd_hash())?;
        if !check_old_pwd_res {
            return Err(AuthError::InvalidCredentials);
        }

        (self.cred_validator.validate_password)(&new_password)?;

        let new_pwd_hash = hasher::bcrypt_hash(&new_password)?;

        user.set_pwd_hash(new_pwd_hash);
        user.set_updated_at(Utc::now());

        _ = self.repository.update_user_refresh_token(user.id(), "",Utc::now()).await;
        
        self.repository.update_user(&user).await.map_err(|err| AuthError::AuthRepositoryError(err))
    }

    /// Updates user password by provided admin `admin_access_token`.
    /// 
    /// Note that this method doesn't use [`CredentialValidator`] for a new password validation to reset password to some default value for example
    pub async fn update_user_password_by_admin(&self, admin_access_token: &str, admin_password: &str, target_user_id: i32, target_user_new_password: String) -> Result<(), AuthError> {
        let admin = self.get_authenticated_user(admin_access_token, true).await?;

        if admin.id() == target_user_id {
            return Err(AuthError::InvalidOperation("method is not available to update own password".to_string()));
        }

        let check_old_pwd_res = hasher::bcrypt_verify(admin_password, admin.pwd_hash())?;
        if !check_old_pwd_res {
            return Err(AuthError::InvalidCredentials);
        }

        let mut target_user = self.repository.get_user(target_user_id)
            .await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::UserNotFound(format!("{target_user_id}")))?;

        if target_user.blocked() {
            return Err(AuthError::InvalidOperation("user is blocked".to_string()));
        }

        let new_target_user_pwd_hash = hasher::bcrypt_hash(&target_user_new_password)?;

        target_user.set_pwd_hash(new_target_user_pwd_hash);
        target_user.set_updated_at(Utc::now());

        _ = self.repository.update_user_refresh_token(target_user_id, "",Utc::now()).await;
        
        self.repository.update_user(&target_user).await.map_err(|err| AuthError::AuthRepositoryError(err))
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
            .map_err(|err| AuthError::AuthRepositoryError(format!("user {username} was blocked, but refresh token wasn't cleared in repository: {err}")))
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

        let token_pair = self.generate_token_pair(user.id(), user.admin())?;

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

        let token_pair = self.generate_token_pair(user_id, decoded_token.claims.admin)?;

        self.update_hashed_refresh_in_repo(user_id, &token_pair.refresh).await?;

        Ok(token_pair)
    }

    pub(crate) async fn get_authenticated_user(&self, access_token: &str, check_if_admin: bool) -> Result<TAuthUser, AuthError> {
        let decoded_token = jwt::decode_token(
            access_token,
            self.jwt_algorithm,
            self.jwt_token_settings.access_tokens_secret.as_bytes())?;

        if check_if_admin && !decoded_token.claims.admin {
            return Err(AuthError::InvalidCredentials);
        }

        let user_id: i32 = decoded_token.claims.sub.parse().map_err(|_| AuthError::InvalidCredentials)?;

        let user = self.repository.get_user(user_id)
            .await
            .map_err(|err| AuthError::AuthRepositoryError(err))?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.blocked() {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(user)
    }

    async fn update_hashed_refresh_in_repo(&self, user_id: i32, refresh_token: &str) -> Result<(), AuthError> {
        let refresh_token_hash = hasher::sha256_hash(&refresh_token);
        
        Ok(self.repository.update_user_refresh_token(user_id, &refresh_token_hash,Utc::now()).await
            .map_err(|err| AuthError::AuthRepositoryError(err))?)
    }

    fn generate_token_pair(&self, user_id: i32, admin: bool) -> Result<TokenPair, AuthError> {
        let refresh_token = jwt::generate_token(
            user_id,
            admin,
            self.jwt_algorithm,
            self.jwt_token_settings.refresh_tokens_lifetime,
            self.jwt_token_settings.refresh_tokens_secret.as_bytes())?;

        let access_token = jwt::generate_token(
            user_id,
            admin,
            self.jwt_algorithm,
            self.jwt_token_settings.access_tokens_lifetime,
            self.jwt_token_settings.access_tokens_secret.as_bytes())?;

        Ok(TokenPair {
            access: access_token,
            refresh: refresh_token
        })
    }
}

/// Builder to configure and build [`UserService`]
pub struct UserServiceBuilder<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    jwt_algorithm: Option<Algorithm>,
    jwt_token_settings: Option<JwtTokenSettings>,
    cred_validator: Option<CredentialValidator>,
    repository: Option<Arc<dyn AuthRepository<TAuthUser> + Sync + Send>>
}

/// Creates default builder with the following configuration:
/// + Default [`User`] model
/// + [`CredentialValidator::default`] credential validator
/// + JWT algorithm: [`Algorithm::HS256`]
pub fn default_builder() -> UserServiceBuilder<User> {
    builder()
        .set_credential_validator(CredentialValidator::default())
        .set_jwt_algorithm(Algorithm::HS256)
}

/// Creates builder to configure and build [`UserService`].
/// See also [`AuthUser`]
pub fn builder<TAuthUser: AuthUser + fmt::Debug + Send + Sync>() -> UserServiceBuilder<TAuthUser> {
    UserServiceBuilder {
        jwt_algorithm: None,
        jwt_token_settings: None,
        cred_validator: None,
        repository: None
    }
}

impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> UserServiceBuilder<TAuthUser> {
    /// Sets [`CredentialValidator`] which will be used to valudate [`AuthUser`] credentials in [`UserService`]
    pub fn set_credential_validator(mut self, validator: CredentialValidator) -> Self {
        self.cred_validator = Some(validator);

        self
    }

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
            cred_validator: self.cred_validator.ok_or("Credential validator must be set")?,
            repository: self.repository.ok_or("User service repository can't be empty")?
        })
    }
}

/// Credential validator which is used in [`UserService`] to validate [`AuthUser`]
pub struct CredentialValidator {
    /// Validates if username meets the minimum requirements
    pub validate_username: fn(&str) -> Result<(), AuthError>,
    /// Validates if password meets the minimum requirements
    pub validate_password: fn(&str) -> Result<(), AuthError>
}

impl CredentialValidator {
    fn default() -> CredentialValidator {
        let username_validator = |username: &str| {
            const USERNAME_REQS: &str = 
            "username must be at least 5 characters, a combination of latin letters and numbers with one letter at least";

            let length_check = username.len() >= 5;
            let valid_chars_check = Regex::new(r"^[a-zA-Z0-9]+$").unwrap().is_match(username);
            let contains_letter_check = Regex::new(r"[a-zA-Z]").unwrap().is_match(username);

            if !(length_check && valid_chars_check && contains_letter_check) {
                return Err(AuthError::ValidationError(USERNAME_REQS.to_string()))
            }

            Ok(())
        };

        let password_validator = |password: &str| {
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
        };

        CredentialValidator {
            validate_username: username_validator,
            validate_password: password_validator
        }
    }
}

/// User in auth context
pub trait AuthUser {
    /// Creates new user
    /// (implement validation in  validation requires in implementation)
    fn new(username: String, pwd_hash: String, admin: bool) -> Self;

    /// for mapping purposes
    fn existing(id: i32, username: String, pwd_hash: String, admin: bool, blocked: bool, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self;

    // getters
    fn id(&self) -> i32;
    fn username(&self) -> &str;
    /// Password hash
    fn pwd_hash(&self) -> &str;
    fn admin(&self) -> bool;
    fn blocked(&self) -> bool;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;

    // setters
    fn set_pwd_hash(&mut self, value: String);
    fn set_updated_at(&mut self, value: DateTime<Utc>);
    fn set_blocked(&mut self, value: bool);
}

/// Default implementation of [`AuthUser`]
#[derive(Clone)]
pub struct User {
    id: i32,
    username: String,
    pwd_hash: String,
    admin: bool,
    blocked: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("pwd_hash", &"***")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("blocked", &self.admin)
            .field("blocked", &self.blocked)
            .finish()
    }
}

impl AuthUser for User {
    fn new(username: String, pwd_hash: String, admin: bool) -> Self {
        let now: DateTime<Utc> = Utc::now();

        User {
            id: 0,
            username,
            pwd_hash,
            admin,
            blocked: false,
            created_at: now,
            updated_at: now,
        }
    }
    
    fn existing(id: i32, username: String, pwd_hash: String, admin: bool, blocked: bool, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        User {
            id,
            username,
            pwd_hash,
            admin,
            blocked,
            created_at,
            updated_at            
        }
    }

    fn id(&self) -> i32 { self.id }
    fn username(&self) -> &str { &self.username }
    fn pwd_hash(&self) -> &str { &self.pwd_hash }
    fn admin(&self) -> bool { self.admin }
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
        let validator = CredentialValidator::default();
        let username = "u1s2e3r";

        let res = (validator.validate_username)(username);

        assert!(res.is_ok())
    }

    #[test]
    fn validate_username_0_only_letters_0_ok() {
        let validator = CredentialValidator::default();
        let username = "userr";

        let res = (validator.validate_username)(username);

        assert!(res.is_ok())
    }

    #[test]
    fn validate_username_0_only_numbers_0_err() {
        let validator = CredentialValidator::default();
        let username = "12345";

        let res = (validator.validate_username)(username);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_username_0_too_short_0_err() {
        let validator = CredentialValidator::default();
        let username = "user";

        let res = (validator.validate_username)(username);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_username_0_non_latin_0_err() {
        let validator = CredentialValidator::default();
        let username = "ユーザー";

        let res = (validator.validate_username)(username);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_all_requirements_0_ok() {
        let validator = CredentialValidator::default();
        let password = "1qaz@WSX3edc";

        let res = (validator.validate_password)(password);

        assert!(res.is_ok())
    }

    #[test]
    fn validate_password_0_no_special_simbols_0_err() {
        let validator = CredentialValidator::default();
        let password = "1qaz2WSX3edc";

        let res = (validator.validate_password)(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_no_digits_0_err() {
        let validator = CredentialValidator::default();
        let password = "!qaz@WSX#edc";

        let res = (validator.validate_password)(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_no_uppercases_0_err() {
        let validator = CredentialValidator::default();
        let password = "1qaz@wsx#edc";

        let res = (validator.validate_password)(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_no_lowercases_0_err() {
        let validator = CredentialValidator::default();
        let password = "1QAZ@WSX3EDC";

        let res = (validator.validate_password)(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[test]
    fn validate_password_0_too_short_0_err() {
        let validator = CredentialValidator::default();
        let password = "1qaz@WSX";

        let res = (validator.validate_password)(password);

        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("validation"))
    }

    #[tokio::test]
    async fn create_user_test() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let res = user_service.create_user(AVAILABLE_USERNAME.to_string(), "1qaz@WSX3edc".to_string(), false).await;

        //Assert
        assert!(res.is_ok());
        assert_eq!(1, res.unwrap())
    }

    #[tokio::test]
    async fn create_user_0_existing_usernaime_0_returns_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let res = user_service.create_user(EXISTING_USERNAME.to_string(), "1qaz@WSX3edc".to_string(), false).await;

        //Assert
        assert!(res.is_err());
        assert_eq!(AuthError::UsernameUnavailable.to_string(), res.unwrap_err().to_string());
    }

    #[tokio::test]
    async fn create_user_0_non_valid_username_or_password_validation_0_returns_err() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());

        // Act
        let bad_username = user_service.create_user("usr".to_string(), "1qaz@WSX3edc".to_string(), false).await;
        let bad_pwd = user_service.create_user(AVAILABLE_USERNAME.to_string(), "1qaz".to_string(), false).await;

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
        let token_pair = user_service.generate_token_pair(user.id, false).unwrap();

        // Act
        let res = user_service.update_own_password(&token_pair.access, "123", "1qaz@WSX3edc".to_string()).await;

        //Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn update_own_password_0_invalid_password_0_returns_error() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let token_pair = user_service.generate_token_pair(0, false).unwrap();

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
        let token_pair = user_service.generate_token_pair(0, false).unwrap();

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
        let token_pair = user_service.generate_token_pair(0, false).unwrap();

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
    async fn update_user_password_by_admin_test() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let user = get_existing_user(false);
        let admin_token_pair = user_service.generate_token_pair(ADMIN_ID, true).unwrap();

        // Act
        let res = user_service.update_user_password_by_admin(&admin_token_pair.access, "456", user.id(), "1qaz".to_string()).await;

        //Assert
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn update_user_password_by_admin_0_not_admin_0_returns_invalid_credentials() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let user = get_existing_user(false);
        let admin_token_pair = user_service.generate_token_pair(ADMIN_ID, false).unwrap();

        // Act
        let res = user_service.update_user_password_by_admin(&admin_token_pair.access, "456", user.id(), "1qaz".to_string()).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidCredentials => (),
            _ => panic!("Error is not InvalidCredentials")
        }
    }

    #[tokio::test]
    async fn update_user_password_by_admin_0_self_update_0_returns_invalid_operation() {
        // Arrange
        let user_service = build_user_service(false, "".to_string());
        let admin_token_pair = user_service.generate_token_pair(ADMIN_ID, true).unwrap();

        // Act
        let res = user_service.update_user_password_by_admin(&admin_token_pair.access, "456", ADMIN_ID, "1qaz".to_string()).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidOperation(message) => assert!(message.contains("own")),
            _ => panic!("Error is not InvalidOperation")
        }
    }

    #[tokio::test]
    async fn update_user_password_by_admin_0_for_blocked_user_0_returns_invalid_operation() {
        // Arrange
        let user_service = build_user_service(true, "".to_string());
        let user = get_existing_user(false);
        let admin_token_pair = user_service.generate_token_pair(ADMIN_ID, true).unwrap();

        // Act
        let res = user_service.update_user_password_by_admin(&admin_token_pair.access, "456", user.id(), "1qaz".to_string()).await;

        //Assert
        assert!(res.is_err());
        match res.unwrap_err() {
            AuthError::InvalidOperation(message) => assert!(message.contains("blocked")),
            _ => panic!("Error is not InvalidOperation")
        }
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
        let refresh_token_non_existent_user = get_user_refresh_token(100);
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
    const ADMIN_ID: i32 = 42;

    fn build_user_service(blocked_user: bool, user_refresh_token: String) -> UserService<User> {
        let existing_user = get_existing_user(blocked_user);
        let existing_user_clone = existing_user.clone();
        let existing_username = existing_user.username.clone();
        let existing_admin = get_existing_admin();

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
            .with(predicate::function(move |&id| id == ADMIN_ID))
            .returning(move |_| Ok(Some(existing_admin.clone())));
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
            admin: false,
            blocked,
            pwd_hash: hasher::bcrypt_hash("123").unwrap(),
            created_at: now,
            updated_at: now            
        }
    }

    fn get_user_refresh_token(user_id: i32) -> String {
        jwt::generate_token(
            user_id,
            false,
            Algorithm::HS256,
            TimeDelta::days(7),
            "AnotherSup$rS4ccrettt".as_bytes())
            .unwrap()
    }

    fn get_existing_admin() -> User {
        let now = Utc::now();

        User {
            id: ADMIN_ID,
            username: "admin".to_string(),
            admin: true,
            blocked: false,
            pwd_hash: hasher::bcrypt_hash("456").unwrap(),
            created_at: now,
            updated_at: now            
        }
    }
}