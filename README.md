# some-auth

## Main info
This crate provides auth logic usually used in API services (user management and repository, JWT with refresh auth) out of the box.
For a more detailed description of the security methods used in this crate see [Security methods](#Security-methods).

Now, the crate is generally focused on async usage, in particular [Axum](https://github.com/tokio-rs/axum).

This crate optionally (with `axum-auth` feature enabled) advices auth middleware. Now there are only two roles available in this middleware: admin and others.
More flexible role logic (with custom roles) will be implemented in the future.

The crate is under early development right now, some breaking changes may be implemented in the upcoming versions.

## Setup
To use crate's functionallity one need to create `UserSerice` which is created with `UserServiceBuilder`.
### default builder
The easest way to do it is to use `some_auth::default_builder()` method which returns default builder with the following properties:
- default `AuthUser` (`User`) implementation
- default credentials validator (see `CredentialValidator.default()`)
- HMAC SHA-256 algorithm for JWT

The builder requires to specify `AuthRepository` trait implementation with `use_repository` method. Some features with different implementations (pg, mongo for example) will be added into the crate during the time.

Example:
```rust
let repository = Arc::new(PgRepository::create("postgresql://postgres:postgres@localhost:5432/postgres".to_string()).await.unwrap());
let jwt_token_settings = JwtTokenSettings {
    access_tokens_secret: "supersecret".to_string(),
    access_tokens_lifetime: TimeDelta::minutes(10),
    refresh_tokens_secret: "supersecrettoo".to_string(),
    refresh_tokens_lifetime: TimeDelta::days(7)
};
let user_service = some_auth::default_builder()
    .configure_jwt(jwt_token_settings)
    .use_repository(repository)
    .build()
    .unwrap();
```

PgRepository has `impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> AuthRepository<TAuthUser> for PgRepository` where `AuthUser` is `User` in this case.
Thus, you need to specify all the repository methods, e.g.:
```rust
#[async_trait]
impl<TAuthUser: AuthUser + fmt::Debug + Send + Sync> AuthRepository<TAuthUser> for PgRepository {
    async fn add_user(&self, user: &TAuthUser) -> Result<i32, String> {
        let client = open_connection(&self.conn_string).await.map_err(|err| err.to_string())?;

        let created_res = client.query_one("\
            INSERT INTO users (username, pwd_hash, admin, blocked, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id;",
            &[
                &user.username(),
                &user.pwd_hash(),
                &user.admin(),
                &user.blocked(),
                &user.created_at(),
                &user.updated_at()
            ])
            .await
            .map_err(|err| err.to_string())?;

        Ok(created_res.get("id"))
    }

    ...
}
```

You may also use Axum auth middleware to protect your API (available only with `features = [ "axum-auth" ]` feature):
```rust
/// Controls if user is authenticated and optionally checks if user is admin
pub async fn auth_middleware<TAuthUser: AuthUser + fmt::Debug + Send + Sync>(
    State(state): State<Arc<UserServiceState<TAuthUser>>>,
    req: Request,
    next: Next,
    admin_only: bool
) -> Result<Response, AuthError> { ... }
```

```rust
let user_service_state = Arc::new(UserServiceState { user_service });

let router = Router::new()
    .route("/public-route", post(public_route_handler))
    .route("/authenticated-users-route", post(authenticated_users_route_handler))
        .route_layer(middleware::from_fn_with_state(user_service_state, |state, req, next| some_auth::auth_middleware(state, req, next, false))) // false as this route is available for every authenticated user
    .route("/admin-only-route", post(admin_only_route_handler))
        .route_layer(middleware::from_fn_with_state(user_service_state, |state, req, next| some_auth::auth_middleware(state, req, next, true))) // true as this route is available only for authenticated admins
```

### manual setup
To setup `UserService` manually, one need to use:
```rust
pub fn builder<TAuthUser: AuthUser + fmt::Debug + Send + Sync>() -> UserServiceBuilder<TAuthUser>
```

And set all the required configuration with the following methods:
```rust
/// Sets [`CredentialValidator`] which will be used to valudate [`AuthUser`] credentials in [`UserService`]
pub fn set_credential_validator(mut self, validator: CredentialValidator) -> Self

/// Sets jwt algorithm which will be used in [`UserService`]
pub fn set_jwt_algorithm(mut self, algorithm: Algorithm) -> Self

/// Sets jwt token settings which will be used in [`UserService`]
pub fn configure_jwt(mut self, jwt_token_settings: JwtTokenSettings) -> Self

/// Sets the repository which will be used in [`UserService`]
pub fn use_repository(mut self, repository: Arc<dyn AuthRepository<TAuthUser> + Sync + Send>) -> Self
```

## Security methods
### JWT
This crate uses [jsonwebtoken crate](https://github.com/Keats/jsonwebtoken) for JWT. Now, only symmetric crypto algorithms (HMAC with different SHA) are available. The asymethric algorims may be available in the future. JWT secrets and lifetime are configurable.
For the operations which require the refresh token, there is an additional check if provided refresh token is actual (see also [Storing the secrets](#Storing-the-secrets)).

### User validation
To improve application security, default `CredentialValidator` for user credentials has the following rules:
- at least 5 characters, a combination of latin letters and numbers with one letter at least for the username
- at least 12 characters, a combination of latin uppercase and lowercase letters, numbers, and special symbols for the password

But of course sometimes it may be too strong (or too weak). It's possible to configure own `CredentialValidator` in this case.

### Storing the secrets
User model (and, thus, users in repository) keeps password hashed with bcrypt which is well-protected from brute force attacks.

Refresh tokens are also stored in repository to ensure that refresh token provided by user is actual. To avoid "naked" refresh tokens in database, they are also hashed but with SHA-256 (as it's more useful to make fast hash check in case of tokens meanwhile it's more difficult to brute force "random" token comparing with password). The allowance of disabling ot changing hash algorithm for the tokens may be implemented in the future.