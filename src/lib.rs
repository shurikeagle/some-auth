mod error;
mod user_service;
mod repository;
mod jwt;
mod hasher;
#[cfg(feature = "axum-auth")]
mod axum_middleware;

pub use error::AuthError;
pub use user_service::{ AuthUser, UserService, UserServiceBuilder, builder, default_builder, CredentialValidator, User, Role };
pub use jwt::{ JwtTokenSettings, TokenPair };
pub use repository::AuthRepository;
#[cfg(feature = "axum-auth")]
pub use axum_middleware::{ UserServiceState, auth_middleware };
#[cfg(feature = "pg-repository")]
pub use repository::pg_repository::PgAuthRepository;