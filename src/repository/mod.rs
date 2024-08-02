#[cfg(feature = "pg-repository")]
pub mod pg_repository;

use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mockall::automock;

use crate::user_service::{AuthUser, Role};

/// Auth repository which is used in [`UserService`]
#[automock]
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
    async fn get_user_roles(&self, user_id: i32) -> Result<Vec<Role>, String>;
}