use std::{fmt, sync::Arc};

use axum::{body::Body, extract::{Request, State}, http::{self}, middleware::Next, response::Response };

use crate::{AuthError, AuthUser, UserService};

/// Router [`State`] trait which must be used for [`auth_middleware`]
pub trait UserServiceState<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    fn user_service(&self) -> Arc<UserService<TAuthUser>>;
}

/// Controls if user is authenticated and optionally checks if user is admin
pub async fn auth_middleware<TAuthUser: AuthUser + fmt::Debug + Send + Sync>(
    State(state): State<Arc<dyn UserServiceState<TAuthUser>>>,
    req: Request<Body>,
    next: Next
) -> Result<Response, AuthError> {
    let auth_header = req.headers().get(http::header::AUTHORIZATION).ok_or(AuthError::Unathorized)?;
    let access_token = auth_header.to_str().map_err(|_| AuthError::Internal("Couldn't handle user token".to_string()))?;

    let _ = state.user_service()
        .get_authenticated_user(access_token, false)
        .await
        .map_err(|err| err)?;

    Ok(next.run(req).await)
}