use std::{fmt, sync::Arc};

use axum::{body::Body, extract::{Request, State}, http::{self, StatusCode}, middleware::Next, response::Response };

use crate::{AuthError, AuthUser, UserService};

impl AuthError {
    fn into_status_code(self) -> StatusCode {
        match self {
            AuthError::ValidationError(_) | AuthError::UsernameUnavailable => StatusCode::BAD_REQUEST,
            AuthError::InvalidCredentials => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Router [`State`] trait which must be used for [`auth_middleware`]
pub trait UserServiceState<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    fn user_service(&self) -> Arc<UserService<TAuthUser>>;
}

/// Controls if user is authenticated and optionally checks if user is admin
pub async fn auth_middleware<TAuthUser: AuthUser + fmt::Debug + Send + Sync>(
    State(state): State<Arc<dyn UserServiceState<TAuthUser>>>,
    req: Request<Body>,
    next: Next,
    admin_only: bool
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(http::header::AUTHORIZATION).ok_or(StatusCode::UNAUTHORIZED)?;
    let access_token = auth_header.to_str().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = state.user_service()
        .get_authenticated_user(access_token, admin_only)
        .await
        .map_err(|err| err.into_status_code())?;

    Ok(next.run(req).await)
}