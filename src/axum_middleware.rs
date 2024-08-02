use std::{fmt, sync::Arc};

use axum::{extract::{Request, State}, http::{self, StatusCode}, middleware::Next, response::{IntoResponse, Response}, Json };
use serde::Serialize;

use crate::{user_service::RoleFilter, AuthError, AuthUser, UserService};

#[derive(Serialize)]
pub(super) struct AuthErrorResponse {
    /// Error message
    pub message: String
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            AuthError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AuthError::ValidationError(msg) | AuthError::InvalidOperation(msg) => (StatusCode::BAD_REQUEST, msg),
            AuthError::UsernameUnavailable => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::InvalidCredentials => (StatusCode::FORBIDDEN, self.to_string()),
            AuthError::AuthRepositoryError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AuthError::UserNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AuthError::Unathorized => (StatusCode::UNAUTHORIZED, self.to_string())
        };

        let response = Json(AuthErrorResponse {
            message
        });

        (code, response).into_response()
    }
}

/// Router [`State`] which must be used for [`auth_middleware`]
pub struct  UserServiceState<TAuthUser: AuthUser + fmt::Debug + Send + Sync> {
    pub user_service: Arc<UserService<TAuthUser>>
}

/// Controls if user is authenticated and checks their role aacording to [`RoleFilter`]
pub async fn auth_middleware<TAuthUser: AuthUser + fmt::Debug + Send + Sync>(
    State(state): State<Arc<UserServiceState<TAuthUser>>>,
    req: Request,
    next: Next,
    role_filter: Option<RoleFilter>
) -> Result<Response, AuthError> {
    let auth_header = req.headers().get(http::header::AUTHORIZATION).ok_or(AuthError::Unathorized)?;
    let access_token = auth_header.to_str().map_err(|_| AuthError::Internal("Couldn't handle user token".to_string()))?;

    let _ = state.user_service
        .get_authenticated_user(access_token, role_filter)
        .await
        .map_err(|err| err)?;

    Ok(next.run(req).await)
}