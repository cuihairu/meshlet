use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use meshlet_api_types::{ErrorCode, ErrorResponse};

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AuthApiError {
    Unauthorized,
    ForbiddenCsrf,
    ForbiddenScopes,
    NotFound(String),
    InvalidInput(String),
    AlreadyBootstrapped,
    RateLimited,
    Internal(String),
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AuthApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "invalid credentials or authentication required".into(),
            ),
            AuthApiError::ForbiddenCsrf => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                "mutating console requests must set X-Requested-With".into(),
            ),
            AuthApiError::ForbiddenScopes => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                "api token lacks write scope".into(),
            ),
            AuthApiError::NotFound(m) => (StatusCode::NOT_FOUND, ErrorCode::NotFound, m),
            AuthApiError::InvalidInput(m) => {
                (StatusCode::BAD_REQUEST, ErrorCode::ValidationFailed, m)
            }
            AuthApiError::AlreadyBootstrapped => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "admin user already exists; bootstrap is closed".into(),
            ),
            AuthApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::TooManyRequests,
                "login rate limit exceeded; retry later".into(),
            ),
            AuthApiError::Internal(m) => {
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, m)
            }
        };
        (status, Json(ErrorResponse::new(code, message))).into_response()
    }
}
