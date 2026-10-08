use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use simplus_core::db::rusqlite;
use simplus_vault_proto::{ErrorBody, ErrorCode};

/// An error returned to the client as `{"code": ..., "message": ...}`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: ErrorCode,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, "sign in again")
    }

    pub fn invalid_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials, "wrong email or password")
    }

    pub fn locked() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Locked,
            "too many failed attempts; try again later",
        )
    }

    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited, "too many requests; slow down")
    }

    pub fn disabled() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::AccountDisabled, "this account is disabled")
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, message)
    }

    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!("internal error: {error}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, "internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { code: self.code, message: self.message })).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        Self::internal(e)
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::internal(e)
    }
}
