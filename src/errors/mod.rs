use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("signature invalid: {0}")]
    SignatureInvalid(String),

    #[error("vulnerability found: {0}")]
    VulnerabilityFound(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, ForgeError>;

impl From<rusqlite::Error> for ForgeError {
    fn from(e: rusqlite::Error) -> Self {
        ForgeError::Database(e.to_string())
    }
}

impl IntoResponse for ForgeError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            ForgeError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ForgeError::SignatureInvalid(_) | ForgeError::VerificationFailed(_) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            ForgeError::VulnerabilityFound(_) => (StatusCode::FORBIDDEN, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
