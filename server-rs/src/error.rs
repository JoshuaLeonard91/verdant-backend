use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // Auth
    #[error("The email or password you entered is incorrect")]
    InvalidCredentials,
    #[error("Token required")]
    TokenRequired,
    #[error("Your session has expired. Please sign in again.")]
    TokenInvalid,
    #[error("Your session has been revoked. Please sign in again.")]
    TokenRevoked,
    #[error("Refresh required")]
    RefreshRequired,
    #[error("Registration failed")]
    RegistrationFailed(String),

    // Resources
    #[error("{0}")]
    NotFound(&'static str),
    #[error("You don't have permission to do that")]
    Forbidden,
    #[error("You need to be a member of this server to do that")]
    NotMember,

    // Permissions
    #[error("You don't have permission to do that")]
    MissingPermission,
    #[error("You don't have permission to send messages in this channel")]
    CannotSendMessages,

    // Validation
    #[error("{0}")]
    Validation(String),
    #[error("No changes were made")]
    NoChanges,

    // Rate limiting
    #[error("You're doing that too fast. Please wait a moment and try again.")]
    RateLimited,

    // Server errors
    #[error("Internal server error")]
    Internal,

    // Generic with code
    #[error("{message}")]
    WithCode {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
}

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "AUTH_INVALID_CREDENTIALS"),
            Self::TokenRequired => (StatusCode::UNAUTHORIZED, "AUTH_TOKEN_REQUIRED"),
            Self::TokenInvalid => (StatusCode::UNAUTHORIZED, "AUTH_TOKEN_INVALID"),
            Self::TokenRevoked => (StatusCode::UNAUTHORIZED, "AUTH_TOKEN_REVOKED"),
            Self::RefreshRequired => (StatusCode::UNAUTHORIZED, "AUTH_REFRESH_REQUIRED"),
            Self::RegistrationFailed(_) => (StatusCode::BAD_REQUEST, "AUTH_REGISTRATION_FAILED"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "PERMISSION_MISSING"),
            Self::NotMember => (StatusCode::FORBIDDEN, "PERMISSION_NOT_MEMBER"),
            Self::MissingPermission => (StatusCode::FORBIDDEN, "PERMISSION_MISSING"),
            Self::CannotSendMessages => (StatusCode::FORBIDDEN, "PERMISSION_SEND_MESSAGES"),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_FAILED"),
            Self::NoChanges => (StatusCode::BAD_REQUEST, "VALIDATION_NO_CHANGES"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            Self::WithCode { status, code, .. } => (*status, code),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = match &self {
            Self::Internal => {
                tracing::error!("Internal server error (unspecified)");
                "Internal server error".to_string()
            }
            // User-friendly messages for NotFound variants
            Self::NotFound(resource) => match *resource {
                "channel" => "That channel doesn't exist or you don't have access".to_string(),
                "feed" => "That feed doesn't exist or you don't have access".to_string(),
                "invite" => "This invite is invalid or has expired".to_string(),
                other => {
                    let mut s = String::with_capacity(other.len() + 10);
                    let mut chars = other.chars();
                    if let Some(c) = chars.next() {
                        s.extend(c.to_uppercase());
                    }
                    s.push_str(chars.as_str());
                    s.push_str(" not found");
                    s
                }
            },
            other => other.to_string(),
        };

        let body = json!({ "error": message, "code": code });
        (status, axum::Json(body)).into_response()
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(e: validator::ValidationErrors) -> Self {
        // SECURITY: Never use `e.to_string()` — the validator crate includes raw
        // input values (e.g. passwords) in its Display output. Always build a
        // sanitised human-readable message from the error metadata only.
        for (field, errors) in e.field_errors() {
            if let Some(err) = errors.first() {
                // Helper: extract a u64 from params (handles both integer and float storage)
                let param_u64 = |key: &str| -> Option<u64> {
                    let v = err.params.get(key)?;
                    v.as_u64().or_else(|| v.as_f64().map(|f| f as u64))
                };

                let msg = match err.code.as_ref() {
                    "length" => {
                        let min = param_u64("min");
                        let max = param_u64("max");
                        match (min, max) {
                            (Some(mn), Some(mx)) => {
                                format!("{field} must be between {mn} and {mx} characters")
                            }
                            (Some(mn), None) => {
                                format!("{field} must be at least {mn} characters")
                            }
                            (None, Some(mx)) => {
                                format!("{field} must be at most {mx} characters")
                            }
                            _ => format!("{field} has an invalid length"),
                        }
                    }
                    "email" => "Please enter a valid email address".to_string(),
                    "range" => {
                        let min = err.params.get("min").and_then(|v| v.as_f64());
                        let max = err.params.get("max").and_then(|v| v.as_f64());
                        match (min, max) {
                            (Some(mn), Some(mx)) => {
                                format!("{field} must be between {mn} and {mx}")
                            }
                            _ => format!("{field} is out of range"),
                        }
                    }
                    _ => {
                        // Custom messages are safe (set by us), but never use the
                        // raw error which may embed user input.
                        if let Some(msg) = &err.message {
                            msg.to_string()
                        } else {
                            format!("{field} is invalid")
                        }
                    }
                };
                return AppError::Validation(msg);
            }
        }
        AppError::Validation("Validation failed".into())
    }
}

impl From<axum::extract::rejection::JsonRejection> for AppError {
    fn from(_: axum::extract::rejection::JsonRejection) -> Self {
        AppError::Validation("Invalid request body".into())
    }
}

/// Result alias for handlers.
pub type AppResult<T> = Result<T, AppError>;

/// Extension trait: `.or_not_found("entity")` instead of `.ok_or(AppError::NotFound("entity"))`
pub trait OrNotFound<T> {
    fn or_not_found(self, entity: &'static str) -> AppResult<T>;
}

impl<T> OrNotFound<T> for Option<T> {
    fn or_not_found(self, entity: &'static str) -> AppResult<T> {
        self.ok_or(AppError::NotFound(entity))
    }
}
