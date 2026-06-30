//! App-wide ban enforcement.

use axum::http::StatusCode;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

fn banned_error(code: &'static str, message: &str) -> AppError {
    AppError::WithCode {
        status: StatusCode::FORBIDDEN,
        code,
        message: message.to_string(),
    }
}

pub async fn ensure_user_not_banned(state: &AppState, user_id: i64) -> AppResult<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    match crate::services::pg::app_bans::active_account_ban(&state.pg, user_id, now_ms).await {
        Ok(Some(_)) => Err(banned_error("ACCOUNT_BANNED", "This account is banned.")),
        Ok(None) => Ok(()),
        Err(e) => {
            tracing::error!(user_id, error = %e, "Account ban check failed");
            Err(AppError::Internal)
        }
    }
}

pub async fn ensure_ip_not_banned(state: &AppState, ip: &str) -> AppResult<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    match crate::services::pg::app_bans::active_ip_ban(&state.pg, ip, now_ms).await {
        Ok(Some(_)) => Err(banned_error(
            "IP_BANNED",
            "Access is temporarily restricted.",
        )),
        Ok(None) => Ok(()),
        Err(e) => {
            tracing::error!(%ip, error = %e, "IP ban check failed");
            Err(AppError::Internal)
        }
    }
}
