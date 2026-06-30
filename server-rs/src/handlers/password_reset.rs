use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;

use base64::Engine;
use validator::Validate;

use super::extract_client_ip;
use crate::error::{AppError, AppResult};
use crate::middleware::rate_limit;
use crate::services::audit::{self, AuditAction, AuditEntry};
use crate::services::hash_service;
use crate::services::session;
use crate::state::AppState;

const PASSWORD_RESET_TTL_SECS: i64 = 30 * 60;
const CONSUME_PASSWORD_RESET_LUA: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then
  redis.call('DEL', KEYS[2])
  return 0
end
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[1])
return 1
"#;

fn reset_key(user_id: i64) -> String {
    format!("pwreset:{user_id}")
}

fn reset_hash_key(token_hash: &str) -> String {
    format!("pwreset-hash:{token_hash}")
}

fn invalid_or_expired_reset_token() -> AppError {
    AppError::Validation("Invalid or expired reset token".into())
}

// ─── POST /api/password-reset/request ───────────────────────────────

#[derive(Deserialize, Validate)]
pub struct PasswordResetRequestBody {
    #[validate(email, length(max = 254))]
    pub email: String,
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordResetRequestBody>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("POST /api/password-reset/request");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::PASSWORD_RESET_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;
    let email = body.email.to_lowercase();

    // Find user by email via PG.
    let user_id = crate::services::pg::users::by_email_lower(&state.pg, &email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "request_password_reset: PG lookup failed");
            AppError::Internal
        })?
        .map(|u| u.id);

    if let Some(uid) = user_id {
        // Generate secure random token.
        let mut token_bytes = [0u8; 32];
        getrandom::fill(&mut token_bytes).expect("getrandom failed");
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes);

        // Hash the token for storage.
        let token_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            hex::encode(hasher.finalize())
        };

        // Store the hash in Redis with a 30-minute TTL. Only one
        // outstanding reset at a time: delete any previous reverse
        // index before writing the new forward and reverse keys.
        use fred::interfaces::KeysInterface;
        use fred::types::Expiration;
        let reset_key = reset_key(uid);
        let previous_hash: Option<String> = state.redis.get(&reset_key).await.ok().flatten();
        if let Some(previous_hash) = previous_hash {
            let previous_hash_key = reset_hash_key(&previous_hash);
            let _: Result<i64, _> = state.redis.del(&previous_hash_key).await;
        }

        let _: Result<(), _> = state
            .redis
            .set::<(), _, _>(
                &reset_key,
                token_hash.clone(),
                Some(Expiration::EX(PASSWORD_RESET_TTL_SECS)),
                None,
                false,
            )
            .await;
        // Also store a reverse index token_hash → user_id so the
        // confirm handler can resolve it without iterating.
        let hash_key = reset_hash_key(&token_hash);
        let _: Result<(), _> = state
            .redis
            .set::<(), _, _>(
                &hash_key,
                uid.to_string(),
                Some(Expiration::EX(PASSWORD_RESET_TTL_SECS)),
                None,
                false,
            )
            .await;

        // Send password reset email (best-effort)
        if let Some(ref email_svc) = state.email {
            let user_email = email.clone();
            if let Err(e) = email_svc.send_password_reset(&user_email, &token).await {
                tracing::error!("Failed to send password reset email: {e}");
            }
        } else {
            tracing::warn!(
                "Email service not configured — password reset email not sent for user {uid}"
            );
        }
    }

    // Always return success to prevent user enumeration
    Ok(Json(json!({
        "message": "If an account with that email exists, a password reset link has been sent."
    })))
}

// ─── POST /api/password-reset/confirm ───────────────────────────────

#[derive(Deserialize, Validate)]
pub struct PasswordResetConfirmBody {
    #[validate(length(min = 1))]
    pub token: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

pub async fn confirm_password_reset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordResetConfirmBody>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("POST /api/password-reset/confirm");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::PASSWORD_RESET_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;
    // Hash the token
    let token_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(body.token.as_bytes());
        hex::encode(hasher.finalize())
    };

    // Resolve token hash → user_id via the Redis reverse index.
    use fred::interfaces::{KeysInterface, LuaInterface};
    let hash_key = reset_hash_key(&token_hash);
    let uid_str: Option<String> = state.redis.get(&hash_key).await.ok().flatten();
    let user_id = uid_str
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(invalid_or_expired_reset_token)?;
    crate::services::app_bans::ensure_user_not_banned(&state, user_id).await?;

    let reset_key = reset_key(user_id);
    // Atomically require the reverse index to match the current forward
    // reset token before consuming both keys. If the forward token has
    // moved on, the script deletes the stale reverse index and rejects.
    let consumed: i64 = state
        .redis
        .eval(
            CONSUME_PASSWORD_RESET_LUA,
            vec![reset_key, hash_key],
            vec![token_hash],
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "confirm_password_reset: Redis reset consume script failed");
            AppError::Internal
        })?;
    if consumed != 1 {
        return Err(invalid_or_expired_reset_token());
    }

    // Hash new password
    let new_hash = hash_service::hash_password(&state, body.password.clone()).await?;

    // PG: swap in the new password hash.
    crate::services::pg::users::update(
        &state.pg,
        user_id,
        crate::services::pg::users::UpdateUser {
            password_hash: Some(&new_hash),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "confirm_password_reset: PG write failed");
        AppError::Internal
    })?;

    // Revoke all active sessions through the session service.
    let _revoked_sessions = session::revoke_all_user_sessions(&state.pg, user_id).await?;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id,
            action: AuditAction::PasswordReset,
            target_type: "user",
            target_id: user_id,
            server_id: None,
            metadata: None,
            ip: Some(ip),
        },
        state.pg.clone(),
    );

    tracing::info!("Password reset completed user_id={}", user_id);
    Ok(Json(json!({
        "message": "Password has been reset successfully. Please log in with your new password."
    })))
}

#[cfg(test)]
mod tests {
    use super::{CONSUME_PASSWORD_RESET_LUA, reset_hash_key, reset_key};

    #[test]
    fn reset_key_helpers_use_expected_prefixes() {
        assert_eq!(reset_key(42), "pwreset:42");
        assert_eq!(reset_hash_key("abc123"), "pwreset-hash:abc123");
    }

    #[test]
    fn consume_password_reset_lua_deletes_stale_and_current_keys() {
        assert!(CONSUME_PASSWORD_RESET_LUA.contains("redis.call('GET', KEYS[1])"));
        assert!(CONSUME_PASSWORD_RESET_LUA.contains("redis.call('DEL', KEYS[2])"));
        assert!(CONSUME_PASSWORD_RESET_LUA.contains("redis.call('DEL', KEYS[1])"));
    }
}
