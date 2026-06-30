use axum::{Json, extract::State, http::StatusCode};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::UserId;
use crate::middleware::rate_limit;
use crate::repo::users::UserRow;
use crate::services::{
    audit::{self, AuditAction, AuditEntry},
    crypto, hash_service, totp,
};
use crate::state::AppState;

fn twofa_not_configured() -> AppError {
    AppError::WithCode {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "AUTH_2FA_NOT_CONFIGURED",
        message: "Two-factor authentication is not available on this server".into(),
    }
}

fn get_totp_key(state: &AppState) -> AppResult<&str> {
    state
        .config
        .totp_encryption_key
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or_else(twofa_not_configured)
}

async fn load_user(state: &AppState, user_id: i64) -> AppResult<UserRow> {
    crate::services::pg::users::by_id(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "twofa: PG user read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))
}

/// Decode the encrypted TOTP secret string into the raw bytea bytes
/// the pg::users::set_totp call expects. encrypt_secret returns base64;
/// the bytea column stores the raw nonce|ciphertext|tag.
fn encrypted_secret_to_bytes(encrypted_b64: &str) -> AppResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .map_err(|e| {
            tracing::error!(error = %e, "twofa: base64 decode of encrypted secret failed");
            AppError::Internal
        })
}

// ─── GET /api/2fa/status ────────────────────────────────────────────

pub async fn twofa_status(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/2fa/status user_id={}", user_id.0);
    let user = load_user(&state, user_id.0).await?;

    let enabled = user.totp_enabled_at.is_some();
    let enabled_at_rfc3339 = user.totp_enabled_at.map(|t| t.to_rfc3339());

    // backup_code_hashes count: pull a fresh hash list directly so the
    // count isn't bottlenecked on the SELECT * UserRow round trip
    // continuing to omit them. UserRow doesn't carry the array.
    let remaining: i64 = if enabled {
        let row: Option<(Vec<String>,)> =
            sqlx::query_as("SELECT backup_code_hashes FROM users WHERE id = $1")
                .bind(user_id.0)
                .fetch_optional(&state.pg)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "twofa_status: PG backup count read failed");
                    AppError::Internal
                })?;
        row.map(|(arr,)| arr.len() as i64).unwrap_or(0)
    } else {
        0
    };

    Ok(Json(json!({
        "enabled": enabled,
        "enabledAt": enabled_at_rfc3339,
        "remainingBackupCodes": remaining,
    })))
}

// ─── POST /api/2fa/setup ────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFaSetupRequest {
    pub current_password: String,
}

pub async fn twofa_setup(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<TwoFaSetupRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("POST /api/2fa/setup user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let encryption_key = get_totp_key(&state)?;

    let user = load_user(&state, user_id.0).await?;

    let valid = hash_service::verify_password(
        &state,
        user.password_hash.clone(),
        body.current_password.clone(),
    )
    .await?;
    if !valid {
        tracing::warn!("2FA setup failed: invalid password user_id={}", user_id.0);
        return Err(AppError::Validation("Invalid password".into()));
    }

    if user.totp_enabled_at.is_some() {
        return Err(AppError::Validation("2FA is already enabled".into()));
    }

    let secret = totp::generate_secret();
    let encrypted =
        totp::encrypt_secret(&secret, encryption_key).map_err(|_| AppError::Internal)?;
    let encrypted_bytes = encrypted_secret_to_bytes(&encrypted)?;

    // Persist the pending secret. enabled_at stays NULL until the user
    // proves possession via /verify-setup. set_totp stamps both the
    // secret and enabled_at_ms; we use a partial write here via a raw
    // query so enabled_at_ms remains NULL.
    sqlx::query("UPDATE users SET totp_secret = $2, updated_at_ms = $3 WHERE id = $1")
        .bind(user_id.0)
        .bind(&encrypted_bytes)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(&state.pg)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "twofa_setup: PG write failed");
            AppError::Internal
        })?;

    let raw =
        totp::generate_qr_data_url(&secret, &user.username).map_err(|_| AppError::Internal)?;
    let qr_data_url = format!("data:image/png;base64,{}", raw);

    tracing::info!("2FA setup initiated user_id={}", user_id.0);
    Ok(Json(json!({
        "secret": secret,
        "qrDataUrl": qr_data_url,
    })))
}

// ─── POST /api/2fa/verify-setup ─────────────────────────────────────

#[derive(Deserialize)]
pub struct TwoFaVerifySetupRequest {
    pub code: String,
}

pub async fn twofa_verify_setup(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<TwoFaVerifySetupRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("POST /api/2fa/verify-setup user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let encryption_key = get_totp_key(&state)?;

    let user = load_user(&state, user_id.0).await?;
    let encrypted_secret = user
        .totp_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("2FA setup not started".into()))?;

    let secret =
        totp::decrypt_secret(encrypted_secret, encryption_key).map_err(|_| AppError::Internal)?;
    let valid =
        totp::verify_code(&secret, &body.code, &user.username).map_err(|_| AppError::Internal)?;
    if !valid {
        tracing::warn!(
            "2FA verify-setup failed: invalid code user_id={}",
            user_id.0
        );
        return Err(AppError::Validation("Invalid verification code".into()));
    }

    let backup_codes = totp::generate_backup_codes();

    let backup_hashes: Vec<String> = backup_codes
        .iter()
        .map(|c| crypto::hmac_hash(c, encryption_key))
        .collect();

    let now_ms = chrono::Utc::now().timestamp_millis();
    let encrypted_bytes = encrypted_secret_to_bytes(encrypted_secret)?;
    crate::services::pg::users::set_totp(
        &state.pg,
        user_id.0,
        &encrypted_bytes,
        &backup_hashes,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "twofa_verify_setup: PG write failed");
        AppError::Internal
    })?;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::TotpEnable,
            target_type: "user",
            target_id: user_id.0,
            server_id: None,
            metadata: None,
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!("2FA enabled user_id={}", user_id.0);
    Ok(Json(json!({
        "success": true,
        "backupCodes": backup_codes,
    })))
}

// ─── POST /api/2fa/disable ──────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFaDisableRequest {
    pub current_password: String,
    pub code: String,
}

pub async fn twofa_disable(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<TwoFaDisableRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("POST /api/2fa/disable user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let encryption_key = get_totp_key(&state)?;

    let user = load_user(&state, user_id.0).await?;

    let valid = hash_service::verify_password(
        &state,
        user.password_hash.clone(),
        body.current_password.clone(),
    )
    .await?;
    if !valid {
        tracing::warn!("2FA disable failed: invalid password user_id={}", user_id.0);
        return Err(AppError::Validation("Invalid password".into()));
    }

    let encrypted_secret = user
        .totp_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("2FA is not enabled".into()))?;
    if user.totp_enabled_at.is_none() {
        return Err(AppError::Validation("2FA is not enabled".into()));
    }

    let secret =
        totp::decrypt_secret(encrypted_secret, encryption_key).map_err(|_| AppError::Internal)?;
    let code_valid =
        totp::verify_code(&secret, &body.code, &user.username).map_err(|_| AppError::Internal)?;
    if !code_valid {
        tracing::warn!(
            "2FA disable failed: invalid TOTP code user_id={}",
            user_id.0
        );
        return Err(AppError::Validation("Invalid verification code".into()));
    }

    crate::services::pg::users::clear_totp(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "twofa_disable: PG write failed");
            AppError::Internal
        })?;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::TotpDisable,
            target_type: "user",
            target_id: user_id.0,
            server_id: None,
            metadata: None,
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!("2FA disabled user_id={}", user_id.0);
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/2fa/backup-codes/regenerate ──────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFaRegenerateRequest {
    pub current_password: String,
    pub totp_code: String,
}

pub async fn twofa_regenerate_backup_codes(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<TwoFaRegenerateRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/2fa/backup-codes/regenerate user_id={}",
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let encryption_key = get_totp_key(&state)?;

    let user = load_user(&state, user_id.0).await?;

    let valid = hash_service::verify_password(
        &state,
        user.password_hash.clone(),
        body.current_password.clone(),
    )
    .await?;
    if !valid {
        tracing::warn!(
            "Backup code regen failed: invalid password user_id={}",
            user_id.0
        );
        return Err(AppError::Validation("Invalid password".into()));
    }

    let encrypted_secret = user
        .totp_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("2FA is not enabled".into()))?;
    if user.totp_enabled_at.is_none() {
        return Err(AppError::Validation("2FA is not enabled".into()));
    }

    let secret =
        totp::decrypt_secret(encrypted_secret, encryption_key).map_err(|_| AppError::Internal)?;
    let code_valid = totp::verify_code(&secret, &body.totp_code, &user.username)
        .map_err(|_| AppError::Internal)?;
    if !code_valid {
        tracing::warn!(
            "Backup code regen failed: invalid TOTP code user_id={}",
            user_id.0
        );
        return Err(AppError::Validation("Invalid verification code".into()));
    }

    let backup_codes = totp::generate_backup_codes();

    let backup_hashes: Vec<String> = backup_codes
        .iter()
        .map(|c| crypto::hmac_hash(c, encryption_key))
        .collect();

    sqlx::query(
        r#"
        UPDATE users
           SET backup_code_hashes = $2,
               updated_at_ms      = $3
         WHERE id = $1
        "#,
    )
    .bind(user_id.0)
    .bind(&backup_hashes)
    .bind(chrono::Utc::now().timestamp_millis())
    .execute(&state.pg)
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "twofa_regenerate_backup_codes: PG write failed");
        AppError::Internal
    })?;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::TotpRegenerateBackup,
            target_type: "user",
            target_id: user_id.0,
            server_id: None,
            metadata: None,
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!("Backup codes regenerated user_id={}", user_id.0);
    Ok(Json(json!({
        "success": true,
        "backupCodes": backup_codes,
    })))
}
