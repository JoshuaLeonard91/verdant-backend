use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::state::AppState;

/// Character set for key generation — no 0/O/1/I to avoid confusion.
const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn require_invite_codes_enabled(state: &AppState, user_id: i64) -> AppResult<()> {
    if state.feature_flags.resolve("invite_codes", user_id) {
        return Ok(());
    }
    Err(AppError::WithCode {
        status: StatusCode::FORBIDDEN,
        code: "FEATURE_DISABLED",
        message: "Invite codes are not currently enabled".into(),
    })
}

fn generate_registration_key() -> String {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).expect("getrandom failed");

    let mut segments = Vec::with_capacity(3);
    for chunk in bytes.chunks(4) {
        let segment: String = chunk
            .iter()
            .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
            .collect();
        segments.push(segment);
    }
    format!("VRD-{}", segments.join("-"))
}

fn invite_key_preview(key: &str) -> String {
    key.chars().take(8).collect()
}

// ─── POST /api/invite-codes ────────────────────────────────────────

pub async fn create_invite_code(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Response> {
    tracing::info!("POST /api/invite-codes user_id={}", user_id.0);
    require_invite_codes_enabled(&state, user_id.0)?;
    rate_limit::enforce(&state, &rate_limit::INVITE_LIMIT, &user_id.0.to_string()).await?;

    let key = generate_registration_key();
    let now_ms = chrono::Utc::now().timestamp_millis();

    crate::services::pg::auth::invite_insert(&state.pg, &key, user_id.0, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create_invite_code: PG insert failed");
            AppError::Internal
        })?;

    tracing::info!(
        "Invite code created key={}... by={}",
        invite_key_preview(&key),
        user_id.0
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "key": key,
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        })),
    )
        .into_response())
}

// ─── GET /api/invite-codes ─────────────────────────────────────────

pub async fn list_invite_codes(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/invite-codes user_id={}", user_id.0);
    require_invite_codes_enabled(&state, user_id.0)?;

    let codes = crate::services::pg::auth::invite_list_by_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list_invite_codes: PG read failed");
            AppError::Internal
        })?;

    let mut entries: Vec<Value> = Vec::with_capacity(codes.len());
    for code in &codes {
        let used_by_username: Option<String> = match code.used_by {
            Some(uid) => crate::services::pg::users::by_id(&state.pg, uid)
                .await
                .ok()
                .flatten()
                .map(|u| u.username),
            None => None,
        };
        entries.push(json!({
            "key": code.code,
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(code.created_at_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
            "usedBy": code.used_by.map(|id| id.to_string()),
            "usedByUsername": used_by_username,
            "usedAt": code.used_at_ms
                .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
                .map(|t| Value::String(t.to_rfc3339()))
                .unwrap_or(Value::Null),
        }));
    }

    Ok(Json(json!(entries)))
}

// ─── DELETE /api/invite-codes/:key ─────────────────────────────────

pub async fn delete_invite_code(
    State(state): State<AppState>,
    user_id: UserId,
    Path(key): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/invite-codes/{}... user_id={}",
        invite_key_preview(&key),
        user_id.0
    );
    require_invite_codes_enabled(&state, user_id.0)?;
    rate_limit::enforce(&state, &rate_limit::INVITE_LIMIT, &user_id.0.to_string()).await?;

    let row = crate::services::pg::auth::invite_get(&state.pg, &key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete_invite_code: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite code"))?;

    // Owner-only delete; used codes are immutable history.
    if row.invited_by != user_id.0 || row.used_by.is_some() {
        return Err(AppError::NotFound("invite code"));
    }

    crate::services::pg::auth::invite_delete(&state.pg, &key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete_invite_code: PG delete failed");
            AppError::Internal
        })?;

    tracing::info!(
        "Invite code deleted key={}... by={}",
        invite_key_preview(&key),
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

/// Atomically mark a registration key as consumed. Returns `true`
/// if the key existed, was unused, and has now been claimed by
/// `user_id`. Returns `false` for unknown keys OR keys already
/// consumed. Backs the auth::register flow.
pub async fn consume_registration_key(pool: &sqlx::PgPool, key: &str, user_id: i64) -> bool {
    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::auth::invite_consume(pool, key, user_id, now_ms)
        .await
        .unwrap_or(false)
}
