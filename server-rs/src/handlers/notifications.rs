use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::UserId;
use crate::state::AppState;

/// Wire-type sentinels mirroring the legacy notification target enum:
/// `global` / `server` / `channel`. Stored as integers in the per-user
/// JSONB column for compactness; surfaced as strings on the HTTP API.
const TARGET_GLOBAL: i32 = 0;
const TARGET_SERVER: i32 = 1;
const TARGET_CHANNEL: i32 = 2;

fn target_type_label(t: i32) -> &'static str {
    match t {
        TARGET_SERVER => "server",
        TARGET_CHANNEL => "channel",
        _ => "global",
    }
}

fn parse_target_type(s: &str) -> Option<i32> {
    match s {
        "global" => Some(TARGET_GLOBAL),
        "server" => Some(TARGET_SERVER),
        "channel" => Some(TARGET_CHANNEL),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrefResponse {
    pub target_type: String,
    pub target_id: String,
    pub muted: bool,
    pub desktop_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertNotificationPref {
    pub target_type: String,
    pub target_id: Option<String>,
    pub muted: Option<bool>,
    pub desktop_enabled: Option<bool>,
}

/// Internal shape stored inside the `users.notification_prefs` JSONB array.
/// Field names preserve the existing JSON wire format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NotificationPrefRow {
    target_type: i32,
    target_id: i64,
    muted: bool,
    desktop_enabled: bool,
}

/// Pull the JSONB array off the user row, decoding into typed structs.
/// Empty / null jsonb folds to an empty list.
async fn load_prefs(
    pool: &sqlx::PgPool,
    user_id: i64,
) -> Result<Vec<NotificationPrefRow>, sqlx::Error> {
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT notification_prefs FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    let Some((value,)) = row else {
        return Ok(Vec::new());
    };
    let parsed: Vec<NotificationPrefRow> = serde_json::from_value(value).unwrap_or_default();
    Ok(parsed)
}

/// Atomic write of the typed list back into the JSONB column. Bumps
/// updated_at_ms to match the legacy timestamp behaviour.
async fn save_prefs(
    pool: &sqlx::PgPool,
    user_id: i64,
    prefs: &[NotificationPrefRow],
) -> Result<(), sqlx::Error> {
    let value = serde_json::to_value(prefs).unwrap_or(serde_json::Value::Array(vec![]));
    sqlx::query("UPDATE users SET notification_prefs = $2, updated_at_ms = $3 WHERE id = $1")
        .bind(user_id)
        .bind(value)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(pool)
        .await?;
    Ok(())
}

/// GET /api/users/me/notifications — list all notification preferences
pub async fn list_notification_prefs(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    let prefs = load_prefs(&state.pg, user_id.0).await.map_err(|e| {
        tracing::error!(error = %e, "list_notification_prefs: PG read failed");
        AppError::Internal
    })?;
    let resp: Vec<NotificationPrefResponse> = prefs
        .iter()
        .map(|p| NotificationPrefResponse {
            target_type: target_type_label(p.target_type).to_string(),
            target_id: p.target_id.to_string(),
            muted: p.muted,
            desktop_enabled: p.desktop_enabled,
        })
        .collect();
    Ok(Json(json!(resp)))
}

/// PUT /api/users/me/notifications — upsert a notification preference
pub async fn upsert_notification_pref(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<UpsertNotificationPref>,
) -> AppResult<Json<Value>> {
    let target_type = parse_target_type(&body.target_type).ok_or_else(|| {
        AppError::Validation("target_type must be one of: global, server, channel".into())
    })?;

    // Resolve + validate the target id. Global → 0; server/channel →
    // verify the caller has access before persisting.
    let target_id: i64 = if target_type == TARGET_GLOBAL {
        0
    } else {
        let id = body
            .target_id
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| {
                AppError::Validation("target_id is required for non-global targets".into())
            })?;

        if target_type == TARGET_SERVER {
            state
                .require_membership(user_id.0, id)
                .await
                .map_err(|_| AppError::NotFound("server"))?;
        } else {
            use crate::services::permissions::CacheResult;
            match state.permissions.verify_access(user_id.0, id) {
                CacheResult::Hit(_) => {}
                CacheResult::Denied(_) => return Err(AppError::NotFound("channel")),
                CacheResult::Miss => {
                    // Cache miss — pull the channel row from PG to find
                    // its server_id (None ⇒ DM channel; lookup the
                    // user's DM membership separately).
                    let channel =
                        crate::services::pg::channels::by_id(&state.pg, id).await.map_err(|e| {
                            tracing::error!(channel_id = id, error = %e, "upsert_notification_pref: PG channel read failed");
                            AppError::Internal
                        })?;
                    match channel {
                        Some(c) if c.server_id.is_some() => {
                            state
                                .require_membership(user_id.0, c.server_id.unwrap())
                                .await
                                .map_err(|_| AppError::NotFound("channel"))?;
                        }
                        _ => {
                            // No row in `channels` → maybe a DM channel
                            // (lives in dm_channels). Verify membership.
                            let dm_ids = crate::services::pg::dms::list_channel_ids_for_user(
                                &state.pg,
                                user_id.0,
                            )
                            .await
                            .map_err(|e| {
                                tracing::error!(error = %e, "upsert_notification_pref: PG DM list failed");
                                AppError::Internal
                            })?;
                            if !dm_ids.contains(&id) {
                                return Err(AppError::NotFound("channel"));
                            }
                        }
                    }
                }
            }
        }
        id
    };

    let muted = body.muted.unwrap_or(false);
    let desktop_enabled = body.desktop_enabled.unwrap_or(true);

    // RMW the JSONB column. Bounded list (~50 entries max in practice)
    // — single scan is fine.
    let mut prefs = load_prefs(&state.pg, user_id.0).await.map_err(|e| {
        tracing::error!(error = %e, "upsert_notification_pref: PG read failed");
        AppError::Internal
    })?;

    if let Some(p) = prefs
        .iter_mut()
        .find(|p| p.target_type == target_type && p.target_id == target_id)
    {
        p.muted = muted;
        p.desktop_enabled = desktop_enabled;
    } else {
        prefs.push(NotificationPrefRow {
            target_type,
            target_id,
            muted,
            desktop_enabled,
        });
    }

    save_prefs(&state.pg, user_id.0, &prefs).await.map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "upsert_notification_pref: PG write failed");
        AppError::Internal
    })?;

    Ok(Json(json!({ "ok": true })))
}
