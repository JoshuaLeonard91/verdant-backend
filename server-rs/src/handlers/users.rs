use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::{SessionId, UserId};
use crate::middleware::rate_limit;
use crate::repo::users::UserRow;
use crate::services::audit::{self, AuditAction, AuditEntry};
use crate::services::banner_crop;
use crate::services::cdn;
use crate::services::crypto::{blacklist_access_token, generate_verification_code, hash_token};
use crate::services::hash_service;
use crate::services::sanitize::sanitize_text;
use crate::services::session;
use crate::services::totp;
use crate::services::username_safety;
use crate::state::AppState;
use crate::ws::{events, topics};

/// Load the user record from PG or return NotFound.
async fn load_pg_user(state: &AppState, user_id: i64) -> AppResult<UserRow> {
    crate::services::pg::users::by_id_with_crypto(&state.pg, user_id, state.field_crypto.as_ref())
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "users: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))
}

/// Build the same JSON shape as `FullUserResponse::from(&UserRow)`.
pub(crate) fn user_to_full_response_json(
    rec: &UserRow,
    status: &str,
    member_list_banner_visible: bool,
) -> Value {
    json!({
        "id": rec.id.to_string(),
        "username": rec.username,
        "avatarUrl": cdn::resolve(rec.avatar_url.as_deref()),
        "bannerUrl": cdn::resolve(rec.banner_url.as_deref()),
        "bannerBaseColor": normalize_optional_text(rec.banner_base_color.as_deref()),
        "bannerCrop": banner_crop::to_json(rec.banner_crop),
        "memberListBannerUrl": if member_list_banner_visible { cdn::resolve(rec.member_list_banner_url.as_deref()) } else { None },
        "memberListBannerCrop": if member_list_banner_visible { banner_crop::to_json(rec.member_list_banner_crop) } else { serde_json::Value::Null },
        "status": status,
        "subscribed": rec.subscribed,
        "displayName": rec.display_name,
        "bio": normalize_optional_text(rec.bio.as_deref()),
        "customStatusText": normalize_optional_text(rec.custom_status_text.as_deref()),
        "customStatusEmoji": normalize_optional_text(rec.custom_status_emoji.as_deref()),
        "emailVerified": rec.email_verified,
        "usernameSet": rec.username_set,
        "preferences": rec.preferences,
        "createdAt": rec.created_at.to_rfc3339(),
        "updatedAt": rec.updated_at.to_rfc3339(),
    })
}

/// Public-profile JSON — strips email / updatedAt / password_hash / totp.
fn user_to_public_response_json(
    rec: &UserRow,
    status: &str,
    member_list_banner_visible: bool,
) -> Value {
    json!({
        "id": rec.id.to_string(),
        "username": rec.username,
        "avatarUrl": cdn::resolve(rec.avatar_url.as_deref()),
        "bannerUrl": cdn::resolve(rec.banner_url.as_deref()),
        "bannerBaseColor": normalize_optional_text(rec.banner_base_color.as_deref()),
        "bannerCrop": banner_crop::to_json(rec.banner_crop),
        "memberListBannerUrl": if member_list_banner_visible { cdn::resolve(rec.member_list_banner_url.as_deref()) } else { None },
        "memberListBannerCrop": if member_list_banner_visible { banner_crop::to_json(rec.member_list_banner_crop) } else { serde_json::Value::Null },
        "status": status,
        "displayName": rec.display_name,
        "bio": normalize_optional_text(rec.bio.as_deref()),
        "customStatusText": normalize_optional_text(rec.custom_status_text.as_deref()),
        "customStatusEmoji": normalize_optional_text(rec.custom_status_emoji.as_deref()),
        "createdAt": rec.created_at.to_rfc3339(),
    })
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub(crate) fn member_list_banner_visible_for_record(state: &AppState, rec: &UserRow) -> bool {
    let official_subscription_active =
        crate::services::entitlements::official_subscription_active_from_db(
            rec.subscribed,
            rec.subscription_expires_at,
        );
    crate::services::entitlements::member_list_banner_visible(
        &state.config,
        official_subscription_active,
    )
}

async fn broadcast_profile_fields_update(
    state: &AppState,
    user_id: i64,
    display_name: Option<&str>,
    bio: Option<&str>,
    banner_base_color: Option<&str>,
) {
    let uid_str = user_id.to_string();
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id)
        .await
        .unwrap_or_default();

    let json_text = events::user_profile_update_json(
        &uid_str,
        None,
        None,
        display_name,
        bio,
        banner_base_color,
        None,
        None,
        None,
    );
    let proto_msg = events::user_profile_update_proto(
        uid_str,
        None,
        None,
        display_name.map(String::from),
        bio.map(String::from),
        banner_base_color.map(String::from),
    );

    for sid in server_ids {
        let topic = topics::presence_topic(sid);
        topics::publish(state, &topic, &json_text, &proto_msg).await;
    }
}

// ─── Request types ──────────────────────────────────────────────────

#[derive(Deserialize, validator::Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    #[validate(length(max = 128))]
    pub password: Option<String>,
    #[validate(length(max = 128))]
    pub current_password: Option<String>,
    pub display_name: Option<Option<String>>,
    pub bio: Option<Option<String>>,
    pub banner_base_color: Option<Option<String>>,
    pub custom_status_text: Option<Option<String>>,
    pub custom_status_emoji: Option<Option<String>>,
}

fn normalize_banner_base_color(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() != 7 || !trimmed.starts_with('#') {
        return None;
    }
    let hex = &trimmed[1..];
    if !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("#{}", hex.to_ascii_uppercase()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOrderRequest {
    pub server_ids: Vec<String>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    #[validate(length(max = 254))]
    pub current_email: String,
    #[validate(length(min = 1, max = 254))]
    pub new_email: String,
    #[validate(length(min = 1, max = 128))]
    pub current_password: String,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmEmailChangeRequest {
    #[validate(length(min = 1, max = 10))]
    pub code: String,
}

// ─── POST /api/users/me/change-email ────────────────────────────────

pub async fn change_email(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<ChangeEmailRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("POST /api/users/me/change-email user_id={}", user_id.0);
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::AUTH_LIMIT,
        &format!("change-email:{}", user_id.0),
    )
    .await?;

    let new_email = crate::services::email_validation::normalize_routable_email(&body.new_email)?;

    let user = load_pg_user(&state, user_id.0).await?;

    let valid = hash_service::verify_password(
        &state,
        user.password_hash.clone(),
        body.current_password.clone(),
    )
    .await?;
    if !valid {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "USER_PASSWORD_INCORRECT",
            message: "Current password is incorrect".into(),
        });
    }

    if user.email.to_lowercase() != body.current_email.trim().to_lowercase() {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "USER_EMAIL_MISMATCH",
            message: "Current email is incorrect".into(),
        });
    }

    // Check new email uniqueness — case-insensitive lookup against PG.
    match crate::services::pg::users::by_email_lower_with_crypto(
        &state.pg,
        &new_email,
        state.field_crypto.as_ref(),
    )
    .await
    {
        Ok(Some(existing)) if existing.id != user_id.0 => {
            return Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "USER_DUPLICATE_FIELD",
                message: "Unable to update email. Please try a different address.".into(),
            });
        }
        Err(e) => {
            tracing::error!(error = %e, "email_change: PG uniqueness check failed");
            return Err(AppError::Internal);
        }
        _ => {}
    }

    let has_2fa = user.totp_enabled_at.is_some();

    let code = generate_verification_code();
    let code_hash = hash_token(&code);
    let redis_key = format!("email-change:{}", user_id.0);
    let redis_value = format!("{}|{}", code_hash, new_email);
    let _: Result<(), _> = fred::interfaces::KeysInterface::set(
        &state.redis,
        &redis_key,
        redis_value.as_str(),
        Some(fred::types::Expiration::EX(600)),
        None,
        false,
    )
    .await;

    if let Some(ref email_svc) = state.email {
        let svc = email_svc.clone();
        let to = user.email.clone();
        let c = code.clone();
        let ne = new_email.clone();
        tokio::spawn(async move {
            if let Err(e) = svc.send_email_change_verification(&to, &c, &ne).await {
                tracing::error!("Failed to send email change verification: {e}");
            }
        });
    } else {
        tracing::warn!(
            user_id = user_id.0,
            "change_email: email service not configured; verification email not sent"
        );
    }

    tracing::info!(
        "Email change code sent user_id={} has_2fa={}",
        user_id.0,
        has_2fa
    );
    Ok(Json(json!({ "codeSent": true, "has2fa": has_2fa })))
}

// ─── POST /api/users/me/change-email/confirm ────────────────────────

pub async fn confirm_email_change(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<ConfirmEmailChangeRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "POST /api/users/me/change-email/confirm user_id={}",
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::AUTH_LIMIT,
        &format!("change-email-confirm:{}", user_id.0),
    )
    .await?;

    let redis_key = format!("email-change:{}", user_id.0);
    let stored: Option<String> = fred::interfaces::KeysInterface::get(&state.redis, &redis_key)
        .await
        .unwrap_or(None);

    let stored = stored.ok_or_else(|| AppError::WithCode {
        status: StatusCode::BAD_REQUEST,
        code: "EMAIL_CHANGE_EXPIRED",
        message: "Email change request expired or not found. Please start again.".into(),
    })?;

    let (stored_hash, new_email) = stored.split_once('|').ok_or(AppError::Internal)?;

    let record = load_pg_user(&state, user_id.0).await?;

    let code_hash = hash_token(&body.code);
    let mut verified = code_hash == stored_hash;

    // Try TOTP if 2FA is enabled and the email code didn't match.
    if !verified && record.totp_enabled_at.is_some() {
        if let Some(secret_b64) = record.totp_secret.as_deref() {
            if let Some(ref enc_key) = state.config.totp_encryption_key {
                if let Ok(secret) = totp::decrypt_secret(secret_b64, enc_key) {
                    if let Ok(true) = totp::verify_code(&secret, &body.code, &record.username) {
                        verified = true;
                    }
                }
            }
        }
    }

    if !verified {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "EMAIL_CHANGE_INVALID_CODE",
            message: "Invalid verification code".into(),
        });
    }

    // Swap the email + mark verified in one PG update.
    crate::services::pg::users::update_with_crypto(
        &state.pg,
        user_id.0,
        crate::services::pg::users::UpdateUser {
            email: Some(new_email),
            email_verified: Some(true),
            ..Default::default()
        },
        state.field_crypto.as_ref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "confirm_email_change: PG write failed");
        AppError::Internal
    })?;

    let _: Result<(), _> = fred::interfaces::KeysInterface::del(&state.redis, &redis_key).await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::EmailChange,
            target_type: "user",
            target_id: user_id.0,
            server_id: None,
            metadata: None,
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!("Email changed successfully user_id={}", user_id.0);
    let updated = load_pg_user(&state, user_id.0).await?;
    let status = crate::services::presence::effective_status(&state.redis, user_id.0).await;
    Ok(Json(user_to_full_response_json(
        &updated,
        &status,
        member_list_banner_visible_for_record(&state, &updated),
    )))
}

// ─── GET /api/users/me ──────────────────────────────────────────────

pub async fn get_me(State(state): State<AppState>, user_id: UserId) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/users/me user_id={}", user_id.0);
    let record = load_pg_user(&state, user_id.0).await?;
    let status = crate::services::presence::effective_status(&state.redis, user_id.0).await;
    let member_list_banner_visible = member_list_banner_visible_for_record(&state, &record);
    let response = user_to_full_response_json(&record, &status, member_list_banner_visible);
    let media = crate::handlers::media_diagnostics::summarize_user_media(&response, "currentUser");
    tracing::info!(
        user_id = user_id.0,
        member_list_banner_visible,
        media = ?media,
        "users.get_me emitted media fields"
    );
    Ok(Json(response))
}

// ─── PATCH /api/users/me ────────────────────────────────────────────

pub async fn update_me(
    State(state): State<AppState>,
    user_id: UserId,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateUserRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("PATCH /api/users/me user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let uid = user_id.0;

    let body = UpdateUserRequest {
        display_name: body.display_name.map(|opt| opt.map(|s| sanitize_text(&s))),
        bio: body.bio.map(|opt| opt.map(|s| sanitize_text(&s))),
        banner_base_color: body.banner_base_color,
        custom_status_text: body
            .custom_status_text
            .map(|opt| opt.map(|s| sanitize_text(&s))),
        custom_status_emoji: body
            .custom_status_emoji
            .map(|opt| opt.map(|s| sanitize_text(&s))),
        ..body
    };

    if let Some(Some(ref display_name)) = body.display_name {
        if display_name.chars().count() > 100 {
            return Err(AppError::Validation(
                "Display name must be at most 100 characters".into(),
            ));
        }
    }
    if let Some(Some(ref bio)) = body.bio {
        if bio.chars().count() > 500 {
            return Err(AppError::Validation(
                "Bio must be at most 500 characters".into(),
            ));
        }
    }
    if let Some(Some(ref banner_base_color)) = body.banner_base_color {
        if normalize_banner_base_color(banner_base_color).is_none() {
            return Err(AppError::Validation(
                "Banner base color must be a #RRGGBB hex value".into(),
            ));
        }
    }
    if let Some(Some(ref custom_status_text)) = body.custom_status_text {
        if custom_status_text.chars().count() > 80 {
            return Err(AppError::Validation(
                "Status text must be at most 80 characters".into(),
            ));
        }
    }
    if let Some(Some(ref custom_status_emoji)) = body.custom_status_emoji {
        if custom_status_emoji.chars().count() > 64 {
            return Err(AppError::Validation(
                "Status emoji must be at most 64 characters".into(),
            ));
        }
    }

    let record = load_pg_user(&state, uid).await?;

    if body.password.is_some() {
        let current_pw = body
            .current_password
            .as_deref()
            .ok_or_else(|| AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "USER_PASSWORD_REQUIRED",
                message: "Current password is required to change password".into(),
            })?;

        let valid = hash_service::verify_password(
            &state,
            record.password_hash.clone(),
            current_pw.to_string(),
        )
        .await?;
        if !valid {
            tracing::warn!("update_me: incorrect current password user_id={}", uid);
            return Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "USER_PASSWORD_INCORRECT",
                message: "Current password is incorrect".into(),
            });
        }
    }

    let new_hash = if let Some(ref password) = body.password {
        if password.len() < 8 {
            return Err(AppError::Validation(
                "Password must be at least 8 characters".into(),
            ));
        }
        Some(hash_service::hash_password(&state, password.clone()).await?)
    } else {
        None
    };

    let has_changes = body.password.is_some()
        || body.display_name.is_some()
        || body.bio.is_some()
        || body.banner_base_color.is_some()
        || body.custom_status_text.is_some()
        || body.custom_status_emoji.is_some();
    if !has_changes {
        return Err(AppError::NoChanges);
    }

    // Translate Option<Option<String>> into the PG patch shape. Empty
    // string is the legacy "unset" sentinel and is preserved here so
    // a clear-to-null on the wire writes "" to the column; reads
    // map both NULL and "" to None on the response builder.
    let display_name_arg: Option<String> = body
        .display_name
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());
    let bio_arg: Option<String> = body.bio.as_ref().map(|opt| opt.clone().unwrap_or_default());
    let banner_base_color_arg: Option<String> = body.banner_base_color.as_ref().map(|opt| {
        opt.as_deref()
            .and_then(normalize_banner_base_color)
            .unwrap_or_default()
    });
    let custom_status_text_arg: Option<String> = body
        .custom_status_text
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());
    let custom_status_emoji_arg: Option<String> = body
        .custom_status_emoji
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());

    crate::services::pg::users::update(
        &state.pg,
        uid,
        crate::services::pg::users::UpdateUser {
            display_name: display_name_arg.as_deref(),
            bio: bio_arg.as_deref(),
            banner_base_color: banner_base_color_arg.as_deref(),
            custom_status_text: custom_status_text_arg.as_deref(),
            custom_status_emoji: custom_status_emoji_arg.as_deref(),
            password_hash: new_hash.as_deref(),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = uid, error = %e, "update_me: PG write failed");
        AppError::Internal
    })?;

    if body.display_name.is_some()
        || body.bio.is_some()
        || body.banner_base_color.is_some()
        || body.custom_status_text.is_some()
        || body.custom_status_emoji.is_some()
    {
        state.user_profiles.invalidate(uid);
    }

    if body.password.is_some() {
        audit::log_async(
            state.redis.clone(),
            AuditEntry {
                id: state.snowflake.next_id(),
                actor_id: uid,
                action: AuditAction::PasswordChange,
                target_type: "user",
                target_id: uid,
                server_id: None,
                metadata: None,
                ip: None,
            },
            state.pg.clone(),
        );

        tracing::info!("Password changed, revoking all sessions user_id={}", uid);
        let _ = session::revoke_all_user_sessions(&state.pg, uid).await?;

        if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                blacklist_access_token(token, &state.config.jwt_secret, &state.redis).await;
            }
        }
    }

    let updated = load_pg_user(&state, uid).await?;
    if body.display_name.is_some() || body.bio.is_some() || body.banner_base_color.is_some() {
        let display_name_for_event = if body.display_name.is_some() {
            display_name_arg.as_deref()
        } else {
            None
        };
        let bio_for_event = if body.bio.is_some() {
            bio_arg.as_deref()
        } else {
            None
        };
        let banner_base_color_for_event = if body.banner_base_color.is_some() {
            banner_base_color_arg.as_deref()
        } else {
            None
        };
        broadcast_profile_fields_update(
            &state,
            uid,
            display_name_for_event,
            bio_for_event,
            banner_base_color_for_event,
        )
        .await;
    }
    let status = crate::services::presence::effective_status(&state.redis, uid).await;
    Ok(Json(user_to_full_response_json(
        &updated,
        &status,
        member_list_banner_visible_for_record(&state, &updated),
    )))
}

// ─── PATCH /api/users/me/server-order ───────────────────────────────

pub async fn update_server_order(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<ServerOrderRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("PATCH /api/users/me/server-order user_id={}", user_id.0);
    if body.server_ids.len() > 200 {
        return Err(AppError::Validation("Too many server IDs".into()));
    }

    let member_ids: std::collections::HashSet<i64> =
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id.0)
            .await
            .map_err(|e| {
                tracing::error!(user_id = user_id.0, error = %e, "update_server_order: PG servers read failed");
                AppError::Internal
            })?
            .into_iter()
            .collect();

    let validated: Vec<i64> = body
        .server_ids
        .into_iter()
        .filter_map(|s| s.parse::<i64>().ok())
        .filter(|id| member_ids.contains(id))
        .collect();

    crate::services::pg::users::update(
        &state.pg,
        user_id.0,
        crate::services::pg::users::UpdateUser {
            server_order: Some(&validated),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "update_server_order: PG write failed");
        AppError::Internal
    })?;

    tracing::info!(
        "Updated server order user_id={} count={}",
        user_id.0,
        validated.len()
    );
    let validated_str: Vec<String> = validated.iter().map(|id| id.to_string()).collect();
    Ok(Json(json!({ "serverOrder": validated_str })))
}

// ─── PATCH /api/users/me/favorite-order ─────────────────────────────

pub async fn update_favorite_order(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<ServerOrderRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("PATCH /api/users/me/favorite-order user_id={}", user_id.0);
    if body.server_ids.len() > 8 {
        return Err(AppError::Validation("Too many favorite IDs".into()));
    }

    let member_ids: std::collections::HashSet<i64> =
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id.0)
            .await
            .map_err(|e| {
                tracing::error!(user_id = user_id.0, error = %e, "update_favorite_order: PG servers read failed");
                AppError::Internal
            })?
            .into_iter()
            .collect();

    let validated: Vec<i64> = body
        .server_ids
        .into_iter()
        .filter_map(|s| s.parse::<i64>().ok())
        .filter(|id| member_ids.contains(id))
        .collect();

    crate::services::pg::users::update(
        &state.pg,
        user_id.0,
        crate::services::pg::users::UpdateUser {
            favorite_order: Some(&validated),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "update_favorite_order: PG write failed");
        AppError::Internal
    })?;

    tracing::info!(
        "Updated favorite order user_id={} count={}",
        user_id.0,
        validated.len()
    );
    let validated_str: Vec<String> = validated.iter().map(|id| id.to_string()).collect();
    Ok(Json(json!({ "favoriteOrder": validated_str })))
}

// ─── GET /api/users/:userId ─────────────────────────────────────────

pub async fn get_user(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/users/{} user_id={}", target_id_str, user_id.0);
    let target_id: i64 = target_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid user ID".into()))?;

    if target_id != user_id.0 {
        // Shared context = (A) common server membership or (B) shared DM
        let caller_servers = crate::services::pg::servers::list_server_ids_for_user(
            &state.pg, user_id.0,
        )
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "get_user: PG server list failed");
            AppError::Internal
        })?;
        let target_servers =
            crate::services::pg::servers::list_server_ids_for_user(&state.pg, target_id)
                .await
                .map_err(|e| {
                    tracing::error!(target_id, error = %e, "get_user: PG server list failed");
                    AppError::Internal
                })?;
        let caller_set: std::collections::HashSet<i64> = caller_servers.into_iter().collect();
        let shares_server = target_servers.iter().any(|id| caller_set.contains(id));

        let shares_context = if shares_server {
            true
        } else {
            let caller_dms = crate::services::pg::dms::list_channel_ids_for_user(
                &state.pg, user_id.0,
            )
            .await
            .map_err(|e| {
                tracing::error!(user_id = user_id.0, error = %e, "get_user: PG DM list failed");
                AppError::Internal
            })?;
            let target_dms =
                crate::services::pg::dms::list_channel_ids_for_user(&state.pg, target_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(target_id, error = %e, "get_user: PG DM list failed");
                        AppError::Internal
                    })?;
            let caller_dm_set: std::collections::HashSet<i64> = caller_dms.into_iter().collect();
            target_dms.iter().any(|id| caller_dm_set.contains(id))
        };

        if !shares_context {
            return Err(AppError::NotFound("user"));
        }
    }

    let record = load_pg_user(&state, target_id).await?;
    if record.deleted_at.is_some() {
        return Err(AppError::NotFound("user"));
    }

    let status = crate::services::presence::effective_status(&state.redis, target_id).await;
    let member_list_banner_visible = member_list_banner_visible_for_record(&state, &record);
    let response = user_to_public_response_json(&record, &status, member_list_banner_visible);
    let media = crate::handlers::media_diagnostics::summarize_user_media(&response, "user");
    tracing::info!(
        requester_id = user_id.0,
        target_id,
        member_list_banner_visible,
        media = ?media,
        "users.get_user emitted media fields"
    );
    Ok(Json(response))
}

// ─── GET /api/users/:userId/mutual-servers ────────────────────────────

pub async fn get_mutual_servers(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/users/{}/mutual-servers user_id={}",
        target_id_str,
        user_id.0
    );
    let target_id: i64 = target_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid user ID".into()))?;

    let (caller_server_ids, target_server_ids) = tokio::try_join!(
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id.0),
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, target_id),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "get_mutual_servers: PG server list failed");
        AppError::Internal
    })?;

    let target_set: std::collections::HashSet<i64> = target_server_ids.into_iter().collect();
    let mutual_ids: Vec<i64> = caller_server_ids
        .into_iter()
        .filter(|id| target_set.contains(id))
        .collect();

    if target_id != user_id.0 && mutual_ids.is_empty() {
        let (caller_dm_ids, target_dm_ids) = tokio::try_join!(
            crate::services::pg::dms::list_channel_ids_for_user(&state.pg, user_id.0),
            crate::services::pg::dms::list_channel_ids_for_user(&state.pg, target_id),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "get_mutual_servers: PG DM list failed");
            AppError::Internal
        })?;
        let target_dm_set: std::collections::HashSet<i64> = target_dm_ids.iter().copied().collect();
        let shares_dm = caller_dm_ids.iter().any(|id| target_dm_set.contains(id));
        if !shares_dm {
            return Err(AppError::NotFound("user"));
        }
    }

    let mutual_servers = crate::services::pg::servers::by_ids(&state.pg, &mutual_ids)
        .await
        .unwrap_or_default();

    let result: Vec<Value> = mutual_servers
        .iter()
        .map(|s| {
            json!({
                "id": s.id.to_string(),
                "name": s.name,
                "iconUrl": cdn::resolve(s.icon_url.as_deref()),
            })
        })
        .collect();

    tracing::info!(
        "Found {} mutual servers for user_id={} target_id={}",
        result.len(),
        user_id.0,
        target_id
    );
    Ok(Json(json!(result)))
}

// ─── Session helpers ────────────────────────────────────────────

fn parse_device_label(ua: Option<&str>) -> String {
    let ua = match ua {
        Some(s) if !s.is_empty() => s,
        _ => return "Unknown device".to_string(),
    };

    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else {
        ""
    };

    let is_desktop_app = ua.contains("Edg/") && ua.contains("Windows") && !ua.contains("Mobile");
    if is_desktop_app {
        return if os.is_empty() {
            "Verdant Desktop".to_string()
        } else {
            format!("Verdant Desktop on {os}")
        };
    }

    let browser = if ua.contains("Firefox") {
        "Firefox"
    } else if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome") {
        "Chrome"
    } else if ua.contains("Safari") {
        "Safari"
    } else {
        "Unknown"
    };

    if os.is_empty() {
        browser.to_string()
    } else {
        format!("{browser} on {os}")
    }
}

// ─── GET /api/users/me/sessions ──────────────────────────────────

pub async fn list_sessions(
    State(state): State<AppState>,
    user_id: UserId,
    session_id: SessionId,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/users/me/sessions user_id={}", user_id.0);
    let mut sessions = crate::services::pg::sessions::list_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "list_sessions: PG read failed");
            AppError::Internal
        })?;
    sessions.sort_by_key(|s| s.created_at_ms);

    let current_sid = session_id.0;
    let fmt_rfc = |ms: i64| -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339()
    };
    let result: Vec<Value> = sessions
        .iter()
        .map(|s| {
            let device = parse_device_label(s.user_agent.as_deref());
            json!({
                "id": s.id.to_string(),
                "isCurrent": current_sid == Some(s.id),
                "device": device,
                "city": s.city.clone(),
                "country": s.country.clone(),
                "lastCity": s.city.clone(),
                "lastCountry": s.country.clone(),
                "createdAt": fmt_rfc(s.created_at_ms),
                "lastRefreshAt": fmt_rfc(if s.last_used_at_ms != 0 { s.last_used_at_ms } else { s.created_at_ms }),
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

// ─── DELETE /api/users/me/sessions/:sessionId ───────────────────

pub async fn revoke_session(
    State(state): State<AppState>,
    user_id: UserId,
    session_id: SessionId,
    Path(target_session_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/users/me/sessions/{} user_id={}",
        target_session_id_str,
        user_id.0
    );
    let target_session_id: i64 = target_session_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid session ID".into()))?;

    if session_id.0 == Some(target_session_id) {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "SESSION_IS_CURRENT",
            message: "Cannot revoke your current session. Use logout instead.".into(),
        });
    }

    let session_record = crate::services::pg::sessions::by_id(&state.pg, target_session_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "revoke_session: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("session"))?;
    if session_record.user_id != user_id.0 {
        return Err(AppError::NotFound("session"));
    }

    let _ = crate::services::pg::sessions::delete_one(&state.pg, target_session_id).await;

    tracing::info!(
        "Session revoked session_id={} user_id={}",
        target_session_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/users/me/sessions/revoke-all ─────────────────────

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    user_id: UserId,
    session_id: SessionId,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/users/me/sessions/revoke-all user_id={}",
        user_id.0
    );

    let current_sid = session_id.0.unwrap_or(0);
    // Single delete that excludes the current session — simpler than
    // the iterate-and-skip pattern and avoids race windows where a new
    // session could land between list and delete.
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
        .bind(user_id.0)
        .bind(current_sid)
        .execute(&state.pg)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "revoke_all_sessions: PG delete failed");
            AppError::Internal
        })?;

    tracing::info!("All other sessions revoked user_id={}", user_id.0);
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/users/me/delete ──────────────────────────────────

#[derive(Deserialize, Validate)]
pub struct DeleteAccountRequest {
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    user_id: UserId,
    headers: axum::http::HeaderMap,
    Json(body): Json<DeleteAccountRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("POST /api/users/me/delete user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;

    let record = load_pg_user(&state, user_id.0).await?;

    let valid =
        hash_service::verify_password(&state, record.password_hash.clone(), body.password).await?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    crate::services::pg::users::soft_delete(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "delete_account: PG soft-delete failed");
            AppError::Internal
        })?;

    // Soft-delete every owned server in one update.
    let now_ms = chrono::Utc::now().timestamp_millis();
    let _ = sqlx::query(
        "UPDATE servers SET deleted_at_ms = $2 WHERE owner_id = $1 AND deleted_at_ms IS NULL",
    )
    .bind(user_id.0)
    .bind(now_ms)
    .execute(&state.pg)
    .await;

    let _ = session::revoke_all_user_sessions(&state.pg, user_id.0).await?;

    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            blacklist_access_token(token, &state.config.jwt_secret, &state.redis).await;
        }
    }

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::DeleteAccount,
            target_type: "user",
            target_id: user_id.0,
            server_id: None,
            metadata: None,
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!("Account soft-deleted user_id={}", user_id.0);
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/users/me/username — set username (one-time) ──

#[derive(Deserialize)]
pub struct SetUsernameRequest {
    pub username: String,
}

pub async fn set_username(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<SetUsernameRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!("POST /api/users/me/username user_id={}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;

    let username = sanitize_text(&body.username);
    if username.is_empty() || username.len() > 32 {
        return Err(AppError::Validation(
            "Username must be 1-32 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(AppError::Validation(
            "Username may only contain letters, numbers, and underscores".into(),
        ));
    }

    if let Err(reason) = username_safety::check_username(&username) {
        return Err(AppError::Validation(reason.into()));
    }

    if username.to_lowercase().starts_with("loadtest_user_") {
        return Err(AppError::Validation("Username is reserved".into()));
    }

    // Case-insensitive uniqueness check against PG (also writes the
    // Redis index below for the friend-request resolver).
    if let Some(existing) = crate::services::pg::users::by_username_lower(&state.pg, &username)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "set_username: PG uniqueness check failed");
            AppError::Internal
        })?
    {
        if existing.id != user_id.0 {
            return Err(AppError::Validation("Username is already taken".into()));
        }
    }

    use fred::interfaces::KeysInterface;
    let lc = username.to_lowercase();
    let index_key = format!("username:{lc}");

    let record = load_pg_user(&state, user_id.0).await?;
    if record.username_set {
        return Err(AppError::Validation("Username has already been set".into()));
    }

    crate::services::pg::users::update(
        &state.pg,
        user_id.0,
        crate::services::pg::users::UpdateUser {
            username: Some(&username),
            username_set: Some(true),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "set_username: PG write failed");
        AppError::Internal
    })?;

    let _: Result<(), _> = state
        .redis
        .set::<(), _, _>(&index_key, user_id.0.to_string(), None, None, false)
        .await;

    tracing::info!("Username set user_id={} username={}", user_id.0, username);
    let updated = load_pg_user(&state, user_id.0).await?;
    let status = crate::services::presence::effective_status(&state.redis, user_id.0).await;
    Ok(Json(json!({ "user": user_to_full_response_json(
            &updated,
            &status,
            member_list_banner_visible_for_record(&state, &updated),
        ) })))
}

// ─── Deprecated Subscription Ring Style ──────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRingStyleRequest {
    pub ring_style: Option<String>,
}

pub async fn set_ring_style(
    State(state): State<AppState>,
    user_id: UserId,
    Json(_body): Json<SetRingStyleRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/users/me/subscription/ring-style user_id={}",
        user_id.0
    );

    rate_limit::enforce(&state, &rate_limit::UPDATE_LIMIT, &user_id.0.to_string()).await?;

    crate::services::subscription::set_ring_style(&state.pg, user_id.0, None)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "set_ring_style: PG clear failed");
            AppError::Internal
        })?;

    Ok(Json(json!({ "ringStyle": null })))
}

// ─── Preferences ────────────────────────────────────────────────────

const KNOWN_PREF_KEYS: &[&str] = &[
    "activeServerId",
    "activeChannels",
    "hiddenDmIds",
    "collapsedCategoryIds",
    "recentEmojis",
    "favoriteEmojis",
    "emojiSkinTone",
];
const MAX_RECENT_EMOJIS: usize = 30;
const MAX_FAVORITE_EMOJIS: usize = 50;
const MAX_HIDDEN_DM_IDS: usize = 500;
const MAX_HIDDEN_DM_ID_LEN: usize = 160;
const MAX_PREF_BODY_SIZE: usize = 16 * 1024;

pub async fn update_preferences(
    State(state): State<AppState>,
    UserId(user_id): UserId,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::UPDATE_LIMIT, &user_id.to_string()).await?;

    let obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("Body must be a JSON object".into()))?;

    let serialized = serde_json::to_string(&body).unwrap_or_default();
    if serialized.len() > MAX_PREF_BODY_SIZE {
        return Err(AppError::Validation(
            "Preferences body too large (max 16KB)".into(),
        ));
    }

    for key in obj.keys() {
        if !KNOWN_PREF_KEYS.contains(&key.as_str()) {
            return Err(AppError::Validation(format!(
                "Unknown preference key: {key}"
            )));
        }
    }

    if let Some(v) = obj.get("activeServerId") {
        if !v.is_string() && !v.is_null() {
            return Err(AppError::Validation(
                "activeServerId must be a string or null".into(),
            ));
        }
    }
    if let Some(v) = obj.get("activeChannels") {
        if let Some(map) = v.as_object() {
            for (_, val) in map {
                if !val.is_string() {
                    return Err(AppError::Validation(
                        "activeChannels values must be strings".into(),
                    ));
                }
            }
        } else {
            return Err(AppError::Validation(
                "activeChannels must be an object".into(),
            ));
        }
    }
    let owned_dm_channel_ids = if obj.contains_key("hiddenDmIds") {
        let ids = crate::services::pg::dms::list_channel_ids_for_user(&state.pg, user_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    user_id,
                    error = %e,
                    "update_preferences: PG DM membership read failed"
                );
                AppError::Internal
            })?;
        Some(
            ids.into_iter()
                .map(|id| id.to_string())
                .collect::<HashSet<_>>(),
        )
    } else {
        None
    };
    let mut sanitized_hidden_dm_ids = None;
    if let Some(v) = obj.get("hiddenDmIds") {
        let owned = owned_dm_channel_ids.as_ref().expect("owned DM IDs loaded");
        sanitized_hidden_dm_ids = Some(hidden_dm_ids_owned_by_user(v, owned)?);
    }
    if let Some(v) = obj.get("collapsedCategoryIds") {
        if !v.is_array() {
            return Err(AppError::Validation(
                "collapsedCategoryIds must be an array".into(),
            ));
        }
    }
    if let Some(v) = obj.get("recentEmojis") {
        match v.as_array() {
            Some(arr) if arr.len() <= MAX_RECENT_EMOJIS => {}
            Some(_) => {
                return Err(AppError::Validation(format!(
                    "recentEmojis max {MAX_RECENT_EMOJIS} items"
                )));
            }
            None => return Err(AppError::Validation("recentEmojis must be an array".into())),
        }
    }
    if let Some(v) = obj.get("favoriteEmojis") {
        match v.as_array() {
            Some(arr) if arr.len() <= MAX_FAVORITE_EMOJIS => {}
            Some(_) => {
                return Err(AppError::Validation(format!(
                    "favoriteEmojis max {MAX_FAVORITE_EMOJIS} items"
                )));
            }
            None => {
                return Err(AppError::Validation(
                    "favoriteEmojis must be an array".into(),
                ));
            }
        }
    }
    if let Some(v) = obj.get("emojiSkinTone") {
        match v.as_u64() {
            Some(n) if n <= 5 => {}
            _ => return Err(AppError::Validation("emojiSkinTone must be 0-5".into())),
        }
    }

    // PG stores preferences as a single jsonb value. We RMW: pull the
    // current map, merge the patch (null clears a key), write back.
    let record = load_pg_user(&state, user_id).await?;
    let mut merged = record.preferences.clone();
    if !merged.is_object() {
        merged = json!({});
    }
    if let Some(merged_obj) = merged.as_object_mut() {
        for (k, v) in obj {
            if v.is_null() {
                merged_obj.remove(k);
            } else if k == "hiddenDmIds" {
                merged_obj.insert(
                    k.clone(),
                    json!(
                        sanitized_hidden_dm_ids
                            .clone()
                            .expect("hiddenDmIds sanitized")
                    ),
                );
            } else {
                merged_obj.insert(k.clone(), v.clone());
            }
        }
    }

    crate::services::pg::users::update(
        &state.pg,
        user_id,
        crate::services::pg::users::UpdateUser {
            preferences: Some(&merged),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "update_preferences: PG write failed");
        AppError::Internal
    })?;

    Ok(Json(json!({ "preferences": merged })))
}

fn validate_hidden_dm_ids(value: &Value) -> AppResult<()> {
    let Some(items) = value.as_array() else {
        return Err(AppError::Validation("hiddenDmIds must be an array".into()));
    };
    if items.len() > MAX_HIDDEN_DM_IDS {
        return Err(AppError::Validation(format!(
            "hiddenDmIds max {MAX_HIDDEN_DM_IDS} items"
        )));
    }
    for item in items {
        let Some(id) = item.as_str() else {
            return Err(AppError::Validation(
                "hiddenDmIds values must be strings".into(),
            ));
        };
        if !is_safe_preference_local_id(id) {
            return Err(AppError::Validation(
                "hiddenDmIds values must be backend-local IDs".into(),
            ));
        }
    }
    Ok(())
}

fn hidden_dm_ids_owned_by_user(
    value: &Value,
    owned_dm_channel_ids: &HashSet<String>,
) -> AppResult<Vec<String>> {
    validate_hidden_dm_ids(value)?;
    let items = value
        .as_array()
        .expect("validate_hidden_dm_ids requires an array");
    Ok(items
        .iter()
        .filter_map(|item| item.as_str())
        .filter(|id| owned_dm_channel_ids.contains(*id))
        .map(str::to_string)
        .collect())
}

fn is_safe_preference_local_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= MAX_HIDDEN_DM_ID_LEN
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
        && !trimmed.chars().any(char::is_whitespace)
        && !trimmed.chars().any(char::is_control)
        && !trimmed.contains("%2f")
        && !trimmed.contains("%2F")
        && !trimmed.contains("%5c")
        && !trimmed.contains("%5C")
}

#[cfg(test)]
mod preference_tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashSet;

    #[test]
    fn hidden_dm_preferences_accept_backend_local_ids_only() {
        validate_hidden_dm_ids(&json!(["123", "dm-avery"])).unwrap();

        for value in [
            json!("123"),
            json!([123]),
            json!(["official/123"]),
            json!(["origin%3Ahttps%253A%252F%252Fapi.example.test/123"]),
            json!(["dm/poison"]),
            json!(["dm\\poison"]),
            json!(["dm poison"]),
            json!(["dm%2Fpoison"]),
            json!([""]),
        ] {
            assert!(validate_hidden_dm_ids(&value).is_err());
        }
    }

    #[test]
    fn hidden_dm_preferences_keep_only_owned_backend_local_ids() {
        let owned = HashSet::from(["dm-owned".to_string(), "123".to_string()]);

        assert_eq!(
            hidden_dm_ids_owned_by_user(&json!(["dm-owned", "dm-foreign", "123"]), &owned).unwrap(),
            vec!["dm-owned".to_string(), "123".to_string()]
        );
    }

    #[test]
    fn full_user_response_includes_preferences_without_secrets() {
        let now = Utc::now();
        let row = UserRow {
            id: 42,
            username: "joshi".into(),
            email: "private@example.test".into(),
            password_hash: "hash-secret".into(),
            avatar_url: None,
            status: "online".into(),
            status_type: "manual".into(),
            subscribed: false,
            display_name: Some("Joshy".into()),
            bio: None,
            custom_status_text: None,
            custom_status_emoji: None,
            created_at: now,
            updated_at: now,
            totp_secret: Some("totp-secret".into()),
            totp_enabled_at: Some(now),
            banner_url: None,
            banner_base_color: None,
            banner_crop: None,
            member_list_banner_url: None,
            member_list_banner_crop: None,
            server_order: json!([]),
            favorite_order: json!([]),
            email_verified: true,
            deleted_at: None,
            username_set: true,
            preferences: json!({ "hiddenDmIds": ["dm-avery"] }),
            subscription_tier: None,
            subscription_expires_at: None,
            subscription_ring_style: None,
            status_auto: false,
            preferred_status: "online".into(),
        };

        let response = user_to_full_response_json(&row, "online", false);

        assert_eq!(
            response.pointer("/preferences/hiddenDmIds/0"),
            Some(&json!("dm-avery"))
        );
        assert!(response.get("email").is_none());
        assert!(response.get("passwordHash").is_none());
        assert!(response.get("password_hash").is_none());
        assert!(response.get("totpSecret").is_none());
        assert!(response.get("totp_secret").is_none());
    }
}
