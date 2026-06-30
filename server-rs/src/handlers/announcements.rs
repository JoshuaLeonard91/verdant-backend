use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::{OptionalBot, UserId};
use crate::middleware::rate_limit;
use crate::services::announcements::Announcement;
use crate::services::permissions::bits;
use crate::services::pg::announcements::{AnnouncementRow, InsertAnnouncement};
use crate::services::pg::bots::{SCOPE_ANNOUNCEMENTS_WRITE, has_scope};
use crate::services::pg::feeds::FeedRow;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const DEFAULT_ANNOUNCEMENT_LIMIT: usize = 25;
const MAX_ANNOUNCEMENT_LIMIT: usize = 50;

// ─── Serialization helpers ─────────────────────────────────────────

fn announcement_to_json(a: &AnnouncementRow) -> Value {
    json!({
        "id": a.id.to_string(),
        "feedId": a.feed_id.to_string(),
        "serverId": a.server_id.to_string(),
        "content": a.content.clone(),
        "postedBy": a.posted_by.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
        "botId": a.bot_id.map(|v| Value::String(v.to_string())).unwrap_or(Value::Null),
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(a.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        "updatedAt": a.updated_at_ms
            .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
            .map(|t| Value::String(t.to_rfc3339()))
            .unwrap_or(Value::Null),
    })
}

fn announcement_to_proto(a: &AnnouncementRow) -> crate::proto::Announcement {
    let title = a
        .content
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let content = serde_json::to_string(&a.content).unwrap_or_default();
    let author_id = a
        .posted_by
        .or(a.bot_id)
        .map(|v| v.to_string())
        .unwrap_or_default();
    crate::proto::Announcement {
        id: a.id.to_string(),
        feed_id: a.feed_id.to_string(),
        server_id: a.server_id.to_string(),
        title,
        content,
        author_id,
        author_username: None,
        author_avatar: None,
        created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(a.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        updated_at: a
            .updated_at_ms
            .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
            .map(|t| t.to_rfc3339()),
    }
}

// ─── Request types ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AnnouncementQueryParams {
    pub before: Option<String>,
    pub limit: Option<i64>,
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Check if a user can publish to a feed based on publish_role_ids.
async fn can_publish(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    publish_role_ids: &[i64],
) -> bool {
    // MANAGE_SERVER always can publish
    if state
        .permissions
        .check_server_permission(user_id, server_id, bits::MANAGE_SERVER)
        .await
        .is_ok()
    {
        return true;
    }
    // Empty publish_role_ids → only MANAGE_SERVER can publish (checked above)
    if publish_role_ids.is_empty() {
        return false;
    }
    let Ok(role_ids) =
        crate::services::pg::roles::list_role_ids(&state.pg, user_id, server_id).await
    else {
        return false;
    };
    let user_roles: std::collections::HashSet<i64> = role_ids.into_iter().collect();
    publish_role_ids.iter().any(|r| user_roles.contains(r))
}

async fn can_publish_visible_feed(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    feed: &FeedRow,
) -> bool {
    can_view_feed(state, user_id, server_id, &feed.visible_role_ids).await
        && can_publish(state, user_id, server_id, &feed.publish_role_ids).await
}

/// Check if a user can view a feed based on visible_role_ids.
async fn can_view_feed(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    visible_role_ids: &[i64],
) -> bool {
    // ADMINISTRATOR sees all feeds
    if state
        .permissions
        .check_server_permission(user_id, server_id, bits::ADMINISTRATOR)
        .await
        .is_ok()
    {
        return true;
    }
    // Empty visible_role_ids → visible to all members
    if visible_role_ids.is_empty() {
        return true;
    }
    let Ok(role_ids) =
        crate::services::pg::roles::list_role_ids(&state.pg, user_id, server_id).await
    else {
        return false;
    };
    let user_roles: std::collections::HashSet<i64> = role_ids.into_iter().collect();
    visible_role_ids.iter().any(|r| user_roles.contains(r))
}

async fn load_feed(state: &AppState, feed_id: i64) -> AppResult<FeedRow> {
    crate::services::pg::feeds::by_id(&state.pg, feed_id)
        .await
        .map_err(|e| {
            tracing::error!(feed_id, error = %e, "announcements: PG feed read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("feed"))
}

async fn bot_can_publish_feed(
    state: &AppState,
    bot: &crate::middleware::auth::BotIdentity,
    feed: &FeedRow,
) -> AppResult<bool> {
    if !(has_scope(&bot.scopes, SCOPE_ANNOUNCEMENTS_WRITE)
        && bot.allowed_feed_ids.contains(&feed.id))
    {
        return Ok(false);
    }
    crate::services::bot_permissions::can_publish_feed(state, bot, feed).await
}

fn bot_id_from_optional(optional_bot: &OptionalBot) -> Option<i64> {
    match optional_bot {
        OptionalBot(Some(bot)) => Some(bot.bot_id),
        OptionalBot(None) => None,
    }
}

fn idempotency_key(headers: &HeaderMap, namespace: &str) -> AppResult<Option<String>> {
    let Some(raw) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let value = raw
        .to_str()
        .map_err(|_| AppError::Validation("Invalid Idempotency-Key".into()))?
        .trim();
    let valid_chars = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if value.is_empty() || value.len() > 128 || !valid_chars {
        return Err(AppError::Validation(
            "Idempotency-Key must be 1-128 ASCII letters, numbers, dots, dashes, underscores, or colons".into(),
        ));
    }
    Ok(Some(format!("{namespace}:{value}")))
}

// ─── POST /api/feeds/:feedId/announcements ─────────────────────────

pub async fn create_announcement(
    State(state): State<AppState>,
    user_id: UserId,
    optional_bot: OptionalBot,
    headers: HeaderMap,
    Path(feed_id_str): Path<String>,
    Json(body): Json<Announcement>,
) -> AppResult<Response> {
    create_announcement_inner(state, user_id, optional_bot, headers, feed_id_str, body).await
}

pub async fn create_bot_announcement(
    State(state): State<AppState>,
    user_id: UserId,
    optional_bot: OptionalBot,
    headers: HeaderMap,
    Path(feed_id_str): Path<String>,
    Json(body): Json<Announcement>,
) -> AppResult<Response> {
    if matches!(optional_bot, OptionalBot(None)) {
        return Err(AppError::TokenRequired);
    }
    create_announcement_inner(state, user_id, optional_bot, headers, feed_id_str, body).await
}

async fn create_announcement_inner(
    state: AppState,
    user_id: UserId,
    optional_bot: OptionalBot,
    headers: HeaderMap,
    feed_id_str: String,
    mut body: Announcement,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/feeds/{}/announcements user_id={}",
        feed_id_str,
        user_id.0
    );
    let feed_id = parse_id(&feed_id_str)?;

    // Rate limit — key on bot_id if bot-authenticated, otherwise user_id
    let rl_key = if let OptionalBot(Some(ref bot)) = optional_bot {
        format!("bot:{}", bot.bot_id)
    } else {
        user_id.0.to_string()
    };
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &rl_key).await?;

    let feed = load_feed(&state, feed_id).await?;
    let server_id = feed.server_id;
    let idem_key = idempotency_key(&headers, &format!("feed-announcement:{feed_id}"))?;

    // Auth: either bot scoped to the same server, or user with publish role
    let bot_id: Option<i64> = if let OptionalBot(Some(ref bot)) = optional_bot {
        if bot.server_id != server_id {
            return Err(AppError::Forbidden);
        }
        if !bot_can_publish_feed(&state, bot, &feed).await? {
            return Err(AppError::WithCode {
                status: axum::http::StatusCode::FORBIDDEN,
                code: "FEED_NO_PUBLISH_PERMISSION",
                message: "Bot role permissions do not allow posting to this feed".into(),
            });
        }
        Some(bot.bot_id)
    } else {
        None
    };

    let posted_by: Option<i64> = if bot_id.is_some() {
        None
    } else {
        state.require_membership(user_id.0, server_id).await?;
        if !can_publish_visible_feed(&state, user_id.0, server_id, &feed).await {
            return Err(AppError::Forbidden);
        }
        Some(user_id.0)
    };

    // Sanitize + validate
    crate::services::announcements::sanitize(&mut body);
    crate::services::announcements::validate(&body)
        .await
        .map_err(AppError::Validation)?;
    if let OptionalBot(Some(ref bot)) = optional_bot {
        crate::services::announcements::validate_server_targets_for_bot(
            &state, server_id, &body, bot,
        )
        .await?;
    } else {
        crate::services::announcements::validate_server_targets_for_user(
            &state, server_id, &body, user_id.0,
        )
        .await?;
    }

    let content_value = serde_json::to_value(&body)
        .map_err(|_| AppError::Validation("Failed to serialize announcement content".into()))?;

    let id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();

    let row = AnnouncementRow {
        id,
        feed_id,
        server_id,
        content: content_value.clone(),
        posted_by,
        bot_id,
        updated_at_ms: None,
        deleted_at_ms: None,
        created_at_ms: now_ms,
    };

    // Broadcast ANNOUNCEMENT_CREATE scoped to the feed's visibility —
    // a role-gated feed delivers announcements only to members who
    // hold a matching role or ADMINISTRATOR.
    let announcement_data = announcement_to_json(&row);
    if let (Some(bot_id), Some(ref key)) = (bot_id, idem_key.as_ref()) {
        let mut tx = state.pg.begin().await.map_err(|e| {
            tracing::error!(id, error = %e, "create_announcement: PG tx begin failed");
            AppError::Internal
        })?;
        match crate::services::pg::bot_outbox::reserve_bot_idempotency_key(
            &mut tx,
            bot_id,
            key,
            &announcement_data,
            now_ms,
        )
        .await
        .map_err(|e| {
            tracing::error!(id, error = %e, "create_announcement: idempotency reserve failed");
            AppError::Internal
        })? {
            crate::services::pg::bot_outbox::BotIdempotencyReservation::Existing(existing) => {
                tx.rollback().await.map_err(|e| {
                    tracing::error!(id, error = %e, "create_announcement: PG tx rollback failed");
                    AppError::Internal
                })?;
                return Ok((StatusCode::OK, Json(existing)).into_response());
            }
            crate::services::pg::bot_outbox::BotIdempotencyReservation::Reserved => {}
        }
        crate::services::pg::announcements::insert_tx(
            &mut tx,
            InsertAnnouncement {
                id,
                feed_id,
                server_id,
                content: &content_value,
                posted_by,
                bot_id: Some(bot_id),
                now_ms,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(id, error = %e, "create_announcement: PG write failed");
            AppError::Internal
        })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(id, error = %e, "create_announcement: PG tx commit failed");
            AppError::Internal
        })?;
    } else {
        crate::services::pg::announcements::insert(
            &state.pg,
            InsertAnnouncement {
                id,
                feed_id,
                server_id,
                content: &content_value,
                posted_by,
                bot_id,
                now_ms,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(id, error = %e, "create_announcement: PG write failed");
            AppError::Internal
        })?;
    }
    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_FEED_ANNOUNCEMENT_CREATE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: Some(feed_id),
            actor_user_id: posted_by,
            actor_bot_id: bot_id,
            payload: json!({
                "serverId": server_id.to_string(),
                "feedId": feed_id.to_string(),
                "announcement": announcement_data.clone(),
            }),
        },
    );
    let json_text = events::announcement_create_json(&announcement_data);
    let proto_msg = events::announcement_create_proto(
        server_id.to_string(),
        feed_id.to_string(),
        announcement_to_proto(&row),
    );
    topics::publish_feed_scoped(
        &state,
        server_id,
        &feed.visible_role_ids,
        &json_text,
        &proto_msg,
    )
    .await;

    tracing::info!(
        "Announcement created id={} feed={} server={}",
        id,
        feed_id,
        server_id
    );
    Ok((StatusCode::CREATED, Json(announcement_data)).into_response())
}

// ─── GET /api/feeds/:feedId/announcements ──────────────────────────

pub async fn list_announcements(
    State(state): State<AppState>,
    user_id: UserId,
    Path(feed_id_str): Path<String>,
    Query(params): Query<AnnouncementQueryParams>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/feeds/{}/announcements user_id={}",
        feed_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let feed_id = parse_id(&feed_id_str)?;

    let feed = load_feed(&state, feed_id).await?;
    let server_id = feed.server_id;

    state.require_membership(user_id.0, server_id).await?;

    if !can_view_feed(&state, user_id.0, server_id, &feed.visible_role_ids).await {
        return Err(AppError::NotFound("feed"));
    }

    let limit = params
        .limit
        .map(|l| l.max(1).min(MAX_ANNOUNCEMENT_LIMIT as i64))
        .unwrap_or(DEFAULT_ANNOUNCEMENT_LIMIT as i64);
    let before_id = params.before.as_deref().and_then(|s| parse_id(s).ok());

    let records =
        crate::services::pg::announcements::list_for_feed(&state.pg, feed_id, limit, before_id)
            .await
            .map_err(|e| {
                tracing::error!(feed_id, error = %e, "list_announcements: PG read failed");
                AppError::Internal
            })?;

    let result: Vec<Value> = records.iter().map(announcement_to_json).collect();
    Ok(Json(json!(result)))
}

// ─── PATCH /api/feeds/:feedId/announcements/:announcementId ────────

pub async fn update_announcement(
    State(state): State<AppState>,
    user_id: UserId,
    optional_bot: OptionalBot,
    Path((feed_id_str, announcement_id_str)): Path<(String, String)>,
    Json(mut body): Json<Announcement>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/feeds/{}/announcements/{} user_id={}",
        feed_id_str,
        announcement_id_str,
        user_id.0
    );
    let rl_key = if let OptionalBot(Some(ref bot)) = optional_bot {
        format!("bot:{}", bot.bot_id)
    } else {
        user_id.0.to_string()
    };
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &rl_key).await?;
    let feed_id = parse_id(&feed_id_str)?;
    let announcement_id = parse_id(&announcement_id_str)?;

    let mut record = crate::services::pg::announcements::by_id(&state.pg, announcement_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update_announcement: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("announcement"))?;
    if record.feed_id != feed_id || record.deleted_at_ms.is_some() {
        return Err(AppError::NotFound("announcement"));
    }
    let server_id = record.server_id;

    let feed = load_feed(&state, feed_id).await?;

    // Verify authorization: author user, MANAGE_SERVER, or the bot that posted it
    let authorized = if let OptionalBot(Some(ref bot)) = optional_bot {
        bot.server_id == server_id
            && record.bot_id == Some(bot.bot_id)
            && bot_can_publish_feed(&state, bot, &feed).await?
    } else {
        let can_manage = state
            .permissions
            .check_server_permission(user_id.0, server_id, bits::MANAGE_SERVER)
            .await
            .is_ok();
        can_manage
            || (record.posted_by == Some(user_id.0)
                && can_publish_visible_feed(&state, user_id.0, server_id, &feed).await)
    };
    if !authorized {
        return Err(AppError::Forbidden);
    }

    // Sanitize + re-validate content
    crate::services::announcements::sanitize(&mut body);
    crate::services::announcements::validate(&body)
        .await
        .map_err(AppError::Validation)?;
    if let OptionalBot(Some(ref bot)) = optional_bot {
        crate::services::announcements::validate_server_targets_for_bot(
            &state, server_id, &body, bot,
        )
        .await?;
    } else {
        crate::services::announcements::validate_server_targets_for_user(
            &state, server_id, &body, user_id.0,
        )
        .await?;
    }

    let content_value = serde_json::to_value(&body)
        .map_err(|_| AppError::Validation("Failed to serialize announcement content".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::announcements::edit(&state.pg, announcement_id, &content_value, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(announcement_id, error = %e, "update_announcement: PG write failed");
            AppError::Internal
        })?;

    record.content = content_value;
    record.updated_at_ms = Some(now_ms);

    // Broadcast ANNOUNCEMENT_UPDATE scoped to the feed's visibility.
    let announcement_data = announcement_to_json(&record);
    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_FEED_ANNOUNCEMENT_UPDATE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: Some(feed_id),
            actor_user_id: if bot_id_from_optional(&optional_bot).is_none() {
                Some(user_id.0)
            } else {
                None
            },
            actor_bot_id: bot_id_from_optional(&optional_bot),
            payload: json!({
                "serverId": server_id.to_string(),
                "feedId": feed_id.to_string(),
                "announcement": announcement_data.clone(),
            }),
        },
    );
    let json_text = events::announcement_update_json(&announcement_data);
    let proto_msg = events::announcement_update_proto(
        server_id.to_string(),
        feed_id.to_string(),
        announcement_to_proto(&record),
    );
    topics::publish_feed_scoped(
        &state,
        server_id,
        &feed.visible_role_ids,
        &json_text,
        &proto_msg,
    )
    .await;

    tracing::info!(
        "Announcement updated id={} feed={} server={}",
        announcement_id,
        feed_id,
        server_id
    );
    Ok(Json(announcement_data))
}

// ─── DELETE /api/feeds/:feedId/announcements/:announcementId ───────

pub async fn delete_announcement(
    State(state): State<AppState>,
    user_id: UserId,
    optional_bot: OptionalBot,
    Path((feed_id_str, announcement_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/feeds/{}/announcements/{} user_id={}",
        feed_id_str,
        announcement_id_str,
        user_id.0
    );
    let rl_key = if let OptionalBot(Some(ref bot)) = optional_bot {
        format!("bot:{}", bot.bot_id)
    } else {
        user_id.0.to_string()
    };
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &rl_key).await?;
    let feed_id = parse_id(&feed_id_str)?;
    let announcement_id = parse_id(&announcement_id_str)?;

    let record = crate::services::pg::announcements::by_id(&state.pg, announcement_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete_announcement: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("announcement"))?;
    if record.feed_id != feed_id || record.deleted_at_ms.is_some() {
        return Err(AppError::NotFound("announcement"));
    }
    let server_id = record.server_id;

    let feed = load_feed(&state, feed_id).await?;

    let authorized = if let OptionalBot(Some(ref bot)) = optional_bot {
        bot.server_id == server_id
            && record.bot_id == Some(bot.bot_id)
            && bot_can_publish_feed(&state, bot, &feed).await?
    } else {
        let can_manage = state
            .permissions
            .check_server_permission(user_id.0, server_id, bits::MANAGE_SERVER)
            .await
            .is_ok();
        can_manage
            || (record.posted_by == Some(user_id.0)
                && can_publish_visible_feed(&state, user_id.0, server_id, &feed).await)
    };
    if !authorized {
        return Err(AppError::Forbidden);
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::announcements::soft_delete(&state.pg, announcement_id, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(announcement_id, error = %e, "delete_announcement: PG write failed");
            AppError::Internal
        })?;

    // Broadcast ANNOUNCEMENT_DELETE scoped to the feed's visibility.
    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_FEED_ANNOUNCEMENT_DELETE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: Some(feed_id),
            actor_user_id: if bot_id_from_optional(&optional_bot).is_none() {
                Some(user_id.0)
            } else {
                None
            },
            actor_bot_id: bot_id_from_optional(&optional_bot),
            payload: json!({
                "serverId": server_id.to_string(),
                "feedId": feed_id_str.clone(),
                "announcementId": announcement_id_str.clone(),
            }),
        },
    );
    let json_text = events::announcement_delete_json(
        &server_id.to_string(),
        &feed_id_str,
        &announcement_id_str,
    );
    let proto_msg = events::announcement_delete_proto(
        server_id.to_string(),
        feed_id_str.clone(),
        announcement_id_str.clone(),
    );
    topics::publish_feed_scoped(
        &state,
        server_id,
        &feed.visible_role_ids,
        &json_text,
        &proto_msg,
    )
    .await;

    tracing::info!(
        "Announcement deleted id={} feed={} server={}",
        announcement_id,
        feed_id,
        server_id
    );
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("announcements.rs");

    #[test]
    fn bot_announcement_reserves_idempotency_before_insert() {
        let handler = SOURCE
            .split("pub async fn create_announcement")
            .nth(1)
            .expect("create_announcement handler source should exist")
            .split("#[cfg(test)]")
            .next()
            .expect("handler body should precede tests");
        let reservation = handler
            .find("reserve_bot_idempotency_key")
            .expect("handler should reserve bot idempotency key");
        let insert = handler
            .find("crate::services::pg::announcements::insert")
            .expect("handler should insert announcement");

        assert!(
            reservation < insert,
            "bot idempotency must be reserved before inserting the announcement"
        );
    }
}
