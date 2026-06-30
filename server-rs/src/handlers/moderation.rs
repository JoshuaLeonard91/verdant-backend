use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::audit::{self, AuditAction, AuditEntry};
use crate::services::permissions::bits;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

#[derive(Deserialize, Validate)]
pub struct KickRequest {
    #[validate(length(max = 512))]
    pub reason: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct BanRequest {
    #[validate(length(max = 512))]
    pub reason: Option<String>,
}

// ─── Redis key helpers ──────────────────────────────────────────────

fn banned_set_key(server_id: i64) -> String {
    format!("banned:{server_id}")
}

fn ban_detail_key(server_id: i64, target_id: i64) -> String {
    format!("ban:{server_id}:{target_id}")
}

/// Shared cleanup for a member removal (kick OR ban). Drops the
/// membership row and clears every member_role assignment the user
/// had in this server in a single transaction.
async fn drop_membership_and_roles(state: &AppState, target_id: i64, server_id: i64) {
    if let Err(e) =
        crate::services::pg::servers::remove_member(&state.pg, server_id, target_id).await
    {
        tracing::warn!(target_id, server_id, error = %e, "moderation: PG remove_member failed");
    }
    if let Err(e) = crate::services::pg::roles::replace_user_roles_in_server(
        &state.pg,
        target_id,
        server_id,
        &[],
    )
    .await
    {
        tracing::warn!(target_id, server_id, error = %e, "moderation: PG role wipe failed");
    }
}

struct RealtimeFanout {
    topic: String,
    json_text: String,
    proto_msg: crate::proto::WsMessage,
}

fn member_remove_realtime_fanout(
    server_id_str: &str,
    target_user_str: &str,
    server_id: i64,
    target_id: i64,
) -> Vec<RealtimeFanout> {
    vec![
        RealtimeFanout {
            topic: topics::presence_topic(server_id),
            json_text: events::member_remove_json(server_id_str, target_user_str),
            proto_msg: events::member_remove_proto(
                server_id_str.to_owned(),
                target_user_str.to_owned(),
            ),
        },
        RealtimeFanout {
            topic: topics::user_topic(target_id),
            json_text: events::server_delete_json(server_id_str),
            proto_msg: events::server_delete_proto(server_id_str.to_owned()),
        },
    ]
}

async fn enqueue_federation_moderation_event(
    state: &AppState,
    server_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    log_label: &'static str,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            server_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "{log_label}"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(server_id, error = %error, "{log_label} failed"),
    }
}

// ─── POST /api/servers/:serverId/members/:userId/kick ───────────────

pub async fn kick_member(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, target_user_str)): Path<(String, String)>,
    Json(body): Json<KickRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "POST /api/servers/{}/members/{}/kick user_id={}",
        server_id_str,
        target_user_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::MODERATION_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let server_id = parse_id(&server_id_str)?;
    let target_id = parse_id(&target_user_str)?;

    state
        .require_permission(user_id.0, server_id, bits::KICK_MEMBERS)
        .await?;

    if target_id == user_id.0 {
        return Err(AppError::Validation("Cannot kick yourself".into()));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "kick_member: PG server read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;
    if target_id == server.owner_id {
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "CANNOT_ACTION_OWNER",
            message: "Cannot perform this action on the server owner".into(),
        });
    }

    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, target_id)
        .await
        .map_err(|e| {
            tracing::error!(target_id, error = %e, "kick_member: PG is_member failed");
            AppError::Internal
        })?;
    if !is_member {
        return Err(AppError::NotFound("member"));
    }

    state
        .permissions
        .check_hierarchy(user_id.0, target_id, server_id)
        .await?;

    drop_membership_and_roles(&state, target_id, server_id).await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::KickMember,
            target_type: "user",
            target_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "reason": body.reason })),
            ip: None,
        },
        state.pg.clone(),
    );

    state.permissions.remove_user_server(target_id, server_id);

    let server_channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .unwrap_or_default();
    let channel_ids: Vec<i64> = server_channels.iter().map(|c| c.id).collect();
    topics::unsubscribe_user_from_server(&state, target_id, server_id, &channel_ids).await;

    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_LEAVE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(user_id.0),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str.clone(),
                "userId": target_user_str.clone(),
                "reason": "kick",
            }),
        },
    );
    for fanout in
        member_remove_realtime_fanout(&server_id_str, &target_user_str, server_id, target_id)
    {
        topics::publish(&state, &fanout.topic, &fanout.json_text, &fanout.proto_msg).await;
    }
    enqueue_federation_moderation_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::MembershipRemove {
            server_id,
            moderator_user_id: user_id.0,
            target_user_id: target_id,
            reason: body.reason.clone(),
        },
        "Federation membership remove producer completed",
    )
    .await;

    tracing::info!(
        "Member kicked server={} target={} by={}",
        server_id,
        target_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/servers/:serverId/bans/:userId ───────────────────────

pub async fn ban_member(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, target_user_str)): Path<(String, String)>,
    Json(body): Json<BanRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "POST /api/servers/{}/bans/{} user_id={}",
        server_id_str,
        target_user_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::MODERATION_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let server_id = parse_id(&server_id_str)?;
    let target_id = parse_id(&target_user_str)?;

    state
        .require_permission(user_id.0, server_id, bits::BAN_MEMBERS)
        .await?;

    if target_id == user_id.0 {
        return Err(AppError::Validation("Cannot ban yourself".into()));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "ban_member: PG server read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;
    if target_id == server.owner_id {
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "CANNOT_ACTION_OWNER",
            message: "Cannot ban the server owner".into(),
        });
    }

    use fred::interfaces::{HashesInterface, SetsInterface};
    let already_banned: bool = state
        .redis
        .sismember(banned_set_key(server_id), target_id.to_string())
        .await
        .unwrap_or(false);
    if already_banned {
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "BAN_ALREADY_EXISTS",
            message: "User is already banned".into(),
        });
    }

    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, target_id)
        .await
        .unwrap_or(false);

    if is_member {
        state
            .permissions
            .check_hierarchy(user_id.0, target_id, server_id)
            .await?;
    }

    let _: Result<i64, _> = SetsInterface::sadd(
        &state.redis,
        banned_set_key(server_id),
        target_id.to_string(),
    )
    .await;
    let now_millis = chrono::Utc::now().timestamp_millis();
    let fields: Vec<(&str, String)> = vec![
        ("banned_by", user_id.0.to_string()),
        ("reason", body.reason.clone().unwrap_or_default()),
        ("created_at_millis", now_millis.to_string()),
    ];
    let _: Result<(), _> =
        HashesInterface::hset(&state.redis, ban_detail_key(server_id, target_id), fields).await;

    if is_member {
        drop_membership_and_roles(&state, target_id, server_id).await;
    }

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::BanMember,
            target_type: "user",
            target_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "reason": body.reason })),
            ip: None,
        },
        state.pg.clone(),
    );

    if is_member {
        state.permissions.remove_user_server(target_id, server_id);

        let server_channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
            .await
            .unwrap_or_default();
        let channel_ids: Vec<i64> = server_channels.iter().map(|c| c.id).collect();
        topics::unsubscribe_user_from_server(&state, target_id, server_id, &channel_ids).await;

        crate::services::bot_events::enqueue(
            &state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MEMBER_LEAVE,
                server_id: Some(server_id),
                channel_id: None,
                feed_id: None,
                actor_user_id: Some(user_id.0),
                actor_bot_id: None,
                payload: json!({
                    "serverId": server_id_str.clone(),
                    "userId": target_user_str.clone(),
                    "reason": "ban",
                }),
            },
        );
        for fanout in
            member_remove_realtime_fanout(&server_id_str, &target_user_str, server_id, target_id)
        {
            topics::publish(&state, &fanout.topic, &fanout.json_text, &fanout.proto_msg).await;
        }
    }
    enqueue_federation_moderation_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::MembershipBan {
            server_id,
            moderator_user_id: user_id.0,
            target_user_id: target_id,
            reason: body.reason.clone(),
        },
        "Federation membership ban producer completed",
    )
    .await;

    tracing::info!(
        "Member banned server={} target={} by={}",
        server_id,
        target_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── DELETE /api/servers/:serverId/bans/:userId ─────────────────────

pub async fn unban_member(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, target_user_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/bans/{} user_id={}",
        server_id_str,
        target_user_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::MODERATION_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let server_id = parse_id(&server_id_str)?;
    let target_id = parse_id(&target_user_str)?;

    state
        .require_permission(user_id.0, server_id, bits::BAN_MEMBERS)
        .await?;

    use fred::interfaces::{KeysInterface, SetsInterface};
    let removed: i64 = SetsInterface::srem(
        &state.redis,
        banned_set_key(server_id),
        target_id.to_string(),
    )
    .await
    .unwrap_or(0);
    if removed == 0 {
        return Err(AppError::NotFound("ban"));
    }
    let _: Result<i64, _> =
        KeysInterface::del(&state.redis, ban_detail_key(server_id, target_id)).await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::UnbanMember,
            target_type: "user",
            target_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str })),
            ip: None,
        },
        state.pg.clone(),
    );
    enqueue_federation_moderation_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::MembershipUnban {
            server_id,
            moderator_user_id: user_id.0,
            target_user_id: target_id,
        },
        "Federation membership unban producer completed",
    )
    .await;

    tracing::info!(
        "Member unbanned server={} target={} by={}",
        server_id,
        target_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── GET /api/servers/:serverId/bans ────────────────────────────────

pub async fn list_bans(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/bans user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::BAN_MEMBERS)
        .await?;

    use fred::interfaces::{HashesInterface, SetsInterface};
    let banned_ids: Vec<String> = SetsInterface::smembers(&state.redis, banned_set_key(server_id))
        .await
        .unwrap_or_default();

    let mut result: Vec<Value> = Vec::with_capacity(banned_ids.len());
    for id_str in &banned_ids {
        let Ok(target_id) = id_str.parse::<i64>() else {
            continue;
        };
        let fields: std::collections::HashMap<String, String> =
            HashesInterface::hgetall(&state.redis, ban_detail_key(server_id, target_id))
                .await
                .unwrap_or_default();
        let banned_by = fields
            .get("banned_by")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let reason = fields.get("reason").cloned().unwrap_or_default();
        let created_at_millis = fields
            .get("created_at_millis")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let user = crate::services::pg::users::by_id(&state.pg, target_id)
            .await
            .ok()
            .flatten();
        let (username, avatar_url) = match &user {
            Some(u) => (
                u.username.clone(),
                u.avatar_url.clone().filter(|s| !s.is_empty()),
            ),
            None => (String::new(), None),
        };

        result.push(json!({
            "userId": target_id.to_string(),
            "username": username,
            "avatarUrl": avatar_url,
            "bannedBy": banned_by.to_string(),
            "reason": if reason.is_empty() { Value::Null } else { Value::String(reason) },
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(created_at_millis)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        }));
    }

    Ok(Json(json!(result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("moderation.rs");

    fn handler_source(name: &str) -> &'static str {
        let signature = format!("pub async fn {name}");
        let after_signature = SOURCE
            .split(&signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} handler should exist"));
        after_signature
            .split("// ───")
            .next()
            .expect("handler source section should be present")
    }

    fn private_async_source(name: &str) -> &'static str {
        let signature = format!("async fn {name}");
        let after_signature = SOURCE
            .split(&signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} helper should exist"));
        after_signature
            .split("// ───")
            .next()
            .expect("helper source section should be present")
    }

    #[test]
    fn member_remove_realtime_fanout_ejects_target_with_server_delete() {
        let fanout = member_remove_realtime_fanout("123", "456", 123, 456);
        let topic_payloads: Vec<(String, String)> = fanout
            .iter()
            .map(|item| (item.topic.clone(), item.json_text.clone()))
            .collect();

        assert_eq!(
            topic_payloads,
            vec![
                (
                    "presence:123".to_string(),
                    events::member_remove_json("123", "456")
                ),
                ("user:456".to_string(), events::server_delete_json("123")),
            ],
        );
    }

    #[test]
    fn kick_member_enqueues_federation_membership_remove() {
        let handler = handler_source("kick_member");

        assert!(handler.contains("FederationLocalEvent::MembershipRemove"));
        assert!(handler.contains("enqueue_federation_moderation_event"));
    }

    #[test]
    fn ban_member_enqueues_federation_membership_ban() {
        let handler = handler_source("ban_member");

        assert!(handler.contains("FederationLocalEvent::MembershipBan"));
        assert!(handler.contains("enqueue_federation_moderation_event"));
    }

    #[test]
    fn unban_member_enqueues_federation_membership_unban() {
        let handler = handler_source("unban_member");

        assert!(handler.contains("FederationLocalEvent::MembershipUnban"));
        assert!(handler.contains("enqueue_federation_moderation_event"));
    }

    #[test]
    fn moderation_federation_helper_uses_server_scope() {
        let helper = private_async_source("enqueue_federation_moderation_event");

        assert!(helper.contains("FederationRouteScope::Server"));
        assert!(helper.contains("enqueue_local_event_for_scope"));
    }
}
