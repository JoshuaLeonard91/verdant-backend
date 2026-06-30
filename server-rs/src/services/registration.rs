use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::ws::{events, topics};

const MAX_MEMBERS_PER_SERVER: i64 = 10_000;

pub async fn auto_join_default_server(state: &AppState, user_id: i64) -> AppResult<()> {
    let Some(server_id) = state.config.registration_default_server_id else {
        return Ok(());
    };

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, user_id, error = %e, "auto_join: default server read failed");
            AppError::Internal
        })?;

    let Some(server) = server else {
        tracing::error!(
            server_id,
            user_id,
            "auto_join: configured default server not found"
        );
        return Ok(());
    };

    if server.deleted_at.is_some() {
        tracing::error!(
            server_id,
            user_id,
            "auto_join: configured default server is deleted"
        );
        return Ok(());
    }

    let already_member = crate::services::pg::servers::is_member(&state.pg, server_id, user_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, user_id, error = %e, "auto_join: membership check failed");
            AppError::Internal
        })?;
    if already_member {
        return Ok(());
    }

    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .unwrap_or(0);
    if member_count >= MAX_MEMBERS_PER_SERVER {
        tracing::error!(
            server_id,
            user_id,
            "auto_join: configured default server is full"
        );
        return Ok(());
    }

    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();
    crate::services::pg::servers::add_member(&state.pg, server_id, user_id, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(server_id, user_id, error = %e, "auto_join: add_member failed");
            AppError::Internal
        })?;

    state.permissions.add_user_server(user_id, server_id);

    let (username, avatar_url, display_name) =
        state.user_profiles.get_or_fetch_vdb(state, user_id).await;
    let uid_str = user_id.to_string();
    let server_id_str = server_id.to_string();
    let joined_at = now.to_rfc3339();
    let join_json = events::member_join_json(
        &server_id_str,
        &uid_str,
        &username,
        display_name.as_deref(),
        avatar_url.as_deref(),
        &joined_at,
    );
    let join_proto = events::member_join_proto(
        server_id_str.clone(),
        uid_str.clone(),
        username.clone(),
        display_name.clone(),
        avatar_url.clone(),
        joined_at.clone(),
    );
    crate::services::bot_events::enqueue(
        state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_JOIN,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(user_id),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str,
                "userId": uid_str,
                "username": username,
                "displayName": display_name,
                "avatarUrl": avatar_url,
                "joinedAt": joined_at,
            }),
        },
    );
    topics::publish(
        state,
        &topics::presence_topic(server_id),
        &join_json,
        &join_proto,
    )
    .await;

    Ok(())
}
