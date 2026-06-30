use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::{
    auth::{OptionalFederatedClient, UserId, require_federated_client_channel_scope},
    rate_limit,
};
use crate::services::channel_access::verify_channel_access;
use crate::services::permissions::bits;
use crate::services::reactions::{self, AddReactionResult};
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

// ─── PUT /api/channels/:channelId/messages/:messageId/reactions/:emoji ──

pub async fn add_reaction(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path((channel_id_str, message_id_str, emoji)): Path<(String, String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PUT /api/channels/{}/messages/{}/reactions user_id={}",
        channel_id_str,
        message_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&message_id_str)?;
    let emoji = urlencoding::decode(&emoji)
        .map(|s| s.into_owned())
        .unwrap_or(emoji);

    rate_limit::enforce(&state, &rate_limit::REACTION_LIMIT, &user_id.0.to_string()).await?;

    if emoji.is_empty() || emoji.len() > 64 {
        return Err(AppError::Validation("Invalid emoji".into()));
    }

    let server_id = verify_channel_access(&state, user_id.0, channel_id)
        .await
        .map_err(|_| AppError::NotFound("message"))?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)
        .map_err(|_| AppError::NotFound("message"))?;

    // A member denied VIEW_CHANNEL via a channel override must not be
    // able to react in that channel — treat as nonexistent.
    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("message"))?;
    }

    // Verify message exists in this channel and isn't tombstoned.
    let msg = crate::services::pg::messages::by_id_unhinted(&state.pg, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "add_reaction: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("message"))?;
    if msg.channel_id != channel_id || crate::services::pg::messages::is_deleted(&msg) {
        return Err(AppError::NotFound("message"));
    }

    if crate::services::subscription::is_custom_emoji_reaction_shortcode_candidate(&emoji) {
        let entitlements =
            crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id.0)
                .await;
        if !crate::services::subscription::validate_reaction_emoji_with_entitlement(
            &state.pg,
            user_id.0,
            server_id,
            &emoji,
            entitlements.cross_server_emoji,
        )
        .await
        {
            return Err(AppError::WithCode {
                status: axum::http::StatusCode::FORBIDDEN,
                code: "EMOJI_NOT_ALLOWED",
                message: "Emoji is not available".into(),
            });
        }
    }

    // Atomic add via the Redis Lua script
    match reactions::add_reaction(&state.redis, message_id, &emoji, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "add_reaction: redis eval failed");
            AppError::Internal
        })? {
        AddReactionResult::LimitReached => {
            return Err(AppError::WithCode {
                status: axum::http::StatusCode::FORBIDDEN,
                code: "REACTION_LIMIT_REACHED",
                message: format!(
                    "Maximum of {} unique reactions per message",
                    reactions::MAX_UNIQUE_REACTIONS_PER_MESSAGE
                ),
            });
        }
        AddReactionResult::AlreadyPresent => {
            // Idempotent success — no broadcast.
            return Ok(Json(json!({ "success": true })));
        }
        AddReactionResult::Added => {}
    }

    // Broadcast REACTION_ADD
    let topic = topics::channel_live_topic(channel_id);
    let json_text = events::reaction_add_json(
        &message_id.to_string(),
        &channel_id_str,
        &user_id.0.to_string(),
        &emoji,
        None,
    );
    let proto_msg = events::reaction_add_proto(
        message_id.to_string(),
        channel_id_str.clone(),
        user_id.0.to_string(),
        emoji.clone(),
        None,
    );
    topics::publish(&state, &topic, &json_text, &proto_msg).await;

    // Invalidate cache entry (fire-and-forget)
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.invalidate_channel(channel_id).await });

    // PG dual-write (fire-and-forget — Redis is the hot-read source).
    let pg = state.pg.clone();
    let emoji_clone = emoji.clone();
    let now_ms = chrono::Utc::now().timestamp_millis();
    tokio::spawn(async move {
        if let Err(e) =
            crate::services::pg::reactions::add(&pg, message_id, &emoji_clone, user_id.0, now_ms)
                .await
        {
            tracing::warn!(error = %e, "add_reaction: PG dual-write failed");
        }
    });

    tracing::info!(
        "Reaction added message={} channel={} by={}",
        message_id,
        channel_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── DELETE /api/channels/:channelId/messages/:messageId/reactions/:emoji ──

pub async fn remove_reaction(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path((channel_id_str, message_id_str, emoji)): Path<(String, String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/channels/{}/messages/{}/reactions user_id={}",
        channel_id_str,
        message_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&message_id_str)?;
    let emoji = urlencoding::decode(&emoji)
        .map(|s| s.into_owned())
        .unwrap_or(emoji);

    rate_limit::enforce(&state, &rate_limit::REACTION_LIMIT, &user_id.0.to_string()).await?;

    let server_id = verify_channel_access(&state, user_id.0, channel_id)
        .await
        .map_err(|_| AppError::NotFound("message"))?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)
        .map_err(|_| AppError::NotFound("message"))?;

    // A member denied VIEW_CHANNEL via a channel override must not be
    // able to remove reactions in that channel — treat as nonexistent.
    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("message"))?;
    }

    // Verify the reaction target belongs to this channel before mutating
    // the Redis reaction set. Message IDs are globally addressable, so the
    // caller-provided channel ID is not enough by itself.
    let msg = crate::services::pg::messages::by_id_unhinted(&state.pg, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "remove_reaction: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("message"))?;
    if msg.channel_id != channel_id || crate::services::pg::messages::is_deleted(&msg) {
        return Err(AppError::NotFound("message"));
    }

    let removed = reactions::remove_reaction(&state.redis, message_id, &emoji, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "remove_reaction: redis eval failed");
            AppError::Internal
        })?;

    if !removed {
        return Err(AppError::NotFound("reaction"));
    }

    // Broadcast REACTION_REMOVE
    let topic = topics::channel_live_topic(channel_id);
    let json_text = events::reaction_remove_json(
        &message_id.to_string(),
        &channel_id_str,
        &user_id.0.to_string(),
        &emoji,
    );
    let proto_msg = events::reaction_remove_proto(
        message_id.to_string(),
        channel_id_str.clone(),
        user_id.0.to_string(),
        emoji.clone(),
    );
    topics::publish(&state, &topic, &json_text, &proto_msg).await;

    // Invalidate cache entry (fire-and-forget)
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.invalidate_channel(channel_id).await });

    // PG dual-write (fire-and-forget).
    let pg = state.pg.clone();
    let emoji_clone = emoji.clone();
    tokio::spawn(async move {
        if let Err(e) =
            crate::services::pg::reactions::remove(&pg, message_id, &emoji_clone, user_id.0).await
        {
            tracing::warn!(error = %e, "remove_reaction: PG dual-write failed");
        }
    });

    tracing::info!(
        "Reaction removed message={} channel={} by={}",
        message_id,
        channel_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}
