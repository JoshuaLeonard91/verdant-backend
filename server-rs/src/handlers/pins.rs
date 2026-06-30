use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::{
    OptionalFederatedClient, UserId, require_federated_client_channel_scope,
};
use crate::services::permissions::bits;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_PINS_PER_CHANNEL: usize = 50;

/// Verify channel access and return the parent server_id.
/// Enforces both server membership AND VIEW_CHANNEL — a server
/// member denied VIEW_CHANNEL via a channel override must not be
/// able to read pins (message content disclosure) or write pins
/// (graffiti on hidden channels).
async fn verify_channel(
    state: &AppState,
    user_id: i64,
    federated_client: Option<&crate::middleware::auth::FederatedClientIdentity>,
    channel_id: i64,
) -> AppResult<i64> {
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "pins: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    let server_id = channel.server_id.ok_or(AppError::NotFound("channel"))?;
    require_federated_client_channel_scope(federated_client, Some(server_id))?;
    state
        .require_membership(user_id, server_id)
        .await
        .map_err(|_| AppError::NotFound("channel"))?;
    state
        .permissions
        .check_channel_permission(user_id, channel_id, server_id, bits::VIEW_CHANNEL)
        .await
        .map_err(|_| AppError::NotFound("channel"))?;
    Ok(server_id)
}

async fn enqueue_federation_pin_event(
    state: &AppState,
    channel_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    log_label: &'static str,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            channel_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "{log_label}"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(channel_id, error = %error, "{log_label} failed"),
    }
}

// ─── GET /api/channels/:channelId/pins ──────────────────────────────

pub async fn list_pins(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/channels/{}/pins user_id={}",
        channel_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    verify_channel(&state, user_id.0, federated_client.as_ref(), channel_id).await?;

    // Pins now live in their own table; list newest-first directly.
    let pins = crate::services::pg::channels::list_pins(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "list_pins: PG read failed");
            AppError::Internal
        })?;

    let mut result: Vec<Value> = Vec::with_capacity(pins.len());
    for pin in &pins {
        // The partition key (created_at_ms) for a message can be
        // recovered from its snowflake id, but the cheaper path is
        // the unhinted lookup — pins is bounded to ~50 per channel.
        let Ok(Some(msg)) =
            crate::services::pg::messages::by_id_unhinted(&state.pg, pin.message_id).await
        else {
            continue;
        };
        if crate::services::pg::messages::is_deleted(&msg) {
            continue;
        }
        let author_id = if msg.author_id == 0 {
            None
        } else {
            Some(msg.author_id)
        };
        let (author_username, author_avatar_url, author_display_name) = match author_id {
            Some(aid) => state.user_profiles.get_or_fetch_vdb(&state, aid).await,
            None => ("Deleted User".to_string(), None, None),
        };

        let created_at_millis = (msg.id >> 22) + 1_735_689_600_000;
        let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(created_at_millis)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();
        let pinned_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(pin.pinned_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();
        let author_id_str = author_id.map(|id| id.to_string());

        result.push(json!({
            "pinnedBy": pin.pinned_by.to_string(),
            "pinnedAt": pinned_at,
            "message": {
                "id": msg.id.to_string(),
                "channelId": channel_id_str.clone(),
                "authorId": author_id_str,
                "author": {
                    "id": author_id_str,
                    "username": author_username,
                    "displayName": author_display_name,
                    "avatarUrl": crate::services::cdn::resolve(author_avatar_url.as_deref()),
                },
                "content": msg.content,
                "type": 0,
                "edited": msg.edited_at_ms.is_some(),
                "editedAt": Value::Null,
                "createdAt": created_at,
                "updatedAt": created_at,
            }
        }));
    }

    Ok(Json(json!(result)))
}

// ─── PUT /api/channels/:channelId/pins/:messageId ───────────────────

pub async fn pin_message(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path((channel_id_str, message_id_str)): Path<(String, String)>,
) -> AppResult<Response> {
    tracing::info!(
        "PUT /api/channels/{}/pins/{} user_id={}",
        channel_id_str,
        message_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&message_id_str)?;
    let server_id =
        verify_channel(&state, user_id.0, federated_client.as_ref(), channel_id).await?;

    state
        .permissions
        .check_channel_permission(user_id.0, channel_id, server_id, bits::MANAGE_MESSAGES)
        .await?;

    // Verify the message exists + belongs to this channel + not deleted
    let msg = crate::services::pg::messages::by_id_unhinted(&state.pg, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "pin_message: PG message read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("message"))?;
    if msg.channel_id != channel_id || crate::services::pg::messages::is_deleted(&msg) {
        return Err(AppError::NotFound("message"));
    }

    // Cap check via the dedicated pin index, then atomic insert
    // (ON CONFLICT DO NOTHING gives idempotency for free).
    let pin_count = crate::services::pg::channels::pin_count(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "pin_message: PG pin count failed");
            AppError::Internal
        })?;
    if pin_count >= MAX_PINS_PER_CHANNEL as i64 {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "PIN_LIMIT_REACHED",
            message: format!("Channel has reached the maximum of {MAX_PINS_PER_CHANNEL} pins"),
        });
    }

    crate::services::pg::channels::add_pin(
        &state.pg,
        channel_id,
        message_id,
        user_id.0,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, message_id, error = %e, "pin_message: PG insert failed");
        AppError::Internal
    })?;

    // Broadcast MESSAGE_PIN
    let topic = topics::channel_live_topic(channel_id);
    let json_text =
        events::message_pin_json(&message_id_str, &channel_id_str, &user_id.0.to_string());
    let proto_msg = events::message_pin_proto(
        message_id_str.clone(),
        channel_id_str.clone(),
        user_id.0.to_string(),
    );
    topics::publish(&state, &topic, &json_text, &proto_msg).await;
    enqueue_federation_pin_event(
        &state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessagePin {
            channel_id,
            message_id,
            actor_user_id: user_id.0,
        },
        "Federation message pin producer completed",
    )
    .await;

    tracing::info!(
        "Message pinned message_id={} channel_id={} by={}",
        message_id,
        channel_id,
        user_id.0
    );
    Ok((StatusCode::OK, Json(json!({ "success": true }))).into_response())
}

// ─── DELETE /api/channels/:channelId/pins/:messageId ────────────────

pub async fn unpin_message(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path((channel_id_str, message_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/channels/{}/pins/{} user_id={}",
        channel_id_str,
        message_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&message_id_str)?;
    let server_id =
        verify_channel(&state, user_id.0, federated_client.as_ref(), channel_id).await?;

    state
        .permissions
        .check_channel_permission(user_id.0, channel_id, server_id, bits::MANAGE_MESSAGES)
        .await?;

    crate::services::pg::channels::remove_pin(&state.pg, channel_id, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "unpin_message: PG delete failed");
            AppError::Internal
        })?;

    // Broadcast MESSAGE_UNPIN
    let topic = topics::channel_live_topic(channel_id);
    let json_text = events::message_unpin_json(&message_id_str, &channel_id_str);
    let proto_msg = events::message_unpin_proto(message_id_str.clone(), channel_id_str.clone());
    topics::publish(&state, &topic, &json_text, &proto_msg).await;
    enqueue_federation_pin_event(
        &state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessageUnpin {
            channel_id,
            message_id,
            actor_user_id: user_id.0,
        },
        "Federation message unpin producer completed",
    )
    .await;

    tracing::info!(
        "Message unpinned message_id={} channel_id={} by={}",
        message_id,
        channel_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("pins.rs");

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
    fn pin_message_enqueues_federation_message_pin() {
        let handler = handler_source("pin_message");

        assert!(handler.contains("FederationLocalEvent::MessagePin"));
        assert!(handler.contains("enqueue_federation_pin_event"));
    }

    #[test]
    fn unpin_message_enqueues_federation_message_unpin() {
        let handler = handler_source("unpin_message");

        assert!(handler.contains("FederationLocalEvent::MessageUnpin"));
        assert!(handler.contains("enqueue_federation_pin_event"));
    }

    #[test]
    fn pin_federation_helper_uses_channel_scope() {
        let helper = private_async_source("enqueue_federation_pin_event");

        assert!(helper.contains("FederationRouteScope::Channel"));
        assert!(helper.contains("enqueue_local_event_for_scope"));
    }
}
