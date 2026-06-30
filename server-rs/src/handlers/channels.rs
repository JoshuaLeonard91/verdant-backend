use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::{
    auth::{
        OptionalFederatedClient, UserId, require_federated_client_channel_scope,
        require_federated_client_server_scope,
    },
    rate_limit,
};
use crate::repo::channels;
use crate::services::permissions::bits;
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_CHANNELS_PER_SERVER: i64 = 500;

fn normalize_channel_name(value: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_dash = false;

    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if ch == '_' {
            normalized.push(ch);
            last_was_dash = false;
        } else if ch == '-' || ch.is_whitespace() {
            if !normalized.is_empty() && !last_was_dash {
                normalized.push('-');
                last_was_dash = true;
            }
        }
    }

    while normalized.ends_with('-') {
        normalized.pop();
    }

    normalized
}

async fn enqueue_federation_channel_event(
    state: &AppState,
    scope: crate::federation::producer::FederationRouteScope,
    event: crate::federation::producer::FederationLocalEvent,
    log_label: &'static str,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        scope,
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "{log_label}"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(error = %error, "{log_label} failed"),
    }
}

async fn grant_federation_channel_routes_from_server_routes(
    state: &AppState,
    server_id: i64,
    channel_id: i64,
    now_ms: i64,
) {
    let peers = match crate::federation::storage::producer_peers_for_scope(
        &state.pg,
        crate::federation::producer::FederationRouteScope::Server { server_id },
    )
    .await
    {
        Ok(peers) => peers,
        Err(error) => {
            tracing::warn!(
                server_id,
                channel_id,
                error = %error,
                "Federation channel route grant peer lookup failed"
            );
            return;
        }
    };

    for peer in peers {
        if peer.peer_id == state.config.instance_id {
            continue;
        }
        if let Err(error) = crate::federation::storage::upsert_peer_route(
            &state.pg,
            state.snowflake.next_id(),
            &peer.peer_id,
            crate::federation::producer::FederationRouteScope::Channel { channel_id },
            now_ms,
        )
        .await
        {
            tracing::warn!(
                server_id,
                channel_id,
                destination_peer_id = %peer.peer_id,
                error = %error,
                "Federation channel route grant failed"
            );
        }
    }
}

async fn revoke_federation_channel_routes(state: &AppState, channel_id: i64, now_ms: i64) {
    let peers = match crate::federation::storage::producer_peers_for_scope(
        &state.pg,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
    )
    .await
    {
        Ok(peers) => peers,
        Err(error) => {
            tracing::warn!(
                channel_id,
                error = %error,
                "Federation channel route revoke peer lookup failed"
            );
            return;
        }
    };

    for peer in peers {
        if let Err(error) = crate::federation::storage::revoke_peer_route(
            &state.pg,
            &peer.peer_id,
            crate::federation::producer::FederationRouteScope::Channel { channel_id },
            now_ms,
        )
        .await
        {
            tracing::warn!(
                channel_id,
                destination_peer_id = %peer.peer_id,
                error = %error,
                "Federation channel route revoke failed"
            );
        }
    }
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateChannelRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(max = 1024))]
    pub topic: Option<String>,
    pub r#type: Option<String>,
    pub category_id: Option<String>,
    pub read_only: Option<bool>,
    pub slowmode_seconds: Option<i32>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateChannelRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    pub topic: Option<Option<String>>,
    pub position: Option<i32>,
    pub category_id: Option<Option<String>>,
    pub read_only: Option<bool>,
    pub slowmode_seconds: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckRequest {
    pub message_id: String,
}

// ─── POST /api/servers/:serverId/channels ───────────────────────────

pub async fn create_channel(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
    Json(body): Json<CreateChannelRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!(
        "POST /api/servers/{}/channels user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::CHANNEL_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    let body = CreateChannelRequest {
        name: normalize_channel_name(&sanitize_text(&body.name)),
        topic: body.topic.map(|s| sanitize_text(&s)),
        ..body
    };

    if body.name.is_empty() || body.name.len() > 100 {
        return Err(AppError::Validation(
            "Channel name must be 1-100 characters".into(),
        ));
    }
    if let Some(slowmode) = body.slowmode_seconds {
        if !(0..=21600).contains(&slowmode) {
            return Err(AppError::Validation(
                "Slowmode must be 0-21600 seconds (0 to 6 hours)".into(),
            ));
        }
    }

    let existing = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_channel: PG list channels failed");
            AppError::Internal
        })?;
    if existing.len() as i64 >= MAX_CHANNELS_PER_SERVER {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "CHANNEL_LIMIT_REACHED",
            message: format!(
                "Server has reached the maximum of {MAX_CHANNELS_PER_SERVER} channels"
            ),
        });
    }

    let category_id: Option<i64> = if let Some(ref cat_id_str) = body.category_id {
        let cat_id = parse_id(cat_id_str)?;
        let cat = crate::services::pg::categories::by_id(&state.pg, cat_id)
            .await
            .map_err(|e| {
                tracing::error!(cat_id, error = %e, "create_channel: PG category read failed");
                AppError::Internal
            })?
            .ok_or_else(|| AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "CATEGORY_INVALID",
                message: "Category not found or does not belong to this server".into(),
            })?;
        if cat.server_id != server_id {
            return Err(AppError::WithCode {
                status: StatusCode::BAD_REQUEST,
                code: "CATEGORY_INVALID",
                message: "Category does not belong to this server".into(),
            });
        }
        Some(cat_id)
    } else {
        None
    };

    let position = if let Some(cat_id) = category_id {
        existing
            .iter()
            .filter(|c| c.category_id == Some(cat_id))
            .map(|c| c.position)
            .max()
            .map(|p| p + 1)
            .unwrap_or(0)
    } else {
        let max_ch = existing
            .iter()
            .filter(|c| c.category_id.is_none())
            .map(|c| c.position)
            .max()
            .unwrap_or(-1);
        let max_cat = crate::services::pg::categories::list_for_server(&state.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "create_channel: PG list categories failed");
                AppError::Internal
            })?
            .iter()
            .map(|c| c.position)
            .max()
            .unwrap_or(-1);
        std::cmp::max(max_ch, max_cat) + 1
    };

    let channel_type: i16 = if body.r#type.as_deref() == Some("voice") {
        3
    } else {
        0
    };
    let read_only = body.read_only.unwrap_or(false);
    let slowmode_seconds = body.slowmode_seconds.unwrap_or(0);
    let id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();

    crate::services::pg::channels::insert(
        &state.pg,
        id,
        server_id,
        channel_type,
        Some(&body.name),
        body.topic.as_deref(),
        position,
        category_id,
        read_only,
        slowmode_seconds,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id = id, error = %e, "create_channel: PG primary write failed");
        AppError::Internal
    })?;

    state
        .permissions
        .add_channel_meta(id, server_id, channel_type as i32);

    let channel_data = json!({
        "id": id.to_string(),
        "type": channel_type as i32,
        "serverId": server_id_str,
        "name": body.name,
        "topic": body.topic,
        "position": position,
        "categoryId": body.category_id,
        "readOnly": read_only,
        "slowmodeSeconds": slowmode_seconds,
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    });

    let json_text = events::channel_create_json(&channel_data);
    let proto_msg = events::channel_create_proto(crate::proto::Channel {
        id: id.to_string(),
        r#type: channel_type as i32,
        server_id: Some(server_id_str.clone()),
        name: Some(body.name.clone()),
        topic: body.topic.clone(),
        position,
        category_id: body.category_id.clone(),
        read_only,
        slowmode_seconds,
        created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    });
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    if channel_type == 0 {
        enqueue_federation_channel_event(
            &state,
            crate::federation::producer::FederationRouteScope::Server { server_id },
            crate::federation::producer::FederationLocalEvent::ChannelCreate {
                server_id,
                actor_user_id: user_id.0,
                channel_id: id,
                name: body.name.clone(),
                topic: body.topic.clone(),
                category_id,
                read_only,
                slowmode_seconds,
            },
            "Federation channel create producer completed",
        )
        .await;
        grant_federation_channel_routes_from_server_routes(&state, server_id, id, now_ms).await;
    } else {
        tracing::debug!(
            server_id,
            channel_id = id,
            channel_type,
            "Federation channel create skipped for unsupported non-text channel"
        );
    }

    tracing::info!(
        "Channel created id={} name={} server_id={}",
        id,
        body.name,
        server_id
    );
    Ok((StatusCode::CREATED, Json(channel_data)).into_response())
}

// ─── GET /api/servers/:serverId/channels ────────────────────────────

pub async fn list_channels(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/channels user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    state.require_membership(user_id.0, server_id).await?;

    let rows = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_channels: PG read failed");
            AppError::Internal
        })?;

    let mut result = Vec::with_capacity(rows.len());
    for c in &rows {
        let can_view = state
            .permissions
            .check_channel_permission(user_id.0, c.id, server_id, bits::VIEW_CHANNEL)
            .await
            .is_ok();
        if can_view {
            result.push(json!(channels::ChannelResponse::from(c)));
        }
    }

    tracing::info!(
        "Listed {} channels (of {} total) for server_id={}",
        result.len(),
        rows.len(),
        server_id
    );
    Ok(Json(json!(result)))
}

// ─── PATCH /api/channels/:channelId ─────────────────────────────────

pub async fn update_channel(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
    Json(body): Json<UpdateChannelRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "PATCH /api/channels/{} user_id={}",
        channel_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::CHANNEL_LIMIT, &user_id.0.to_string()).await?;
    let channel_id = parse_id(&channel_id_str)?;

    let existing = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "update_channel: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    let server_id = existing.server_id.ok_or(AppError::NotFound("channel"))?;
    require_federated_client_channel_scope(federated_client.as_ref(), Some(server_id))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    let body = UpdateChannelRequest {
        name: body
            .name
            .map(|s| normalize_channel_name(&sanitize_text(&s))),
        topic: body.topic.map(|opt| opt.map(|s| sanitize_text(&s))),
        ..body
    };

    if let Some(ref name) = body.name {
        if name.is_empty() || name.len() > 100 {
            return Err(AppError::Validation(
                "Channel name must be 1-100 characters".into(),
            ));
        }
    }
    if let Some(slowmode) = body.slowmode_seconds {
        if !(0..=21600).contains(&slowmode) {
            return Err(AppError::Validation(
                "Slowmode must be 0-21600 seconds (0 to 6 hours)".into(),
            ));
        }
    }

    let category_id_val: Option<Option<i64>> = if let Some(ref cat_opt) = body.category_id {
        match cat_opt {
            None => Some(None),
            Some(cat_id_str) => {
                let cat_id = parse_id(cat_id_str)?;
                let cat = crate::services::pg::categories::by_id(&state.pg, cat_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(cat_id, error = %e, "update_channel: PG category read failed");
                        AppError::Internal
                    })?
                    .ok_or_else(|| AppError::WithCode {
                        status: StatusCode::BAD_REQUEST,
                        code: "CATEGORY_INVALID",
                        message: "Category not found".into(),
                    })?;
                if cat.server_id != server_id {
                    return Err(AppError::WithCode {
                        status: StatusCode::BAD_REQUEST,
                        code: "CATEGORY_INVALID",
                        message: "Category does not belong to this server".into(),
                    });
                }
                Some(Some(cat_id))
            }
        }
    } else {
        None
    };

    let has_changes = body.name.is_some()
        || body.topic.is_some()
        || body.position.is_some()
        || body.category_id.is_some()
        || body.read_only.is_some()
        || body.slowmode_seconds.is_some();
    if !has_changes {
        return Err(AppError::NoChanges);
    }

    // Translate body.topic into the COALESCE-pattern arg. PG channels::update
    // takes Option<&str>; for clear-to-empty we send Some("") rather than NULL
    // because the column is nullable and the legacy path stored "" as the
    // unset sentinel. Either round-trips to None on the read side via
    // ChannelRow.topic.is_empty filtering.
    let topic_arg: Option<String> = body
        .topic
        .as_ref()
        .map(|outer| outer.clone().unwrap_or_default());

    crate::services::pg::channels::update(
        &state.pg,
        channel_id,
        crate::services::pg::channels::UpdateChannel {
            name: body.name.as_deref(),
            topic: topic_arg.as_deref(),
            position: body.position,
            category_id: category_id_val,
            read_only: body.read_only,
            slowmode_seconds: body.slowmode_seconds,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, error = %e, "update_channel: PG write failed");
        AppError::Internal
    })?;

    let updated = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "update_channel: PG re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;

    let ch_json = json!(channels::ChannelResponse::from(&updated));
    let json_text = events::channel_update_json(&ch_json);
    let proto_msg = events::channel_update_proto(crate::proto::Channel {
        id: updated.id.to_string(),
        r#type: updated.r#type,
        server_id: updated.server_id.map(|s| s.to_string()),
        name: updated.name.clone(),
        topic: updated.topic.clone(),
        position: updated.position,
        category_id: updated.category_id.map(|c| c.to_string()),
        read_only: updated.read_only,
        slowmode_seconds: updated.slowmode_seconds,
        created_at: updated.created_at.to_rfc3339(),
    });
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    if updated.r#type == 0 {
        enqueue_federation_channel_event(
            &state,
            crate::federation::producer::FederationRouteScope::Channel { channel_id },
            crate::federation::producer::FederationLocalEvent::ChannelUpdate {
                server_id,
                actor_user_id: user_id.0,
                channel_id,
                name: body.name.clone(),
                topic: body.topic.clone(),
                position: body.position,
                category_id: category_id_val,
                read_only: body.read_only,
                slowmode_seconds: body.slowmode_seconds,
            },
            "Federation channel update producer completed",
        )
        .await;
    } else {
        tracing::debug!(
            server_id,
            channel_id,
            channel_type = updated.r#type,
            "Federation channel update skipped for unsupported non-text channel"
        );
    }

    tracing::info!("Channel updated id={} server_id={}", channel_id, server_id);
    Ok(Json(ch_json))
}

#[cfg(test)]
mod tests {
    use super::normalize_channel_name;

    const SOURCE: &str = include_str!("channels.rs");

    fn handler_source(name: &str) -> &str {
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

    #[test]
    fn normalizes_text_channel_names() {
        assert_eq!(normalize_channel_name("Change Logs"), "change-logs");
        assert_eq!(
            normalize_channel_name("  Release   Notes  "),
            "release-notes"
        );
        assert_eq!(normalize_channel_name("Ops_ALERTS"), "ops_alerts");
        assert_eq!(normalize_channel_name("Dev!!!Ops"), "devops");
        assert_eq!(normalize_channel_name("---General---"), "general");
    }

    #[test]
    fn create_channel_enqueues_federation_channel_create_and_grants_route() {
        let handler = handler_source("create_channel");

        assert!(handler.contains("FederationLocalEvent::ChannelCreate"));
        assert!(handler.contains("grant_federation_channel_routes_from_server_routes"));
        assert!(handler.contains("FederationRouteScope::Server"));
    }

    #[test]
    fn update_channel_enqueues_federation_channel_update() {
        let handler = handler_source("update_channel");

        assert!(handler.contains("FederationLocalEvent::ChannelUpdate"));
        assert!(handler.contains("FederationRouteScope::Channel"));
    }

    #[test]
    fn delete_channel_enqueues_federation_channel_delete_and_revokes_route() {
        let handler = handler_source("delete_channel");

        assert!(handler.contains("FederationLocalEvent::ChannelDelete"));
        assert!(handler.contains("revoke_federation_channel_routes"));
        assert!(handler.contains("FederationRouteScope::Channel"));
    }

    #[test]
    fn ack_channel_enqueues_federation_read_state_update() {
        let handler = handler_source("ack_channel");

        assert!(handler.contains("FederationLocalEvent::ReadStateUpdate"));
        assert!(handler.contains("FederationRouteScope::Channel"));
    }
}

// ─── DELETE /api/channels/:channelId ────────────────────────────────

pub async fn delete_channel(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/channels/{} user_id={}",
        channel_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::CHANNEL_LIMIT, &user_id.0.to_string()).await?;
    let channel_id = parse_id(&channel_id_str)?;

    let existing = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "delete_channel: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    let server_id = existing.server_id.ok_or(AppError::NotFound("channel"))?;
    require_federated_client_channel_scope(federated_client.as_ref(), Some(server_id))?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    crate::services::pg::channels::delete(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "delete_channel: PG delete failed");
            AppError::Internal
        })?;

    let json_text = events::channel_delete_json(&channel_id_str, &server_id.to_string());
    let proto_msg = events::channel_delete_proto(channel_id_str.clone(), server_id.to_string());
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    if existing.r#type == 0 {
        enqueue_federation_channel_event(
            &state,
            crate::federation::producer::FederationRouteScope::Channel { channel_id },
            crate::federation::producer::FederationLocalEvent::ChannelDelete {
                server_id,
                actor_user_id: user_id.0,
                channel_id,
            },
            "Federation channel delete producer completed",
        )
        .await;
        revoke_federation_channel_routes(&state, channel_id, chrono::Utc::now().timestamp_millis())
            .await;
    } else {
        tracing::debug!(
            server_id,
            channel_id,
            channel_type = existing.r#type,
            "Federation channel delete skipped for unsupported non-text channel"
        );
    }

    for ch_topic in topics::all_channel_topics(channel_id) {
        topics::cleanup_topic(&state, &ch_topic).await;
    }

    state.permissions.remove_channel_meta(channel_id);

    tracing::info!("Channel deleted id={} server_id={}", channel_id, server_id);
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/channels/:channelId/ack ──────────────────────────────

pub async fn ack_channel(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
    Json(body): Json<AckRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/channels/{}/ack user_id={} message_id={}",
        channel_id_str,
        user_id.0,
        body.message_id
    );
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&body.message_id)?;

    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "channel_ack: PG channel read failed");
            AppError::Internal
        })?;

    match channel {
        Some(c) if c.server_id.is_some() => {
            let sid = c.server_id.unwrap();
            require_federated_client_channel_scope(federated_client.as_ref(), Some(sid))?;
            state
                .require_membership(user_id.0, sid)
                .await
                .map_err(|_| AppError::NotFound("channel"))?;
            state
                .permissions
                .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
                .await
                .map_err(|_| AppError::NotFound("channel"))?;
        }
        _ => {
            // No row in channels → maybe a DM channel. Verify membership.
            require_federated_client_channel_scope(federated_client.as_ref(), None)?;
            let dm_ids = crate::services::pg::dms::list_channel_ids_for_user(&state.pg, user_id.0)
                .await
                .unwrap_or_default();
            if !dm_ids.contains(&channel_id) {
                return Err(AppError::NotFound("channel"));
            }
        }
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::read_states::update(&state.pg, user_id.0, channel_id, message_id, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(
                user_id = user_id.0, channel_id, message_id, error = %e,
                "PG read_state update failed"
            );
            AppError::Internal
        })?;
    enqueue_federation_channel_event(
        &state,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
        crate::federation::producer::FederationLocalEvent::ReadStateUpdate {
            channel_id,
            message_id,
            user_id: user_id.0,
        },
        "Federation read state producer completed",
    )
    .await;

    tracing::info!(
        "Channel ack channel_id={} message_id={} user_id={}",
        channel_id,
        message_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}
