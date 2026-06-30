use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::UserId;
use crate::services::channel_visibility;
use crate::services::permissions::{CacheInvalidationEvent, bits};
use crate::state::AppState;

use super::parse_id;

/// Resolve the channel row + assert it's a server channel (not a DM
/// — DMs don't carry overrides). Returns server_id.
async fn require_server_channel(state: &AppState, channel_id: i64) -> AppResult<i64> {
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "channel_overrides: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    channel.server_id.ok_or(AppError::NotFound("channel"))
}

fn hide_channel_access_error(err: AppError) -> AppError {
    match err {
        AppError::Forbidden | AppError::MissingPermission | AppError::NotMember => {
            AppError::NotFound("channel")
        }
        err => err,
    }
}

async fn require_channel_override_access(
    state: &AppState,
    user_id: i64,
    channel_id: i64,
) -> AppResult<i64> {
    let server_id = require_server_channel(state, channel_id).await?;

    state
        .require_membership(user_id, server_id)
        .await
        .map_err(|_| AppError::NotFound("channel"))?;
    state
        .permissions
        .check_channel_permission(user_id, channel_id, server_id, bits::VIEW_CHANNEL)
        .await
        .map_err(hide_channel_access_error)?;
    state
        .permissions
        .check_channel_permission(user_id, channel_id, server_id, bits::MANAGE_ROLES)
        .await?;

    Ok(server_id)
}

async fn require_role_in_server(state: &AppState, role_id: i64, server_id: i64) -> AppResult<()> {
    let role = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "channel_overrides: PG role read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }
    if role.color_only {
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "ROLE_COLOR_ONLY",
            message: "Color-only roles cannot be used for channel permissions".into(),
        });
    }
    Ok(())
}

async fn enqueue_federation_channel_override_event(
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

// ─── GET /api/channels/:channelId/overrides ─────────────────────────

pub async fn list_overrides(
    State(state): State<AppState>,
    user_id: UserId,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/channels/{}/overrides user_id={}",
        channel_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    require_channel_override_access(&state, user_id.0, channel_id).await?;

    let overrides = crate::services::pg::channels::list_overrides(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "list_overrides: PG read failed");
            AppError::Internal
        })?;

    // Convenience: also surface each role's server-level perms so the
    // UI can render the effective allow/deny delta.
    let mut out: Vec<Value> = Vec::with_capacity(overrides.len());
    for ov in &overrides {
        let role_perms = crate::services::pg::roles::by_id(&state.pg, ov.role_id)
            .await
            .map_err(|e| {
                tracing::error!(role_id = ov.role_id, error = %e, "list_overrides: PG role read failed");
                AppError::Internal
            })?
            .map(|r| r.permissions)
            .unwrap_or(0);
        out.push(json!({
            "channelId": channel_id.to_string(),
            "roleId": ov.role_id.to_string(),
            "allow": ov.allow_bits.to_string(),
            "deny": ov.deny_bits.to_string(),
            "permissions": role_perms.to_string(),
        }));
    }

    Ok(Json(json!(out)))
}

// ─── PUT /api/channels/:channelId/overrides/:roleId ─────────────────

#[derive(Deserialize)]
pub struct UpsertOverrideRequest {
    pub allow: Option<String>,
    pub deny: Option<String>,
}

pub async fn upsert_override(
    State(state): State<AppState>,
    user_id: UserId,
    Path((channel_id_str, role_id_str)): Path<(String, String)>,
    Json(body): Json<UpsertOverrideRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PUT /api/channels/{}/overrides/{} user_id={}",
        channel_id_str,
        role_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let role_id = parse_id(&role_id_str)?;
    let server_id = require_channel_override_access(&state, user_id.0, channel_id).await?;
    require_role_in_server(&state, role_id, server_id).await?;
    let before_viewers = state
        .permissions
        .collect_online_channel_viewers(server_id, channel_id);

    // Privilege escalation guard: actor can't grant or deny bits they
    // don't already hold. allow wins on overlap (Discord semantic).
    let actor_perms = state
        .permissions
        .resolve_server_permissions(user_id.0, server_id)
        .await?;
    let allow: i64 = body
        .allow
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
        & actor_perms;
    let deny: i64 = body
        .deny
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
        & actor_perms;
    let deny = deny & !allow;

    crate::services::pg::channels::upsert_override(&state.pg, channel_id, role_id, allow, deny)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, role_id, error = %e, "upsert_override: PG write failed");
            AppError::Internal
        })?;

    // Invalidate permission cache + broadcast to other instances
    state
        .permissions
        .invalidate_channel_overrides(channel_id)
        .await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::ChannelOverridesChanged {
                channel_id,
                server_id,
            },
            &state.node_id,
        )
        .await;

    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "upsert_override: PG channel re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    channel_visibility::reconcile_single_channel_visibility(&state, &channel, &before_viewers)
        .await?;
    enqueue_federation_channel_override_event(
        &state,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
        crate::federation::producer::FederationLocalEvent::ChannelOverrideSet {
            server_id,
            actor_user_id: user_id.0,
            channel_id,
            role_id,
            allow: Some(allow),
            deny: Some(deny),
        },
        "Federation channel override set producer completed",
    )
    .await;

    tracing::info!(
        "Override upserted channel={} role={} allow={} deny={} by={}",
        channel_id,
        role_id,
        allow,
        deny,
        user_id.0
    );
    Ok(Json(json!({
        "channelId": channel_id_str,
        "roleId": role_id_str,
        "allow": allow.to_string(),
        "deny": deny.to_string(),
    })))
}

// ─── DELETE /api/channels/:channelId/overrides/:roleId ──────────────

pub async fn delete_override(
    State(state): State<AppState>,
    user_id: UserId,
    Path((channel_id_str, role_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/channels/{}/overrides/{} user_id={}",
        channel_id_str,
        role_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let role_id = parse_id(&role_id_str)?;
    let server_id = require_channel_override_access(&state, user_id.0, channel_id).await?;
    require_role_in_server(&state, role_id, server_id).await?;
    let before_viewers = state
        .permissions
        .collect_online_channel_viewers(server_id, channel_id);

    crate::services::pg::channels::remove_override(&state.pg, channel_id, role_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, role_id, error = %e, "delete_override: PG delete failed");
            AppError::Internal
        })?;

    // Invalidate permission cache + broadcast
    state
        .permissions
        .invalidate_channel_overrides(channel_id)
        .await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::ChannelOverridesChanged {
                channel_id,
                server_id,
            },
            &state.node_id,
        )
        .await;

    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "delete_override: PG channel re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    channel_visibility::reconcile_single_channel_visibility(&state, &channel, &before_viewers)
        .await?;
    enqueue_federation_channel_override_event(
        &state,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
        crate::federation::producer::FederationLocalEvent::ChannelOverrideDelete {
            server_id,
            actor_user_id: user_id.0,
            channel_id,
            role_id,
        },
        "Federation channel override delete producer completed",
    )
    .await;

    tracing::info!(
        "Override deleted channel={} role={} by={}",
        channel_id,
        role_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("channel_overrides.rs");

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

    #[test]
    fn upsert_override_enqueues_federation_channel_override_set() {
        let handler = handler_source("upsert_override");

        assert!(handler.contains("FederationLocalEvent::ChannelOverrideSet"));
        assert!(handler.contains("FederationRouteScope::Channel"));
    }

    #[test]
    fn delete_override_enqueues_federation_channel_override_delete() {
        let handler = handler_source("delete_override");

        assert!(handler.contains("FederationLocalEvent::ChannelOverrideDelete"));
        assert!(handler.contains("FederationRouteScope::Channel"));
    }
}
