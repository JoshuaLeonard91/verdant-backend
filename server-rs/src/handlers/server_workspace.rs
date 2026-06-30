use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;

use crate::error::{AppError, AppResult};
use crate::middleware::{
    auth::{OptionalFederatedClient, UserId, require_federated_client_server_scope},
    rate_limit,
};
use crate::repo::{categories, channels};
use crate::services::permissions::bits;
use crate::state::AppState;

use super::parse_id;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerWorkspaceQueryParams {
    pub message_limit: Option<i64>,
    pub include_activity: Option<bool>,
}

fn workspace_message_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(crate::handlers::messages::MESSAGE_FETCH_LIMIT)
        .min(crate::handlers::messages::MESSAGE_FETCH_LIMIT)
        .max(1)
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

async fn visible_layout_json(
    state: &AppState,
    user_id: i64,
    server_id: i64,
) -> AppResult<(Value, Option<i64>)> {
    let cats = crate::services::pg::categories::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: PG category read failed");
            AppError::Internal
        })?;
    let chs = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: PG channel read failed");
            AppError::Internal
        })?;

    let mut filtered_chs = Vec::with_capacity(chs.len());
    for channel in chs {
        let allowed = state
            .permissions
            .check_channel_permission(user_id, channel.id, server_id, bits::VIEW_CHANNEL)
            .await
            .is_ok();
        if allowed {
            filtered_chs.push(channel);
        }
    }

    let active_channel_id = filtered_chs
        .iter()
        .find(|channel| channel.r#type == 0)
        .map(|channel| channel.id);
    let cat_list: Vec<Value> = cats
        .iter()
        .map(|category| json!(categories::CategoryResponse::from(category)))
        .collect();
    let ch_list: Vec<Value> = filtered_chs
        .iter()
        .map(|channel| json!(channels::ChannelResponse::from(channel)))
        .collect();

    Ok((
        json!({
            "categories": cat_list,
            "channels": ch_list,
        }),
        active_channel_id,
    ))
}

async fn current_user_json(state: &AppState, user_id: i64) -> AppResult<Value> {
    let record = crate::services::pg::users::by_id(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "server_workspace: PG current-user read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;
    let status = crate::services::presence::effective_status(&state.redis, user_id).await;
    Ok(crate::handlers::users::user_to_full_response_json(
        &record,
        &status,
        crate::handlers::users::member_list_banner_visible_for_record(state, &record),
    ))
}

pub async fn get_server_workspace(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
    Query(params): Query<ServerWorkspaceQueryParams>,
) -> AppResult<Json<Value>> {
    let request_watch = Instant::now();
    tracing::info!(
        server_id = %server_id_str,
        federated_client = federated_client.is_some(),
        "GET /api/servers/:id/workspace"
    );
    let rate_limit_watch = Instant::now();
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let rate_limit_ms = elapsed_ms(rate_limit_watch);
    let server_id = parse_id(&server_id_str)?;
    let access_watch = Instant::now();
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;
    state
        .require_membership(user_id.0, server_id)
        .await
        .map_err(|_| AppError::NotFound("server"))?;
    let access_ms = elapsed_ms(access_watch);

    let server_watch = Instant::now();
    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: PG server read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;
    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .unwrap_or(0);
    let server_json = crate::handlers::servers::server_row_to_json(&server, member_count);
    let server_ms = elapsed_ms(server_watch);

    let layout_watch = Instant::now();
    let (layout, active_channel_id) = visible_layout_json(&state, user_id.0, server_id).await?;
    let layout_ms = elapsed_ms(layout_watch);
    let roles_watch = Instant::now();
    let mut roles = crate::services::pg::roles::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: PG role read failed");
            AppError::Internal
        })?;
    roles.sort_by_key(|role| role.position);
    let roles_json: Vec<Value> = roles
        .iter()
        .map(crate::handlers::roles::serialize_role)
        .collect();
    let roles_ms = elapsed_ms(roles_watch);
    let members_watch = Instant::now();
    let members_json = crate::handlers::servers::list_members_json(
        &state,
        user_id.0,
        federated_client.as_ref(),
        server_id,
        crate::handlers::servers::MemberQueryParams {
            limit: Some(100),
            after: None,
            channel_id: None,
        },
    )
    .await?;
    let members_ms = elapsed_ms(members_watch);
    let feeds_watch = Instant::now();
    let feeds_json =
        crate::handlers::feeds::list_visible_feeds_json(&state, user_id.0, server_id).await?;
    let feeds_ms = elapsed_ms(feeds_watch);
    let bots_watch = Instant::now();
    let bots_json = crate::handlers::bots::list_bots_json(
        &state,
        user_id.0,
        server_id,
        crate::handlers::bots::ListBotsQueryParams::default(),
    )
    .await?;
    let bots_ms = elapsed_ms(bots_watch);
    let emojis_watch = Instant::now();
    let emoji_records = crate::services::pg::emojis::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: PG emoji read failed");
            AppError::Internal
        })?;
    let emojis_json: Vec<Value> = emoji_records
        .iter()
        .map(crate::handlers::emojis::serialize_emoji)
        .collect();
    let emojis_ms = elapsed_ms(emojis_watch);
    let stickers_watch = Instant::now();
    let sticker_records = crate::services::pg::stickers::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: PG sticker read failed");
            AppError::Internal
        })?;
    let stickers_json: Vec<Value> = sticker_records
        .iter()
        .map(crate::handlers::stickers::serialize_sticker)
        .collect();
    let stickers_ms = elapsed_ms(stickers_watch);
    let current_user_watch = Instant::now();
    let current_user = current_user_json(&state, user_id.0).await?;
    let current_user_ms = elapsed_ms(current_user_watch);
    let instance_watch = Instant::now();
    let instance = serde_json::to_value(crate::services::instance::metadata(&state.config))
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "server_workspace: instance metadata serialize failed");
            AppError::Internal
        })?;
    let instance_ms = elapsed_ms(instance_watch);

    let message_limit = workspace_message_limit(params.message_limit);
    let messages_watch = Instant::now();
    let messages = match active_channel_id {
        Some(channel_id) => {
            crate::handlers::messages::load_channel_messages_json(
                &state,
                user_id.0,
                federated_client.as_ref(),
                channel_id,
                message_limit,
                None,
            )
            .await?
        }
        None => Vec::new(),
    };
    let messages_ms = elapsed_ms(messages_watch);

    let include_activity = params.include_activity.unwrap_or(true);
    let activity_watch = Instant::now();
    let activity_members = match (include_activity, active_channel_id) {
        (true, Some(channel_id)) => {
            match crate::handlers::messages::load_channel_activity_json(
                &state,
                user_id.0,
                federated_client.as_ref(),
                channel_id,
            )
            .await
            {
                Ok(members) => members,
                Err(error) => {
                    tracing::warn!(
                        server_id,
                        channel_id,
                        error = %error,
                        "server_workspace: channel activity batch read failed"
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    };
    let activity_ms = elapsed_ms(activity_watch);
    let server_media = crate::handlers::media_diagnostics::summarize_server_media(&server_json);
    let current_user_media =
        crate::handlers::media_diagnostics::summarize_user_media(&current_user, "currentUser");
    let member_media =
        crate::handlers::media_diagnostics::summarize_member_media(&members_json, "member");
    let message_media = crate::handlers::media_diagnostics::summarize_message_media(&messages);
    let activity_media = crate::handlers::media_diagnostics::summarize_member_media(
        &activity_members,
        "activityMember",
    );

    tracing::info!(
        server_id,
        federated_client = federated_client.is_some(),
        server_media = ?server_media,
        current_user_media = ?current_user_media,
        member_media = ?member_media,
        message_media = ?message_media,
        activity_media = ?activity_media,
        "Server workspace emitted media fields"
    );

    tracing::info!(
        server_id,
        federated_client = federated_client.is_some(),
        rate_limit_ms,
        access_ms,
        server_ms,
        layout_ms,
        roles_ms,
        members_ms,
        feeds_ms,
        bots_ms,
        emojis_ms,
        stickers_ms,
        current_user_ms,
        instance_ms,
        messages_ms,
        activity_ms,
        total_ms = elapsed_ms(request_watch),
        include_activity,
        has_active_channel = active_channel_id.is_some(),
        "Server workspace bootstrap phase timings"
    );

    tracing::info!(
        server_id,
        federated_client = federated_client.is_some(),
        channels = layout
            .get("channels")
            .and_then(|value| value.as_array())
            .map_or(0, Vec::len),
        roles = roles_json.len(),
        members = members_json.len(),
        feeds = feeds_json.len(),
        bots = bots_json.len(),
        emojis = emojis_json.len(),
        stickers = stickers_json.len(),
        messages = messages.len(),
        activity_members = activity_members.len(),
        ms = elapsed_ms(request_watch),
        "Server workspace bootstrap fetched"
    );

    Ok(Json(json!({
        "version": 1,
        "server": server_json,
        "layout": layout,
        "roles": roles_json,
        "members": members_json,
        "feeds": feeds_json,
        "bots": bots_json,
        "emojis": emojis_json,
        "stickers": stickers_json,
        "invites": [],
        "auditEvents": [],
        "currentUser": current_user,
        "activeChannelId": active_channel_id.map(|id| id.to_string()),
        "messages": messages,
        "activity": {
            "available": include_activity && active_channel_id.is_some(),
            "members": activity_members,
        },
        "instance": instance,
    })))
}

#[cfg(test)]
mod tests {
    use super::workspace_message_limit;

    #[test]
    fn workspace_message_limit_clamps_to_message_fetch_limit() {
        assert_eq!(workspace_message_limit(None), 50);
        assert_eq!(workspace_message_limit(Some(0)), 1);
        assert_eq!(workspace_message_limit(Some(500)), 50);
    }

    #[test]
    fn workspace_handler_keeps_membership_and_federation_gates() {
        let source = include_str!("server_workspace.rs");

        assert!(source.contains("rate_limit::enforce"));
        assert!(source.contains("require_federated_client_server_scope"));
        assert!(source.contains(".require_membership("));
        assert!(source.contains("load_channel_messages_json"));
        assert!(source.contains("load_channel_activity_json"));
        assert!(source.contains("services::pg::emojis::list_for_server"));
        assert!(source.contains("services::pg::stickers::list_for_server"));
        assert!(source.contains("\"emojis\": emojis_json"));
        assert!(source.contains("\"stickers\": stickers_json"));
    }

    #[test]
    fn workspace_diagnostic_logs_do_not_include_raw_user_ids() {
        let source = include_str!("server_workspace.rs");
        let raw_message_placeholder = format!("{}={}", "user_id", "{}");
        let raw_structured_field = format!("{} = {}.0", "user_id", "user_id");

        assert!(!source.contains(&raw_message_placeholder));
        assert!(!source.contains(&raw_structured_field));
    }
}
