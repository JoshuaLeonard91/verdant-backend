use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::UserId;
use crate::middleware::rate_limit;
use crate::services::permissions::bits;
use crate::services::pg::feeds::{FeedRow, InsertFeed, UpdateFeed};
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_FEEDS_PER_SERVER: usize = 25;

fn visibility_revoke_targets(
    old_visible_role_ids: &[i64],
    new_visible_role_ids: &[i64],
    old_entitled: HashSet<i64>,
    new_entitled: HashSet<i64>,
    all_online: HashSet<i64>,
) -> Vec<i64> {
    if new_visible_role_ids.is_empty() {
        return Vec::new();
    }

    let old_viewers = if old_visible_role_ids.is_empty() {
        all_online.clone()
    } else {
        old_entitled
    };
    let new_viewers = if new_visible_role_ids.is_empty() {
        all_online
    } else {
        new_entitled
    };
    let mut losing = old_viewers
        .difference(&new_viewers)
        .copied()
        .collect::<Vec<_>>();
    losing.sort_unstable();
    losing
}

// ─── Serialization helpers ─────────────────────────────────────────

/// Treat None or empty string as JSON null. PG nullable text columns
/// can land in either state depending on whether prior writes cleared
/// or NULL'd them; both should render the same on the wire.
fn opt_str_or_null(s: &Option<String>) -> Value {
    match s {
        Some(v) if !v.is_empty() => Value::String(v.clone()),
        _ => Value::Null,
    }
}

fn opt_str_some_nonempty(s: &Option<String>) -> Option<String> {
    s.as_ref().filter(|v| !v.is_empty()).cloned()
}

pub(crate) fn feed_to_json(f: &FeedRow) -> Value {
    json!({
        "id": f.id.to_string(),
        "serverId": f.server_id.to_string(),
        "name": f.name,
        "description": opt_str_or_null(&f.description),
        "icon": opt_str_or_null(&f.icon),
        "position": f.position,
        "publishRoleIds": if f.publish_role_ids.is_empty() {
            Value::Null
        } else {
            Value::Array(f.publish_role_ids.iter().map(|id| Value::String(id.to_string())).collect())
        },
        "visibleRoleIds": if f.visible_role_ids.is_empty() {
            Value::Null
        } else {
            Value::Array(f.visible_role_ids.iter().map(|id| Value::String(id.to_string())).collect())
        },
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(f.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    })
}

fn feed_to_proto(f: &FeedRow) -> crate::proto::Feed {
    crate::proto::Feed {
        id: f.id.to_string(),
        server_id: f.server_id.to_string(),
        name: f.name.clone(),
        description: opt_str_some_nonempty(&f.description),
        publish_role_ids: f.publish_role_ids.iter().map(|id| id.to_string()).collect(),
        view_role_ids: f.visible_role_ids.iter().map(|id| id.to_string()).collect(),
        created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(f.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        icon: opt_str_some_nonempty(&f.icon),
        position: f.position,
    }
}

// ─── Request types ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFeedRequest {
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub publish_role_ids: Option<Vec<String>>,
    pub visible_role_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFeedRequest {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub icon: Option<Option<String>>,
    pub publish_role_ids: Option<Option<Vec<String>>>,
    pub visible_role_ids: Option<Option<Vec<String>>>,
}

fn parse_role_ids(raw: &Option<Vec<String>>) -> Vec<i64> {
    raw.as_ref()
        .map(|ids| ids.iter().filter_map(|s| s.parse::<i64>().ok()).collect())
        .unwrap_or_default()
}

// ─── POST /api/servers/:serverId/feeds ─────────────────────────────

pub async fn create_feed(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<CreateFeedRequest>,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/feeds user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    // Sanitize and validate name
    let name = sanitize_text(&body.name);
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::Validation(
            "Feed name must be 1-100 characters".into(),
        ));
    }

    // Validate description
    if let Some(ref desc) = body.description {
        if desc.len() > 500 {
            return Err(AppError::Validation(
                "Feed description must be at most 500 characters".into(),
            ));
        }
    }

    // Validate icon (emoji, max 10 bytes)
    if let Some(ref icon) = body.icon {
        if icon.len() > 10 {
            return Err(AppError::Validation(
                "Feed icon must be at most 10 bytes".into(),
            ));
        }
    }

    // Enforce the per-server feed cap. Non-atomic vs the index — worst
    // case a race lets one extra feed through, which is fine on a
    // solo deployment.
    let existing = crate::services::pg::feeds::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_feed: PG list failed");
            AppError::Internal
        })?;
    if existing.len() >= MAX_FEEDS_PER_SERVER {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "FEED_LIMIT_REACHED",
            message: format!("Server has reached the maximum of {MAX_FEEDS_PER_SERVER} feeds"),
        });
    }

    let id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let description = body
        .description
        .as_deref()
        .map(sanitize_text)
        .unwrap_or_default();
    let icon = body.icon.as_deref().map(sanitize_text).unwrap_or_default();
    let publish_role_ids = parse_role_ids(&body.publish_role_ids);
    let visible_role_ids = parse_role_ids(&body.visible_role_ids);

    // `position` = max existing + 1 (or 0 if first)
    let next_position = existing
        .iter()
        .map(|f| f.position)
        .max()
        .map(|p| p + 1)
        .unwrap_or(0);

    crate::services::pg::feeds::insert(
        &state.pg,
        InsertFeed {
            id,
            server_id,
            name: &name,
            description: if description.is_empty() {
                None
            } else {
                Some(&description)
            },
            icon: if icon.is_empty() { None } else { Some(&icon) },
            position: next_position,
            publish_role_ids: &publish_role_ids,
            visible_role_ids: &visible_role_ids,
            now_ms,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(id, error = %e, "create_feed: PG write failed");
        AppError::Internal
    })?;

    let row = FeedRow {
        id,
        server_id,
        name: name.clone(),
        description: if description.is_empty() {
            None
        } else {
            Some(description)
        },
        icon: if icon.is_empty() { None } else { Some(icon) },
        position: next_position,
        publish_role_ids,
        visible_role_ids,
        created_at_ms: now_ms,
    };

    // Broadcast FEED_CREATE scoped to the feed's visible_role_ids.
    // An unrestricted feed fans out to every member; a role-gated
    // feed is delivered only to entitled members so non-entitled
    // clients never learn the feed exists.
    let feed_data = feed_to_json(&row);
    let json_text = events::feed_create_json(&feed_data);
    let proto_msg = events::feed_create_proto(server_id.to_string(), feed_to_proto(&row));
    topics::publish_feed_scoped(
        &state,
        server_id,
        &row.visible_role_ids,
        &json_text,
        &proto_msg,
    )
    .await;

    tracing::info!(
        "Feed created id={} server={} by={}",
        id,
        server_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(feed_data)).into_response())
}

// ─── GET /api/servers/:serverId/feeds ──────────────────────────────

pub async fn list_feeds(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/feeds user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let result = list_visible_feeds_json(&state, user_id.0, server_id).await?;

    Ok(Json(json!(result)))
}

pub(crate) async fn list_visible_feeds_json(
    state: &AppState,
    user_id: i64,
    server_id: i64,
) -> AppResult<Vec<Value>> {
    state.require_membership(user_id, server_id).await?;

    // Already ordered by position ASC, id ASC
    let feeds = crate::services::pg::feeds::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_feeds: PG read failed");
            AppError::Internal
        })?;

    // Check if user has ADMINISTRATOR — they see all feeds
    let is_admin = state
        .permissions
        .check_server_permission(user_id, server_id, bits::ADMINISTRATOR)
        .await
        .is_ok();

    let result: Vec<Value> = if is_admin {
        feeds.iter().map(feed_to_json).collect()
    } else {
        // Get user's roles in this server
        let user_role_ids: std::collections::HashSet<i64> =
            crate::services::pg::roles::list_role_ids(&state.pg, user_id, server_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();

        feeds
            .iter()
            .filter(|feed| {
                // Empty visible_role_ids → visible to all members.
                // Non-empty → user must hold at least one listed role.
                feed.visible_role_ids.is_empty()
                    || feed
                        .visible_role_ids
                        .iter()
                        .any(|r| user_role_ids.contains(r))
            })
            .map(feed_to_json)
            .collect()
    };

    Ok(result)
}

// ─── PATCH /api/servers/:serverId/feeds/:feedId ────────────────────

pub async fn update_feed(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, feed_id_str)): Path<(String, String)>,
    Json(body): Json<UpdateFeedRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/servers/{}/feeds/{} user_id={}",
        server_id_str,
        feed_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let feed_id = parse_id(&feed_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let mut row = crate::services::pg::feeds::by_id(&state.pg, feed_id)
        .await
        .map_err(|e| {
            tracing::error!(feed_id, error = %e, "update_feed: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("feed"))?;
    if row.server_id != server_id {
        return Err(AppError::NotFound("feed"));
    }

    // Snapshot the pre-update visibility so we can compute which
    // users lose access after the PATCH (they must receive FEED_DELETE
    // to drop the feed from their client cache).
    let old_visible_role_ids: Vec<i64> = row.visible_role_ids.clone();

    let has_changes = body.name.is_some()
        || body.description.is_some()
        || body.icon.is_some()
        || body.publish_role_ids.is_some()
        || body.visible_role_ids.is_some();
    if !has_changes {
        return Err(AppError::NoChanges);
    }

    // Apply the patch in-memory + collect the changed fields for the
    // SQL update. PG `update` uses COALESCE so we only override what
    // changed; cleared optional text becomes the empty-string sentinel.
    let mut new_name: Option<String> = None;
    let mut new_description: Option<String> = None;
    let mut new_icon: Option<String> = None;
    let mut new_publish: Option<Vec<i64>> = None;
    let mut new_visible: Option<Vec<i64>> = None;

    if let Some(ref name) = body.name {
        let n = sanitize_text(name);
        if n.is_empty() || n.len() > 100 {
            return Err(AppError::Validation(
                "Feed name must be 1-100 characters".into(),
            ));
        }
        row.name = n.clone();
        new_name = Some(n);
    }
    if let Some(ref desc_opt) = body.description {
        let v = match desc_opt {
            Some(d) => {
                if d.len() > 500 {
                    return Err(AppError::Validation(
                        "Feed description must be at most 500 characters".into(),
                    ));
                }
                sanitize_text(d)
            }
            None => String::new(),
        };
        row.description = if v.is_empty() { None } else { Some(v.clone()) };
        new_description = Some(v);
    }
    if let Some(ref icon_opt) = body.icon {
        let v = match icon_opt {
            Some(i) => {
                if i.len() > 10 {
                    return Err(AppError::Validation(
                        "Feed icon must be at most 10 bytes".into(),
                    ));
                }
                sanitize_text(i)
            }
            None => String::new(),
        };
        row.icon = if v.is_empty() { None } else { Some(v.clone()) };
        new_icon = Some(v);
    }
    if let Some(ref role_opt) = body.publish_role_ids {
        let ids: Vec<i64> = match role_opt {
            Some(ids) => ids.iter().filter_map(|s| s.parse::<i64>().ok()).collect(),
            None => Vec::new(),
        };
        row.publish_role_ids = ids.clone();
        new_publish = Some(ids);
    }
    if let Some(ref role_opt) = body.visible_role_ids {
        let ids: Vec<i64> = match role_opt {
            Some(ids) => ids.iter().filter_map(|s| s.parse::<i64>().ok()).collect(),
            None => Vec::new(),
        };
        row.visible_role_ids = ids.clone();
        new_visible = Some(ids);
    }

    crate::services::pg::feeds::update(
        &state.pg,
        feed_id,
        UpdateFeed {
            name: new_name.as_deref(),
            description: new_description.as_deref(),
            icon: new_icon.as_deref(),
            position: None,
            publish_role_ids: new_publish.as_deref(),
            visible_role_ids: new_visible.as_deref(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(feed_id, error = %e, "update_feed: PG write failed");
        AppError::Internal
    })?;

    // Broadcast FEED_UPDATE to the new entitled set.
    // If the visibility list shrank (or changed), also emit
    // FEED_DELETE to members who lost access so their client removes
    // the feed from state. Members who newly qualify will discover
    // the feed on next IDENTIFY; they don't receive a mid-session
    // FEED_CREATE here (a minor UX gap, but not a security issue).
    let feed_data = feed_to_json(&row);
    let json_text = events::feed_update_json(&feed_data);
    let proto_msg = events::feed_update_proto(server_id.to_string(), feed_to_proto(&row));
    topics::publish_feed_scoped(
        &state,
        server_id,
        &row.visible_role_ids,
        &json_text,
        &proto_msg,
    )
    .await;

    if old_visible_role_ids != row.visible_role_ids {
        let old_allowed: HashSet<i64> = old_visible_role_ids.iter().copied().collect();
        let new_allowed: HashSet<i64> = row.visible_role_ids.iter().copied().collect();
        let all_online = if old_visible_role_ids.is_empty() || row.visible_role_ids.is_empty() {
            state.permissions.collect_online_server_members(server_id)
        } else {
            HashSet::new()
        };
        let old_entitled = if old_visible_role_ids.is_empty() {
            HashSet::new()
        } else {
            state
                .permissions
                .collect_entitled_online_members(server_id, &old_allowed)
        };
        let new_entitled = if row.visible_role_ids.is_empty() {
            HashSet::new()
        } else {
            state
                .permissions
                .collect_entitled_online_members(server_id, &new_allowed)
        };
        let losing = visibility_revoke_targets(
            &old_visible_role_ids,
            &row.visible_role_ids,
            old_entitled,
            new_entitled,
            all_online,
        );
        if !losing.is_empty() {
            let del_json = events::feed_delete_json(&server_id_str, &feed_id_str);
            let del_proto = events::feed_delete_proto(server_id_str.clone(), feed_id_str.clone());
            for uid in losing {
                topics::publish(&state, &topics::user_topic(uid), &del_json, &del_proto).await;
            }
        }
    }

    tracing::info!(
        "Feed updated id={} server={} by={}",
        feed_id,
        server_id,
        user_id.0
    );
    Ok(Json(feed_data))
}

// ─── DELETE /api/servers/:serverId/feeds/:feedId ───────────────────

pub async fn delete_feed(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, feed_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/feeds/{} user_id={}",
        server_id_str,
        feed_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let feed_id = parse_id(&feed_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let row = crate::services::pg::feeds::by_id(&state.pg, feed_id)
        .await
        .map_err(|e| {
            tracing::error!(feed_id, error = %e, "delete_feed: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("feed"))?;
    if row.server_id != server_id {
        return Err(AppError::NotFound("feed"));
    }

    crate::services::pg::feeds::delete(&state.pg, feed_id)
        .await
        .map_err(|e| {
            tracing::error!(feed_id, error = %e, "delete_feed: PG delete failed");
            AppError::Internal
        })?;

    // Broadcast FEED_DELETE scoped to the feed's visible_role_ids.
    // Only members who could previously see the feed need to know
    // it vanished.
    let json_text = events::feed_delete_json(&server_id_str, &feed_id_str);
    let proto_msg = events::feed_delete_proto(server_id_str.clone(), feed_id_str.clone());
    topics::publish_feed_scoped(
        &state,
        server_id,
        &row.visible_role_ids,
        &json_text,
        &proto_msg,
    )
    .await;

    tracing::info!(
        "Feed deleted id={} server={} by={}",
        feed_id,
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn visibility_revoke_targets_include_public_viewers_who_lose_access() {
        let all_online = HashSet::from([1, 2, 3, 4]);
        let old_entitled = HashSet::new();
        let new_entitled = HashSet::from([1, 3]);

        let losing = visibility_revoke_targets(&[], &[44], old_entitled, new_entitled, all_online);

        assert_eq!(losing, vec![2, 4]);
    }

    #[test]
    fn visibility_revoke_targets_keep_role_entitled_members() {
        let all_online = HashSet::from([1, 2, 3, 4]);
        let old_entitled = HashSet::from([1, 2, 4]);
        let new_entitled = HashSet::from([2, 4]);

        let losing =
            visibility_revoke_targets(&[11], &[44], old_entitled, new_entitled, all_online);

        assert_eq!(losing, vec![1]);
    }

    #[test]
    fn visibility_revoke_targets_do_not_delete_when_feed_becomes_public() {
        let all_online = HashSet::from([2, 4]);
        let old_entitled = HashSet::from([1, 2, 4]);
        let new_entitled = HashSet::new();

        let losing = visibility_revoke_targets(&[11], &[], old_entitled, new_entitled, all_online);

        assert!(losing.is_empty());
    }
}
