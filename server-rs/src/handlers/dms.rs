use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::cdn;
use crate::services::pg::dms::{DM_DIRECT, DM_GROUP};
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_DM_GROUP_SIZE: usize = 10;

async fn enqueue_federation_dm_event(
    state: &AppState,
    channel_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    now_ms: i64,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Dm { channel_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        now_ms,
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            channel_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "Federation DM event producer completed"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            channel_id,
            error = %error,
            "Federation DM event producer failed"
        ),
    }
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateDmRequest {
    #[validate(length(min = 1))]
    pub recipient_ids: Vec<String>,
    pub name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListDmsQuery {
    pub include_preferences: Option<bool>,
}

// ─── POST /api/dms ──────────────────────────────────────────────────

pub async fn create_dm(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<CreateDmRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!(
        "POST /api/dms user_id={} recipients={}",
        user_id.0,
        body.recipient_ids.len()
    );
    tracing::warn!(
        target: "runtime_test",
        route = "dms.create",
        user_id = user_id.0,
        recipient_count = body.recipient_ids.len(),
        "runtime_test.dm.create.request"
    );
    rate_limit::enforce(&state, &rate_limit::DM_LIMIT, &user_id.0.to_string()).await?;
    if body.recipient_ids.is_empty() {
        return Err(AppError::Validation(
            "At least one recipient is required".into(),
        ));
    }
    if body.recipient_ids.len() >= MAX_DM_GROUP_SIZE {
        return Err(AppError::Validation(format!(
            "Group DMs can have at most {MAX_DM_GROUP_SIZE} members"
        )));
    }

    let mut all_ids: Vec<i64> = vec![user_id.0];
    for rid in &body.recipient_ids {
        let id = parse_id(rid)?;
        if !all_ids.contains(&id) {
            all_ids.push(id);
        }
    }
    if all_ids.len() < 2 {
        return Err(AppError::Validation(
            "At least one other recipient is required".into(),
        ));
    }
    if all_ids.len() > MAX_DM_GROUP_SIZE {
        return Err(AppError::Validation(format!(
            "Group DMs can have at most {MAX_DM_GROUP_SIZE} members"
        )));
    }

    // Validate every recipient exists.
    let recipient_i64s: Vec<i64> = all_ids.iter().skip(1).copied().collect();
    let resolved = crate::services::pg::users::by_ids(&state.pg, &recipient_i64s)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create_dm: PG recipient batch read failed");
            AppError::Internal
        })?;
    if resolved.len() != recipient_i64s.len() {
        return Err(AppError::NotFound("user"));
    }

    let is_group = all_ids.len() > 2;

    // A DM can only be opened with users who are friends or share a server.
    // This is enforced server-side so direct API calls cannot bypass the UI.
    for other in &recipient_i64s {
        crate::services::channel_access::ensure_dm_user_allowed(&state, user_id.0, *other)
            .await
            .map_err(|e| match e {
                AppError::WithCode {
                    status,
                    code,
                    message: _,
                } => AppError::WithCode {
                    status,
                    code,
                    message: "Unable to create DM with this user".into(),
                },
                other => other,
            })?;
    }

    // 1-on-1 DM: dedupe via the existing-channel index.
    if !is_group {
        let recipient_id = all_ids[1];
        let existing_direct =
            crate::services::pg::dms::find_direct_between(&state.pg, user_id.0, recipient_id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        user_id = user_id.0,
                        recipient_id,
                        error = %e,
                        "create_dm: PG direct DM dedupe read failed"
                    );
                    AppError::Internal
                })?;
        if let Some(existing_id) = existing_direct {
            state.permissions.add_dm_channel(user_id.0, existing_id);
            state.permissions.add_dm_channel(recipient_id, existing_id);
            let dm = build_dm_response(&state, existing_id).await?;
            tracing::warn!(
                target: "runtime_test",
                route = "dms.create",
                outcome = "existing",
                channel_id = existing_id,
                participant_count = all_ids.len(),
                "runtime_test.dm.create.response"
            );
            return Ok(Json(dm).into_response());
        }
    }

    let channel_id = state.snowflake.next_id();
    let channel_type: i16 = if is_group { DM_GROUP } else { DM_DIRECT };
    let dm_name = if is_group { body.name.as_deref() } else { None };
    let owner_id: Option<i64> = if is_group { Some(user_id.0) } else { None };
    let now_ms = chrono::Utc::now().timestamp_millis();

    crate::services::pg::dms::create_channel(
        &state.pg,
        channel_id,
        channel_type,
        dm_name,
        owner_id,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, error = %e, "create_dm: PG channel insert failed");
        AppError::Internal
    })?;
    crate::services::pg::dms::add_members_bulk(&state.pg, channel_id, &all_ids, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "create_dm: PG bulk member insert failed");
            AppError::Internal
        })?;

    for &uid in &all_ids {
        state.permissions.add_dm_channel(uid, channel_id);
    }

    let channel_topics = vec![topics::channel_notify_topic(channel_id)];
    for &uid in &all_ids {
        topics::subscribe_user(&state, uid, &channel_topics).await;
    }

    let dm = build_dm_response(&state, channel_id).await?;

    let json_text = events::dm_channel_create_json(&dm);
    let proto_participants: Vec<crate::proto::DmParticipant> = dm
        .get("participants")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(crate::proto::DmParticipant {
                        id: p.get("id")?.as_str()?.to_string(),
                        username: p.get("username")?.as_str()?.to_string(),
                        avatar_url: p
                            .get("avatarUrl")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        status: p
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("offline")
                            .to_string(),
                        display_name: p
                            .get("displayName")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        name_color: p
                            .get("nameColor")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let proto_msg = events::dm_channel_create_proto(crate::proto::DmChannel {
        id: channel_id.to_string(),
        r#type: channel_type as i32,
        name: dm_name.map(String::from),
        participants: proto_participants,
        last_message_id: None,
        last_message_at: None,
        created_at: dm
            .get("createdAt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    });
    for &uid in &all_ids {
        let topic = topics::user_topic(uid);
        topics::publish(&state, &topic, &json_text, &proto_msg).await;
    }
    if is_group {
        enqueue_federation_dm_event(
            &state,
            channel_id,
            crate::federation::producer::FederationLocalEvent::DmGroupCreate {
                dm_id: channel_id,
                actor_user_id: user_id.0,
                local_user_ids: all_ids
                    .iter()
                    .copied()
                    .filter(|id| *id != user_id.0)
                    .collect(),
                name: dm_name.map(String::from),
            },
            now_ms,
        )
        .await;
    } else {
        enqueue_federation_dm_event(
            &state,
            channel_id,
            crate::federation::producer::FederationLocalEvent::DmCreate {
                dm_id: channel_id,
                actor_user_id: user_id.0,
                local_user_id: all_ids[1],
            },
            now_ms,
        )
        .await;
    }
    tracing::info!("DM channel created id={} by={}", channel_id, user_id.0);
    tracing::warn!(
        target: "runtime_test",
        route = "dms.create",
        outcome = "created",
        channel_id,
        participant_count = all_ids.len(),
        "runtime_test.dm.create.response"
    );
    Ok((StatusCode::CREATED, Json(dm)).into_response())
}

// ─── GET /api/dms ───────────────────────────────────────────────────

pub async fn list_dms(
    State(state): State<AppState>,
    user_id: UserId,
    Query(query): Query<ListDmsQuery>,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/dms user_id={}", user_id.0);
    let include_preferences = query.include_preferences.unwrap_or(false);

    let channel_ids = crate::services::pg::dms::list_channel_ids_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "list_dms: PG channel ids read failed");
            AppError::Internal
        })?;
    if channel_ids.is_empty() {
        if include_preferences {
            let hidden_dm_ids = load_hidden_dm_ids_for_user(&state, user_id.0).await?;
            return Ok(Json(build_dm_list_response(Vec::new(), hidden_dm_ids)));
        }
        return Ok(Json(json!([])));
    }

    let channels = crate::services::pg::dms::channels_by_ids(&state.pg, &channel_ids)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list_dms: PG channels batch read failed");
            AppError::Internal
        })?;
    let last_messages =
        crate::services::pg::messages::latest_by_channel_ids(&state.pg, &channel_ids)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "list_dms: PG last message batch read failed");
                AppError::Internal
            })?;

    // Fan out per-channel member loads. The DM count per user is
    // bounded (~25 typical, ~hundred outlier) so n+1 is fine here.
    let mut bundles: Vec<(
        crate::services::pg::dms::DmChannelRow,
        Vec<crate::services::pg::dms::DmMemberRow>,
    )> = Vec::with_capacity(channels.len());
    for ch in channels {
        let members = crate::services::pg::dms::list_members(&state.pg, ch.id)
            .await
            .unwrap_or_default();
        bundles.push((ch, members));
    }

    // Collect distinct participant ids for batched user + presence read.
    let mut all_uids: Vec<i64> = bundles
        .iter()
        .flat_map(|(_, m)| m.iter().map(|x| x.user_id))
        .collect();
    all_uids.sort();
    all_uids.dedup();

    let users = crate::services::pg::users::by_ids(&state.pg, &all_uids)
        .await
        .unwrap_or_default();
    let user_lookup: HashMap<i64, _> = users.into_iter().map(|u| (u.id, u)).collect();
    let presence_map: HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &all_uids)
            .await
            .into_iter()
            .collect();

    let mut results: Vec<Value> = bundles
        .iter()
        .map(|(ch, members)| {
            build_dm_value(
                ch,
                members,
                &user_lookup,
                &presence_map,
                last_messages.get(&ch.id),
            )
        })
        .collect();

    // Newest channel first — deterministic until last-message lands.
    results.sort_by(|a, b| {
        let a_ts = a
            .get("_sort_last_activity_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let b_ts = b
            .get("_sort_last_activity_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        b_ts.cmp(&a_ts)
    });
    for r in results.iter_mut() {
        if let Some(obj) = r.as_object_mut() {
            obj.remove("_sort_last_activity_ms");
        }
    }

    tracing::info!(
        user_id = user_id.0,
        count = results.len(),
        "GET /api/dms: served from PG"
    );
    tracing::warn!(
        target: "runtime_test",
        route = "dms.list",
        user_id = user_id.0,
        result_count = results.len(),
        "runtime_test.dm.list.response"
    );
    if include_preferences {
        let hidden_dm_ids = load_hidden_dm_ids_for_user(&state, user_id.0).await?;
        Ok(Json(build_dm_list_response(results, hidden_dm_ids)))
    } else {
        Ok(Json(json!(results)))
    }
}

async fn load_hidden_dm_ids_for_user(state: &AppState, user_id: i64) -> AppResult<Vec<String>> {
    let Some(user) = crate::services::pg::users::by_id(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "list_dms: PG user preference read failed");
            AppError::Internal
        })?
    else {
        return Err(AppError::NotFound("user"));
    };
    let owned_channel_ids = crate::services::pg::dms::list_channel_ids_for_user(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                user_id,
                error = %e,
                "list_dms: PG user DM membership read failed"
            );
            AppError::Internal
        })?
        .into_iter()
        .map(|id| id.to_string())
        .collect::<HashSet<_>>();
    Ok(hidden_dm_ids_from_preferences(&user.preferences)
        .into_iter()
        .filter(|id| owned_channel_ids.contains(id))
        .collect())
}

fn build_dm_list_response(channels: Vec<Value>, hidden_dm_ids: Vec<String>) -> Value {
    json!({
        "dmChannels": channels,
        "hiddenDmIds": hidden_dm_ids,
    })
}

fn hidden_dm_ids_from_preferences(preferences: &Value) -> Vec<String> {
    let Some(items) = preferences
        .get("hiddenDmIds")
        .and_then(|value| value.as_array())
    else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .filter(|id| is_safe_hidden_dm_preference_id(id))
        .map(str::to_string)
        .collect()
}

fn is_safe_hidden_dm_preference_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 160
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
        && !trimmed.chars().any(char::is_whitespace)
        && !trimmed.chars().any(char::is_control)
        && !trimmed.contains("%2f")
        && !trimmed.contains("%2F")
        && !trimmed.contains("%5c")
        && !trimmed.contains("%5C")
}

fn build_dm_value(
    ch: &crate::services::pg::dms::DmChannelRow,
    members: &[crate::services::pg::dms::DmMemberRow],
    user_lookup: &HashMap<i64, crate::repo::users::UserRow>,
    presence_map: &HashMap<i64, String>,
    last_message: Option<&crate::services::pg::messages::ChannelLastMessageRow>,
) -> Value {
    let participant_ids: Vec<String> = members.iter().map(|m| m.user_id.to_string()).collect();
    let participants: Vec<Value> = members
        .iter()
        .map(|m| {
            let user = user_lookup.get(&m.user_id);
            let username = user.map(|u| u.username.clone()).unwrap_or_default();
            let avatar_url = user.and_then(|u| u.avatar_url.clone());
            let display_name = user.and_then(|u| u.display_name.clone());
            let status = presence_map
                .get(&m.user_id)
                .map(|s| s.as_str())
                .unwrap_or("offline");
            let name_color = m.name_color.clone().filter(|s| !s.is_empty());
            json!({
                "id": m.user_id.to_string(),
                "username": username,
                "avatarUrl": cdn::resolve(avatar_url.as_deref()),
                "displayName": display_name,
                "status": status,
                "nameColor": name_color,
            })
        })
        .collect();
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ch.created_at_ms)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    let last_message_at = last_message
        .and_then(|m| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(m.created_at_ms))
        .map(|t| t.to_rfc3339());
    json!({
        "id": ch.id.to_string(),
        "type": ch.r#type as i32,
        "name": ch.name.clone().filter(|n| !n.is_empty()),
        "participantIds": participant_ids,
        "participants": participants,
        "lastMessageId": last_message.map(|m| m.id.to_string()),
        "lastMessageAt": last_message_at,
        "createdAt": created_at,
        "_sort_last_activity_ms": last_message.map(|m| m.created_at_ms).unwrap_or(ch.created_at_ms),
    })
}

/// Build a single DM channel response with participants. PG-native
/// for the post-create path.
async fn build_dm_response(state: &AppState, channel_id: i64) -> AppResult<Value> {
    let channel = crate::services::pg::dms::channel_by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "build_dm_response: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;

    let members = crate::services::pg::dms::list_members(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "build_dm_response: PG members read failed");
            AppError::Internal
        })?;

    let member_ids: Vec<i64> = members.iter().map(|m| m.user_id).collect();
    let users = crate::services::pg::users::by_ids(&state.pg, &member_ids)
        .await
        .unwrap_or_default();
    let user_lookup: HashMap<i64, _> = users.into_iter().map(|u| (u.id, u)).collect();
    let presence_map: HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &member_ids)
            .await
            .into_iter()
            .collect();
    let last_messages = crate::services::pg::messages::latest_by_channel_ids(
        &state.pg,
        &[channel_id],
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, error = %e, "build_dm_response: PG last message read failed");
        AppError::Internal
    })?;

    let mut value = build_dm_value(
        &channel,
        &members,
        &user_lookup,
        &presence_map,
        last_messages.get(&channel_id),
    );
    if let Some(obj) = value.as_object_mut() {
        obj.remove("_sort_last_activity_ms");
    }
    Ok(value)
}

// ─── PUT /api/dms/:channelId/name-color ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNameColorRequest {
    pub name_color: Option<String>,
}

fn is_valid_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

pub async fn update_name_color(
    State(state): State<AppState>,
    user_id: UserId,
    Path(channel_id_str): Path<String>,
    Json(body): Json<UpdateNameColorRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PUT /api/dms/{}/name-color user_id={}",
        channel_id_str,
        user_id.0
    );
    tracing::warn!(
        target: "runtime_test",
        route = "dms.name_color",
        user_id = user_id.0,
        channel_id = %channel_id_str,
        has_color = body.name_color.is_some(),
        "runtime_test.dm.name_color.request"
    );
    rate_limit::enforce(&state, &rate_limit::DM_LIMIT, &user_id.0.to_string()).await?;
    let channel_id: i64 = channel_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid channel ID".into()))?;

    if let Some(ref color) = body.name_color {
        if !is_valid_hex_color(color) {
            return Err(AppError::Validation(
                "Invalid color format — must be #RRGGBB".into(),
            ));
        }
    }

    let members = crate::services::pg::dms::list_members(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "update_name_color: PG members read failed");
            AppError::Internal
        })?;
    let is_member = members.iter().any(|m| m.user_id == user_id.0);
    if !is_member {
        return Err(AppError::NotFound("channel"));
    }

    crate::services::pg::dms::set_name_color(
        &state.pg,
        channel_id,
        user_id.0,
        body.name_color.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, user_id = user_id.0, error = %e, "update_name_color: PG write failed");
        AppError::Internal
    })?;

    let participant_ids: Vec<i64> = members.iter().map(|m| m.user_id).collect();

    let event_data = json!({
        "channelId": channel_id_str,
        "userId": user_id.0.to_string(),
        "nameColor": body.name_color,
    });
    let json_text = events::dm_name_color_update_json(&event_data);
    let proto_msg = events::dm_name_color_update_proto(
        channel_id_str.clone(),
        user_id.0.to_string(),
        body.name_color.clone(),
    );
    for pid in &participant_ids {
        let topic = topics::user_topic(*pid);
        topics::publish(&state, &topic, &json_text, &proto_msg).await;
    }

    tracing::info!(
        "DM name color updated channel={} user={} color={:?}",
        channel_id,
        user_id.0,
        body.name_color
    );
    tracing::warn!(
        target: "runtime_test",
        route = "dms.name_color",
        user_id = user_id.0,
        channel_id,
        has_color = body.name_color.is_some(),
        "runtime_test.dm.name_color.response"
    );
    Ok(Json(json!({ "nameColor": body.name_color })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("dms.rs");

    #[test]
    fn direct_dm_dedupe_errors_fail_closed() {
        let create_dm = SOURCE
            .split("pub async fn create_dm")
            .nth(1)
            .expect("create_dm should exist")
            .split("let channel_id = state.snowflake.next_id()")
            .next()
            .expect("create_dm dedupe section should be present");

        assert!(create_dm.contains("find_direct_between"));
        assert!(create_dm.contains("create_dm: PG direct DM dedupe read failed"));
        assert!(create_dm.contains("AppError::Internal"));
        assert!(!create_dm.contains("unwrap_or(None)"));
    }

    #[test]
    fn dm_value_includes_latest_message_metadata_for_sorting() {
        let channel = crate::services::pg::dms::DmChannelRow {
            id: 10,
            r#type: DM_DIRECT,
            name: None,
            owner_id: None,
            created_at_ms: 1_700_000_000_000,
        };
        let latest = crate::services::pg::messages::ChannelLastMessageRow {
            channel_id: 10,
            id: 99,
            created_at_ms: 1_700_000_010_000,
        };

        let value = build_dm_value(
            &channel,
            &[],
            &HashMap::new(),
            &HashMap::new(),
            Some(&latest),
        );

        assert_eq!(
            value.get("lastMessageId").and_then(|v| v.as_str()),
            Some("99")
        );
        assert_eq!(
            value.get("lastMessageAt").and_then(|v| v.as_str()),
            Some("2023-11-14T22:13:30+00:00")
        );
        assert_eq!(
            value.get("_sort_last_activity_ms").and_then(|v| v.as_i64()),
            Some(1_700_000_010_000)
        );
    }

    #[test]
    fn dm_value_falls_back_to_created_at_when_empty() {
        let channel = crate::services::pg::dms::DmChannelRow {
            id: 10,
            r#type: DM_DIRECT,
            name: None,
            owner_id: None,
            created_at_ms: 1_700_000_000_000,
        };

        let value = build_dm_value(&channel, &[], &HashMap::new(), &HashMap::new(), None);

        assert!(value.get("lastMessageId").is_some_and(Value::is_null));
        assert!(value.get("lastMessageAt").is_some_and(Value::is_null));
        assert_eq!(
            value.get("_sort_last_activity_ms").and_then(|v| v.as_i64()),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn dm_list_bootstrap_response_includes_hidden_dm_ids() {
        let response = build_dm_list_response(
            vec![json!({ "id": "10", "participants": [] })],
            vec!["10".to_string(), "11".to_string()],
        );

        assert_eq!(
            response
                .pointer("/dmChannels/0/id")
                .and_then(|v| v.as_str()),
            Some("10")
        );
        assert_eq!(
            response.pointer("/hiddenDmIds/0").and_then(|v| v.as_str()),
            Some("10")
        );
        assert!(response.get("preferences").is_none());
    }
}
