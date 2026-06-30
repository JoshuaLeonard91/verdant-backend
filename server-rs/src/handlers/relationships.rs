use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::banner_crop::{self, BannerCrop};
use crate::services::cdn;
use crate::services::pg::relationships::{
    REL_BLOCKED, REL_FRIEND, REL_REQUEST_RECEIVED, REL_REQUEST_SENT, RelationshipRow,
};
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

// Wire-format aliases. Match the legacy i32 sentinels so existing
// clients keep working — see pg::relationships docs for the mapping.
const RELATIONSHIP_FRIEND: i32 = REL_FRIEND as i32;
const RELATIONSHIP_BLOCKED: i32 = REL_BLOCKED as i32;
const RELATIONSHIP_PENDING_OUTGOING: i32 = REL_REQUEST_SENT as i32;
const RELATIONSHIP_PENDING_INCOMING: i32 = REL_REQUEST_RECEIVED as i32;

#[derive(Debug)]
struct UserInfo {
    id: i64,
    username: String,
    avatar_url: Option<String>,
    banner_url: Option<String>,
    banner_base_color: Option<String>,
    banner_crop: Option<BannerCrop>,
}

async fn get_user_info(state: &AppState, id: i64) -> AppResult<UserInfo> {
    let full = crate::services::pg::users::by_id(&state.pg, id)
        .await
        .map_err(|e| {
            tracing::error!(user_id = id, error = %e, "get_user_info: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;
    Ok(UserInfo {
        id: full.id,
        username: full.username,
        avatar_url: full.avatar_url,
        banner_url: full.banner_url,
        banner_base_color: full.banner_base_color,
        banner_crop: full.banner_crop,
    })
}

fn build_relationship(
    user: &UserInfo,
    status: &str,
    rel_type: i32,
    created_at: &str,
    notes: &str,
    nickname_color: &Option<String>,
) -> Value {
    json!({
        "userId": user.id.to_string(),
        "type": rel_type,
        "user": {
            "id": user.id.to_string(),
            "username": user.username,
            "avatarUrl": cdn::resolve(user.avatar_url.as_deref()),
            "bannerUrl": cdn::resolve(user.banner_url.as_deref()),
            "bannerBaseColor": user.banner_base_color.as_deref().filter(|s| !s.trim().is_empty()),
            "bannerCrop": banner_crop::to_json(user.banner_crop),
            "status": status,
        },
        "createdAt": created_at,
        "notes": notes,
        "nicknameColor": nickname_color,
    })
}

fn build_relationship_proto(
    user: &UserInfo,
    status: &str,
    rel_type: i32,
    created_at: &str,
) -> crate::proto::Relationship {
    crate::proto::Relationship {
        user_id: user.id.to_string(),
        r#type: rel_type,
        user: Some(crate::proto::RelationshipUser {
            id: user.id.to_string(),
            username: user.username.clone(),
            avatar_url: cdn::resolve(user.avatar_url.as_deref()),
            status: status.to_string(),
        }),
        created_at: created_at.to_string(),
        notes: None,
        nickname_color: None,
    }
}

async fn enqueue_federation_relationship_event(
    state: &AppState,
    target_user_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    log_label: &'static str,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Principal {
            user_id: target_user_id,
        },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            target_user_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "{log_label}"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(target_user_id, error = %error, "{log_label} failed"),
    }
}

// ─── GET /api/relationships ─────────────────────────────────────────

pub async fn list_relationships(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/relationships user_id={}", user_id.0);

    let entries = crate::services::pg::relationships::list_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list_relationships: PG read failed");
            AppError::Internal
        })?;

    // Batch-fetch user summaries + presence for every target.
    let target_ids: Vec<i64> = entries.iter().map(|r| r.target_id).collect();
    let users = crate::services::pg::users::by_ids(&state.pg, &target_ids)
        .await
        .unwrap_or_default();
    let user_lookup: std::collections::HashMap<i64, _> =
        users.into_iter().map(|u| (u.id, u)).collect();
    let presence_map: std::collections::HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &target_ids)
            .await
            .into_iter()
            .collect();

    let result: Vec<Value> = entries
        .iter()
        .map(|r| {
            let target = user_lookup.get(&r.target_id);
            let username = target.map(|u| u.username.clone()).unwrap_or_default();
            let avatar_url = target.and_then(|u| u.avatar_url.clone());
            // Force status=offline for blocked users so the blocker
            // cannot see their blockee's real-time presence.
            let status = if r.rel_type as i32 == RELATIONSHIP_BLOCKED {
                "offline".to_string()
            } else {
                presence_map
                    .get(&r.target_id)
                    .cloned()
                    .unwrap_or_else(|| "offline".to_string())
            };
            let nickname_color = r.nickname_color.clone().filter(|s| !s.is_empty());
            let created_at =
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.created_at_ms)
                    .unwrap_or_else(chrono::Utc::now)
                    .to_rfc3339();
            json!({
                "userId": r.target_id.to_string(),
                "type": r.rel_type as i32,
                "user": {
                    "id": r.target_id.to_string(),
                    "username": username,
                    "avatarUrl": cdn::resolve(avatar_url.as_deref()),
                    "status": status,
                },
                "createdAt": created_at,
                "notes": r.notes.clone().unwrap_or_default(),
                "nicknameColor": nickname_color,
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

// ─── POST /api/relationships — send friend request ──────────────────

#[derive(Deserialize)]
#[serde(untagged)]
pub enum SendFriendRequest {
    ById {
        #[serde(rename = "targetId")]
        target_id: String,
    },
    ByName {
        username: String,
    },
}

pub async fn send_friend_request(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<SendFriendRequest>,
) -> AppResult<Response> {
    tracing::info!("POST /api/relationships user_id={}", user_id.0);
    rate_limit::enforce(
        &state,
        &rate_limit::RELATIONSHIP_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;

    // Resolve target user. By-id hits PG. By-username walks
    // pg::users::by_username_lower for the case-insensitive lookup.
    let target = match body {
        SendFriendRequest::ById { ref target_id } => {
            let id = parse_id(target_id)?;
            match get_user_info(&state, id).await {
                Ok(info) => Some(info),
                Err(AppError::NotFound(_)) => None,
                Err(e) => return Err(e),
            }
        }
        SendFriendRequest::ByName { ref username } => {
            match crate::services::pg::users::by_username_lower(&state.pg, username)
                .await
                .ok()
                .flatten()
            {
                Some(u) => Some(UserInfo {
                    id: u.id,
                    username: u.username,
                    avatar_url: u.avatar_url,
                    banner_url: u.banner_url,
                    banner_base_color: u.banner_base_color,
                    banner_crop: u.banner_crop,
                }),
                None => None,
            }
        }
    };

    let target = target.ok_or_else(|| {
        AppError::Validation(
            "Unable to send friend request. Please check the username and try again.".into(),
        )
    })?;

    if target.id == user_id.0 {
        return Err(AppError::Validation(
            "You can't add yourself as a friend — try searching for someone else!".into(),
        ));
    }

    let my_rel = crate::services::pg::relationships::get(&state.pg, user_id.0, target.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "send_friend_request: PG actor rel lookup failed");
            AppError::Internal
        })?;
    let their_rel = crate::services::pg::relationships::get(&state.pg, target.id, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "send_friend_request: PG target rel lookup failed");
            AppError::Internal
        })?;

    let my_rel_type = my_rel.as_ref().map(|r| r.rel_type as i32);
    let their_rel_type = their_rel.as_ref().map(|r| r.rel_type as i32);

    match my_rel_type {
        Some(RELATIONSHIP_FRIEND) => {
            return Err(AppError::Validation(
                "You are already friends with this user".into(),
            ));
        }
        Some(RELATIONSHIP_BLOCKED) => {
            return Err(AppError::Validation(
                "Unable to send friend request. Please check the username and try again.".into(),
            ));
        }
        Some(RELATIONSHIP_PENDING_OUTGOING) => {
            return Err(AppError::Validation(
                "You already have a pending friend request to this user".into(),
            ));
        }
        _ => {}
    }

    if their_rel_type == Some(RELATIONSHIP_BLOCKED) {
        return Err(AppError::Validation(
            "Unable to send friend request. Please check the username and try again.".into(),
        ));
    }

    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    // They already sent me a request — auto-accept
    if my_rel_type == Some(RELATIONSHIP_PENDING_INCOMING)
        && their_rel_type == Some(RELATIONSHIP_PENDING_OUTGOING)
    {
        crate::services::pg::relationships::upsert(
            &state.pg, user_id.0, target.id, REL_FRIEND, now_ms,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "send_friend_request: auto-accept upsert A failed");
            AppError::Internal
        })?;
        crate::services::pg::relationships::upsert(
            &state.pg, target.id, user_id.0, REL_FRIEND, now_ms,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "send_friend_request: auto-accept upsert B failed");
            AppError::Internal
        })?;

        let my_info = get_user_info(&state, user_id.0).await?;
        let target_status =
            crate::services::presence::effective_status(&state.redis, target.id).await;
        let my_status = crate::services::presence::effective_status(&state.redis, user_id.0).await;
        let my_rel = build_relationship(
            &target,
            &target_status,
            RELATIONSHIP_FRIEND,
            &now.to_rfc3339(),
            "",
            &None,
        );
        let their_rel = build_relationship(
            &my_info,
            &my_status,
            RELATIONSHIP_FRIEND,
            &now.to_rfc3339(),
            "",
            &None,
        );

        let my_proto = events::relationship_add_proto(build_relationship_proto(
            &target,
            &target_status,
            RELATIONSHIP_FRIEND,
            &now.to_rfc3339(),
        ));
        let their_proto = events::relationship_add_proto(build_relationship_proto(
            &my_info,
            &my_status,
            RELATIONSHIP_FRIEND,
            &now.to_rfc3339(),
        ));
        let my_topic = topics::user_topic(user_id.0);
        topics::publish(
            &state,
            &my_topic,
            &events::relationship_add_json(&my_rel),
            &my_proto,
        )
        .await;
        let their_topic = topics::user_topic(target.id);
        topics::publish(
            &state,
            &their_topic,
            &events::relationship_add_json(&their_rel),
            &their_proto,
        )
        .await;
        enqueue_federation_relationship_event(
            &state,
            target.id,
            crate::federation::producer::FederationLocalEvent::RelationshipAccept {
                user_id: user_id.0,
                local_user_id: target.id,
            },
            "Federation relationship accept producer completed",
        )
        .await;

        tracing::info!(
            "Friend request auto-accepted user={} target={}",
            user_id.0,
            target.id
        );
        return Ok(Json(my_rel).into_response());
    }

    crate::services::pg::relationships::upsert(
        &state.pg,
        user_id.0,
        target.id,
        REL_REQUEST_SENT,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "send_friend_request: pending upsert A failed");
        AppError::Internal
    })?;
    crate::services::pg::relationships::upsert(
        &state.pg,
        target.id,
        user_id.0,
        REL_REQUEST_RECEIVED,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "send_friend_request: pending upsert B failed");
        AppError::Internal
    })?;

    let my_info = get_user_info(&state, user_id.0).await?;
    let target_status = crate::services::presence::effective_status(&state.redis, target.id).await;
    let my_status = crate::services::presence::effective_status(&state.redis, user_id.0).await;
    let my_rel = build_relationship(
        &target,
        &target_status,
        RELATIONSHIP_PENDING_OUTGOING,
        &now.to_rfc3339(),
        "",
        &None,
    );
    let their_rel = build_relationship(
        &my_info,
        &my_status,
        RELATIONSHIP_PENDING_INCOMING,
        &now.to_rfc3339(),
        "",
        &None,
    );

    let my_proto = events::relationship_add_proto(build_relationship_proto(
        &target,
        &target_status,
        RELATIONSHIP_PENDING_OUTGOING,
        &now.to_rfc3339(),
    ));
    let their_proto = events::relationship_add_proto(build_relationship_proto(
        &my_info,
        &my_status,
        RELATIONSHIP_PENDING_INCOMING,
        &now.to_rfc3339(),
    ));
    let my_topic = topics::user_topic(user_id.0);
    topics::publish(
        &state,
        &my_topic,
        &events::relationship_add_json(&my_rel),
        &my_proto,
    )
    .await;
    let their_topic = topics::user_topic(target.id);
    topics::publish(
        &state,
        &their_topic,
        &events::relationship_add_json(&their_rel),
        &their_proto,
    )
    .await;
    enqueue_federation_relationship_event(
        &state,
        target.id,
        crate::federation::producer::FederationLocalEvent::RelationshipRequest {
            user_id: user_id.0,
            local_user_id: target.id,
        },
        "Federation relationship request producer completed",
    )
    .await;

    tracing::info!(
        "Friend request sent user={} target={}",
        user_id.0,
        target.id
    );
    Ok((StatusCode::CREATED, Json(my_rel)).into_response())
}

// ─── PATCH /api/relationships/:userId — accept friend request ───────

#[derive(Deserialize)]
pub struct AcceptFriendRequest {}

pub async fn accept_friend_request(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
    Json(_body): Json<AcceptFriendRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/relationships/{} user_id={}",
        target_id_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::RELATIONSHIP_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let target_id = parse_id(&target_id_str)?;

    let rel = crate::services::pg::relationships::get(&state.pg, user_id.0, target_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, target_id, error = %e, "accept_friend_request: PG rel lookup failed");
            AppError::Internal
        })?;
    if rel.map(|r| r.rel_type) != Some(REL_REQUEST_RECEIVED) {
        return Err(AppError::NotFound("relationship"));
    }

    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    crate::services::pg::relationships::upsert(&state.pg, user_id.0, target_id, REL_FRIEND, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, target_id, error = %e, "accept_friend_request: PG upsert A failed");
            AppError::Internal
        })?;
    crate::services::pg::relationships::upsert(&state.pg, target_id, user_id.0, REL_FRIEND, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(user_id = target_id, target_id = user_id.0, error = %e, "accept_friend_request: PG upsert B failed");
            AppError::Internal
        })?;

    let target = get_user_info(&state, target_id).await?;
    let my_info = get_user_info(&state, user_id.0).await?;
    let target_status = crate::services::presence::effective_status(&state.redis, target_id).await;
    let my_status = crate::services::presence::effective_status(&state.redis, user_id.0).await;
    let my_rel = build_relationship(
        &target,
        &target_status,
        RELATIONSHIP_FRIEND,
        &now.to_rfc3339(),
        "",
        &None,
    );
    let their_rel = build_relationship(
        &my_info,
        &my_status,
        RELATIONSHIP_FRIEND,
        &now.to_rfc3339(),
        "",
        &None,
    );

    let my_proto = events::relationship_add_proto(build_relationship_proto(
        &target,
        &target_status,
        RELATIONSHIP_FRIEND,
        &now.to_rfc3339(),
    ));
    let their_proto = events::relationship_add_proto(build_relationship_proto(
        &my_info,
        &my_status,
        RELATIONSHIP_FRIEND,
        &now.to_rfc3339(),
    ));
    topics::publish(
        &state,
        &topics::user_topic(user_id.0),
        &events::relationship_add_json(&my_rel),
        &my_proto,
    )
    .await;
    topics::publish(
        &state,
        &topics::user_topic(target_id),
        &events::relationship_add_json(&their_rel),
        &their_proto,
    )
    .await;
    enqueue_federation_relationship_event(
        &state,
        target_id,
        crate::federation::producer::FederationLocalEvent::RelationshipAccept {
            user_id: user_id.0,
            local_user_id: target_id,
        },
        "Federation relationship accept producer completed",
    )
    .await;

    tracing::info!(
        "Friend request accepted user={} target={}",
        user_id.0,
        target_id
    );
    Ok(Json(my_rel))
}

// ─── DELETE /api/relationships/:userId — remove/cancel/decline ──────

pub async fn delete_relationship(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/relationships/{} user_id={}",
        target_id_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::RELATIONSHIP_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let target_id = parse_id(&target_id_str)?;

    let rel = crate::services::pg::relationships::get(&state.pg, user_id.0, target_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, target_id, error = %e, "delete_relationship: PG rel lookup failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("relationship"))?;
    let rel_type = rel.rel_type;

    crate::services::pg::relationships::delete(&state.pg, user_id.0, target_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, target_id, error = %e, "delete_relationship: PG remove A failed");
            AppError::Internal
        })?;
    if rel_type != REL_BLOCKED {
        crate::services::pg::relationships::delete(&state.pg, target_id, user_id.0)
            .await
            .map_err(|e| {
                tracing::error!(user_id = target_id, target_id = user_id.0, error = %e, "delete_relationship: PG remove B failed");
                AppError::Internal
            })?;
    }

    let my_proto = events::relationship_remove_proto(target_id_str.clone());
    topics::publish(
        &state,
        &topics::user_topic(user_id.0),
        &events::relationship_remove_json(&target_id_str),
        &my_proto,
    )
    .await;
    if rel_type != REL_BLOCKED {
        let uid_str = user_id.0.to_string();
        let their_proto = events::relationship_remove_proto(uid_str.clone());
        topics::publish(
            &state,
            &topics::user_topic(target_id),
            &events::relationship_remove_json(&uid_str),
            &their_proto,
        )
        .await;
    }
    enqueue_federation_relationship_event(
        &state,
        target_id,
        crate::federation::producer::FederationLocalEvent::RelationshipRemove {
            user_id: user_id.0,
            local_user_id: target_id,
        },
        "Federation relationship remove producer completed",
    )
    .await;

    tracing::info!(
        "Relationship deleted user={} target={} type={}",
        user_id.0,
        target_id,
        rel_type as i32
    );
    Ok(Json(json!({ "success": true })))
}

// ─── PUT /api/relationships/:userId/block ───────────────────────────

pub async fn block_user(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PUT /api/relationships/{}/block user_id={}",
        target_id_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::RELATIONSHIP_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let target_id = parse_id(&target_id_str)?;

    if target_id == user_id.0 {
        return Err(AppError::Validation("You cannot block yourself".into()));
    }

    // Verify target exists.
    let exists = crate::services::pg::users::by_id(&state.pg, target_id)
        .await
        .map_err(|e| {
            tracing::error!(target_id, error = %e, "block_user: PG target lookup failed");
            AppError::Internal
        })?
        .is_some();
    if !exists {
        return Err(AppError::Validation("Unable to block this user".into()));
    }

    // Drop the reverse edge first so any stale friend/pending row
    // can't outlive the block, then upsert the actor's block entry.
    crate::services::pg::relationships::delete(&state.pg, target_id, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = target_id, target_id = user_id.0, error = %e, "block_user: PG reverse remove failed");
            AppError::Internal
        })?;
    let block_now = chrono::Utc::now();
    crate::services::pg::relationships::upsert(
        &state.pg,
        user_id.0,
        target_id,
        REL_BLOCKED,
        block_now.timestamp_millis(),
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, target_id, error = %e, "block_user: PG block upsert failed");
        AppError::Internal
    })?;

    let uid_str = user_id.0.to_string();
    let remove_proto = events::relationship_remove_proto(uid_str.clone());
    topics::publish(
        &state,
        &topics::user_topic(target_id),
        &events::relationship_remove_json(&uid_str),
        &remove_proto,
    )
    .await;

    let target_info = get_user_info(&state, target_id).await?;
    let now_str = chrono::Utc::now().to_rfc3339();
    let block_rel = build_relationship(
        &target_info,
        "offline",
        RELATIONSHIP_BLOCKED,
        &now_str,
        "",
        &None,
    );
    let block_proto = events::relationship_add_proto(build_relationship_proto(
        &target_info,
        "offline",
        RELATIONSHIP_BLOCKED,
        &now_str,
    ));
    topics::publish(
        &state,
        &topics::user_topic(user_id.0),
        &events::relationship_add_json(&block_rel),
        &block_proto,
    )
    .await;
    enqueue_federation_relationship_event(
        &state,
        target_id,
        crate::federation::producer::FederationLocalEvent::RelationshipBlock {
            user_id: user_id.0,
            local_user_id: target_id,
        },
        "Federation relationship block producer completed",
    )
    .await;

    tracing::info!("User blocked user={} target={}", user_id.0, target_id);
    Ok(Json(json!({ "success": true })))
}

// ─── PUT /api/relationships/:userId/metadata ────────────────────────

#[derive(Deserialize)]
pub struct UpdateMetadataBody {
    notes: Option<String>,
    #[serde(rename = "nicknameColor")]
    nickname_color: Option<Option<String>>,
}

fn is_valid_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

pub async fn update_metadata(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
    Json(body): Json<UpdateMetadataBody>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PUT /api/relationships/{}/metadata user_id={}",
        target_id_str,
        user_id.0
    );
    rate_limit::enforce(
        &state,
        &rate_limit::RELATIONSHIP_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let target_id = parse_id(&target_id_str)?;

    if let Some(ref notes) = body.notes {
        if notes.len() > 256 {
            return Err(AppError::Validation(
                "Notes must be 256 characters or fewer".into(),
            ));
        }
    }
    if let Some(Some(ref color)) = body.nickname_color {
        if !is_valid_hex_color(color) {
            return Err(AppError::Validation(
                "Invalid color format — must be #RRGGBB".into(),
            ));
        }
    }

    // Pull the current row so we can short-circuit "no changes" with
    // its current metadata, then issue a single PG patch for any
    // field that was sent.
    let entry: RelationshipRow =
        crate::services::pg::relationships::get(&state.pg, user_id.0, target_id)
            .await
            .map_err(|e| {
                tracing::error!(user_id = user_id.0, error = %e, "update_metadata: PG read failed");
                AppError::Internal
            })?
            .ok_or(AppError::NotFound("relationship"))?;

    let nothing_to_update = body.notes.is_none() && body.nickname_color.is_none();
    if nothing_to_update {
        return Ok(Json(json!({
            "notes": entry.notes.clone().unwrap_or_default(),
            "nicknameColor": entry.nickname_color.clone().filter(|s| !s.is_empty()),
        })));
    }

    // For nickname_color, JSON null clears (writes empty string);
    // omitted leaves untouched. set_metadata uses COALESCE so passing
    // None => no change, Some => write through.
    let notes_arg: Option<&str> = body.notes.as_deref();
    let nickname_arg: Option<String> = body
        .nickname_color
        .as_ref()
        .map(|outer| outer.clone().unwrap_or_default());
    let nickname_arg_ref: Option<&str> = nickname_arg.as_deref();

    crate::services::pg::relationships::set_metadata(
        &state.pg,
        user_id.0,
        target_id,
        notes_arg,
        nickname_arg_ref,
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, target_id, error = %e, "update_metadata: PG write failed");
        AppError::Internal
    })?;

    let updated_notes = body
        .notes
        .clone()
        .unwrap_or_else(|| entry.notes.clone().unwrap_or_default());
    let updated_nickname_color: Option<String> = match body.nickname_color {
        Some(ref opt) => opt.clone().filter(|s| !s.is_empty()),
        None => entry.nickname_color.clone().filter(|s| !s.is_empty()),
    };

    tracing::info!(
        "Relationship metadata updated user={} target={}",
        user_id.0,
        target_id
    );
    Ok(Json(json!({
        "notes": updated_notes,
        "nicknameColor": updated_nickname_color,
    })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("relationships.rs");

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
    fn send_friend_request_enqueues_federation_relationship_request_or_accept() {
        let handler = handler_source("send_friend_request");

        assert!(handler.contains("FederationLocalEvent::RelationshipRequest"));
        assert!(handler.contains("FederationLocalEvent::RelationshipAccept"));
        assert!(handler.contains("enqueue_federation_relationship_event"));
    }

    #[test]
    fn accept_friend_request_enqueues_federation_relationship_accept() {
        let handler = handler_source("accept_friend_request");

        assert!(handler.contains("FederationLocalEvent::RelationshipAccept"));
        assert!(handler.contains("enqueue_federation_relationship_event"));
    }

    #[test]
    fn delete_relationship_enqueues_federation_relationship_remove() {
        let handler = handler_source("delete_relationship");

        assert!(handler.contains("FederationLocalEvent::RelationshipRemove"));
        assert!(handler.contains("enqueue_federation_relationship_event"));
    }

    #[test]
    fn block_user_enqueues_federation_relationship_block() {
        let handler = handler_source("block_user");

        assert!(handler.contains("FederationLocalEvent::RelationshipBlock"));
        assert!(handler.contains("enqueue_federation_relationship_event"));
    }

    #[test]
    fn relationship_federation_helper_uses_principal_scope() {
        let helper = private_async_source("enqueue_federation_relationship_event");

        assert!(helper.contains("FederationRouteScope::Principal"));
        assert!(helper.contains("enqueue_local_event_for_scope"));
    }
}
