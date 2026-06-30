use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::{
    OptionalBot, OptionalFederatedClient, UserId, require_federated_client_channel_scope,
};
use crate::services::banner_crop;
use crate::services::cdn;
use crate::services::channel_access::verify_channel_access;
use crate::services::message_cache;
use crate::services::message_media_policy::check_media_urls;
use crate::services::permissions::bits;
use crate::services::pg::bots::{SCOPE_MESSAGES_WRITE, has_scope};
use crate::services::pg::messages::{FLAG_DELETED, MessageRow};
use crate::services::sanitize::sanitize_message_content;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_MESSAGE_LENGTH: usize = 4000;
pub(crate) const MESSAGE_FETCH_LIMIT: i64 = 50;
const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;

#[derive(Deserialize)]
pub struct MessageQueryParams {
    pub before: Option<String>,
    pub after: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, Validate)]
pub struct CreateMessageRequest {
    #[validate(length(max = 4000))]
    pub content: String,
    #[serde(default, rename = "attachmentIds")]
    pub attachment_ids: Vec<String>,
    #[serde(default, rename = "replyToId")]
    pub reply_to_id: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct UpdateMessageRequest {
    #[validate(length(min = 1, max = 4000))]
    pub content: String,
}

#[derive(Deserialize, Validate)]
pub struct SearchQueryParams {
    #[validate(length(min = 1, max = 200))]
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub before: Option<String>,
    #[serde(rename = "authorId")]
    pub author_id: Option<String>,
}

fn bot_idempotency_key(headers: &HeaderMap, namespace: &str) -> AppResult<Option<String>> {
    let Some(raw) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let value = raw
        .to_str()
        .map_err(|_| AppError::Validation("Invalid Idempotency-Key".into()))?
        .trim();
    let valid_chars = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if value.is_empty() || value.len() > 128 || !valid_chars {
        return Err(AppError::Validation(
            "Idempotency-Key must be 1-128 ASCII letters, numbers, dots, dashes, underscores, or colons".into(),
        ));
    }
    Ok(Some(format!("{namespace}:{value}")))
}

fn message_to_json_with_author(
    m: &MessageRow,
    channel_id_str: &str,
    author_username: &str,
    author_avatar_url: Option<&str>,
    author_display_name: Option<&str>,
    reply_json: Value,
    msg_reactions: Vec<Value>,
    msg_attachments: Vec<Value>,
) -> Value {
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(m.created_at_ms)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    let edited_at: Option<String> = m
        .edited_at_ms
        .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
        .map(|t| t.to_rfc3339());
    let edited = m.edited_at_ms.is_some();
    let updated_at = edited_at.clone().unwrap_or_else(|| created_at.clone());
    let author_id_str = m.author_id.to_string();
    json!({
        "id": m.id.to_string(),
        "channelId": channel_id_str,
        "authorId": author_id_str,
        "author": {
            "id": author_id_str,
            "username": author_username,
            "displayName": author_display_name,
            "avatarUrl": cdn::resolve(author_avatar_url),
        },
        "content": m.content,
        "type": m.r#type as i32,
        "edited": edited,
        "editedAt": edited_at.map(Value::String).unwrap_or(Value::Null),
        "createdAt": created_at,
        "updatedAt": updated_at,
        "reactions": msg_reactions,
        "attachments": msg_attachments,
        "replyTo": reply_json,
    })
}

fn attachment_to_json(a: &crate::services::pg::attachments::AttachmentRow, api_url: &str) -> Value {
    json!({
        "id": a.id.to_string(),
        "messageId": a.message_id.map(|id| id.to_string()).unwrap_or_default(),
        "filename": a.filename,
        "url": crate::handlers::uploads::attachment_media_url(api_url, a.id),
        "contentType": a.content_type,
        "size": a.size_bytes,
    })
}

fn attachment_to_proto(
    a: &crate::services::pg::attachments::AttachmentRow,
    api_url: &str,
) -> crate::proto::Attachment {
    crate::proto::Attachment {
        id: a.id.to_string(),
        message_id: a.message_id.map(|id| id.to_string()).unwrap_or_default(),
        filename: a.filename.clone(),
        url: crate::handlers::uploads::attachment_media_url(api_url, a.id),
        content_type: a.content_type.clone(),
        size: a.size_bytes.min(i32::MAX as i64).max(0) as i32,
    }
}

fn parse_attachment_ids(raw_ids: &[String]) -> AppResult<Vec<i64>> {
    if raw_ids.len() > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(AppError::Validation(format!(
            "A message can include at most {MAX_ATTACHMENTS_PER_MESSAGE} attachments"
        )));
    }

    let mut seen = HashSet::with_capacity(raw_ids.len());
    let mut parsed = Vec::with_capacity(raw_ids.len());
    for raw in raw_ids {
        let id = parse_id(raw)?;
        if seen.insert(id) {
            parsed.push(id);
        }
    }
    Ok(parsed)
}

async fn require_file_sharing_for_message(state: &AppState, user_id: i64) -> AppResult<()> {
    if !state.feature_flags.resolve("file_sharing", user_id) {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEATURE_DISABLED",
            message: "File sharing is not enabled on this instance".into(),
        });
    }
    if !state.config.local_capabilities.message_attachments {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEATURE_DISABLED",
            message: "Message attachments are not enabled on this instance".into(),
        });
    }

    let entitlements =
        crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id).await;
    if !entitlements.file_sharing || !entitlements.message_attachments {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "ENTITLEMENT_REQUIRED",
            message: "Message attachments are not available for this account".into(),
        });
    }

    Ok(())
}

async fn record_channel_activity(state: &AppState, channel_id: i64, user_id: i64, ts_ms: i64) {
    use fred::interfaces::{HashesInterface, KeysInterface};
    let key = format!("channel:{channel_id}:activity");
    if let Err(e) = state
        .redis
        .hset::<(), _, _>(&key, (user_id.to_string(), ts_ms.to_string()))
        .await
    {
        tracing::warn!(channel_id, user_id, error = %e, "Failed to record channel activity");
        return;
    }
    let _: Result<bool, _> = state.redis.expire(&key, 86400, None).await;
}

async fn enqueue_federation_channel_event(
    state: &AppState,
    channel_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    now_ms: i64,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
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
            "Federation channel event producer completed"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            channel_id,
            error = %error,
            "Federation channel event producer failed"
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_message_create_scoped(
    state: &AppState,
    channel_id: i64,
    channel_id_str: &str,
    server_id: Option<i64>,
    message_id: &str,
    author_id: &str,
    created_at: &str,
    author_username: Option<&str>,
    author_display_name: Option<&str>,
    author_avatar_url: Option<&str>,
    message_json: &str,
    message_proto: &crate::proto::WsMessage,
    mention_source: &str,
) {
    let live_topic = topics::channel_live_topic(channel_id);
    let notify_topic = topics::channel_notify_topic(channel_id);
    let live_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&live_topic)
        .map(|set| set.len())
        .unwrap_or(0);
    let notify_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&notify_topic)
        .map(|set| set.len())
        .unwrap_or(0);
    crate::realtime_trace!(
        channel_id,
        server_id = ?server_id,
        message_id,
        author_id,
        live_topic = %live_topic,
        notify_topic = %notify_topic,
        live_local_subscribers,
        notify_local_subscribers,
        "realtime_scope: publishing MESSAGE_CREATE live, CHANNEL_UNREAD_SIGNAL notify, and CHANNEL_ACTIVITY_UPDATE live"
    );
    topics::publish(state, &live_topic, message_json, message_proto).await;

    let server_id_str = server_id.map(|sid| sid.to_string());
    let unread_json = events::channel_unread_signal_json(
        channel_id_str,
        server_id_str.as_deref(),
        message_id,
        author_id,
        created_at,
        false,
        server_id.is_none(),
    );
    let unread_proto = events::channel_unread_signal_proto(
        channel_id_str.to_string(),
        server_id_str,
        message_id.to_string(),
        author_id.to_string(),
        created_at.to_string(),
        false,
        server_id.is_none(),
    );
    topics::publish(state, &notify_topic, &unread_json, &unread_proto).await;

    if let Ok(author_id_i64) = author_id.parse::<i64>() {
        match crate::services::message_notifications::publish_targeted_unread_signals(
            state,
            channel_id,
            channel_id_str,
            server_id,
            message_id,
            author_id_i64,
            created_at,
            mention_source,
        )
        .await
        {
            Ok(stats) => crate::realtime_trace!(
                channel_id,
                server_id = ?server_id,
                message_id,
                targeted = stats.target_count,
                mentions = stats.mention_count,
                channel_prefs = stats.channel_pref_count,
                skipped_permissions = stats.skipped_permission_count,
                "realtime_scope: targeted unread fanout complete"
            ),
            Err(err) => tracing::warn!(
                channel_id,
                server_id = ?server_id,
                message_id,
                error = %err,
                "targeted unread fanout failed"
            ),
        }
    } else {
        crate::realtime_trace!(
            channel_id,
            server_id = ?server_id,
            message_id,
            author_id,
            "realtime_scope: skipped targeted unread fanout because author id was not numeric"
        );
    }

    let activity_json = events::channel_activity_update_json(
        channel_id_str,
        author_id,
        created_at,
        author_username,
        author_display_name,
        author_avatar_url,
    );
    let activity_proto = events::channel_activity_update_proto(
        channel_id_str.to_string(),
        author_id.to_string(),
        created_at.to_string(),
        author_username.map(str::to_string),
        author_display_name.map(str::to_string),
        author_avatar_url.map(str::to_string),
    );
    topics::publish(state, &live_topic, &activity_json, &activity_proto).await;
}

// ─── GET /api/channels/:channelId/messages ──────────────────────────

pub async fn get_messages(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
    Query(params): Query<MessageQueryParams>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/channels/{}/messages user_id={}",
        channel_id_str,
        user_id.0
    );
    let channel_id = parse_id(&channel_id_str)?;
    let server_id = verify_channel_access(&state, user_id.0, channel_id).await?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)?;

    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
    }

    let limit = params
        .limit
        .unwrap_or(MESSAGE_FETCH_LIMIT)
        .min(MESSAGE_FETCH_LIMIT)
        .max(1);
    let before = params.before.as_ref().map(|s| parse_id(s)).transpose()?;
    let _after = params.after.as_ref().map(|s| parse_id(s)).transpose()?;
    crate::realtime_trace!(
        user_id = user_id.0,
        channel_id,
        server_id = ?server_id,
        limit,
        before = ?before,
        "realtime_scope: HTTP message fetch authorized for viewed channel"
    );

    if before.is_none() {
        let user_str = user_id.0.to_string();
        if let Some(cached) = state
            .message_cache
            .get_messages(
                channel_id,
                before,
                limit,
                &user_str,
                &state.config.instance_api_url,
            )
            .await
        {
            crate::realtime_trace!(
                user_id = user_id.0,
                channel_id,
                count = cached.len(),
                "realtime_scope: HTTP message fetch served from cache"
            );
            return Ok(Json(json!(cached)));
        }
    }

    let mut rls_tx = state.rls_transaction(user_id.0).await.map_err(|e| {
        tracing::error!(channel_id, user_id = user_id.0, error = %e, "get_messages: RLS transaction failed");
        AppError::Internal
    })?;
    let records: Vec<MessageRow> = match before {
        Some(before_id) => {
            crate::services::pg::messages::before_tx(&mut rls_tx, channel_id, before_id, limit)
                .await
        }
        None => crate::services::pg::messages::latest_tx(&mut rls_tx, channel_id, limit).await,
    }
    .map_err(|e| {
        tracing::error!(channel_id, error = %e, "get_messages: PG read failed");
        AppError::Internal
    })?;
    crate::realtime_trace!(
        user_id = user_id.0,
        channel_id,
        count = records.len(),
        "realtime_scope: HTTP message fetch served from database"
    );

    // Reactions: Redis is the authoritative reaction store.
    let message_ids: Vec<i64> = records.iter().map(|m| m.id).collect();
    let reaction_map = crate::services::reactions::list_reactions_batch_with_fallback(
        &state.redis,
        None,
        &message_ids,
    )
    .await;

    let attachment_rows = crate::services::pg::attachments::for_messages(&state.pg, &message_ids)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(channel_id, error = %e, "get_messages: attachment batch lookup failed");
            Vec::new()
        });
    let mut attachment_map: HashMap<i64, Vec<crate::services::pg::attachments::AttachmentRow>> =
        HashMap::new();
    for attachment in attachment_rows {
        if let Some(message_id) = attachment.message_id {
            attachment_map
                .entry(message_id)
                .or_default()
                .push(attachment);
        }
    }

    // Batch reply-to lookups: one SELECT for every reply_to in the
    // page instead of N sequential lookups in the per-message loop.
    let reply_ids: Vec<i64> = {
        let mut ids: Vec<i64> = records.iter().filter_map(|m| m.reply_to).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    };
    let reply_rows = if reply_ids.is_empty() {
        Vec::new()
    } else {
        crate::services::pg::messages::by_ids_tx(&mut rls_tx, &reply_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "get_messages: reply-to batch lookup failed");
                Vec::new()
            })
    };
    rls_tx.commit().await.map_err(|e| {
        tracing::error!(channel_id, user_id = user_id.0, error = %e, "get_messages: RLS transaction commit failed");
        AppError::Internal
    })?;
    let reply_map: std::collections::HashMap<i64, &MessageRow> =
        reply_rows.iter().map(|m| (m.id, m)).collect();

    // Batch profile lookups: every author + every reply author in one
    // pg::users::by_ids round-trip (cache hits short-circuit first).
    let mut author_ids: Vec<i64> = records.iter().map(|m| m.author_id).collect();
    for rm in &reply_rows {
        author_ids.push(rm.author_id);
    }
    author_ids.sort_unstable();
    author_ids.dedup();
    let profile_map = state
        .user_profiles
        .get_or_fetch_many(&state.pg, &author_ids)
        .await;

    let current_user_str = user_id.0.to_string();

    let mut result: Vec<Value> = Vec::with_capacity(records.len());
    let mut backfill_msgs: Vec<crate::proto::CachedMessage> = Vec::with_capacity(records.len());

    let unknown_profile = || ("Unknown".to_string(), None, None);

    for m in &records {
        let (author_username, author_avatar_url, author_display_name) = profile_map
            .get(&m.author_id)
            .cloned()
            .unwrap_or_else(unknown_profile);

        // Reply-to: resolve from the prefetched maps. Soft-deleted rows
        // are already filtered out by `messages::by_ids`.
        let reply_data: Option<(i64, String, i64, String, Option<String>, Option<String>)> = m
            .reply_to
            .and_then(|rid| reply_map.get(&rid).copied())
            .map(|rm| {
                let (ru, ra, rd) = profile_map
                    .get(&rm.author_id)
                    .cloned()
                    .unwrap_or_else(unknown_profile);
                (rm.id, rm.content.clone(), rm.author_id, ru, ra, rd)
            });

        let reply_json: Value = reply_data
            .as_ref()
            .map(|(id, content, aid, username, avatar, display)| {
                json!({
                    "id": id.to_string(),
                    "content": content,
                    "author": {
                        "id": aid.to_string(),
                        "username": username,
                        "displayName": display,
                        "avatarUrl": cdn::resolve(avatar.as_deref()),
                    }
                })
            })
            .unwrap_or(Value::Null);

        let reply_proto: Option<crate::proto::ReplySnapshot> =
            reply_data.map(|(id, content, aid, username, avatar, display)| {
                crate::proto::ReplySnapshot {
                    id: id.to_string(),
                    content,
                    author: Some(crate::proto::MessageAuthor {
                        id: aid.to_string(),
                        username,
                        avatar_url: avatar,
                        display_name: display,
                    }),
                }
            });

        let msg_reactions: Vec<Value> = reaction_map
            .get(&m.id)
            .map(|mr| {
                mr.by_emoji
                    .iter()
                    .map(|(emoji, user_ids)| {
                        json!({
                            "emoji": emoji,
                            "emojiId": Value::Null,
                            "count": user_ids.len(),
                            "me": user_ids.iter().any(|u| u.to_string() == current_user_str),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let cached_reactions: Vec<crate::proto::CachedReaction> = reaction_map
            .get(&m.id)
            .map(|mr| {
                mr.by_emoji
                    .iter()
                    .map(|(emoji, user_ids)| crate::proto::CachedReaction {
                        emoji: emoji.clone(),
                        emoji_id: None,
                        count: user_ids.len() as i32,
                        user_ids: user_ids.iter().map(|u| u.to_string()).collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let msg_attachment_rows = attachment_map.get(&m.id).cloned().unwrap_or_default();
        let msg_attachments: Vec<Value> = msg_attachment_rows
            .iter()
            .map(|a| attachment_to_json(a, &state.config.instance_api_url))
            .collect();
        let cached_attachments: Vec<crate::proto::Attachment> = msg_attachment_rows
            .iter()
            .map(|a| attachment_to_proto(a, &state.config.instance_api_url))
            .collect();

        result.push(message_to_json_with_author(
            m,
            &channel_id_str,
            &author_username,
            author_avatar_url.as_deref(),
            author_display_name.as_deref(),
            reply_json,
            msg_reactions,
            msg_attachments,
        ));

        backfill_msgs.push(message_cache::build_cached_message_from_vdb(
            m.id,
            channel_id,
            m.author_id,
            author_username,
            author_avatar_url,
            author_display_name,
            m.content.clone(),
            m.flags as u16,
            reply_proto,
            cached_reactions,
            cached_attachments,
        ));
    }

    if before.is_none() {
        let cache = state.message_cache.clone();
        let latest_page_complete = records.len() < limit as usize;
        tokio::spawn(async move {
            cache
                .backfill(channel_id, backfill_msgs, latest_page_complete)
                .await;
        });
    }

    tracing::info!(
        "Fetched {} messages for channel_id={}",
        result.len(),
        channel_id
    );
    Ok(Json(json!(result)))
}

pub(crate) async fn load_channel_messages_json(
    state: &AppState,
    user_id: i64,
    federated_client: Option<&crate::middleware::auth::FederatedClientIdentity>,
    channel_id: i64,
    limit: i64,
    before: Option<i64>,
) -> AppResult<Vec<Value>> {
    let response = get_messages(
        State(state.clone()),
        UserId(user_id),
        OptionalFederatedClient(federated_client.cloned()),
        Path(channel_id.to_string()),
        Query(MessageQueryParams {
            before: before.map(|id| id.to_string()),
            after: None,
            limit: Some(limit.min(MESSAGE_FETCH_LIMIT).max(1)),
        }),
    )
    .await?;
    let Json(value) = response;
    Ok(value.as_array().cloned().unwrap_or_default())
}

// ─── POST /api/channels/:channelId/messages ─────────────────────────

pub async fn create_message(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
    Json(body): Json<CreateMessageRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!(
        "POST /api/channels/{}/messages user_id={}",
        channel_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::MESSAGE_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;

    let channel_id = parse_id(&channel_id_str)?;
    // Audit note: path channel IDs are authorized before message content can
    // reach storage, fanout, or bot event queues.
    let server_id = verify_channel_access(&state, user_id.0, channel_id).await?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)?;

    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::SEND_MESSAGES)
            .await?;

        let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
            .await
            .map_err(|e| {
                tracing::error!(channel_id, error = %e, "create_message: PG channel read failed");
                AppError::Internal
            })?
            .ok_or(AppError::NotFound("channel"))?;

        if channel.read_only
            && state
                .permissions
                .check_channel_permission(user_id.0, channel_id, sid, bits::MANAGE_MESSAGES)
                .await
                .is_err()
        {
            return Err(AppError::WithCode {
                status: StatusCode::FORBIDDEN,
                code: "CHANNEL_READ_ONLY",
                message: "This channel is read-only".into(),
            });
        }

        if channel.slowmode_seconds > 0 {
            let has_manage = state
                .permissions
                .check_channel_permission(user_id.0, channel_id, sid, bits::MANAGE_MESSAGES)
                .await
                .is_ok();
            if !has_manage {
                use fred::interfaces::KeysInterface;
                let key = format!("slowmode:{}:{}", channel_id, user_id.0);
                let set_result: bool = state
                    .redis
                    .set(
                        &key,
                        "1",
                        Some(fred::types::Expiration::EX(channel.slowmode_seconds as i64)),
                        Some(fred::types::SetOptions::NX),
                        false,
                    )
                    .await
                    .unwrap_or(false);
                if !set_result {
                    let ttl: i64 = state.redis.ttl::<i64, _>(&key).await.unwrap_or(0);
                    return Err(AppError::WithCode {
                        status: StatusCode::TOO_MANY_REQUESTS,
                        code: "SLOWMODE_ACTIVE",
                        message: format!("Slowmode active, retry in {} seconds", ttl.max(1)),
                    });
                }
            }
        }
    } else {
        crate::services::channel_access::ensure_dm_channel_send_allowed(
            &state, user_id.0, channel_id,
        )
        .await?;
    }

    let attachment_ids = parse_attachment_ids(&body.attachment_ids)?;
    if !attachment_ids.is_empty() {
        require_file_sharing_for_message(&state, user_id.0).await?;
    }

    let content = sanitize_message_content(&body.content);
    if content.is_empty() && attachment_ids.is_empty() {
        return Err(AppError::Validation(
            "Message content must not be empty".into(),
        ));
    }
    if content.len() > MAX_MESSAGE_LENGTH {
        return Err(AppError::Validation(format!(
            "Message content must not exceed {MAX_MESSAGE_LENGTH} characters"
        )));
    }

    let content =
        if crate::services::subscription::contains_custom_emoji_shortcode_candidate(&content) {
            let entitlements = crate::services::entitlements::current_for_user(
                &state.pg,
                &state.config,
                user_id.0,
            )
            .await;
            crate::services::subscription::validate_message_emojis_with_entitlement(
                &state.pg,
                user_id.0,
                server_id,
                &content,
                entitlements.cross_server_emoji,
            )
            .await
        } else {
            content
        };

    if let Some(host) = check_media_urls(&content) {
        tracing::warn!(user_id = user_id.0, %host, "Blocked media URL from untrusted host in create_message");
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "BLOCKED_MEDIA_URL",
            message: "Media URLs are only allowed from trusted sources".into(),
        });
    }

    let reply_to_id: Option<i64> = match body.reply_to_id.as_deref() {
        Some(s) if !s.is_empty() => Some(parse_id(s)?),
        _ => None,
    };
    let reply_snapshot: Option<(i64, String, i64, String, Option<String>, Option<String>)> =
        if let Some(rid) = reply_to_id {
            match crate::services::pg::messages::by_id_unhinted(&state.pg, rid).await {
                Ok(Some(msg))
                    if !crate::services::pg::messages::is_deleted(&msg)
                        && msg.channel_id == channel_id =>
                {
                    let (ruser, ravatar, rdisplay) = state
                        .user_profiles
                        .get_or_fetch(&state.pg, msg.author_id)
                        .await;
                    Some((
                        msg.id,
                        msg.content.clone(),
                        msg.author_id,
                        ruser,
                        ravatar,
                        rdisplay,
                    ))
                }
                Ok(_) => {
                    return Err(AppError::WithCode {
                        status: StatusCode::BAD_REQUEST,
                        code: "REPLY_TARGET_NOT_FOUND",
                        message: "Reply target not found in this channel".into(),
                    });
                }
                Err(e) => {
                    tracing::error!(user_id = user_id.0, channel_id, reply_to = rid, error = %e, "create_message: reply target read failed");
                    return Err(AppError::Internal);
                }
            }
        } else {
            None
        };

    let (author_username, author_avatar, author_display_name) =
        state.user_profiles.get_or_fetch(&state.pg, user_id.0).await;

    let id = state.snowflake.next_id();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let row = MessageRow {
        id,
        channel_id,
        author_id: user_id.0,
        r#type: 0,
        flags: 0,
        content: content.clone(),
        reply_to: reply_to_id,
        edited_at_ms: None,
        created_at_ms: now_ms,
    };
    // Enqueue into the message batcher: coalesces concurrent sends
    // into a single multi-row INSERT every ~2ms (or sooner under
    // burst). Awaits commit success before broadcasting so a failed
    // INSERT still surfaces as a 500 — same external contract as the
    // pre-batch call.
    let attached_rows: Vec<crate::services::pg::attachments::AttachmentRow> = if attachment_ids
        .is_empty()
    {
        state
                .message_batcher
                .enqueue_and_wait(row.clone())
                .await
                .map_err(|e| {
                    tracing::error!(channel_id, message_id = id, error = %e, "create_message: batched PG insert failed");
                    AppError::Internal
                })?;
        Vec::new()
    } else {
        let mut tx = state.pg.begin().await.map_err(|e| {
                tracing::error!(channel_id, message_id = id, error = %e, "create_message: transaction begin failed");
                AppError::Internal
            })?;
        crate::services::pg::messages::insert_tx(&mut tx, &row)
                .await
                .map_err(|e| {
                    tracing::error!(channel_id, message_id = id, error = %e, "create_message: PG insert failed");
                    AppError::Internal
                })?;

        let mut rows = Vec::with_capacity(attachment_ids.len());
        for attachment_id in attachment_ids {
            let attached = crate::services::pg::attachments::claim_pending_for_message_tx(
                    &mut tx,
                    attachment_id,
                    id,
                    channel_id,
                    user_id.0,
                )
                .await
                .map_err(|e| {
                    tracing::error!(channel_id, message_id = id, attachment_id, error = %e, "create_message: attachment claim failed");
                    AppError::Internal
                })?
                .ok_or_else(|| AppError::WithCode {
                    status: StatusCode::BAD_REQUEST,
                    code: "INVALID_ATTACHMENT",
                    message: "Attachment is not available for this message".into(),
                })?;
            rows.push(attached);
        }
        tx.commit().await.map_err(|e| {
                tracing::error!(channel_id, message_id = id, error = %e, "create_message: transaction commit failed");
                AppError::Internal
            })?;
        rows
    };

    record_channel_activity(&state, channel_id, user_id.0, now_ms).await;

    let uid_str = user_id.0.to_string();
    let attachments_json: Vec<Value> = attached_rows
        .iter()
        .map(|a| attachment_to_json(a, &state.config.instance_api_url))
        .collect();
    let attachments_proto: Vec<crate::proto::Attachment> = attached_rows
        .iter()
        .map(|a| attachment_to_proto(a, &state.config.instance_api_url))
        .collect();
    let reply_to_json = reply_snapshot
        .as_ref()
        .map(|(rid, rcontent, raid, ruser, ravatar, rdisplay)| {
            json!({
                "id": rid.to_string(),
                "content": rcontent,
                "author": {
                    "id": raid.to_string(),
                    "username": ruser,
                    "displayName": rdisplay,
                    "avatarUrl": cdn::resolve(ravatar.as_deref()),
                }
            })
        })
        .unwrap_or(Value::Null);
    let reply_to_proto =
        reply_snapshot
            .as_ref()
            .map(
                |(rid, rcontent, raid, ruser, ravatar, rdisplay)| crate::proto::ReplySnapshot {
                    id: rid.to_string(),
                    content: rcontent.clone(),
                    author: Some(crate::proto::MessageAuthor {
                        id: raid.to_string(),
                        username: ruser.clone(),
                        avatar_url: ravatar.clone(),
                        display_name: rdisplay.clone(),
                    }),
                },
            );
    let message = json!({
        "id": id.to_string(),
        "channelId": channel_id_str,
        "authorId": uid_str,
        "author": {
            "id": uid_str,
            "username": author_username,
            "displayName": author_display_name,
            "avatarUrl": author_avatar,
        },
        "content": content.clone(),
        "type": 0,
        "edited": false,
        "editedAt": null,
        "createdAt": now.to_rfc3339(),
        "updatedAt": now.to_rfc3339(),
        "reactions": [],
        "attachments": attachments_json,
        "replyTo": reply_to_json,
    });

    if let Some(sid) = server_id {
        crate::services::bot_events::enqueue(
            &state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MESSAGE_CREATE,
                server_id: Some(sid),
                channel_id: Some(channel_id),
                feed_id: None,
                actor_user_id: Some(user_id.0),
                actor_bot_id: None,
                payload: json!({
                    "serverId": sid.to_string(),
                    "channelId": channel_id_str.clone(),
                    "message": message.clone(),
                }),
            },
        );
    }

    let json_text = events::message_create_json(&message);
    let proto_msg = events::message_create_proto(crate::proto::Message {
        id: id.to_string(),
        channel_id: channel_id_str.clone(),
        author_id: uid_str.clone(),
        author: Some(crate::proto::MessageAuthor {
            id: uid_str.clone(),
            username: author_username.clone(),
            avatar_url: author_avatar.clone(),
            display_name: author_display_name.clone(),
        }),
        content: content.clone(),
        r#type: 0,
        edited: false,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        nonce: None,
        attachments: attachments_proto.clone(),
        reactions: vec![],
        reply_to: reply_to_proto.clone(),
        edited_at: None,
    });
    publish_message_create_scoped(
        &state,
        channel_id,
        &channel_id_str,
        server_id,
        &id.to_string(),
        &user_id.0.to_string(),
        &now.to_rfc3339(),
        Some(&author_username),
        author_display_name.as_deref(),
        author_avatar.as_deref(),
        &json_text,
        &proto_msg,
        &content,
    )
    .await;
    if attached_rows.is_empty() {
        enqueue_federation_channel_event(
            &state,
            channel_id,
            crate::federation::producer::FederationLocalEvent::MessageCreate {
                channel_id,
                server_id,
                message_id: id,
                author_user_id: user_id.0,
                content: content.clone(),
                nonce: None,
                reply_to_message_id: reply_to_id,
            },
            now_ms,
        )
        .await;
    } else {
        tracing::debug!(
            channel_id,
            message_id = id,
            "Federation message_create skipped because attachments are not federated"
        );
    }

    let cache = state.message_cache.clone();
    let cache_content = content.clone();
    let cache_channel_id_str = channel_id_str.clone();
    let cache_pg = state.pg.clone();
    let cache_profiles = state.user_profiles.clone();
    let cache_user_id = user_id.0;
    tokio::spawn(async move {
        let (u, a, d) = cache_profiles.get_or_fetch(&cache_pg, cache_user_id).await;
        let cached_msg = message_cache::build_cached_message_new(
            id.to_string(),
            cache_channel_id_str,
            cache_user_id.to_string(),
            u,
            a,
            d,
            cache_content,
            0,
            now.to_rfc3339(),
            reply_to_proto,
            attachments_proto,
        );
        cache.cache_message(channel_id, id, &cached_msg).await;
    });

    tracing::info!(
        "Message created id={} channel_id={} author_id={}",
        id,
        channel_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(message)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("messages.rs");

    #[test]
    fn create_message_validation_allows_attachment_only_content() {
        let body = CreateMessageRequest {
            content: String::new(),
            attachment_ids: vec!["123".to_string()],
            reply_to_id: None,
        };

        assert!(body.validate().is_ok());
    }

    #[test]
    fn create_message_validation_keeps_max_content_length() {
        let body = CreateMessageRequest {
            content: "x".repeat(MAX_MESSAGE_LENGTH + 1),
            attachment_ids: vec!["123".to_string()],
            reply_to_id: None,
        };

        assert!(body.validate().is_err());
    }

    #[test]
    fn bot_channel_card_reserves_idempotency_before_insert() {
        let handler = SOURCE
            .split("\npub async fn create_bot_card")
            .nth(1)
            .expect("create_bot_card handler source should exist")
            .split("#[cfg(test)]")
            .next()
            .expect("handler body should precede tests");
        let reservation = handler
            .find("reserve_bot_idempotency_key")
            .expect("handler should reserve bot idempotency key");
        let insert = handler
            .find("crate::services::pg::messages::insert")
            .expect("handler should insert channel card message");

        assert!(
            reservation < insert,
            "bot idempotency must be reserved before inserting the channel card"
        );
    }

    #[test]
    fn http_message_edit_and_delete_enforce_message_limit_before_mutation() {
        let update = SOURCE
            .split("\npub async fn update_message")
            .nth(1)
            .expect("update_message handler source should exist")
            .split("\npub async fn delete_message")
            .next()
            .expect("delete_message follows update_message");
        let update_limit = update
            .find("MESSAGE_LIMIT")
            .expect("update_message must enforce MESSAGE_LIMIT");
        let update_db_read = update
            .find("messages::by_id_unhinted")
            .expect("update_message DB read should exist");
        assert!(
            update_limit < update_db_read,
            "HTTP message edits must be rate-limited before DB mutation work"
        );

        let delete = SOURCE
            .split("\npub async fn delete_message")
            .nth(1)
            .expect("delete_message handler source should exist")
            .split("\n    let topic = topics::channel_live_topic")
            .next()
            .expect("delete_message live fanout follows authorization");
        let delete_limit = delete
            .find("MESSAGE_LIMIT")
            .expect("delete_message must enforce MESSAGE_LIMIT");
        let delete_db_read = delete
            .find("messages::by_id_unhinted")
            .expect("delete_message DB read should exist");
        assert!(
            delete_limit < delete_db_read,
            "HTTP message deletes must be rate-limited before DB mutation work"
        );
    }
}

// ─── POST /api/channels/:channelId/announcements ────────────────────

pub async fn create_announcement(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
    Json(mut announcement): Json<crate::services::announcements::Announcement>,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/channels/{}/announcements user_id={}",
        channel_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::MESSAGE_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;

    let channel_id = parse_id(&channel_id_str)?;
    let server_id = verify_channel_access(&state, user_id.0, channel_id)
        .await?
        .ok_or(AppError::Validation(
            "Announcements are only available in server text channels".into(),
        ))?;
    require_federated_client_channel_scope(federated_client.as_ref(), Some(server_id))?;

    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "create_announcement: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    if channel.server_id != Some(server_id) || channel.r#type != 0 {
        return Err(AppError::Validation(
            "Announcements are only available in server text channels".into(),
        ));
    }

    state
        .permissions
        .check_channel_permission(user_id.0, channel_id, server_id, bits::VIEW_CHANNEL)
        .await
        .map_err(|_| AppError::NotFound("channel"))?;
    state
        .permissions
        .check_channel_permission(user_id.0, channel_id, server_id, bits::MANAGE_CHANNELS)
        .await?;

    crate::services::announcements::sanitize(&mut announcement);
    crate::services::announcements::validate(&announcement)
        .await
        .map_err(AppError::Validation)?;
    crate::services::announcements::validate_server_targets_for_user(
        &state,
        server_id,
        &announcement,
        user_id.0,
    )
    .await?;

    let content = serde_json::to_string(&announcement)
        .map_err(|e| AppError::Validation(format!("Failed to serialize announcement: {e}")))?;

    let (author_username, author_avatar, author_display_name) =
        state.user_profiles.get_or_fetch(&state.pg, user_id.0).await;

    let id = state.snowflake.next_id();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let row = MessageRow {
        id,
        channel_id,
        author_id: user_id.0,
        r#type: crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT as i16,
        flags: 0,
        content: content.clone(),
        reply_to: None,
        edited_at_ms: None,
        created_at_ms: now_ms,
    };
    crate::services::pg::messages::insert(&state.pg, &row).await.map_err(|e| {
        tracing::error!(channel_id, message_id = id, error = %e, "create_announcement: PG write failed");
        AppError::Internal
    })?;

    let uid_str = user_id.0.to_string();
    let message = json!({
        "id": id.to_string(),
        "channelId": channel_id_str.clone(),
        "authorId": uid_str.clone(),
        "author": {
            "id": uid_str.clone(),
            "username": author_username.clone(),
            "displayName": author_display_name.clone(),
            "avatarUrl": cdn::resolve(author_avatar.as_deref()),
        },
        "content": content,
        "type": crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT,
        "pinned": false,
        "edited": false,
        "createdAt": now.to_rfc3339(),
        "attachments": [],
        "reactions": [],
    });

    let json_text = events::message_create_json(&message);
    let proto_msg = events::message_create_proto(crate::proto::Message {
        id: id.to_string(),
        channel_id: channel_id_str.clone(),
        author_id: uid_str.clone(),
        author: Some(crate::proto::MessageAuthor {
            id: uid_str.clone(),
            username: author_username.clone(),
            avatar_url: cdn::resolve(author_avatar.as_deref()),
            display_name: author_display_name.clone(),
        }),
        content: content.clone(),
        r#type: crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT,
        edited: false,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        nonce: None,
        attachments: vec![],
        reactions: vec![],
        reply_to: None,
        edited_at: None,
    });
    record_channel_activity(&state, channel_id, user_id.0, now.timestamp_millis()).await;
    publish_message_create_scoped(
        &state,
        channel_id,
        &channel_id_str,
        Some(server_id),
        &id.to_string(),
        &uid_str,
        &now.to_rfc3339(),
        Some(&author_username),
        author_display_name.as_deref(),
        author_avatar.as_deref(),
        &json_text,
        &proto_msg,
        "",
    )
    .await;

    tracing::info!(
        "Announcement created id={} channel_id={} author_id={}",
        id,
        channel_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(message)).into_response())
}

// ─── POST /api/bot/channels/:channelId/cards ─────────────────────────

pub async fn create_bot_card(
    State(state): State<AppState>,
    optional_bot: OptionalBot,
    headers: HeaderMap,
    Path(channel_id_str): Path<String>,
    Json(mut card): Json<crate::services::announcements::Announcement>,
) -> AppResult<Response> {
    let OptionalBot(Some(bot)) = optional_bot else {
        return Err(AppError::TokenRequired);
    };
    tracing::info!(
        "POST /api/bot/channels/{}/cards bot_id={}",
        channel_id_str,
        bot.bot_id
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::MESSAGE_LIMIT,
        &format!("bot:{}", bot.bot_id),
    )
    .await?;

    if !has_scope(&bot.scopes, SCOPE_MESSAGES_WRITE) {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "BOT_SCOPE_MISSING",
            message: "Bot token is missing messages:write".into(),
        });
    }

    let channel_id = parse_id(&channel_id_str)?;
    if !bot.allowed_channel_ids.contains(&channel_id) {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "BOT_CHANNEL_NOT_ALLOWED",
            message: "Bot cannot post to this channel".into(),
        });
    }

    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "create_bot_card: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    let server_id = channel.server_id.ok_or(AppError::NotFound("channel"))?;
    if server_id != bot.server_id {
        return Err(AppError::NotFound("channel"));
    }
    if channel.r#type != 0 {
        return Err(AppError::Validation(
            "Cards can only be posted to text channels".into(),
        ));
    }
    if !crate::services::bot_permissions::has_channel_permission(
        &state,
        &bot,
        channel_id,
        bits::VIEW_CHANNEL | bits::SEND_MESSAGES,
    )
    .await?
    {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "BOT_CHANNEL_NOT_ALLOWED",
            message: "Bot role permissions do not allow posting to this channel".into(),
        });
    }

    let idem_key = bot_idempotency_key(&headers, &format!("channel-card:{channel_id}"))?;

    crate::services::announcements::sanitize(&mut card);
    crate::services::announcements::validate(&card)
        .await
        .map_err(AppError::Validation)?;
    crate::services::announcements::validate_server_targets_for_bot(&state, server_id, &card, &bot)
        .await?;

    let content = serde_json::to_string(&card)
        .map_err(|e| AppError::Validation(format!("Failed to serialize card: {e}")))?;

    let id = state.snowflake.next_id();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let row = MessageRow {
        id,
        channel_id,
        author_id: bot.bot_id,
        r#type: crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT as i16,
        flags: 0,
        content: content.clone(),
        reply_to: None,
        edited_at_ms: None,
        created_at_ms: now_ms,
    };

    let bot_id_str = bot.bot_id.to_string();
    let bot_avatar_url = cdn::resolve(bot.avatar_url.as_deref());
    let message = json!({
        "id": id.to_string(),
        "channelId": channel_id_str.clone(),
        "authorId": bot_id_str.clone(),
        "author": {
            "id": bot_id_str.clone(),
            "username": bot.name.clone(),
            "displayName": Value::Null,
            "avatarUrl": bot_avatar_url.clone(),
            "bot": true,
        },
        "content": content,
        "type": crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT,
        "pinned": false,
        "edited": false,
        "editedAt": Value::Null,
        "createdAt": now.to_rfc3339(),
        "updatedAt": now.to_rfc3339(),
        "attachments": [],
        "reactions": [],
        "replyTo": Value::Null,
    });

    if let Some(ref key) = idem_key {
        let mut tx = state.pg.begin().await.map_err(|e| {
            tracing::error!(channel_id, message_id = id, error = %e, "create_bot_card: PG tx begin failed");
            AppError::Internal
        })?;
        match crate::services::pg::bot_outbox::reserve_bot_idempotency_key(
            &mut tx,
            bot.bot_id,
            key,
            &message,
            now_ms,
        )
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id = id, error = %e, "create_bot_card: idempotency reserve failed");
            AppError::Internal
        })? {
            crate::services::pg::bot_outbox::BotIdempotencyReservation::Existing(existing) => {
                tx.rollback().await.map_err(|e| {
                    tracing::error!(channel_id, message_id = id, error = %e, "create_bot_card: PG tx rollback failed");
                    AppError::Internal
                })?;
                return Ok((StatusCode::OK, Json(existing)).into_response());
            }
            crate::services::pg::bot_outbox::BotIdempotencyReservation::Reserved => {}
        }
        crate::services::pg::messages::insert_tx(&mut tx, &row)
            .await
            .map_err(|e| {
                tracing::error!(channel_id, message_id = id, error = %e, "create_bot_card: PG write failed");
                AppError::Internal
            })?;
        tx.commit().await.map_err(|e| {
            tracing::error!(channel_id, message_id = id, error = %e, "create_bot_card: PG tx commit failed");
            AppError::Internal
        })?;
    } else {
        crate::services::pg::messages::insert(&state.pg, &row)
            .await
            .map_err(|e| {
                tracing::error!(channel_id, message_id = id, error = %e, "create_bot_card: PG write failed");
                AppError::Internal
            })?;
    }

    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MESSAGE_CREATE,
            server_id: Some(server_id),
            channel_id: Some(channel_id),
            feed_id: None,
            actor_user_id: None,
            actor_bot_id: Some(bot.bot_id),
            payload: json!({
                "serverId": server_id.to_string(),
                "channelId": channel_id_str.clone(),
                "message": message.clone(),
            }),
        },
    );

    let json_text = events::message_create_json(&message);
    let proto_msg = events::message_create_proto(crate::proto::Message {
        id: id.to_string(),
        channel_id: channel_id_str.clone(),
        author_id: bot_id_str.clone(),
        author: Some(crate::proto::MessageAuthor {
            id: bot_id_str.clone(),
            username: bot.name.clone(),
            avatar_url: bot_avatar_url.clone(),
            display_name: None,
        }),
        content: content.clone(),
        r#type: crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT,
        edited: false,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        nonce: None,
        attachments: vec![],
        reactions: vec![],
        reply_to: None,
        edited_at: None,
    });
    publish_message_create_scoped(
        &state,
        channel_id,
        &channel_id_str,
        Some(server_id),
        &id.to_string(),
        &bot_id_str,
        &now.to_rfc3339(),
        Some(&bot.name),
        None,
        bot_avatar_url.as_deref(),
        &json_text,
        &proto_msg,
        "",
    )
    .await;

    let cache = state.message_cache.clone();
    let cache_channel_id_str = channel_id_str.clone();
    let cache_author_name = bot.name.clone();
    let cache_avatar = bot_avatar_url.clone();
    tokio::spawn(async move {
        let cached_msg = message_cache::build_cached_message_new(
            id.to_string(),
            cache_channel_id_str,
            bot_id_str,
            cache_author_name,
            cache_avatar,
            None,
            content,
            crate::services::announcements::MESSAGE_TYPE_ANNOUNCEMENT,
            now.to_rfc3339(),
            None,
            vec![],
        );
        cache.cache_message(channel_id, id, &cached_msg).await;
    });

    tracing::info!(
        "Bot card created id={} channel_id={} bot_id={}",
        id,
        channel_id,
        bot.bot_id
    );
    Ok((StatusCode::CREATED, Json(message)).into_response())
}

// ─── PATCH /api/channels/:channelId/messages/:messageId ─────────────

pub async fn update_message(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path((channel_id_str, message_id_str)): Path<(String, String)>,
    Json(body): Json<UpdateMessageRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "PATCH /api/channels/{}/messages/{} user_id={}",
        channel_id_str,
        message_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::MESSAGE_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&message_id_str)?;

    let server_id = verify_channel_access(&state, user_id.0, channel_id).await?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)?;
    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
    }

    let body = UpdateMessageRequest {
        content: sanitize_message_content(&body.content),
    };
    if body.content.is_empty() || body.content.len() > MAX_MESSAGE_LENGTH {
        return Err(AppError::Validation(format!(
            "Message content must be 1-{MAX_MESSAGE_LENGTH} characters"
        )));
    }

    let existing = crate::services::pg::messages::by_id_unhinted(&state.pg, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "update_message: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("message"))?;
    // IDOR guard: message ID alone is never enough; the stored channel must
    // match the path channel before author ownership is considered.
    if existing.channel_id != channel_id || crate::services::pg::messages::is_deleted(&existing) {
        return Err(AppError::NotFound("message"));
    }
    if existing.author_id != user_id.0 {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "MESSAGE_NOT_AUTHOR",
            message: "You can only edit your own messages".into(),
        });
    }

    let content = if crate::services::subscription::contains_custom_emoji_shortcode_candidate(
        &body.content,
    ) {
        let entitlements =
            crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id.0)
                .await;
        crate::services::subscription::validate_message_emojis_with_entitlement(
            &state.pg,
            user_id.0,
            server_id,
            &body.content,
            entitlements.cross_server_emoji,
        )
        .await
    } else {
        body.content
    };

    if let Some(host) = check_media_urls(&content) {
        tracing::warn!(user_id = user_id.0, %host, "Blocked media URL from untrusted host in update_message");
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "BLOCKED_MEDIA_URL",
            message: "Media URLs are only allowed from trusted sources".into(),
        });
    }

    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    crate::services::pg::messages::edit(
        &state.pg,
        message_id,
        existing.created_at_ms,
        &content,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, message_id, error = %e, "update_message: PG edit failed");
        AppError::Internal
    })?;

    let (author_username, author_avatar_url, author_display_name) =
        state.user_profiles.get_or_fetch(&state.pg, user_id.0).await;
    let author_id_str = user_id.0.to_string();

    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(existing.created_at_ms)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    let reaction_map = crate::services::reactions::list_reactions_batch_with_fallback(
        &state.redis,
        None,
        &[message_id],
    )
    .await;
    let msg_reactions: Vec<Value> = reaction_map
        .get(&message_id)
        .map(|mr| {
            mr.by_emoji
                .iter()
                .map(|(emoji, user_ids)| {
                    json!({
                        "emoji": emoji,
                        "emojiId": Value::Null,
                        "count": user_ids.len(),
                        "me": user_ids.iter().any(|u| *u == user_id.0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let proto_reactions: Vec<crate::proto::Reaction> = reaction_map
        .get(&message_id)
        .map(|mr| {
            mr.by_emoji
                .iter()
                .map(|(emoji, user_ids)| crate::proto::Reaction {
                    emoji: emoji.clone(),
                    emoji_id: None,
                    count: user_ids.len() as i32,
                    me: user_ids.iter().any(|u| *u == user_id.0),
                })
                .collect()
        })
        .unwrap_or_default();
    let attachment_rows = crate::services::pg::attachments::for_messages(&state.pg, &[message_id])
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                channel_id,
                message_id,
                error = %e,
                "update_message: attachment lookup failed"
            );
            Vec::new()
        });
    let msg_attachments: Vec<Value> = attachment_rows
        .iter()
        .map(|a| attachment_to_json(a, &state.config.instance_api_url))
        .collect();
    let cached_attachments: Vec<crate::proto::Attachment> = attachment_rows
        .iter()
        .map(|a| attachment_to_proto(a, &state.config.instance_api_url))
        .collect();

    let updated_msg = json!({
        "id": message_id.to_string(),
        "channelId": channel_id_str,
        "authorId": author_id_str,
        "author": {
            "id": author_id_str,
            "username": author_username,
            "displayName": author_display_name,
            "avatarUrl": cdn::resolve(author_avatar_url.as_deref()),
        },
        "content": content.clone(),
        "type": existing.r#type as i32,
        "edited": true,
        "editedAt": now.to_rfc3339(),
        "createdAt": created_at,
        "updatedAt": now.to_rfc3339(),
        "reactions": msg_reactions,
        "attachments": msg_attachments,
        "replyTo": Value::Null,
    });

    if let Some(sid) = server_id {
        crate::services::bot_events::enqueue(
            &state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MESSAGE_UPDATE,
                server_id: Some(sid),
                channel_id: Some(channel_id),
                feed_id: None,
                actor_user_id: Some(user_id.0),
                actor_bot_id: None,
                payload: json!({
                    "serverId": sid.to_string(),
                    "channelId": channel_id_str.clone(),
                    "message": updated_msg.clone(),
                }),
            },
        );
    }

    let topic = topics::channel_live_topic(channel_id);
    let json_text = events::message_update_json(&updated_msg);
    let proto_msg = events::message_update_proto(crate::proto::Message {
        id: message_id.to_string(),
        channel_id: channel_id_str.clone(),
        author_id: author_id_str.clone(),
        author: Some(crate::proto::MessageAuthor {
            id: author_id_str.clone(),
            username: author_username.clone(),
            avatar_url: author_avatar_url.clone(),
            display_name: author_display_name.clone(),
        }),
        content: content.clone(),
        r#type: existing.r#type as i32,
        edited: true,
        created_at,
        updated_at: now.to_rfc3339(),
        nonce: None,
        attachments: cached_attachments,
        reactions: proto_reactions,
        reply_to: None,
        edited_at: Some(now.to_rfc3339()),
    });
    topics::publish(&state, &topic, &json_text, &proto_msg).await;
    enqueue_federation_channel_event(
        &state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessageUpdate {
            channel_id,
            message_id,
            author_user_id: user_id.0,
            content: content.clone(),
        },
        now_ms,
    )
    .await;

    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.invalidate_channel(channel_id).await });

    tracing::info!(
        "Message updated id={} channel_id={}",
        message_id,
        channel_id
    );
    Ok(Json(updated_msg))
}

// ─── DELETE /api/channels/:channelId/messages/:messageId ────────────

pub async fn delete_message(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path((channel_id_str, message_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/channels/{}/messages/{} user_id={}",
        channel_id_str,
        message_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::MESSAGE_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let channel_id = parse_id(&channel_id_str)?;
    let message_id = parse_id(&message_id_str)?;

    let server_id = verify_channel_access(&state, user_id.0, channel_id).await?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)?;
    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
    }

    let existing = crate::services::pg::messages::by_id_unhinted(&state.pg, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "delete_message: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("message"))?;
    // IDOR guard: require the message to belong to the path channel before
    // allowing author delete or MANAGE_MESSAGES fallback.
    if existing.channel_id != channel_id || crate::services::pg::messages::is_deleted(&existing) {
        return Err(AppError::NotFound("message"));
    }

    let is_author = existing.author_id == user_id.0;
    if !is_author {
        if let Some(sid) = server_id {
            state
                .permissions
                .check_channel_permission(user_id.0, channel_id, sid, bits::MANAGE_MESSAGES)
                .await?;
        } else {
            return Err(AppError::WithCode {
                status: StatusCode::FORBIDDEN,
                code: "MESSAGE_NOT_AUTHOR",
                message: "You can only delete your own messages in DMs".into(),
            });
        }
    }

    crate::services::pg::messages::tombstone(&state.pg, message_id, existing.created_at_ms)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "delete_message: PG tombstone failed");
            AppError::Internal
        })?;

    let topic = topics::channel_live_topic(channel_id);
    let json_text = events::message_delete_json(&message_id.to_string(), &channel_id_str);
    let proto_msg = events::message_delete_proto(message_id.to_string(), channel_id_str.clone());
    if let Some(sid) = server_id {
        crate::services::bot_events::enqueue(
            &state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MESSAGE_DELETE,
                server_id: Some(sid),
                channel_id: Some(channel_id),
                feed_id: None,
                actor_user_id: Some(user_id.0),
                actor_bot_id: None,
                payload: json!({
                    "serverId": sid.to_string(),
                    "channelId": channel_id_str.clone(),
                    "messageId": message_id.to_string(),
                }),
            },
        );
    }
    let live_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&topic)
        .map(|set| set.len())
        .unwrap_or(0);
    crate::realtime_trace!(
        user_id = user_id.0,
        message_id,
        channel_id,
        is_author,
        live_topic = %topic,
        live_local_subscribers,
        "realtime_scope: publishing MESSAGE_DELETE to focused live subscribers"
    );
    topics::publish(&state, &topic, &json_text, &proto_msg).await;
    enqueue_federation_channel_event(
        &state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessageDelete {
            channel_id,
            message_id,
            author_user_id: existing.author_id,
        },
        chrono::Utc::now().timestamp_millis(),
    )
    .await;

    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.remove_single_message(channel_id, message_id).await });

    let _ = FLAG_DELETED;

    tracing::info!(
        "Message deleted id={} channel_id={} by user_id={}",
        message_id,
        channel_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── GET /api/channels/:channelId/messages/search ───────────────────

pub async fn search_messages(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
    Query(params): Query<SearchQueryParams>,
) -> AppResult<Json<Value>> {
    params.validate()?;
    tracing::info!(
        "GET /api/channels/{}/messages/search user_id={}",
        channel_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::SEARCH_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let channel_id = parse_id(&channel_id_str)?;
    let server_id = verify_channel_access(&state, user_id.0, channel_id).await?;
    require_federated_client_channel_scope(federated_client.as_ref(), server_id)?;

    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
    }

    let query = params.q.as_deref().unwrap_or("").trim();
    let author_id_filter = params.author_id.as_ref().map(|s| parse_id(s)).transpose()?;
    if query.len() > 200 {
        return Err(AppError::Validation(
            "Search query must be 200 characters or less".into(),
        ));
    }
    if query.is_empty() && author_id_filter.is_none() {
        return Err(AppError::Validation(
            "Search query or author filter is required".into(),
        ));
    }

    let limit = params.limit.unwrap_or(20).min(MESSAGE_FETCH_LIMIT).max(1);
    let before = params.before.as_ref().map(|s| parse_id(s)).transpose()?;

    let mut rls_tx = state.rls_transaction(user_id.0).await.map_err(|e| {
        tracing::error!(channel_id, user_id = user_id.0, error = %e, "search_messages: RLS transaction failed");
        AppError::Internal
    })?;
    let matches = crate::services::pg::messages::search_tx(
        &mut rls_tx,
        channel_id,
        query,
        author_id_filter,
        before,
        limit,
    )
    .await
    .map_err(|e| {
        tracing::error!(channel_id, error = %e, "search_messages: PG read failed");
        AppError::Internal
    })?;
    rls_tx.commit().await.map_err(|e| {
        tracing::error!(channel_id, user_id = user_id.0, error = %e, "search_messages: RLS transaction commit failed");
        AppError::Internal
    })?;

    let mut result: Vec<Value> = Vec::with_capacity(matches.len());
    for m in &matches {
        let (author_username, author_avatar_url, author_display_name) = state
            .user_profiles
            .get_or_fetch(&state.pg, m.author_id)
            .await;
        let author_id_str = m.author_id.to_string();
        let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(m.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();
        let edited_at = m
            .edited_at_ms
            .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
            .map(|t| t.to_rfc3339());
        let updated_at = edited_at.clone().unwrap_or_else(|| created_at.clone());
        result.push(json!({
            "id": m.id.to_string(),
            "channelId": channel_id_str,
            "authorId": author_id_str,
            "author": {
                "id": author_id_str,
                "username": author_username,
                "displayName": author_display_name,
                "avatarUrl": cdn::resolve(author_avatar_url.as_deref()),
            },
            "content": m.content,
            "type": m.r#type as i32,
            "edited": m.edited_at_ms.is_some(),
            "editedAt": edited_at.map(Value::String).unwrap_or(Value::Null),
            "createdAt": created_at,
            "updatedAt": updated_at,
            "attachments": [],
            "reactions": [],
            "replyTo": Value::Null,
        }));
    }

    tracing::info!(
        "Search returned {} results for channel_id={}",
        result.len(),
        channel_id
    );
    Ok(Json(json!(result)))
}

// ─── GET /api/channels/:channelId/activity ───────────────────────────

pub async fn get_channel_activity(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/channels/{}/activity user_id={}",
        channel_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::API_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let channel_id = parse_id(&channel_id_str)?;
    let result =
        load_channel_activity_json(&state, user_id.0, federated_client.as_ref(), channel_id)
            .await?;

    tracing::info!(
        "Activity: {} members for channel_id={}",
        result.len(),
        channel_id
    );
    Ok(Json(json!(result)))
}

pub(crate) async fn load_channel_activity_json(
    state: &AppState,
    user_id: i64,
    federated_client: Option<&crate::middleware::auth::FederatedClientIdentity>,
    channel_id: i64,
) -> AppResult<Vec<Value>> {
    let server_id = verify_channel_access(state, user_id, channel_id).await?;
    let sid = server_id.ok_or(AppError::Validation(
        "Activity is only available for server channels".into(),
    ))?;
    require_federated_client_channel_scope(federated_client, Some(sid))?;

    state
        .permissions
        .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
        .await
        .map_err(|_| AppError::NotFound("channel"))?;

    use fred::interfaces::HashesInterface;
    let activity_key = format!("channel:{channel_id}:activity");
    let activity: HashMap<String, String> =
        state.redis.hgetall(&activity_key).await.unwrap_or_default();

    let mut online_member_ids: Vec<i64> = Vec::new();
    for uid in state.ws.connected_user_ids() {
        let is_member = match state.permissions.is_member_cached(uid, sid) {
            Some(v) => v,
            None => state.permissions.check_membership(uid, sid).await.is_ok(),
        };
        if !is_member {
            continue;
        }
        match state
            .permissions
            .check_channel_permission(uid, channel_id, sid, bits::VIEW_CHANNEL)
            .await
        {
            Ok(()) => {}
            Err(AppError::Internal) => return Err(AppError::Internal),
            Err(_) => continue,
        }
        online_member_ids.push(uid);
        if online_member_ids.len() >= 200 {
            break;
        }
    }

    let users = crate::services::pg::users::by_ids(&state.pg, &online_member_ids)
        .await
        .unwrap_or_default();
    let user_lookup: HashMap<i64, _> = users.into_iter().map(|u| (u.id, u)).collect();
    let presence_map: HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &online_member_ids)
            .await
            .into_iter()
            .collect();

    // Per-user role list scoped to this server.
    let mut roles_by_user: HashMap<i64, Vec<String>> = HashMap::new();
    for uid in &online_member_ids {
        if let Ok(role_ids) = crate::services::pg::roles::list_role_ids(&state.pg, *uid, sid).await
        {
            if !role_ids.is_empty() {
                roles_by_user.insert(*uid, role_ids.into_iter().map(|r| r.to_string()).collect());
            }
        }
    }

    let mut result: Vec<(i64, Value, Option<i64>)> = Vec::with_capacity(online_member_ids.len());
    for uid in &online_member_ids {
        let Some(u) = user_lookup.get(uid) else {
            continue;
        };
        let last_ms = activity
            .get(&uid.to_string())
            .and_then(|s| s.parse::<i64>().ok());
        let status = presence_map
            .get(uid)
            .map(|s| s.as_str())
            .unwrap_or("offline");
        let joined_at = u.created_at.to_rfc3339();
        let last_message_at = last_ms
            .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
            .map(|t| t.to_rfc3339());
        let official_subscription_active =
            crate::services::entitlements::official_subscription_active_from_db(
                u.subscribed,
                u.subscription_expires_at,
            );
        let member_list_banner_visible = crate::services::entitlements::member_list_banner_visible(
            &state.config,
            official_subscription_active,
        );
        let json = json!({
            "userId": uid.to_string(),
            "username": u.username,
            "displayName": u.display_name,
            "avatarUrl": cdn::resolve(u.avatar_url.as_deref()),
            "bannerUrl": cdn::resolve(u.banner_url.as_deref()),
            "bannerCrop": banner_crop::to_json(u.banner_crop),
            "memberListBannerUrl": if member_list_banner_visible { cdn::resolve(u.member_list_banner_url.as_deref()) } else { None },
            "memberListBannerCrop": if member_list_banner_visible { banner_crop::to_json(u.member_list_banner_crop) } else { serde_json::Value::Null },
            "nickname": Value::Null,
            "status": status,
            "joinedAt": joined_at,
            "roleIds": roles_by_user.get(uid).cloned().unwrap_or_default(),
            "lastMessageAt": last_message_at,
        });
        result.push((u.created_at.timestamp_millis(), json, last_ms));
    }

    result.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    let result: Vec<Value> = result.into_iter().map(|(_, v, _)| v).collect();
    let media =
        crate::handlers::media_diagnostics::summarize_member_media(&result, "activityMember");
    tracing::info!(
        channel_id,
        server_id = sid,
        user_id,
        online_member_count = online_member_ids.len(),
        redis_activity_count = activity.len(),
        result_member_count = result.len(),
        media = ?media,
        "messages.channel_activity emitted media fields"
    );

    Ok(result)
}
