use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::cdn;
use crate::services::permissions::bits;
use crate::services::pg::emojis::EmojiRow;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

pub(crate) fn serialize_emoji(e: &EmojiRow) -> Value {
    json!({
        "id": e.id.to_string(),
        "serverId": e.server_id.to_string(),
        "name": e.name,
        "url": cdn::resolve(if e.url.is_empty() { None } else { Some(e.url.as_str()) }),
        "createdBy": e.created_by.to_string(),
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(e.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        "assetHash": e.asset_hash.as_deref(),
        "source": e.source_peer_id.as_ref().map(|peer_id| json!({
            "peerId": peer_id,
            "origin": e.source_origin.as_deref(),
            "serverLabel": e.source_server_label.as_deref(),
            "expressionName": e.source_expression_name.as_deref(),
            "importedBy": e.imported_by.map(|id| id.to_string()),
            "importedAt": e.imported_at_ms.and_then(|ms| {
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
                    .map(|t| t.to_rfc3339())
            }),
        })),
    })
}

fn emoji_storage_key(url: &str, server_id: i64, emoji_id: i64) -> Option<String> {
    let candidate = if url.starts_with("http://") || url.starts_with("https://") {
        let index = url.find("emojis/")?;
        &url[index..]
    } else {
        url
    };
    let candidate = candidate
        .split(['?', '#'])
        .next()
        .unwrap_or(candidate)
        .trim();

    if candidate.contains('\\') || candidate.contains('\0') {
        return None;
    }

    let mut parts = candidate.split('/');
    let root = parts.next()?;
    let server = parts.next()?;
    let file = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    if root != "emojis" || server != server_id.to_string() {
        return None;
    }

    let prefix = format!("{emoji_id}.");
    if !file.starts_with(&prefix) || file.len() == prefix.len() {
        return None;
    }
    if !file[prefix.len()..]
        .chars()
        .all(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }

    Some(candidate.to_string())
}

async fn cleanup_deleted_emoji_asset(
    state: &AppState,
    emoji_id: i64,
    server_id: i64,
    cleanup: crate::services::pg::custom_expression_assets::CustomExpressionAssetCleanup,
) {
    let Some(s3) = &state.s3 else {
        tracing::warn!(
            emoji_id,
            server_id,
            asset_id = cleanup.asset_id,
            "delete_emoji: shared asset cleanup skipped because object storage is unavailable"
        );
        return;
    };

    let mut conn = match state.pg.acquire().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(
                emoji_id,
                server_id,
                asset_id = cleanup.asset_id,
                error = %error,
                "delete_emoji: shared asset cleanup connection failed"
            );
            return;
        }
    };

    let lock_key = match crate::services::pg::custom_expression_assets::lock_digest_on_connection(
        &mut conn,
        &cleanup.kind,
        &cleanup.sha256_hex,
    )
    .await
    {
        Ok(lock_key) => lock_key,
        Err(error) => {
            tracing::warn!(
                emoji_id,
                server_id,
                asset_id = cleanup.asset_id,
                error = %error,
                "delete_emoji: shared asset cleanup lock failed"
            );
            return;
        }
    };

    let can_delete =
        match crate::services::pg::custom_expression_assets::is_unreferenced_on_connection(
            &mut conn,
            cleanup.asset_id,
        )
        .await
        {
            Ok(can_delete) => can_delete,
            Err(error) => {
                tracing::warn!(
                    emoji_id,
                    server_id,
                    asset_id = cleanup.asset_id,
                    error = %error,
                    "delete_emoji: shared asset cleanup reference check failed"
                );
                let _ = crate::services::pg::custom_expression_assets::unlock_digest_on_connection(
                    &mut conn, lock_key,
                )
                .await;
                return;
            }
        };

    if can_delete {
        match s3.delete_object(&cleanup.storage_key).await {
            Ok(()) => {
                if let Err(error) = crate::services::pg::custom_expression_assets::delete_if_unreferenced_on_connection(
                    &mut conn,
                    cleanup.asset_id,
                )
                .await
                {
                    tracing::warn!(
                        emoji_id,
                        server_id,
                        asset_id = cleanup.asset_id,
                        error = %error,
                        "delete_emoji: shared asset metadata cleanup failed"
                    );
                }
            }
            Err(error) => tracing::warn!(
                emoji_id,
                server_id,
                asset_id = cleanup.asset_id,
                error = %error,
                "delete_emoji: shared asset object cleanup failed"
            ),
        }
    } else {
        tracing::debug!(
            emoji_id,
            server_id,
            asset_id = cleanup.asset_id,
            "delete_emoji: shared asset cleanup skipped because references were restored"
        );
    }

    if let Err(error) = crate::services::pg::custom_expression_assets::unlock_digest_on_connection(
        &mut conn, lock_key,
    )
    .await
    {
        tracing::warn!(
            emoji_id,
            server_id,
            asset_id = cleanup.asset_id,
            error = %error,
            "delete_emoji: shared asset cleanup unlock failed"
        );
    }
}

async fn enqueue_federation_emoji_event(
    state: &AppState,
    server_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    log_label: &'static str,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            server_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "{log_label}"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(server_id, error = %error, "{log_label} failed"),
    }
}

/// Increment emoji_version on the server and broadcast
/// SERVER_EMOJIS_UPDATE to all members.
pub(crate) async fn broadcast_emojis_update(state: &AppState, server_id: i64) {
    let new_version = match crate::services::pg::servers::bump_emoji_version(&state.pg, server_id)
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            tracing::warn!(server_id, "broadcast_emojis_update: server not in PG");
            return;
        }
        Err(e) => {
            tracing::warn!(server_id, error = %e, "broadcast_emojis_update: PG version bump failed");
            return;
        }
    };

    let records = match crate::services::pg::emojis::list_for_server(&state.pg, server_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(server_id, error = %e, "broadcast_emojis_update: PG emoji list failed");
            return;
        }
    };

    let emojis: Vec<Value> = records.iter().map(serialize_emoji).collect();
    let server_id_str = server_id.to_string();
    let json_text = events::server_emojis_update_json(&server_id_str, new_version, &emojis);
    let proto_emojis: Vec<crate::proto::Emoji> = records
        .iter()
        .map(|e| crate::proto::Emoji {
            id: e.id.to_string(),
            server_id: e.server_id.to_string(),
            name: e.name.clone(),
            url: cdn::resolve(if e.url.is_empty() {
                None
            } else {
                Some(e.url.as_str())
            })
            .unwrap_or_default(),
            created_by: e.created_by.to_string(),
            created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(e.created_at_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        })
        .collect();
    let proto_msg = events::server_emojis_update_proto(server_id_str, new_version, proto_emojis);
    let topic = topics::presence_topic(server_id);
    topics::publish(state, &topic, &json_text, &proto_msg).await;
}

// ─── GET /api/users/@me/emojis ──────────────────────────────────────

pub async fn list_user_emojis(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/users/@me/emojis user_id={}", user_id.0);

    // Walk the caller's servers and concatenate each server's emoji
    // list. Per-server emoji indexes are small (<100 each) so fan-out
    // is fine for a handful of servers.
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list_user_emojis: PG server list failed");
            AppError::Internal
        })?;

    let mut out: Vec<Value> = Vec::new();
    for sid in server_ids {
        match crate::services::pg::emojis::list_for_server(&state.pg, sid).await {
            Ok(records) => {
                for e in &records {
                    out.push(serialize_emoji(e));
                }
            }
            Err(e) => {
                tracing::warn!(server_id = sid, error = %e, "list_user_emojis: PG emoji fetch failed");
            }
        }
    }

    Ok(Json(json!(out)))
}

// ─── GET /api/servers/:serverId/emojis ──────────────────────────────

pub async fn list_server_emojis(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/emojis user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;

    let records = crate::services::pg::emojis::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_server_emojis: PG read failed");
            AppError::Internal
        })?;

    let result: Vec<Value> = records.iter().map(serialize_emoji).collect();
    Ok(Json(json!(result)))
}

// ─── PATCH /api/servers/:serverId/emojis/:emojiId ───────────────────

#[derive(Deserialize, Validate)]
pub struct RenameEmojiRequest {
    #[validate(length(min = 2, max = 32))]
    pub name: String,
}

pub async fn rename_emoji(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, emoji_id_str)): Path<(String, String)>,
    Json(body): Json<RenameEmojiRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "PATCH /api/servers/{}/emojis/{} user_id={}",
        server_id_str,
        emoji_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::EMOJI_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let emoji_id = parse_id(&emoji_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    if body.name.is_empty() || body.name.len() > 32 {
        return Err(AppError::Validation(
            "Emoji name must be 1-32 characters".into(),
        ));
    }

    if !body.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AppError::Validation(
            "Emoji name may only contain letters, numbers, and underscores".into(),
        ));
    }

    let mut record = crate::services::pg::emojis::by_id(&state.pg, emoji_id)
        .await
        .map_err(|e| {
            tracing::error!(emoji_id, error = %e, "rename_emoji: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("emoji"))?;
    if record.server_id != server_id {
        return Err(AppError::NotFound("emoji"));
    }

    crate::services::pg::emojis::rename(&state.pg, emoji_id, &body.name)
        .await
        .map_err(|e| {
            tracing::error!(emoji_id, error = %e, "rename_emoji: PG write failed");
            AppError::Internal
        })?;
    record.name = body.name.clone();

    tracing::info!(
        "Emoji renamed id={} server={} new_name={} by={}",
        emoji_id,
        server_id,
        body.name,
        user_id.0
    );

    broadcast_emojis_update(&state, server_id).await;
    enqueue_federation_emoji_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::EmojiRename {
            server_id,
            actor_user_id: user_id.0,
            emoji_id,
            name: body.name.clone(),
        },
        "Federation emoji rename producer completed",
    )
    .await;

    Ok(Json(serialize_emoji(&record)))
}

// ─── DELETE /api/servers/:serverId/emojis/:emojiId ──────────────────

pub async fn delete_emoji(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, emoji_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/emojis/{} user_id={}",
        server_id_str,
        emoji_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::EMOJI_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let emoji_id = parse_id(&emoji_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let record = crate::services::pg::emojis::by_id(&state.pg, emoji_id)
        .await
        .map_err(|e| {
            tracing::error!(emoji_id, error = %e, "delete_emoji: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("emoji"))?;
    if record.server_id != server_id {
        return Err(AppError::NotFound("emoji"));
    }

    // Best-effort S3 delete for legacy per-row objects. Digest-backed objects
    // are cleaned up only when the deleted catalog row drops the shared asset to
    // zero references.
    if record.asset_id.is_none() {
        if let Some(s3) = &state.s3 {
            if let Some(key) = emoji_storage_key(&record.url, server_id, emoji_id) {
                let _ = s3.delete_object(&key).await;
            } else if !record.url.is_empty() {
                tracing::warn!(
                    emoji_id,
                    server_id,
                    "delete_emoji: skipped unsafe or mismatched emoji storage key"
                );
            }
        }
    }

    let cleanup = crate::services::pg::emojis::delete(&state.pg, emoji_id)
        .await
        .map_err(|e| {
            tracing::error!(emoji_id, error = %e, "delete_emoji: PG delete failed");
            AppError::Internal
        })?;
    if let Some(cleanup) = cleanup {
        cleanup_deleted_emoji_asset(&state, emoji_id, server_id, cleanup).await;
    }

    tracing::info!(
        "Emoji deleted id={} server={} by={}",
        emoji_id,
        server_id,
        user_id.0
    );

    broadcast_emojis_update(&state, server_id).await;
    enqueue_federation_emoji_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::EmojiDelete {
            server_id,
            actor_user_id: user_id.0,
            emoji_id,
        },
        "Federation emoji delete producer completed",
    )
    .await;

    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::emoji_storage_key;

    const SOURCE: &str = include_str!("emojis.rs");

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
    fn rename_emoji_enqueues_federation_emoji_rename() {
        let handler = handler_source("rename_emoji");

        assert!(handler.contains("FederationLocalEvent::EmojiRename"));
        assert!(handler.contains("enqueue_federation_emoji_event"));
    }

    #[test]
    fn delete_emoji_enqueues_federation_emoji_delete() {
        let handler = handler_source("delete_emoji");

        assert!(handler.contains("FederationLocalEvent::EmojiDelete"));
        assert!(handler.contains("enqueue_federation_emoji_event"));
    }

    #[test]
    fn delete_emoji_uses_exact_storage_key() {
        let handler = handler_source("delete_emoji");

        assert!(handler.contains("emoji_storage_key(&record.url, server_id, emoji_id)"));
        assert!(handler.contains("delete_object(&key)"));
        assert!(handler.contains("cleanup_deleted_emoji_asset"));
        assert!(!handler.contains("rsplit('/').next()"));
    }

    #[test]
    fn delete_emoji_cleans_last_shared_asset_with_digest_lock() {
        let helper = private_async_source("cleanup_deleted_emoji_asset");

        assert!(helper.contains("lock_digest_on_connection"));
        assert!(helper.contains("is_unreferenced_on_connection"));
        assert!(helper.contains("delete_object(&cleanup.storage_key)"));
        assert!(helper.contains("delete_if_unreferenced_on_connection"));
        assert!(helper.contains("unlock_digest_on_connection"));
    }

    #[test]
    fn emoji_federation_helper_uses_server_scope() {
        let helper = private_async_source("enqueue_federation_emoji_event");

        assert!(helper.contains("FederationRouteScope::Server"));
        assert!(helper.contains("enqueue_local_event_for_scope"));
    }

    #[test]
    fn emoji_storage_key_preserves_raw_server_path() {
        assert_eq!(
            emoji_storage_key("emojis/123/456.webp", 123, 456),
            Some("emojis/123/456.webp".to_string())
        );
    }

    #[test]
    fn emoji_storage_key_extracts_cdn_url_without_query_or_fragment() {
        assert_eq!(
            emoji_storage_key(
                "https://cdn.example.test/media/emojis/123/456.webp?width=64#preview",
                123,
                456,
            ),
            Some("emojis/123/456.webp".to_string())
        );
    }

    #[test]
    fn emoji_storage_key_rejects_mismatched_or_unsafe_paths() {
        assert_eq!(emoji_storage_key("456.webp", 123, 456), None);
        assert_eq!(emoji_storage_key("emojis/999/456.webp", 123, 456), None);
        assert_eq!(emoji_storage_key("emojis/123/999.webp", 123, 456), None);
        assert_eq!(
            emoji_storage_key("emojis/123/456.webp/extra", 123, 456),
            None
        );
        assert_eq!(emoji_storage_key("emojis/123/456.", 123, 456), None);
        assert_eq!(emoji_storage_key("emojis/123/456.we/bp", 123, 456), None);
        assert_eq!(
            emoji_storage_key("attachments/123/456.webp", 123, 456),
            None
        );
        assert_eq!(emoji_storage_key("emojis\\123\\456.webp", 123, 456), None);
    }
}
