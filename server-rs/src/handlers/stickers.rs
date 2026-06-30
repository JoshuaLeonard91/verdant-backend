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
use crate::services::pg::stickers::StickerRow;
use crate::state::AppState;

use super::parse_id;

pub(crate) fn serialize_sticker(sticker: &StickerRow) -> Value {
    json!({
        "id": sticker.id.to_string(),
        "serverId": sticker.server_id.to_string(),
        "name": sticker.name,
        "url": cdn::resolve(if sticker.url.is_empty() { None } else { Some(sticker.url.as_str()) }),
        "createdBy": sticker.created_by.to_string(),
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(sticker.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        "assetHash": sticker.asset_hash.as_deref(),
        "source": sticker.source_peer_id.as_ref().map(|peer_id| json!({
            "peerId": peer_id,
            "origin": sticker.source_origin.as_deref(),
            "serverLabel": sticker.source_server_label.as_deref(),
            "expressionName": sticker.source_expression_name.as_deref(),
            "importedBy": sticker.imported_by.map(|id| id.to_string()),
            "importedAt": sticker.imported_at_ms.and_then(|ms| {
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
                    .map(|t| t.to_rfc3339())
            }),
        })),
    })
}

fn sticker_storage_key(url: &str, server_id: i64, sticker_id: i64) -> Option<String> {
    let candidate = if url.starts_with("http://") || url.starts_with("https://") {
        let index = url.find("stickers/")?;
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

    if root != "stickers" || server != server_id.to_string() {
        return None;
    }

    let prefix = format!("{sticker_id}.");
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

async fn cleanup_deleted_sticker_asset(
    state: &AppState,
    sticker_id: i64,
    server_id: i64,
    cleanup: crate::services::pg::custom_expression_assets::CustomExpressionAssetCleanup,
) {
    let Some(s3) = &state.s3 else {
        tracing::warn!(
            sticker_id,
            server_id,
            asset_id = cleanup.asset_id,
            "delete_sticker: shared asset cleanup skipped because object storage is unavailable"
        );
        return;
    };

    let mut conn = match state.pg.acquire().await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(
                sticker_id,
                server_id,
                asset_id = cleanup.asset_id,
                error = %error,
                "delete_sticker: shared asset cleanup connection failed"
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
                sticker_id,
                server_id,
                asset_id = cleanup.asset_id,
                error = %error,
                "delete_sticker: shared asset cleanup lock failed"
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
                    sticker_id,
                    server_id,
                    asset_id = cleanup.asset_id,
                    error = %error,
                    "delete_sticker: shared asset cleanup reference check failed"
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
                        sticker_id,
                        server_id,
                        asset_id = cleanup.asset_id,
                        error = %error,
                        "delete_sticker: shared asset metadata cleanup failed"
                    );
                }
            }
            Err(error) => tracing::warn!(
                sticker_id,
                server_id,
                asset_id = cleanup.asset_id,
                error = %error,
                "delete_sticker: shared asset object cleanup failed"
            ),
        }
    } else {
        tracing::debug!(
            sticker_id,
            server_id,
            asset_id = cleanup.asset_id,
            "delete_sticker: shared asset cleanup skipped because references were restored"
        );
    }

    if let Err(error) = crate::services::pg::custom_expression_assets::unlock_digest_on_connection(
        &mut conn, lock_key,
    )
    .await
    {
        tracing::warn!(
            sticker_id,
            server_id,
            asset_id = cleanup.asset_id,
            error = %error,
            "delete_sticker: shared asset cleanup unlock failed"
        );
    }
}

pub async fn list_server_stickers(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/stickers user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;

    let records = crate::services::pg::stickers::list_for_server(&state.pg, server_id)
        .await
        .map_err(|error| {
            tracing::error!(server_id, error = %error, "list_server_stickers: PG read failed");
            AppError::Internal
        })?;

    let result: Vec<Value> = records.iter().map(serialize_sticker).collect();
    Ok(Json(json!(result)))
}

#[derive(Deserialize, Validate)]
pub struct RenameStickerRequest {
    #[validate(length(min = 2, max = 32))]
    pub name: String,
}

pub async fn rename_sticker(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, sticker_id_str)): Path<(String, String)>,
    Json(body): Json<RenameStickerRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "PATCH /api/servers/{}/stickers/{} user_id={}",
        server_id_str,
        sticker_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::EMOJI_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let sticker_id = parse_id(&sticker_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    if body.name.len() < 2 || body.name.len() > 32 {
        return Err(AppError::Validation(
            "Sticker name must be 2-32 characters".into(),
        ));
    }

    if !body.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AppError::Validation(
            "Sticker name may only contain letters, numbers, and underscores".into(),
        ));
    }

    let mut record = crate::services::pg::stickers::by_id(&state.pg, sticker_id)
        .await
        .map_err(|error| {
            tracing::error!(sticker_id, error = %error, "rename_sticker: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("sticker"))?;
    if record.server_id != server_id {
        return Err(AppError::NotFound("sticker"));
    }

    crate::services::pg::stickers::rename(&state.pg, sticker_id, &body.name)
        .await
        .map_err(|error| {
            tracing::error!(sticker_id, error = %error, "rename_sticker: PG write failed");
            AppError::Internal
        })?;
    record.name = body.name.clone();

    tracing::info!(
        "Sticker renamed id={} server={} by={}",
        sticker_id,
        server_id,
        user_id.0
    );

    Ok(Json(serialize_sticker(&record)))
}

pub async fn delete_sticker(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, sticker_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/stickers/{} user_id={}",
        server_id_str,
        sticker_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::EMOJI_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let sticker_id = parse_id(&sticker_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let record = crate::services::pg::stickers::by_id(&state.pg, sticker_id)
        .await
        .map_err(|error| {
            tracing::error!(sticker_id, error = %error, "delete_sticker: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("sticker"))?;
    if record.server_id != server_id {
        return Err(AppError::NotFound("sticker"));
    }

    if record.asset_id.is_none() {
        if let Some(s3) = &state.s3 {
            if let Some(key) = sticker_storage_key(&record.url, server_id, sticker_id) {
                let _ = s3.delete_object(&key).await;
            } else if !record.url.is_empty() {
                tracing::warn!(
                    sticker_id,
                    server_id,
                    "delete_sticker: skipped unsafe or mismatched sticker storage key"
                );
            }
        }
    }

    let cleanup = crate::services::pg::stickers::delete(&state.pg, sticker_id)
        .await
        .map_err(|error| {
            tracing::error!(sticker_id, error = %error, "delete_sticker: PG delete failed");
            AppError::Internal
        })?;
    if let Some(cleanup) = cleanup {
        cleanup_deleted_sticker_asset(&state, sticker_id, server_id, cleanup).await;
    }

    tracing::info!(
        "Sticker deleted id={} server={} by={}",
        sticker_id,
        server_id,
        user_id.0
    );

    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::sticker_storage_key;

    const SOURCE: &str = include_str!("stickers.rs");

    fn handler_source(name: &str) -> &'static str {
        let signature = format!("pub async fn {name}");
        let after_signature = SOURCE
            .split(&signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} handler should exist"));
        after_signature
            .split("pub async fn")
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
            .split("pub async fn")
            .next()
            .expect("helper source section should be present")
    }

    #[test]
    fn sticker_handlers_require_membership_or_manage_server() {
        assert!(handler_source("list_server_stickers").contains("require_membership"));
        assert!(handler_source("rename_sticker").contains("require_permission"));
        assert!(handler_source("delete_sticker").contains("require_permission"));
    }

    #[test]
    fn delete_sticker_uses_exact_storage_key() {
        let handler = handler_source("delete_sticker");

        assert!(handler.contains("sticker_storage_key(&record.url, server_id, sticker_id)"));
        assert!(handler.contains("delete_object(&key)"));
        assert!(handler.contains("cleanup_deleted_sticker_asset"));
        assert!(!handler.contains("rsplit('/').next()"));
    }

    #[test]
    fn delete_sticker_cleans_last_shared_asset_with_digest_lock() {
        let helper = private_async_source("cleanup_deleted_sticker_asset");

        assert!(helper.contains("lock_digest_on_connection"));
        assert!(helper.contains("is_unreferenced_on_connection"));
        assert!(helper.contains("delete_object(&cleanup.storage_key)"));
        assert!(helper.contains("delete_if_unreferenced_on_connection"));
        assert!(helper.contains("unlock_digest_on_connection"));
    }

    #[test]
    fn sticker_storage_key_preserves_raw_server_path() {
        assert_eq!(
            sticker_storage_key("stickers/123/456.webp", 123, 456),
            Some("stickers/123/456.webp".to_string())
        );
    }

    #[test]
    fn sticker_storage_key_extracts_cdn_url_without_query_or_fragment() {
        assert_eq!(
            sticker_storage_key(
                "https://cdn.example.test/media/stickers/123/456.webp?width=160#preview",
                123,
                456,
            ),
            Some("stickers/123/456.webp".to_string())
        );
    }

    #[test]
    fn sticker_storage_key_rejects_mismatched_or_unsafe_paths() {
        assert_eq!(sticker_storage_key("456.webp", 123, 456), None);
        assert_eq!(sticker_storage_key("stickers/999/456.webp", 123, 456), None);
        assert_eq!(sticker_storage_key("stickers/123/999.webp", 123, 456), None);
        assert_eq!(
            sticker_storage_key("stickers/123/456.webp/extra", 123, 456),
            None
        );
        assert_eq!(sticker_storage_key("stickers/123/456.", 123, 456), None);
        assert_eq!(
            sticker_storage_key("stickers/123/456.we/bp", 123, 456),
            None
        );
        assert_eq!(
            sticker_storage_key("attachments/123/456.webp", 123, 456),
            None
        );
        assert_eq!(
            sticker_storage_key("stickers\\123\\456.webp", 123, 456),
            None
        );
    }
}
