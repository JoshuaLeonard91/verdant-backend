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
use crate::middleware::{auth::UserId, rate_limit};
use crate::repo::{categories, channels};
use crate::services::permissions::bits;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_CATEGORIES_PER_SERVER: i64 = 50;

/// Max bytes for a category emoji — one complex ZWJ grapheme fits in ~30.
const MAX_CATEGORY_EMOJI_BYTES: usize = 32;

async fn enqueue_federation_category_event(
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

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateCategoryRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub emoji: Option<String>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCategoryRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    pub position: Option<i32>,
    /// Passing explicit null clears the emoji; omitting the field leaves it unchanged.
    pub emoji: Option<Option<String>>,
}

// ─── POST /api/servers/:serverId/categories ─────────────────────────

pub async fn create_category(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<CreateCategoryRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!(
        "POST /api/servers/{}/categories user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::CATEGORY_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    if body.name.is_empty() || body.name.len() > 100 {
        tracing::warn!(
            "Category name validation failed server_id={} user_id={}",
            server_id,
            user_id.0
        );
        return Err(AppError::Validation(
            "Category name must be 1-100 characters".into(),
        ));
    }
    if let Some(ref emoji) = body.emoji {
        if emoji.len() > MAX_CATEGORY_EMOJI_BYTES {
            return Err(AppError::Validation(format!(
                "Category emoji must be at most {MAX_CATEGORY_EMOJI_BYTES} bytes"
            )));
        }
    }

    let existing_cats = crate::services::pg::categories::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_category: PG list categories failed");
            AppError::Internal
        })?;
    if existing_cats.len() as i64 >= MAX_CATEGORIES_PER_SERVER {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "CATEGORY_LIMIT_REACHED",
            message: format!(
                "Server has reached the maximum of {MAX_CATEGORIES_PER_SERVER} categories"
            ),
        });
    }

    // Position: after all existing top-level items (max category position
    // and max uncategorized channel position).
    let max_cat = existing_cats.iter().map(|c| c.position).max().unwrap_or(-1);
    let server_channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_category: PG list channels failed");
            AppError::Internal
        })?;
    let max_ch = server_channels
        .iter()
        .filter(|c| c.category_id.is_none())
        .map(|c| c.position)
        .max()
        .unwrap_or(-1);
    let position = std::cmp::max(max_cat, max_ch) + 1;

    let id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();

    let emoji_trimmed: Option<String> = body
        .emoji
        .as_ref()
        .map(|e| e.clone())
        .filter(|e| !e.is_empty());

    crate::services::pg::categories::insert(
        &state.pg,
        id,
        server_id,
        &body.name,
        position,
        emoji_trimmed.as_deref(),
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(category_id = id, error = %e, "create_category: PG write failed");
        AppError::Internal
    })?;

    let cat_data = json!({
        "id": id.to_string(),
        "serverId": server_id_str,
        "name": body.name,
        "position": position,
        "emoji": emoji_trimmed,
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    });

    // Broadcast CATEGORY_CREATE
    let json_text = events::category_create_json(&cat_data);
    let proto_msg = events::category_create_proto(crate::proto::Category {
        id: id.to_string(),
        server_id: server_id_str.clone(),
        name: body.name.clone(),
        position,
        created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        emoji: emoji_trimmed.clone(),
    });
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    enqueue_federation_category_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::CategoryCreate {
            server_id,
            actor_user_id: user_id.0,
            category_id: id,
            name: body.name.clone(),
            emoji: emoji_trimmed.clone(),
        },
        "Federation category create producer completed",
    )
    .await;

    tracing::info!(
        "Category created id={} name={} server_id={}",
        id,
        body.name,
        server_id
    );
    Ok((StatusCode::CREATED, Json(cat_data)).into_response())
}

// ─── GET /api/servers/:serverId/categories ──────────────────────────

pub async fn list_categories(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/categories user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;

    let rows = crate::services::pg::categories::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_categories: PG read failed");
            AppError::Internal
        })?;

    let result: Vec<Value> = rows
        .iter()
        .map(|c| json!(categories::CategoryResponse::from(c)))
        .collect();

    tracing::info!(
        "Listed {} categories for server_id={}",
        result.len(),
        server_id
    );
    Ok(Json(json!(result)))
}

// ─── PATCH /api/servers/:serverId/categories/:categoryId ────────────

pub async fn update_category(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, category_id_str)): Path<(String, String)>,
    Json(body): Json<UpdateCategoryRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "PATCH /api/servers/{}/categories/{} user_id={}",
        server_id_str,
        category_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::CATEGORY_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let category_id = parse_id(&category_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    if let Some(ref name) = body.name {
        if name.is_empty() || name.len() > 100 {
            return Err(AppError::Validation(
                "Category name must be 1-100 characters".into(),
            ));
        }
    }
    if let Some(Some(ref emoji)) = body.emoji {
        if emoji.len() > MAX_CATEGORY_EMOJI_BYTES {
            return Err(AppError::Validation(format!(
                "Category emoji must be at most {MAX_CATEGORY_EMOJI_BYTES} bytes"
            )));
        }
    }

    let has_changes = body.name.is_some() || body.position.is_some() || body.emoji.is_some();
    if !has_changes {
        return Err(AppError::NoChanges);
    }

    // Validate the row exists and belongs to this server before patching.
    let existing = crate::services::pg::categories::by_id(&state.pg, category_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, category_id, error = %e, "update_category: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("category"))?;
    if existing.server_id != server_id {
        return Err(AppError::NotFound("category"));
    }

    // Translate the wire-level Option<Option<String>> for emoji into
    // pg::categories::update's Option<Option<&str>> so a JSON null clears
    // the column to SQL NULL while an absent field leaves it untouched.
    let emoji_patch: Option<Option<&str>> = body
        .emoji
        .as_ref()
        .map(|outer| outer.as_deref().filter(|s| !s.is_empty()));

    crate::services::pg::categories::update(
        &state.pg,
        category_id,
        body.name.as_deref(),
        body.position,
        emoji_patch,
    )
    .await
    .map_err(|e| {
        tracing::error!(category_id, error = %e, "update_category: PG write failed");
        AppError::Internal
    })?;

    let updated = crate::services::pg::categories::by_id(&state.pg, category_id)
        .await
        .map_err(|e| {
            tracing::error!(category_id, error = %e, "update_category: PG re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("category"))?;

    // Broadcast CATEGORY_UPDATE
    let cat_json = json!(categories::CategoryResponse::from(&updated));
    let json_text = events::category_update_json(&cat_json);
    let proto_msg = events::category_update_proto(crate::proto::Category {
        id: updated.id.to_string(),
        server_id: updated.server_id.to_string(),
        name: updated.name.clone(),
        position: updated.position,
        created_at: updated.created_at.to_rfc3339(),
        emoji: updated.emoji.clone(),
    });
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    enqueue_federation_category_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::CategoryUpdate {
            server_id,
            actor_user_id: user_id.0,
            category_id,
            name: body.name.clone(),
            position: body.position,
            emoji: body.emoji.clone(),
        },
        "Federation category update producer completed",
    )
    .await;

    tracing::info!(
        "Category updated id={} server_id={}",
        category_id,
        server_id
    );
    Ok(Json(cat_json))
}

// ─── DELETE /api/servers/:serverId/categories/:categoryId ────────────

pub async fn delete_category(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, category_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/categories/{} user_id={}",
        server_id_str,
        category_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::CATEGORY_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let category_id = parse_id(&category_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    let existing = crate::services::pg::categories::by_id(&state.pg, category_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, category_id, error = %e, "delete_category: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("category"))?;
    if existing.server_id != server_id {
        return Err(AppError::NotFound("category"));
    }

    // Clear category_id pointers on channels under this category, then
    // drop the row. Two statements; not atomic, but a stray pointer
    // would just orphan a channel into "uncategorized" — already the
    // intended end-state on delete.
    sqlx::query("UPDATE channels SET category_id = NULL WHERE category_id = $1")
        .bind(category_id)
        .execute(&state.pg)
        .await
        .map_err(|e| {
            tracing::error!(category_id, error = %e, "delete_category: PG orphan-channel update failed");
            AppError::Internal
        })?;

    crate::services::pg::categories::delete(&state.pg, category_id)
        .await
        .map_err(|e| {
            tracing::error!(category_id, server_id, error = %e, "delete_category: PG delete failed");
            AppError::Internal
        })?;

    // Broadcast CATEGORY_DELETE
    let json_text = events::category_delete_json(&category_id_str, &server_id_str);
    let proto_msg = events::category_delete_proto(category_id_str.clone(), server_id_str.clone());
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    enqueue_federation_category_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::CategoryDelete {
            server_id,
            actor_user_id: user_id.0,
            category_id,
        },
        "Federation category delete producer completed",
    )
    .await;

    tracing::info!(
        "Category deleted id={} server_id={}",
        category_id,
        server_id
    );
    Ok(Json(json!({ "success": true })))
}

// ─── GET /api/servers/:serverId/layout ──────────────────────────────

pub async fn get_layout(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/layout user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;

    let cats = crate::services::pg::categories::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "get_layout: PG category read failed");
            AppError::Internal
        })?;
    let chs = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "get_layout: PG channel read failed");
            AppError::Internal
        })?;

    // Filter channels by VIEW_CHANNEL. Use the DB-backed async
    // check so the cache-miss path doesn't fail OPEN to server-level
    // bits and leak the name/id of a channel with a channel-scoped
    // @everyone deny override.
    let mut filtered_chs = Vec::with_capacity(chs.len());
    for c in chs {
        let allowed = state
            .permissions
            .check_channel_permission(user_id.0, c.id, server_id, bits::VIEW_CHANNEL)
            .await
            .is_ok();
        if allowed {
            filtered_chs.push(c);
        }
    }
    let chs = filtered_chs;

    let cat_list: Vec<Value> = cats
        .iter()
        .map(|c| json!(categories::CategoryResponse::from(c)))
        .collect();
    let ch_list: Vec<Value> = chs
        .iter()
        .map(|c| json!(channels::ChannelResponse::from(c)))
        .collect();

    tracing::info!(
        "Layout fetched server_id={} categories={} channels={}",
        server_id,
        cat_list.len(),
        ch_list.len()
    );
    Ok(Json(json!({
        "categories": cat_list,
        "channels": ch_list,
    })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("categories.rs");

    fn source_after_signature(signature_kind: &str, name: &str) -> &'static str {
        let signature = format!("{signature_kind} {name}");
        let after_signature = SOURCE
            .split(&signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} handler should exist"));
        after_signature
            .split("// ───")
            .next()
            .expect("handler source section should be present")
    }

    fn handler_source(name: &str) -> &str {
        source_after_signature("pub async fn", name)
    }

    fn private_async_source(name: &str) -> &str {
        source_after_signature("async fn", name)
    }

    #[test]
    fn create_category_enqueues_federation_category_create() {
        let handler = handler_source("create_category");

        assert!(handler.contains("FederationLocalEvent::CategoryCreate"));
        assert!(handler.contains("enqueue_federation_category_event"));
    }

    #[test]
    fn update_category_enqueues_federation_category_update() {
        let handler = handler_source("update_category");

        assert!(handler.contains("FederationLocalEvent::CategoryUpdate"));
        assert!(handler.contains("enqueue_federation_category_event"));
    }

    #[test]
    fn delete_category_enqueues_federation_category_delete() {
        let handler = handler_source("delete_category");

        assert!(handler.contains("FederationLocalEvent::CategoryDelete"));
        assert!(handler.contains("enqueue_federation_category_event"));
    }

    #[test]
    fn category_federation_helper_uses_server_scope() {
        let helper = private_async_source("enqueue_federation_category_event");

        assert!(helper.contains("FederationRouteScope::Server"));
        assert!(helper.contains("enqueue_local_event_for_scope"));
    }
}
