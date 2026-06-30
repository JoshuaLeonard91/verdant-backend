use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::auth::UserId;
use crate::services::permissions::bits;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopLevelItem {
    pub id: String,
    pub r#type: String, // "channel" or "category"
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReorderRequest {
    pub top_level: Vec<TopLevelItem>,
    pub categories: std::collections::HashMap<String, Vec<String>>,
}

// ─── PUT /api/servers/:serverId/reorder ─────────────────────────────

pub async fn reorder(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<ReorderRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PUT /api/servers/{}/reorder user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_CHANNELS)
        .await?;

    // Load the server's current channel + category sets from PG so
    // we can enforce "id belongs to this server" without per-id round
    // trips AND drive the position / category_id updates below.
    let mut channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "reorder: PG channel list failed");
            AppError::Internal
        })?;
    let mut categories = crate::services::pg::categories::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "reorder: PG category list failed");
            AppError::Internal
        })?;

    // Validate all referenced IDs belong to this server
    for item in &body.top_level {
        let id = parse_id(&item.id)?;
        match item.r#type.as_str() {
            "channel" => {
                if !channels.iter().any(|c| c.id == id) {
                    return Err(AppError::Validation(
                        "Channel does not belong to this server".into(),
                    ));
                }
            }
            "category" => {
                if !categories.iter().any(|c| c.id == id) {
                    return Err(AppError::Validation(
                        "Category does not belong to this server".into(),
                    ));
                }
            }
            _ => return Err(AppError::Validation("Invalid top-level item type".into())),
        }
    }
    for (cat_id, channel_ids) in &body.categories {
        let cid = parse_id(cat_id)?;
        if !categories.iter().any(|c| c.id == cid) {
            return Err(AppError::Validation(
                "Category does not belong to this server".into(),
            ));
        }
        for ch_id in channel_ids {
            let chid = parse_id(ch_id)?;
            if !channels.iter().any(|c| c.id == chid) {
                return Err(AppError::Validation(
                    "Channel does not belong to this server".into(),
                ));
            }
        }
    }

    // 1. Top-level items — set position + clear category_id for channels
    for (i, item) in body.top_level.iter().enumerate() {
        let id = parse_id(&item.id)?;
        let pos = i as i32;
        if item.r#type == "channel" {
            if let Some(ch) = channels.iter_mut().find(|c| c.id == id) {
                ch.position = pos;
                ch.category_id = None;
            }
        } else if let Some(cat) = categories.iter_mut().find(|c| c.id == id) {
            cat.position = pos;
        }
    }

    // 2. Channels within categories — set position + category_id
    for (cat_id, channel_ids) in &body.categories {
        let cid = parse_id(cat_id)?;
        for (i, ch_id) in channel_ids.iter().enumerate() {
            let chid = parse_id(ch_id)?;
            if let Some(ch) = channels.iter_mut().find(|c| c.id == chid) {
                ch.position = i as i32;
                ch.category_id = Some(cid);
            }
        }
    }

    // 3. Persist back to PG. Bounded list, so per-row UPDATE is fine.
    //    The server stays consistent regardless of partial failure.
    for ch in &channels {
        if let Err(e) = crate::services::pg::channels::update(
            &state.pg,
            ch.id,
            crate::services::pg::channels::UpdateChannel {
                position: Some(ch.position),
                category_id: Some(ch.category_id),
                ..Default::default()
            },
        )
        .await
        {
            tracing::warn!(channel_id = ch.id, error = %e, "reorder: PG channel update failed");
        }
    }
    for cat in &categories {
        if let Err(e) = crate::services::pg::categories::update(
            &state.pg,
            cat.id,
            None,
            Some(cat.position),
            None,
        )
        .await
        {
            tracing::warn!(category_id = cat.id, error = %e, "reorder: PG category update failed");
        }
    }

    // Broadcast CHANNEL_UPDATE for each channel — the layout changed.
    let topic = topics::presence_topic(server_id);
    let sid_str = server_id.to_string();

    for ch in &channels {
        let cat_str = ch.category_id.map(|c| c.to_string());
        let ch_json = serde_json::json!({
            "id": ch.id.to_string(),
            "serverId": sid_str,
            "name": ch.name,
            "type": ch.r#type,
            "position": ch.position,
            "categoryId": cat_str
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        });
        let json_text = crate::ws::events::channel_update_json(&ch_json);
        let proto_msg = events::channel_update_proto(crate::proto::Channel {
            id: ch.id.to_string(),
            r#type: ch.r#type,
            server_id: Some(sid_str.clone()),
            name: ch.name.clone(),
            topic: ch.topic.clone(),
            position: ch.position,
            category_id: cat_str,
            created_at: String::new(),
            read_only: ch.read_only,
            slowmode_seconds: ch.slowmode_seconds,
        });
        topics::publish(&state, &topic, &json_text, &proto_msg).await;
    }

    let top_level = body
        .top_level
        .iter()
        .map(|item| {
            Ok(crate::federation::producer::FederationLayoutItem {
                id: parse_id(&item.id)?,
                item_type: item.r#type.clone(),
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let categories = body
        .categories
        .iter()
        .map(|(category_id, channel_ids)| {
            Ok(crate::federation::producer::FederationCategoryLayout {
                category_id: parse_id(category_id)?,
                channel_ids: channel_ids
                    .iter()
                    .map(|id| parse_id(id))
                    .collect::<AppResult<Vec<_>>>()?,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    match crate::federation::producer::enqueue_local_event_for_scope(
        &state,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        &crate::federation::producer::FederationLocalEvent::ChannelReorder {
            server_id,
            actor_user_id: user_id.0,
            top_level,
            categories,
        },
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
            "Federation channel reorder producer completed"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            server_id,
            error = %error,
            "Federation channel reorder producer failed"
        ),
    }

    tracing::info!("Channels reordered server={} by={}", server_id, user_id.0);
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("reorder.rs");

    #[test]
    fn reorder_enqueues_federation_channel_reorder_after_persistence() {
        let handler = SOURCE
            .split("pub async fn reorder")
            .nth(1)
            .expect("reorder handler should exist");

        assert!(handler.contains("FederationLocalEvent::ChannelReorder"));
        assert!(handler.contains("enqueue_local_event_for_scope"));
        assert!(handler.contains("FederationRouteScope::Server"));
    }
}
