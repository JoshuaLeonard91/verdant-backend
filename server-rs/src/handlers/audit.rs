use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::AppResult;
use crate::middleware::auth::UserId;
use crate::services::permissions::bits;
use crate::state::AppState;

use super::parse_id;

#[derive(Deserialize)]
pub struct AuditLogParams {
    pub limit: Option<i64>,
    pub before: Option<String>,
}

// ─── GET /api/servers/:serverId/audit-log ──────────────────────────

pub async fn get_audit_log(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Query(params): Query<AuditLogParams>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/audit-log user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    // Require MANAGE_SERVER permission to view audit log
    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let limit = params.limit.unwrap_or(50).min(100).max(1) as u64;
    let before: Option<i64> = params.before.as_deref().and_then(|s| parse_id(s).ok());

    // Reverse-scan the per-server audit stream. Entries are
    // XADD'd in chronological order so XREVRANGE yields newest-
    // first; entries store the snowflake id as a field so we
    // can apply the `before` cursor against the id rather than
    // the stream id (snowflake is monotonic so this matches the
    // legacy `ORDER BY id DESC`).
    //
    // We overfetch by a small factor so the `before` filter can
    // discard newer entries without a second round trip, then
    // truncate to the requested limit.
    let stream_key = format!("audit-log:{server_id}");
    let fetch_cap = (limit.saturating_mul(2)).min(500);
    use fred::interfaces::StreamsInterface;
    let raw: Vec<(String, std::collections::HashMap<String, String>)> =
        StreamsInterface::xrevrange(
            &state.redis,
            stream_key,
            "+".to_string(),
            "-".to_string(),
            Some(fetch_cap),
        )
        .await
        .unwrap_or_default();

    // Resolve actor usernames from PG. Audit log writes hit
    // only a handful of distinct actors per fetch, so the n+1
    // lookup is fine — we cache per-actor inside the loop.
    let mut actor_cache: std::collections::HashMap<i64, (Option<String>, Option<String>)> =
        std::collections::HashMap::new();

    let mut entries: Vec<Value> = Vec::with_capacity(raw.len());
    for (_stream_id, fields) in raw {
        let get = |k: &str| fields.get(k).cloned().unwrap_or_default();
        let id = get("id").parse::<i64>().unwrap_or(0);
        if let Some(before_id) = before {
            if id >= before_id {
                continue;
            }
        }
        let actor_id = get("actor_id").parse::<i64>().unwrap_or(0);
        let target_id = get("target_id").parse::<i64>().unwrap_or(0);
        let metadata_raw = get("metadata");
        let metadata: Option<Value> = if metadata_raw.is_empty() {
            None
        } else {
            serde_json::from_str(&metadata_raw).ok()
        };
        let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            (id >> 22) + 1_735_689_600_000, // Verdant epoch (2025-01-01) — matches SnowflakeGenerator
        )
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();

        // Resolve the actor's profile info, caching per actor_id
        let (actor_username, actor_avatar) = if let Some(pair) = actor_cache.get(&actor_id) {
            pair.clone()
        } else {
            let pair = if actor_id == 0 {
                (None, None)
            } else {
                match crate::services::pg::users::by_id(&state.pg, actor_id)
                    .await
                    .ok()
                    .flatten()
                {
                    Some(u) => (Some(u.username), u.avatar_url.filter(|s| !s.is_empty())),
                    None => (None, None),
                }
            };
            actor_cache.insert(actor_id, pair.clone());
            pair
        };

        entries.push(json!({
            "id": id.to_string(),
            "actorId": actor_id.to_string(),
            "action": get("action"),
            "targetType": get("target_type"),
            "targetId": target_id.to_string(),
            "metadata": metadata,
            "createdAt": created_at,
            "actorUsername": actor_username,
            "actorAvatar": crate::services::cdn::resolve(actor_avatar.as_deref()),
        }));
        if entries.len() as u64 >= limit {
            break;
        }
    }

    tracing::info!(
        "Returned {} audit log entries for server_id={}",
        entries.len(),
        server_id
    );
    Ok(Json(json!({ "entries": entries })))
}
