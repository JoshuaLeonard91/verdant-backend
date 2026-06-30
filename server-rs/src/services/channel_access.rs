use crate::error::{AppError, AppResult};
use crate::services::permissions::CacheResult;
use crate::state::AppState;

/// Verify user has access to a channel. Returns `Some(server_id)` for server
/// channels, `None` for DM channels.
/// Security invariant: existence and membership are checked together so denied
/// channels can be returned as "not found" without leaking channel IDs.
pub async fn verify_channel_access(
    state: &AppState,
    user_id: i64,
    channel_id: i64,
) -> AppResult<Option<i64>> {
    // Try cache first — avoids DB round-trips for known channels.
    match state.permissions.verify_access(user_id, channel_id) {
        CacheResult::Hit(0) => return Ok(None),        // DM — cached
        CacheResult::Hit(sid) => return Ok(Some(sid)), // Server channel — cached
        CacheResult::Denied(_) => return Err(AppError::NotFound("channel")),
        CacheResult::Miss => {} // Fall through to PG
    }

    // Cache miss — query PG. A row in `channels` is a server channel
    // (with `server_id` set); no row means it might be a DM channel
    // living in `dm_channels`, so we fall back to the per-user DM
    // membership index.
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "verify_channel_access: PG channel read failed");
            AppError::Internal
        })?;

    if let Some(c) = channel {
        let sid = c.server_id.ok_or(AppError::NotFound("channel"))?;
        state
            .require_membership(user_id, sid)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
        Ok(Some(sid))
    } else {
        let dm_ids = crate::services::pg::dms::list_channel_ids_for_user(&state.pg, user_id)
            .await
            .unwrap_or_default();
        if !dm_ids.contains(&channel_id) {
            return Err(AppError::NotFound("channel"));
        }
        state.permissions.add_dm_channel(user_id, channel_id);
        Ok(None)
    }
}

/// Ensure `actor_id` can open or send a direct message to `target_id`.
/// Users must not be blocked and must either be friends or share a server.
pub async fn ensure_dm_user_allowed(
    state: &AppState,
    actor_id: i64,
    target_id: i64,
) -> AppResult<()> {
    let blocked = crate::services::pg::relationships::either_blocks(&state.pg, actor_id, target_id)
        .await
        .map_err(|e| {
            tracing::error!(
                actor_id,
                target_id,
                error = %e,
                "DM block check failed"
            );
            AppError::Internal
        })?;
    if blocked {
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "DM_NOT_ALLOWED",
            message: "Unable to message this user".into(),
        });
    }

    let allowed =
        crate::services::pg::relationships::can_direct_message(&state.pg, actor_id, target_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    actor_id,
                    target_id,
                    error = %e,
                    "DM eligibility check failed"
                );
                AppError::Internal
            })?;
    if !allowed {
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::FORBIDDEN,
            code: "DM_NOT_ALLOWED",
            message: "Unable to message this user".into(),
        });
    }

    Ok(())
}

/// Ensure `actor_id` can currently send to a DM channel. This intentionally
/// rechecks every recipient on send so old DM channels do not remain usable
/// after users stop sharing a server or block each other.
pub async fn ensure_dm_channel_send_allowed(
    state: &AppState,
    actor_id: i64,
    channel_id: i64,
) -> AppResult<()> {
    let members = crate::services::pg::dms::list_members(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(
                actor_id,
                channel_id,
                error = %e,
                "DM member read failed"
            );
            AppError::Internal
        })?;
    if !members.iter().any(|m| m.user_id == actor_id) {
        return Err(AppError::NotFound("channel"));
    }

    for member in members.iter().filter(|m| m.user_id != actor_id) {
        ensure_dm_user_allowed(state, actor_id, member.user_id).await?;
    }

    Ok(())
}
