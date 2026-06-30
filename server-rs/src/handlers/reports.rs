use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::net::SocketAddr;

use crate::error::{AppError, AppResult};
use crate::handlers::extract_client_ip;
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::audit;
use crate::services::channel_access::verify_channel_access;
use crate::services::permissions::bits;
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ReportBody {
    pub reason: Option<String>,
}

fn sanitize_reason(reason: Option<String>) -> String {
    sanitize_text(&reason.unwrap_or_default())
        .trim()
        .chars()
        .take(500)
        .collect::<String>()
}

async fn shared_report_context(
    state: &AppState,
    actor_id: i64,
    target_id: i64,
) -> AppResult<(bool, Option<i64>)> {
    let (actor_servers, target_servers) = tokio::try_join!(
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, actor_id),
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, target_id),
    )
    .map_err(|e| {
        tracing::error!(actor_id, target_id, error = %e, "report_user: PG server list failed");
        AppError::Internal
    })?;

    let target_set: HashSet<i64> = target_servers.into_iter().collect();
    if let Some(server_id) = actor_servers.into_iter().find(|id| target_set.contains(id)) {
        return Ok((true, Some(server_id)));
    }

    let (actor_dms, target_dms) = tokio::try_join!(
        crate::services::pg::dms::list_channel_ids_for_user(&state.pg, actor_id),
        crate::services::pg::dms::list_channel_ids_for_user(&state.pg, target_id),
    )
    .map_err(|e| {
        tracing::error!(actor_id, target_id, error = %e, "report_user: PG DM list failed");
        AppError::Internal
    })?;

    let target_dm_set: HashSet<i64> = target_dms.into_iter().collect();
    let shares_dm = actor_dms.iter().any(|id| target_dm_set.contains(id));
    Ok((shares_dm, None))
}

/// POST /api/channels/:channelId/messages/:messageId/report
///
/// Allows authenticated users to report a message for violating Terms of Service.
/// Emits a ContentReported audit entry when a new pending report is stored.
pub async fn report_message(
    State(state): State<AppState>,
    user_id: UserId,
    Path((channel_id_str, message_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ReportBody>,
) -> AppResult<impl IntoResponse> {
    // Rate limit: 5 reports per minute
    rate_limit::enforce(&state, &rate_limit::REPORT_LIMIT, &user_id.0.to_string()).await?;

    let channel_id: i64 = channel_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid channel ID".into()))?;
    let message_id: i64 = message_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid message ID".into()))?;

    // Verify channel membership
    let server_id = verify_channel_access(&state, user_id.0, channel_id).await?;

    // A member denied VIEW_CHANNEL via an override must not be able
    // to report messages they can't see — treat as nonexistent.
    if let Some(sid) = server_id {
        state
            .permissions
            .check_channel_permission(user_id.0, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .map_err(|_| AppError::NotFound("channel"))?;
    }

    // Validate reason (max 500 chars, default to empty)
    let reason = sanitize_reason(body.reason);

    // PG lookup of the reported message — confirms it exists,
    // belongs to this channel, and gives us the author id for
    // audit metadata. We fall back to the unhinted partition scan
    // because the report flow doesn't carry a created_at cursor.
    let msg = crate::services::pg::messages::by_id_unhinted(&state.pg, message_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, message_id, error = %e, "report_message: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("message"))?;
    if msg.channel_id != channel_id {
        return Err(AppError::NotFound("message"));
    }
    if crate::services::pg::messages::is_deleted(&msg) {
        return Err(AppError::NotFound("message"));
    }
    let reported_user_id = msg.author_id;

    // Cannot report your own messages
    if reported_user_id == user_id.0 {
        return Err(AppError::Validation(
            "Cannot report your own message".into(),
        ));
    }

    let report_id = state.snowflake.next_id();
    let inserted = crate::services::pg::moderation::report_insert(
        &state.pg,
        report_id,
        user_id.0,
        "message",
        message_id,
        &reason,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(|e| {
        tracing::error!(
            report_id,
            reporter_id = user_id.0,
            message_id,
            error = %e,
            "report_message: report insert failed"
        );
        AppError::Internal
    })?;
    if !inserted {
        return Ok(StatusCode::NO_CONTENT);
    }

    // Resolve reported user's email for metadata
    let reported_email = crate::services::pg::users::by_id(&state.pg, reported_user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.email)
        .unwrap_or_else(|| "unknown".to_string());

    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));

    // Audit log entry is the authoritative record of the report.
    // moderation tooling that used to read `flagged_content`
    // can now scan the audit stream for ContentReported entries.
    audit::log_async(
        state.redis.clone(),
        audit::AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: audit::AuditAction::ContentReported,
            target_type: "message",
            target_id: message_id,
            server_id,
            metadata: Some(json!({
                "source": "user_report",
                "channelId": channel_id.to_string(),
                "reportedUserId": reported_user_id.to_string(),
                "reportedUserEmail": reported_email,
                "reason": reason,
            })),
            ip: Some(client_ip),
        },
        state.pg.clone(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/users/:userId/report
///
/// Allows authenticated users to report another user when they share a
/// server or DM context.
pub async fn report_user(
    State(state): State<AppState>,
    user_id: UserId,
    Path(target_id_str): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ReportBody>,
) -> AppResult<impl IntoResponse> {
    rate_limit::enforce(&state, &rate_limit::REPORT_LIMIT, &user_id.0.to_string()).await?;

    let target_id: i64 = target_id_str
        .parse()
        .map_err(|_| AppError::Validation("Invalid user ID".into()))?;

    if target_id == user_id.0 {
        return Err(AppError::Validation("Cannot report yourself".into()));
    }

    let target = crate::services::pg::users::by_id(&state.pg, target_id)
        .await
        .map_err(|e| {
            tracing::error!(target_id, error = %e, "report_user: target user lookup failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;
    if target.deleted_at.is_some() {
        return Err(AppError::NotFound("user"));
    }

    let (shares_context, server_id) = shared_report_context(&state, user_id.0, target_id).await?;
    if !shares_context {
        return Err(AppError::NotFound("user"));
    }

    let reason = sanitize_reason(body.reason);

    let report_id = state.snowflake.next_id();
    let inserted = crate::services::pg::moderation::report_insert(
        &state.pg,
        report_id,
        user_id.0,
        "user",
        target_id,
        &reason,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(|e| {
        tracing::error!(
            report_id,
            reporter_id = user_id.0,
            target_id,
            error = %e,
            "report_user: report insert failed"
        );
        AppError::Internal
    })?;
    if !inserted {
        return Ok(StatusCode::NO_CONTENT);
    }

    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));
    audit::log_async(
        state.redis.clone(),
        audit::AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: audit::AuditAction::ContentReported,
            target_type: "user",
            target_id,
            server_id,
            metadata: Some(json!({
                "source": "user_report",
                "reportedUserId": target_id.to_string(),
                "reportedUsername": target.username,
                "reason": reason,
            })),
            ip: Some(client_ip),
        },
        state.pg.clone(),
    );

    Ok(StatusCode::NO_CONTENT)
}
