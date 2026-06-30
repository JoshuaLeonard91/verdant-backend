use serde_json::Value;
use std::time::Duration;

use crate::state::AppState;

pub const EVENT_FEED_ANNOUNCEMENT_CREATE: &str = "FEED_ANNOUNCEMENT_CREATE";
pub const EVENT_FEED_ANNOUNCEMENT_UPDATE: &str = "FEED_ANNOUNCEMENT_UPDATE";
pub const EVENT_FEED_ANNOUNCEMENT_DELETE: &str = "FEED_ANNOUNCEMENT_DELETE";
pub const EVENT_MESSAGE_CREATE: &str = "MESSAGE_CREATE";
pub const EVENT_MESSAGE_UPDATE: &str = "MESSAGE_UPDATE";
pub const EVENT_MESSAGE_DELETE: &str = "MESSAGE_DELETE";
pub const EVENT_MEMBER_JOIN: &str = "MEMBER_JOIN";
pub const EVENT_MEMBER_LEAVE: &str = "MEMBER_LEAVE";
pub const EVENT_AUDIT_LOG_CREATE: &str = "AUDIT_LOG_CREATE";

const OUTBOX_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const IDEMPOTENCY_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL_SECS: u64 = 60 * 60;

pub struct BotEvent {
    pub event_type: &'static str,
    pub server_id: Option<i64>,
    pub channel_id: Option<i64>,
    pub feed_id: Option<i64>,
    pub actor_user_id: Option<i64>,
    pub actor_bot_id: Option<i64>,
    pub payload: Value,
}

/// Best-effort outbox insert. This table backs optional bot delivery, so a
/// schema drift or transient write failure must never break user-facing writes.
pub fn enqueue(state: &AppState, event: BotEvent) {
    let pg = state.pg.clone();
    let id = state.snowflake.next_id();
    let created_at_ms = chrono::Utc::now().timestamp_millis();
    tokio::spawn(async move {
        let payload = event.payload;
        let result = crate::services::pg::bot_outbox::insert(
            &pg,
            crate::services::pg::bot_outbox::NewBotOutboxEvent {
                id,
                event_type: event.event_type,
                server_id: event.server_id,
                channel_id: event.channel_id,
                feed_id: event.feed_id,
                actor_user_id: event.actor_user_id,
                actor_bot_id: event.actor_bot_id,
                payload: &payload,
                created_at_ms,
            },
        )
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, event_type = event.event_type, "bot outbox insert failed");
        }
    });
}

pub fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now_ms = chrono::Utc::now().timestamp_millis();
            match crate::services::pg::bot_outbox::delete_before(
                &state.pg,
                now_ms - OUTBOX_RETENTION_MS,
            )
            .await
            {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "bot outbox retention cleanup complete")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "bot outbox retention cleanup failed"),
            }
            match crate::services::pg::bot_outbox::delete_idempotency_before(
                &state.pg,
                now_ms - IDEMPOTENCY_RETENTION_MS,
            )
            .await
            {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "bot idempotency retention cleanup complete")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "bot idempotency retention cleanup failed"),
            }
        }
    });
}
