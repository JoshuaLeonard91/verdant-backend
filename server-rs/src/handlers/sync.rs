use axum::{
    Json,
    extract::{Query, State},
    http::header::{CACHE_CONTROL, PRAGMA},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, AppResult},
    middleware::{auth::UserId, rate_limit},
    services::pg::messages::FLAG_DELETED,
    state::AppState,
};

const MAX_FUTURE_CURSOR_SKEW_MS: i64 = 5 * 60 * 1000;
const MAX_SUMMARY_ROWS: i64 = 200;
const SERVER_SUMMARY_SQL: &str = r#"
        WITH visible_channels AS (
            SELECT c.id AS channel_id, c.server_id
              FROM channels c
              JOIN servers s ON s.id = c.server_id
              JOIN server_members sm
                ON sm.server_id = c.server_id
               AND sm.user_id = $1
             WHERE s.deleted_at_ms IS NULL
               AND c.type = 0
               AND app.has_permission(app.user_channel_permissions($1, c.id), 1)
        ),
        unread_messages AS (
            SELECT
                vc.server_id,
                m.content,
                m.created_at_ms
              FROM visible_channels vc
              JOIN messages m ON m.channel_id = vc.channel_id
              LEFT JOIN read_states rs
                ON rs.user_id = $1
               AND rs.channel_id = vc.channel_id
             WHERE (m.flags & $4) = 0
               AND m.author_id <> $1
               AND m.id > COALESCE(rs.last_read_message_id, 0)
        )
        SELECT
            server_id AS id,
            COUNT(*)::bigint AS unread_count,
            COUNT(*) FILTER (
                WHERE content ILIKE $2 OR content ILIKE $3
            )::bigint AS mention_count,
            MAX(created_at_ms) AS last_activity_ms
          FROM unread_messages
         GROUP BY server_id
        HAVING $5::bigint IS NULL OR MAX(created_at_ms) > $5
         ORDER BY MAX(created_at_ms) DESC
         LIMIT $6
        "#;
const DM_SUMMARY_SQL: &str = r#"
        WITH user_dms AS (
            SELECT dm.channel_id
              FROM dm_members dm
             WHERE dm.user_id = $1
        ),
        unread_messages AS (
            SELECT
                ud.channel_id,
                m.content,
                m.created_at_ms
              FROM user_dms ud
              JOIN messages m ON m.channel_id = ud.channel_id
              LEFT JOIN read_states rs
                ON rs.user_id = $1
               AND rs.channel_id = ud.channel_id
             WHERE (m.flags & $4) = 0
               AND m.author_id <> $1
               AND m.id > COALESCE(rs.last_read_message_id, 0)
        )
        SELECT
            channel_id AS id,
            COUNT(*)::bigint AS unread_count,
            COUNT(*) FILTER (
                WHERE content ILIKE $2 OR content ILIKE $3
            )::bigint AS mention_count,
            MAX(created_at_ms) AS last_activity_ms
          FROM unread_messages
         GROUP BY channel_id
        HAVING $5::bigint IS NULL OR MAX(created_at_ms) > $5
         ORDER BY MAX(created_at_ms) DESC
         LIMIT $6
        "#;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummaryQuery {
    since: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncServerSummary {
    pub server_id: String,
    pub unread_count: i64,
    pub mention_count: i64,
    pub last_activity_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDmSummary {
    pub channel_id: String,
    pub unread_count: i64,
    pub mention_count: i64,
    pub last_activity_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncNotificationSummary {
    pub kind: String,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummaryResponse {
    pub cursor: String,
    pub servers: Vec<SyncServerSummary>,
    pub dms: Vec<SyncDmSummary>,
    pub notifications: Vec<SyncNotificationSummary>,
    pub requires_reconnect: bool,
}

impl SyncSummaryResponse {
    #[cfg(test)]
    fn empty(now_ms: i64) -> Self {
        Self {
            cursor: now_ms.to_string(),
            servers: Vec::new(),
            dms: Vec::new(),
            notifications: Vec::new(),
            requires_reconnect: false,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SummaryRow {
    id: i64,
    unread_count: i64,
    mention_count: i64,
    last_activity_ms: Option<i64>,
}

pub async fn summary(
    State(state): State<AppState>,
    user_id: UserId,
    Query(query): Query<SyncSummaryQuery>,
) -> AppResult<impl IntoResponse> {
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let since_ms = parse_summary_cursor(query.since.as_deref(), now_ms)?;
    let user = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|error| {
            tracing::error!(user_id = user_id.0, error = %error, "sync summary: user lookup failed");
            AppError::Internal
        })?
        .ok_or(AppError::TokenInvalid)?;
    let mention_user_id = format!("%@{}%", user_id.0);
    let mention_username = format!("%@{}%", user.username);

    let (server_rows, dm_rows) = tokio::try_join!(
        load_server_summaries(
            &state,
            user_id.0,
            since_ms,
            &mention_user_id,
            &mention_username
        ),
        load_dm_summaries(
            &state,
            user_id.0,
            since_ms,
            &mention_user_id,
            &mention_username
        )
    )?;

    let response = SyncSummaryResponse {
        cursor: now_ms.to_string(),
        servers: server_rows
            .into_iter()
            .map(|row| SyncServerSummary {
                server_id: row.id.to_string(),
                unread_count: row.unread_count,
                mention_count: row.mention_count,
                last_activity_at: row.last_activity_ms.and_then(rfc3339_from_ms),
            })
            .collect(),
        dms: dm_rows
            .into_iter()
            .map(|row| SyncDmSummary {
                channel_id: row.id.to_string(),
                unread_count: row.unread_count,
                mention_count: row.mention_count,
                last_activity_at: row.last_activity_ms.and_then(rfc3339_from_ms),
            })
            .collect(),
        notifications: Vec::new(),
        requires_reconnect: false,
    };

    tracing::info!(
        user_id = user_id.0,
        since_ms = ?since_ms,
        server_count = response.servers.len(),
        dm_count = response.dms.len(),
        "sync summary served"
    );

    Ok((
        [(CACHE_CONTROL, "private, no-store"), (PRAGMA, "no-cache")],
        Json(response),
    ))
}

fn parse_summary_cursor(raw: Option<&str>, now_ms: i64) -> AppResult<Option<i64>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 19
        || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::Validation("Invalid sync cursor".into()));
    }
    let value = trimmed
        .parse::<i64>()
        .map_err(|_| AppError::Validation("Invalid sync cursor".into()))?;
    if value < 0 || value > now_ms.saturating_add(MAX_FUTURE_CURSOR_SKEW_MS) {
        return Err(AppError::Validation("Invalid sync cursor".into()));
    }
    Ok(Some(value))
}

fn rfc3339_from_ms(ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|timestamp| timestamp.to_rfc3339())
}

async fn load_server_summaries(
    state: &AppState,
    user_id: i64,
    since_ms: Option<i64>,
    mention_user_id: &str,
    mention_username: &str,
) -> AppResult<Vec<SummaryRow>> {
    sqlx::query_as::<_, SummaryRow>(SERVER_SUMMARY_SQL)
        .bind(user_id)
        .bind(mention_user_id)
        .bind(mention_username)
        .bind(FLAG_DELETED)
        .bind(since_ms)
        .bind(MAX_SUMMARY_ROWS)
        .fetch_all(&state.pg)
        .await
        .map_err(|error| {
            tracing::error!(user_id, error = %error, "sync summary: server summary query failed");
            AppError::Internal
        })
}

async fn load_dm_summaries(
    state: &AppState,
    user_id: i64,
    since_ms: Option<i64>,
    mention_user_id: &str,
    mention_username: &str,
) -> AppResult<Vec<SummaryRow>> {
    sqlx::query_as::<_, SummaryRow>(DM_SUMMARY_SQL)
        .bind(user_id)
        .bind(mention_user_id)
        .bind(mention_username)
        .bind(FLAG_DELETED)
        .bind(since_ms)
        .bind(MAX_SUMMARY_ROWS)
        .fetch_all(&state.pg)
        .await
        .map_err(|error| {
            tracing::error!(user_id, error = %error, "sync summary: DM summary query failed");
            AppError::Internal
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_cursor_accepts_absent_or_bounded_millis() {
        assert_eq!(parse_summary_cursor(None, 1_800_000_000_000).unwrap(), None);
        assert_eq!(
            parse_summary_cursor(Some("1782864000000"), 1_800_000_000_000).unwrap(),
            Some(1_782_864_000_000)
        );
    }

    #[test]
    fn summary_cursor_rejects_blank_negative_oversized_and_future_values() {
        for raw in ["", "   ", "-1", "123abc", "999999999999999999999"] {
            assert!(parse_summary_cursor(Some(raw), 1_800_000_000_000).is_err());
        }

        assert!(
            parse_summary_cursor(Some("1800000600001"), 1_800_000_000_000).is_err(),
            "cursor more than five minutes in the future must fail closed"
        );
    }

    #[test]
    fn summary_response_defaults_to_content_free_reconnect_false_payload() {
        let response = SyncSummaryResponse::empty(1_800_000_000_000);
        assert_eq!(response.cursor, "1800000000000");
        assert!(response.servers.is_empty());
        assert!(response.dms.is_empty());
        assert!(response.notifications.is_empty());
        assert!(!response.requires_reconnect);
    }

    #[test]
    fn server_summary_sql_keeps_membership_visibility_and_read_state_gates() {
        for required in [
            "JOIN server_members sm",
            "sm.user_id = $1",
            "s.deleted_at_ms IS NULL",
            "c.type = 0",
            "app.has_permission(app.user_channel_permissions($1, c.id), 1)",
            "LEFT JOIN read_states rs",
            "m.author_id <> $1",
            "m.id > COALESCE(rs.last_read_message_id, 0)",
            "LIMIT $6",
        ] {
            assert!(
                SERVER_SUMMARY_SQL.contains(required),
                "server summary SQL must include `{required}`"
            );
        }
    }

    #[test]
    fn dm_summary_sql_keeps_dm_membership_and_read_state_gates() {
        for required in [
            "FROM dm_members dm",
            "dm.user_id = $1",
            "LEFT JOIN read_states rs",
            "m.author_id <> $1",
            "m.id > COALESCE(rs.last_read_message_id, 0)",
            "LIMIT $6",
        ] {
            assert!(
                DM_SUMMARY_SQL.contains(required),
                "DM summary SQL must include `{required}`"
            );
        }
    }

    #[test]
    fn summary_response_serializes_without_message_content_or_media_urls() {
        let response = SyncSummaryResponse {
            cursor: "1800000000100".into(),
            servers: vec![SyncServerSummary {
                server_id: "42".into(),
                unread_count: 5,
                mention_count: 3,
                last_activity_at: Some("2026-06-21T12:00:00+00:00".into()),
            }],
            dms: vec![SyncDmSummary {
                channel_id: "84".into(),
                unread_count: 2,
                mention_count: 1,
                last_activity_at: Some("2026-06-21T12:01:00+00:00".into()),
            }],
            notifications: Vec::new(),
            requires_reconnect: false,
        };

        let json = serde_json::to_value(response).unwrap();
        let text = json.to_string();
        for forbidden in [
            "content",
            "message",
            "body",
            "attachment",
            "url",
            "author",
            "member",
            "role",
            "presence",
            "relationship",
        ] {
            assert!(
                !text.contains(forbidden),
                "summary response must stay content-free and omit `{forbidden}`"
            );
        }
    }
}
