//! Moderation actions (bans, mutes, kicks) + user-submitted reports.
//!
//! Live ban/mute state lives in Redis (`banned:{server_id}` set) for
//! O(1) check on the message hot path; this is the durable record +
//! audit history.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ModerationActionRow {
    pub id: i64,
    pub server_id: i64,
    pub target_user_id: i64,
    pub action_type: String, // 'ban' | 'mute' | 'kick'
    pub reason: Option<String>,
    pub moderator_id: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub struct InsertAction<'a> {
    pub id: i64,
    pub server_id: i64,
    pub target_user_id: i64,
    pub action_type: &'a str,
    pub reason: Option<&'a str>,
    pub moderator_id: i64,
    pub expires_at_ms: Option<i64>,
    pub now_ms: i64,
}

pub async fn insert(pool: &PgPool, a: InsertAction<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO moderation_actions
            (id, server_id, target_user_id, action_type, reason,
             moderator_id, expires_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(a.id)
    .bind(a.server_id)
    .bind(a.target_user_id)
    .bind(a.action_type)
    .bind(a.reason)
    .bind(a.moderator_id)
    .bind(a.expires_at_ms)
    .bind(a.now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke an action (unban / unmute). Records who revoked + when.
pub async fn revoke(pool: &PgPool, id: i64, now_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE moderation_actions SET revoked_at_ms = $2 WHERE id = $1 AND revoked_at_ms IS NULL",
    )
    .bind(id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// "Active actions of type X for user Y in server Z" — partial index covers it.
pub async fn active_for_target(
    pool: &PgPool,
    server_id: i64,
    target_user_id: i64,
    action_type: &str,
    now_ms: i64,
) -> Result<Option<ModerationActionRow>, sqlx::Error> {
    sqlx::query_as::<_, ModerationActionRow>(
        r#"
        SELECT * FROM moderation_actions
         WHERE server_id = $1
           AND target_user_id = $2
           AND action_type = $3
           AND revoked_at_ms IS NULL
           AND (expires_at_ms IS NULL OR expires_at_ms > $4)
         ORDER BY created_at_ms DESC
         LIMIT 1
        "#,
    )
    .bind(server_id)
    .bind(target_user_id)
    .bind(action_type)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

/// Server's recent moderation history (admin UI).
pub async fn list_for_server(
    pool: &PgPool,
    server_id: i64,
    limit: i64,
) -> Result<Vec<ModerationActionRow>, sqlx::Error> {
    sqlx::query_as::<_, ModerationActionRow>(
        r#"
        SELECT * FROM moderation_actions
         WHERE server_id = $1
         ORDER BY created_at_ms DESC
         LIMIT $2
        "#,
    )
    .bind(server_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ─── reports ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReportRow {
    pub id: i64,
    pub reporter_id: i64,
    pub target_type: String, // 'message' | 'user' | 'server' | 'channel'
    pub target_id: i64,
    pub reason: String,
    pub status: String, // 'pending' | 'reviewed' | 'actioned' | 'dismissed'
    pub resolved_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn report_insert(
    pool: &PgPool,
    id: i64,
    reporter_id: i64,
    target_type: &str,
    target_id: i64,
    reason: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query_scalar::<_, i64>(
        r#"
        INSERT INTO reports
            (id, reporter_id, target_type, target_id, reason, status, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,'pending',$6)
        ON CONFLICT (reporter_id, target_type, target_id)
            WHERE status = 'pending'
        DO NOTHING
        RETURNING id
        "#,
    )
    .bind(id)
    .bind(reporter_id)
    .bind(target_type)
    .bind(target_id)
    .bind(reason)
    .bind(now_ms)
    .fetch_optional(pool)
    .await?;
    Ok(inserted.is_some())
}

pub async fn report_set_status(
    pool: &PgPool,
    id: i64,
    status: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE reports SET status = $2, resolved_at_ms = $3 WHERE id = $1")
        .bind(id)
        .bind(status)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn report_pending_queue(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ReportRow>, sqlx::Error> {
    sqlx::query_as::<_, ReportRow>(
        r#"
        SELECT * FROM reports
         WHERE status = 'pending'
         ORDER BY created_at_ms ASC
         LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}
