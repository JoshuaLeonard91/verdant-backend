//! Reactions — durability backstop. Redis Lua scripts in
//! `services/reactions.rs` are the live RMW path; this is the
//! source-of-truth for cache miss + audit.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReactionRow {
    pub message_id: i64,
    pub emoji: String,
    pub user_id: i64,
    pub created_at_ms: i64,
}

pub async fn add(
    pool: &PgPool,
    message_id: i64,
    emoji: &str,
    user_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO reactions (message_id, emoji, user_id, created_at_ms)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (message_id, emoji, user_id) DO NOTHING
        "#,
    )
    .bind(message_id)
    .bind(emoji)
    .bind(user_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove(
    pool: &PgPool,
    message_id: i64,
    emoji: &str,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM reactions WHERE message_id = $1 AND emoji = $2 AND user_id = $3")
        .bind(message_id)
        .bind(emoji)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn for_message(pool: &PgPool, message_id: i64) -> Result<Vec<ReactionRow>, sqlx::Error> {
    sqlx::query_as::<_, ReactionRow>("SELECT * FROM reactions WHERE message_id = $1")
        .bind(message_id)
        .fetch_all(pool)
        .await
}

/// Batch-fetch for a page of messages.
pub async fn for_messages(
    pool: &PgPool,
    message_ids: &[i64],
) -> Result<Vec<ReactionRow>, sqlx::Error> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, ReactionRow>("SELECT * FROM reactions WHERE message_id = ANY($1::bigint[])")
        .bind(message_ids)
        .fetch_all(pool)
        .await
}

pub async fn delete_all(pool: &PgPool, message_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM reactions WHERE message_id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}
