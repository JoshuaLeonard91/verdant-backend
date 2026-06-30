//! Read states — per-user, per-channel last-read pointer.
//!
//! GREATEST semantics on update: an out-of-order ACK from another
//! device must NEVER roll the cursor backward. Implemented with
//! `ON CONFLICT DO UPDATE SET last_read_message_id = GREATEST(...)`.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReadStateRow {
    pub user_id: i64,
    pub channel_id: i64,
    pub last_read_message_id: i64,
    pub updated_at_ms: i64,
}

/// Upsert with GREATEST. Single round trip.
pub async fn update(
    pool: &PgPool,
    user_id: i64,
    channel_id: i64,
    last_read_message_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO read_states (user_id, channel_id, last_read_message_id, updated_at_ms)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, channel_id) DO UPDATE
            SET last_read_message_id = GREATEST(read_states.last_read_message_id, EXCLUDED.last_read_message_id),
                updated_at_ms        = GREATEST(read_states.updated_at_ms,        EXCLUDED.updated_at_ms)
        "#,
    )
    .bind(user_id)
    .bind(channel_id)
    .bind(last_read_message_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Used at READY: every read state for a user.
pub async fn list_for_user(pool: &PgPool, user_id: i64) -> Result<Vec<ReadStateRow>, sqlx::Error> {
    sqlx::query_as::<_, ReadStateRow>("SELECT * FROM read_states WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await
}

pub async fn get(
    pool: &PgPool,
    user_id: i64,
    channel_id: i64,
) -> Result<Option<ReadStateRow>, sqlx::Error> {
    sqlx::query_as::<_, ReadStateRow>(
        "SELECT * FROM read_states WHERE user_id = $1 AND channel_id = $2",
    )
    .bind(user_id)
    .bind(channel_id)
    .fetch_optional(pool)
    .await
}

/// Used when a channel is deleted — drop the per-user pointers.
pub async fn delete_for_channel(pool: &PgPool, channel_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM read_states WHERE channel_id = $1")
        .bind(channel_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Used when a user leaves a server — drop their per-channel pointers
/// for channels in that server.
pub async fn delete_for_user_in_server(
    pool: &PgPool,
    user_id: i64,
    server_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM read_states
         WHERE user_id = $1
           AND channel_id IN (SELECT id FROM channels WHERE server_id = $2)
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .execute(pool)
    .await?;
    Ok(())
}
