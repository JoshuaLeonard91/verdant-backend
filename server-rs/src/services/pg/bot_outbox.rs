//! Durable event outbox for bot websocket delivery.
//!
//! User realtime still uses the existing websocket topic pipeline. Bots read
//! this table so gateway restarts and bot reconnects can resume from a stable
//! event id without depending on Redis pub/sub delivery.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BotOutboxRow {
    pub id: i64,
    pub event_type: String,
    pub server_id: Option<i64>,
    pub channel_id: Option<i64>,
    pub feed_id: Option<i64>,
    pub actor_user_id: Option<i64>,
    pub actor_bot_id: Option<i64>,
    pub payload: Value,
    pub created_at_ms: i64,
}

pub struct NewBotOutboxEvent<'a> {
    pub id: i64,
    pub event_type: &'a str,
    pub server_id: Option<i64>,
    pub channel_id: Option<i64>,
    pub feed_id: Option<i64>,
    pub actor_user_id: Option<i64>,
    pub actor_bot_id: Option<i64>,
    pub payload: &'a Value,
    pub created_at_ms: i64,
}

pub enum BotIdempotencyReservation {
    Reserved,
    Existing(Value),
}

pub async fn insert(pool: &PgPool, event: NewBotOutboxEvent<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO bot_event_outbox
            (id, event_type, server_id, channel_id, feed_id,
             actor_user_id, actor_bot_id, payload, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(event.id)
    .bind(event.event_type)
    .bind(event.server_id)
    .bind(event.channel_id)
    .bind(event.feed_id)
    .bind(event.actor_user_id)
    .bind(event.actor_bot_id)
    .bind(event.payload)
    .bind(event.created_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn latest_id(pool: &PgPool, server_id: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(id), 0) FROM bot_event_outbox WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_one(pool)
    .await
}

pub async fn list_after(
    pool: &PgPool,
    server_id: i64,
    after_id: i64,
    limit: i64,
) -> Result<Vec<BotOutboxRow>, sqlx::Error> {
    sqlx::query_as::<_, BotOutboxRow>(
        r#"
        SELECT *
          FROM bot_event_outbox
         WHERE server_id = $1
           AND id > $2
         ORDER BY id ASC
         LIMIT $3
        "#,
    )
    .bind(server_id)
    .bind(after_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn delete_before(pool: &PgPool, cutoff_ms: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM bot_event_outbox WHERE created_at_ms < $1")
        .bind(cutoff_ms)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delete_idempotency_before(pool: &PgPool, cutoff_ms: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM bot_idempotency_keys WHERE created_at_ms < $1")
        .bind(cutoff_ms)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn reserve_bot_idempotency_key(
    tx: &mut Transaction<'_, Postgres>,
    bot_id: i64,
    key: &str,
    response: &Value,
    created_at_ms: i64,
) -> Result<BotIdempotencyReservation, sqlx::Error> {
    let inserted = sqlx::query(
        r#"
        INSERT INTO bot_idempotency_keys (bot_id, key, response, created_at_ms)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (bot_id, key) DO NOTHING
        "#,
    )
    .bind(bot_id)
    .bind(key)
    .bind(response)
    .bind(created_at_ms)
    .execute(&mut **tx)
    .await?;

    if inserted.rows_affected() == 1 {
        return Ok(BotIdempotencyReservation::Reserved);
    }

    let existing = sqlx::query_scalar::<_, Value>(
        "SELECT response FROM bot_idempotency_keys WHERE bot_id = $1 AND key = $2",
    )
    .bind(bot_id)
    .bind(key)
    .fetch_one(&mut **tx)
    .await?;

    Ok(BotIdempotencyReservation::Existing(existing))
}
