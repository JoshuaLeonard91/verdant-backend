//! Channels + channel_overrides + pinned_messages.

use super::ms_to_dt;
use crate::repo::channels::ChannelRow;
use sqlx::PgPool;

#[derive(Debug, sqlx::FromRow)]
struct ChannelRaw {
    id: i64,
    server_id: i64,
    r#type: i16,
    name: Option<String>,
    topic: Option<String>,
    position: i32,
    category_id: Option<i64>,
    read_only: bool,
    slowmode_seconds: i32,
    created_at_ms: i64,
}

impl From<ChannelRaw> for ChannelRow {
    fn from(r: ChannelRaw) -> Self {
        Self {
            id: r.id,
            r#type: r.r#type as i32,
            // ChannelRow.server_id is Option (it carries DM channels with
            // None). All rows in the channels table have a server_id, so
            // we always Some(_) here.
            server_id: Some(r.server_id),
            name: r.name,
            topic: r.topic,
            position: r.position,
            category_id: r.category_id,
            read_only: r.read_only,
            slowmode_seconds: r.slowmode_seconds,
            created_at: ms_to_dt(r.created_at_ms),
        }
    }
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<ChannelRow>, sqlx::Error> {
    let r = sqlx::query_as::<_, ChannelRaw>("SELECT * FROM channels WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(r.map(Into::into))
}

pub async fn list_for_server(
    pool: &PgPool,
    server_id: i64,
) -> Result<Vec<ChannelRow>, sqlx::Error> {
    let rs = sqlx::query_as::<_, ChannelRaw>(
        "SELECT * FROM channels WHERE server_id = $1 ORDER BY position ASC, id ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(rs.into_iter().map(Into::into).collect())
}

pub async fn insert(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    r#type: i16,
    name: Option<&str>,
    topic: Option<&str>,
    position: i32,
    category_id: Option<i64>,
    read_only: bool,
    slowmode_seconds: i32,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO channels
            (id, server_id, type, name, topic, position, category_id,
             read_only, slowmode_seconds, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(r#type)
    .bind(name)
    .bind(topic)
    .bind(position)
    .bind(category_id)
    .bind(read_only)
    .bind(slowmode_seconds)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Default)]
pub struct UpdateChannel<'a> {
    pub name: Option<&'a str>,
    pub topic: Option<&'a str>,
    pub position: Option<i32>,
    pub category_id: Option<Option<i64>>,
    pub read_only: Option<bool>,
    pub slowmode_seconds: Option<i32>,
}

pub async fn update(pool: &PgPool, id: i64, p: UpdateChannel<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE channels SET
            name             = COALESCE($2, name),
            topic            = COALESCE($3, topic),
            position         = COALESCE($4, position),
            category_id      = CASE WHEN $5::boolean THEN $6 ELSE category_id END,
            read_only        = COALESCE($7, read_only),
            slowmode_seconds = COALESCE($8, slowmode_seconds)
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(p.name)
    .bind(p.topic)
    .bind(p.position)
    .bind(p.category_id.is_some())
    .bind(p.category_id.flatten())
    .bind(p.read_only)
    .bind(p.slowmode_seconds)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM channels WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn reorder(pool: &PgPool, items: &[(i64, i32)]) -> Result<(), sqlx::Error> {
    if items.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for (id, pos) in items {
        sqlx::query("UPDATE channels SET position = $2 WHERE id = $1")
            .bind(id)
            .bind(pos)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ─── channel_overrides ───────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChannelOverrideRow {
    pub channel_id: i64,
    pub role_id: i64,
    pub allow_bits: i64,
    pub deny_bits: i64,
}

pub async fn list_overrides(
    pool: &PgPool,
    channel_id: i64,
) -> Result<Vec<ChannelOverrideRow>, sqlx::Error> {
    sqlx::query_as::<_, ChannelOverrideRow>("SELECT * FROM channel_overrides WHERE channel_id = $1")
        .bind(channel_id)
        .fetch_all(pool)
        .await
}

pub async fn list_overrides_for_server(
    pool: &PgPool,
    server_id: i64,
) -> Result<Vec<ChannelOverrideRow>, sqlx::Error> {
    sqlx::query_as::<_, ChannelOverrideRow>(
        r#"
        SELECT o.*
          FROM channel_overrides o
          JOIN channels c ON c.id = o.channel_id
         WHERE c.server_id = $1
        "#,
    )
    .bind(server_id)
    .fetch_all(pool)
    .await
}

pub async fn upsert_override(
    pool: &PgPool,
    channel_id: i64,
    role_id: i64,
    allow: i64,
    deny: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO channel_overrides (channel_id, role_id, allow_bits, deny_bits)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (channel_id, role_id) DO UPDATE
            SET allow_bits = EXCLUDED.allow_bits,
                deny_bits  = EXCLUDED.deny_bits
        "#,
    )
    .bind(channel_id)
    .bind(role_id)
    .bind(allow)
    .bind(deny)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_override(
    pool: &PgPool,
    channel_id: i64,
    role_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM channel_overrides WHERE channel_id = $1 AND role_id = $2")
        .bind(channel_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── pinned_messages ─────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PinnedRow {
    pub channel_id: i64,
    pub message_id: i64,
    pub pinned_by: i64,
    pub pinned_at_ms: i64,
}

pub async fn list_pins(pool: &PgPool, channel_id: i64) -> Result<Vec<PinnedRow>, sqlx::Error> {
    sqlx::query_as::<_, PinnedRow>(
        "SELECT * FROM pinned_messages WHERE channel_id = $1 ORDER BY pinned_at_ms DESC",
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await
}

pub async fn add_pin(
    pool: &PgPool,
    channel_id: i64,
    message_id: i64,
    pinned_by: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO pinned_messages (channel_id, message_id, pinned_by, pinned_at_ms)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (channel_id, message_id) DO NOTHING
        "#,
    )
    .bind(channel_id)
    .bind(message_id)
    .bind(pinned_by)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_pin(
    pool: &PgPool,
    channel_id: i64,
    message_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pinned_messages WHERE channel_id = $1 AND message_id = $2")
        .bind(channel_id)
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn pin_count(pool: &PgPool, channel_id: i64) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pinned_messages WHERE channel_id = $1")
        .bind(channel_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}
