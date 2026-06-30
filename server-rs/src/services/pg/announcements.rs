//! Announcements — feed cards. content is opaque jsonb (rendered by
//! the client). Soft-delete via `deleted_at_ms`.

use sqlx::{PgPool, Postgres, Transaction};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AnnouncementRow {
    pub id: i64,
    pub feed_id: i64,
    pub server_id: i64,
    pub content: serde_json::Value,
    pub posted_by: Option<i64>,
    pub bot_id: Option<i64>,
    pub updated_at_ms: Option<i64>,
    pub deleted_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<AnnouncementRow>, sqlx::Error> {
    sqlx::query_as::<_, AnnouncementRow>("SELECT * FROM announcements WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// "Feed page", newest first, hide soft-deletes. `before_id` is a
/// snowflake cursor — exclusive upper bound on `id`. Snowflake order
/// matches creation order so this doubles as "before this timestamp".
pub async fn list_for_feed(
    pool: &PgPool,
    feed_id: i64,
    limit: i64,
    before_id: Option<i64>,
) -> Result<Vec<AnnouncementRow>, sqlx::Error> {
    let before = before_id.unwrap_or(i64::MAX);
    sqlx::query_as::<_, AnnouncementRow>(
        r#"
        SELECT * FROM announcements
         WHERE feed_id = $1 AND deleted_at_ms IS NULL AND id < $3
         ORDER BY id DESC
         LIMIT $2
        "#,
    )
    .bind(feed_id)
    .bind(limit)
    .bind(before)
    .fetch_all(pool)
    .await
}

pub struct InsertAnnouncement<'a> {
    pub id: i64,
    pub feed_id: i64,
    pub server_id: i64,
    pub content: &'a serde_json::Value,
    pub posted_by: Option<i64>,
    pub bot_id: Option<i64>,
    pub now_ms: i64,
}

pub async fn insert(pool: &PgPool, a: InsertAnnouncement<'_>) -> Result<(), sqlx::Error> {
    insert_query()
        .bind(a.id)
        .bind(a.feed_id)
        .bind(a.server_id)
        .bind(a.content)
        .bind(a.posted_by)
        .bind(a.bot_id)
        .bind(a.now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_tx(
    tx: &mut Transaction<'_, Postgres>,
    a: InsertAnnouncement<'_>,
) -> Result<(), sqlx::Error> {
    insert_query()
        .bind(a.id)
        .bind(a.feed_id)
        .bind(a.server_id)
        .bind(a.content)
        .bind(a.posted_by)
        .bind(a.bot_id)
        .bind(a.now_ms)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn insert_query<'q>() -> sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        r#"
        INSERT INTO announcements
            (id, feed_id, server_id, content, posted_by, bot_id, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        "#,
    )
}

pub async fn edit(
    pool: &PgPool,
    id: i64,
    content: &serde_json::Value,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE announcements SET content = $2, updated_at_ms = $3 WHERE id = $1 AND deleted_at_ms IS NULL",
    )
    .bind(id)
    .bind(content)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn soft_delete(pool: &PgPool, id: i64, now_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE announcements SET deleted_at_ms = $2 WHERE id = $1 AND deleted_at_ms IS NULL",
    )
    .bind(id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}
