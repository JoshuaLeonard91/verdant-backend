//! Attachments — upload metadata + scan status. Bulk-fetched per
//! message-page for render.

use sqlx::{PgPool, Postgres, Transaction};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AttachmentRow {
    pub id: i64,
    pub message_id: Option<i64>,
    pub channel_id: i64,
    pub uploader_id: i64,
    pub filename: String,
    pub url: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub hash: String,
    pub scan_status: String,
    pub created_at_ms: i64,
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<AttachmentRow>, sqlx::Error> {
    sqlx::query_as::<_, AttachmentRow>("SELECT * FROM attachments WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn for_message(
    pool: &PgPool,
    message_id: i64,
) -> Result<Vec<AttachmentRow>, sqlx::Error> {
    sqlx::query_as::<_, AttachmentRow>(
        "SELECT * FROM attachments WHERE message_id = $1 ORDER BY id ASC",
    )
    .bind(message_id)
    .fetch_all(pool)
    .await
}

/// Batch-fetch for a page of messages — single round trip.
pub async fn for_messages(
    pool: &PgPool,
    message_ids: &[i64],
) -> Result<Vec<AttachmentRow>, sqlx::Error> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, AttachmentRow>(
        "SELECT * FROM attachments WHERE message_id = ANY($1::bigint[])",
    )
    .bind(message_ids)
    .fetch_all(pool)
    .await
}

pub struct InsertAttachment<'a> {
    pub id: i64,
    pub channel_id: i64,
    pub uploader_id: i64,
    pub filename: &'a str,
    pub url: &'a str,
    pub content_type: &'a str,
    pub size_bytes: i64,
    pub hash: &'a str,
    pub scan_status: &'a str,
    pub now_ms: i64,
}

pub async fn insert(pool: &PgPool, a: InsertAttachment<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO attachments
            (id, channel_id, uploader_id, filename, url, content_type,
             size_bytes, hash, scan_status, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(a.id)
    .bind(a.channel_id)
    .bind(a.uploader_id)
    .bind(a.filename)
    .bind(a.url)
    .bind(a.content_type)
    .bind(a.size_bytes)
    .bind(a.hash)
    .bind(a.scan_status)
    .bind(a.now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Associate an attachment with a message post-upload.
pub async fn attach_to_message(
    pool: &PgPool,
    attachment_id: i64,
    message_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE attachments SET message_id = $2 WHERE id = $1")
        .bind(attachment_id)
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Atomically claim a pending upload for a newly-created message.
///
/// This enforces the attachment boundary at the data layer: a message can only
/// link an upload that is still pending, was uploaded by the same user, and
/// belongs to the same channel.
pub async fn claim_pending_for_message_tx(
    tx: &mut Transaction<'_, Postgres>,
    attachment_id: i64,
    message_id: i64,
    channel_id: i64,
    uploader_id: i64,
) -> Result<Option<AttachmentRow>, sqlx::Error> {
    sqlx::query_as::<_, AttachmentRow>(
        r#"
        UPDATE attachments
           SET message_id = $2
         WHERE id = $1
           AND message_id IS NULL
           AND channel_id = $3
           AND uploader_id = $4
         RETURNING *
        "#,
    )
    .bind(attachment_id)
    .bind(message_id)
    .bind(channel_id)
    .bind(uploader_id)
    .fetch_optional(&mut **tx)
    .await
}

pub async fn set_scan_status(pool: &PgPool, id: i64, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE attachments SET scan_status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hash dedup — useful at upload time to skip re-storing identical bytes.
pub async fn by_hash(pool: &PgPool, hash: &str) -> Result<Option<AttachmentRow>, sqlx::Error> {
    sqlx::query_as::<_, AttachmentRow>(
        "SELECT * FROM attachments WHERE hash = $1 ORDER BY created_at_ms ASC LIMIT 1",
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM attachments WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
