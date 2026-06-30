//! Messages — partitioned by created_at_ms, monthly.
//!
//! Hot path. Batched insert is the throughput unlock — N rows in one
//! INSERT round trip via `QueryBuilder::push_values`. With prepared
//! statement caching this becomes ~50K rows/sec on a $7-class instance.

use std::collections::HashMap;

use sqlx::{PgPool, Postgres, Transaction};

/// Bit on `messages.flags` that indicates a soft-delete tombstone.
/// The content is cleared but the row stays for the audit trail.
pub const FLAG_DELETED: i32 = 0x01;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageRow {
    pub id: i64,
    pub channel_id: i64,
    pub author_id: i64,
    pub r#type: i16,
    pub flags: i32,
    pub content: String,
    pub reply_to: Option<i64>,
    pub edited_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChannelLastMessageRow {
    pub channel_id: i64,
    pub id: i64,
    pub created_at_ms: i64,
}

#[inline]
pub fn is_deleted(m: &MessageRow) -> bool {
    (m.flags & FLAG_DELETED) != 0
}

pub async fn by_id(
    pool: &PgPool,
    id: i64,
    created_at_ms: i64,
) -> Result<Option<MessageRow>, sqlx::Error> {
    // Including created_at_ms lets PG do partition pruning. Single-
    // partition lookup is much faster than a scan across all partitions.
    sqlx::query_as::<_, MessageRow>("SELECT * FROM messages WHERE id = $1 AND created_at_ms = $2")
        .bind(id)
        .bind(created_at_ms)
        .fetch_optional(pool)
        .await
}

/// Without partition pruning hint — caller didn't snapshot the
/// timestamp. Falls back to a full id index scan, which still works
/// (every partition has the index inherited from the parent) but
/// touches more data. Prefer `by_id` when you have the timestamp.
pub async fn by_id_unhinted(pool: &PgPool, id: i64) -> Result<Option<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>("SELECT * FROM messages WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn by_id_unhinted_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<Option<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>("SELECT * FROM messages WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
}

/// Batch lookup by id list (no timestamp hint). Single round-trip via
/// `= ANY($1)` + soft-deleted rows excluded. Used by the GET
/// /messages handler to resolve every reply-to in one shot instead of
/// looping `by_id_unhinted` per message. Returns at most `ids.len()`
/// rows — caller indexes into a HashMap by id.
pub async fn by_ids(pool: &PgPool, ids: &[i64]) -> Result<Vec<MessageRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, MessageRow>(
        "SELECT * FROM messages WHERE id = ANY($1::bigint[]) AND (flags & $2) = 0",
    )
    .bind(ids)
    .bind(FLAG_DELETED)
    .fetch_all(pool)
    .await
}

pub async fn by_ids_tx(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[i64],
) -> Result<Vec<MessageRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, MessageRow>(
        "SELECT * FROM messages WHERE id = ANY($1::bigint[]) AND (flags & $2) = 0",
    )
    .bind(ids)
    .bind(FLAG_DELETED)
    .fetch_all(&mut **tx)
    .await
}

/// Latest N messages for a channel. Excludes soft-deleted rows.
pub async fn latest(
    pool: &PgPool,
    channel_id: i64,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT * FROM messages
         WHERE channel_id = $1 AND (flags & $3) = 0
         ORDER BY id DESC
         LIMIT $2
        "#,
    )
    .bind(channel_id)
    .bind(limit)
    .bind(FLAG_DELETED)
    .fetch_all(pool)
    .await
}

pub async fn latest_by_channel_ids(
    pool: &PgPool,
    channel_ids: &[i64],
) -> Result<HashMap<i64, ChannelLastMessageRow>, sqlx::Error> {
    if channel_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query_as::<_, ChannelLastMessageRow>(
        r#"
        SELECT DISTINCT ON (channel_id) channel_id, id, created_at_ms
          FROM messages
         WHERE channel_id = ANY($1::bigint[]) AND (flags & $2) = 0
         ORDER BY channel_id, id DESC
        "#,
    )
    .bind(channel_ids)
    .bind(FLAG_DELETED)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|row| (row.channel_id, row)).collect())
}

pub async fn latest_tx(
    tx: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT * FROM messages
         WHERE channel_id = $1 AND (flags & $3) = 0
         ORDER BY id DESC
         LIMIT $2
        "#,
    )
    .bind(channel_id)
    .bind(limit)
    .bind(FLAG_DELETED)
    .fetch_all(&mut **tx)
    .await
}

/// "page-before" pagination — get N messages older than a cursor id.
pub async fn before(
    pool: &PgPool,
    channel_id: i64,
    before_id: i64,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT * FROM messages
         WHERE channel_id = $1 AND id < $2 AND (flags & $4) = 0
         ORDER BY id DESC
         LIMIT $3
        "#,
    )
    .bind(channel_id)
    .bind(before_id)
    .bind(limit)
    .bind(FLAG_DELETED)
    .fetch_all(pool)
    .await
}

pub async fn before_tx(
    tx: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    before_id: i64,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT * FROM messages
         WHERE channel_id = $1 AND id < $2 AND (flags & $4) = 0
         ORDER BY id DESC
         LIMIT $3
        "#,
    )
    .bind(channel_id)
    .bind(before_id)
    .bind(limit)
    .bind(FLAG_DELETED)
    .fetch_all(&mut **tx)
    .await
}

/// Single-row insert. Most call sites should use `insert_batch` instead
/// — single inserts only make sense for system messages or the very
/// first message of a channel.
pub async fn insert(pool: &PgPool, m: &MessageRow) -> Result<(), sqlx::Error> {
    insert_query()
        .bind(m.id)
        .bind(m.channel_id)
        .bind(m.author_id)
        .bind(m.r#type)
        .bind(m.flags)
        .bind(&m.content)
        .bind(m.reply_to)
        .bind(m.edited_at_ms)
        .bind(m.created_at_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_tx(
    tx: &mut Transaction<'_, Postgres>,
    m: &MessageRow,
) -> Result<(), sqlx::Error> {
    insert_query()
        .bind(m.id)
        .bind(m.channel_id)
        .bind(m.author_id)
        .bind(m.r#type)
        .bind(m.flags)
        .bind(&m.content)
        .bind(m.reply_to)
        .bind(m.edited_at_ms)
        .bind(m.created_at_ms)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn insert_query<'q>() -> sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        r#"
        INSERT INTO messages
            (id, channel_id, author_id, type, flags, content,
             reply_to, edited_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
    )
}

/// Multi-row insert. **Throughput unlock.** N messages in one round
/// trip — pg handles ~50-100K rows/sec INSERT on a $7 instance.
///
/// The caller (the message_batcher) coalesces N MESSAGE_SEND opcodes
/// in a per-channel time window (1-2 ms) and ships the batch here.
/// Every row's `created_at_ms` must fall in an existing partition (we
/// pre-create monthly partitions through 2027 in 0004).
pub async fn insert_batch(pool: &PgPool, rows: &[MessageRow]) -> Result<(), sqlx::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO messages (id, channel_id, author_id, type, flags, content, reply_to, edited_at_ms, created_at_ms) ",
    );
    qb.push_values(rows.iter(), |mut b, m| {
        b.push_bind(m.id)
            .push_bind(m.channel_id)
            .push_bind(m.author_id)
            .push_bind(m.r#type)
            .push_bind(m.flags)
            .push_bind(&m.content)
            .push_bind(m.reply_to)
            .push_bind(m.edited_at_ms)
            .push_bind(m.created_at_ms);
    });
    qb.build().execute(pool).await?;
    Ok(())
}

/// Edit content + bump edited_at. Caller has already permission-checked.
pub async fn edit(
    pool: &PgPool,
    id: i64,
    created_at_ms: i64,
    new_content: &str,
    edited_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE messages
           SET content = $3, edited_at_ms = $4
         WHERE id = $1 AND created_at_ms = $2
        "#,
    )
    .bind(id)
    .bind(created_at_ms)
    .bind(new_content)
    .bind(edited_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Tombstone delete: set FLAG_DELETED + clear content. Row stays for
/// the audit trail; clients filter on `(flags & 0x01) = 0` for visibility.
pub async fn tombstone(pool: &PgPool, id: i64, created_at_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE messages
           SET flags = flags | $3, content = ''
         WHERE id = $1 AND created_at_ms = $2
        "#,
    )
    .bind(id)
    .bind(created_at_ms)
    .bind(FLAG_DELETED)
    .execute(pool)
    .await?;
    Ok(())
}

/// Hard-delete (used by GDPR purge). Cascade-deletes attachments +
/// reactions through their FKs.
pub async fn hard_delete(pool: &PgPool, id: i64, created_at_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM messages WHERE id = $1 AND created_at_ms = $2")
        .bind(id)
        .bind(created_at_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn count_in_channel(pool: &PgPool, channel_id: i64) -> Result<i64, sqlx::Error> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM messages WHERE channel_id = $1 AND (flags & $2) = 0")
            .bind(channel_id)
            .bind(FLAG_DELETED)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Search by content substring. Uses ILIKE until full-text indexing is available.
pub async fn search(
    pool: &PgPool,
    channel_id: i64,
    query: &str,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT * FROM messages
         WHERE channel_id = $1
           AND content ILIKE '%' || $2 || '%'
           AND (flags & $4) = 0
         ORDER BY id DESC
         LIMIT $3
        "#,
    )
    .bind(channel_id)
    .bind(query)
    .bind(limit)
    .bind(FLAG_DELETED)
    .fetch_all(pool)
    .await
}

pub async fn search_tx(
    tx: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    query: &str,
    author_id: Option<i64>,
    before_id: Option<i64>,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT * FROM messages
         WHERE channel_id = $1
           AND ($2 = '' OR content ILIKE '%' || $2 || '%')
           AND ($3::bigint IS NULL OR author_id = $3)
           AND ($4::bigint IS NULL OR id < $4)
           AND (flags & $6) = 0
         ORDER BY id DESC
         LIMIT $5
        "#,
    )
    .bind(channel_id)
    .bind(query)
    .bind(author_id)
    .bind(before_id)
    .bind(limit)
    .bind(FLAG_DELETED)
    .fetch_all(&mut **tx)
    .await
}
