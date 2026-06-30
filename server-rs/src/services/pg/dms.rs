//! DM channels + DM members.
//!
//! DM messages live in the same partitioned `messages` table as server
//! messages — channel_id distinguishes them via the type column on
//! whichever channel table holds the row.

use sqlx::{PgPool, Postgres, Transaction};

pub const DM_DIRECT: i16 = 1;
pub const DM_GROUP: i16 = 2;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmChannelRow {
    pub id: i64,
    pub r#type: i16,
    pub name: Option<String>,
    pub owner_id: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmMemberRow {
    pub channel_id: i64,
    pub user_id: i64,
    pub name_color: Option<String>,
    pub joined_at_ms: i64,
}

/// Create a DM channel. For direct DMs the `owner_id` and `name` are
/// None; for group DMs the caller supplies both.
pub async fn create_channel(
    pool: &PgPool,
    id: i64,
    r#type: i16,
    name: Option<&str>,
    owner_id: Option<i64>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO dm_channels (id, type, name, owner_id, created_at_ms)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(id)
    .bind(r#type)
    .bind(name)
    .bind(owner_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Transactional variant for callers that must atomically create the DM and
/// related rows such as federation mappings.
pub async fn create_channel_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    r#type: i16,
    name: Option<&str>,
    owner_id: Option<i64>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO dm_channels (id, type, name, owner_id, created_at_ms)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(id)
    .bind(r#type)
    .bind(name)
    .bind(owner_id)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn channel_by_id(pool: &PgPool, id: i64) -> Result<Option<DmChannelRow>, sqlx::Error> {
    sqlx::query_as::<_, DmChannelRow>("SELECT * FROM dm_channels WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn channels_by_ids(pool: &PgPool, ids: &[i64]) -> Result<Vec<DmChannelRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, DmChannelRow>("SELECT * FROM dm_channels WHERE id = ANY($1::bigint[])")
        .bind(ids)
        .fetch_all(pool)
        .await
}

/// Add a member (single).
pub async fn add_member(
    pool: &PgPool,
    channel_id: i64,
    user_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO dm_members (channel_id, user_id, joined_at_ms)
        VALUES ($1, $2, $3)
        ON CONFLICT (channel_id, user_id) DO NOTHING
        "#,
    )
    .bind(channel_id)
    .bind(user_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Bulk-add members in one round trip — used at DM creation when the
/// caller knows every participant up front.
pub async fn add_members_bulk(
    pool: &PgPool,
    channel_id: i64,
    user_ids: &[i64],
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    if user_ids.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO dm_members (channel_id, user_id, joined_at_ms) ",
    );
    qb.push_values(user_ids.iter(), |mut b, uid| {
        b.push_bind(channel_id).push_bind(uid).push_bind(now_ms);
    });
    qb.push(" ON CONFLICT (channel_id, user_id) DO NOTHING");
    qb.build().execute(pool).await?;
    Ok(())
}

/// Transactional bulk-add used when channel creation and mapping insertion
/// must be committed as one unit.
pub async fn add_members_bulk_tx(
    tx: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    user_ids: &[i64],
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    if user_ids.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO dm_members (channel_id, user_id, joined_at_ms) ",
    );
    qb.push_values(user_ids.iter(), |mut b, uid| {
        b.push_bind(channel_id).push_bind(uid).push_bind(now_ms);
    });
    qb.push(" ON CONFLICT (channel_id, user_id) DO NOTHING");
    qb.build().execute(&mut **tx).await?;
    Ok(())
}

pub async fn remove_member(
    pool: &PgPool,
    channel_id: i64,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM dm_members WHERE channel_id = $1 AND user_id = $2")
        .bind(channel_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_members(pool: &PgPool, channel_id: i64) -> Result<Vec<DmMemberRow>, sqlx::Error> {
    sqlx::query_as::<_, DmMemberRow>(
        "SELECT * FROM dm_members WHERE channel_id = $1 ORDER BY joined_at_ms ASC",
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await
}

/// "User's DMs". Index `(user_id, channel_id)` covers it.
pub async fn list_channel_ids_for_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT channel_id FROM dm_members WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn set_name_color(
    pool: &PgPool,
    channel_id: i64,
    user_id: i64,
    name_color: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE dm_members SET name_color = $3 WHERE channel_id = $1 AND user_id = $2")
        .bind(channel_id)
        .bind(user_id)
        .bind(name_color)
        .execute(pool)
        .await?;
    Ok(())
}

/// Find a direct (1-on-1) DM that already exists between two users —
/// used to dedupe new-DM creation.
pub async fn find_direct_between(
    pool: &PgPool,
    a: i64,
    b: i64,
) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT c.id
          FROM dm_channels c
          JOIN dm_members m1 ON m1.channel_id = c.id AND m1.user_id = $1
          JOIN dm_members m2 ON m2.channel_id = c.id AND m2.user_id = $2
         WHERE c.type = $3
         LIMIT 1
        "#,
    )
    .bind(a)
    .bind(b)
    .bind(DM_DIRECT)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}
