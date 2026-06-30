//! Categories — sidebar grouping inside a server.

use super::ms_to_dt;
use crate::repo::categories::CategoryRow;
use sqlx::PgPool;

#[derive(Debug, sqlx::FromRow)]
struct CategoryRaw {
    id: i64,
    server_id: i64,
    name: String,
    position: i32,
    emoji: Option<String>,
    created_at_ms: i64,
}

impl From<CategoryRaw> for CategoryRow {
    fn from(r: CategoryRaw) -> Self {
        Self {
            id: r.id,
            server_id: r.server_id,
            name: r.name,
            position: r.position,
            emoji: r.emoji,
            created_at: ms_to_dt(r.created_at_ms),
        }
    }
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<CategoryRow>, sqlx::Error> {
    let r = sqlx::query_as::<_, CategoryRaw>("SELECT * FROM categories WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(r.map(Into::into))
}

pub async fn list_for_server(
    pool: &PgPool,
    server_id: i64,
) -> Result<Vec<CategoryRow>, sqlx::Error> {
    let rs = sqlx::query_as::<_, CategoryRaw>(
        "SELECT * FROM categories WHERE server_id = $1 ORDER BY position ASC, id ASC",
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
    name: &str,
    position: i32,
    emoji: Option<&str>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO categories (id, server_id, name, position, emoji, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(position)
    .bind(emoji)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update(
    pool: &PgPool,
    id: i64,
    name: Option<&str>,
    position: Option<i32>,
    emoji: Option<Option<&str>>,
) -> Result<(), sqlx::Error> {
    // Emoji uses the "patchable nullable" CASE shape: outer Some
    // means write the inner value (which may itself be None → SQL NULL),
    // outer None means leave column untouched.
    sqlx::query(
        r#"
        UPDATE categories SET
            name     = COALESCE($2, name),
            position = COALESCE($3, position),
            emoji    = CASE WHEN $4::boolean THEN $5 ELSE emoji END
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(position)
    .bind(emoji.is_some())
    .bind(emoji.flatten())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM categories WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Bulk reorder — used by the sidebar drag-drop. Single round trip.
pub async fn reorder(pool: &PgPool, items: &[(i64, i32)]) -> Result<(), sqlx::Error> {
    if items.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for (id, pos) in items {
        sqlx::query("UPDATE categories SET position = $2 WHERE id = $1")
            .bind(id)
            .bind(pos)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
