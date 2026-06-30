//! Feeds — announcement channels inside servers, with per-role
//! publish/visibility.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FeedRow {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub position: i32,
    pub publish_role_ids: Vec<i64>,
    pub visible_role_ids: Vec<i64>,
    pub created_at_ms: i64,
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<FeedRow>, sqlx::Error> {
    sqlx::query_as::<_, FeedRow>("SELECT * FROM feeds WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_for_server(pool: &PgPool, server_id: i64) -> Result<Vec<FeedRow>, sqlx::Error> {
    sqlx::query_as::<_, FeedRow>(
        "SELECT * FROM feeds WHERE server_id = $1 ORDER BY position ASC, id ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await
}

pub struct InsertFeed<'a> {
    pub id: i64,
    pub server_id: i64,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub icon: Option<&'a str>,
    pub position: i32,
    pub publish_role_ids: &'a [i64],
    pub visible_role_ids: &'a [i64],
    pub now_ms: i64,
}

pub async fn insert(pool: &PgPool, f: InsertFeed<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO feeds
            (id, server_id, name, description, icon, position,
             publish_role_ids, visible_role_ids, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
    )
    .bind(f.id)
    .bind(f.server_id)
    .bind(f.name)
    .bind(f.description)
    .bind(f.icon)
    .bind(f.position)
    .bind(f.publish_role_ids)
    .bind(f.visible_role_ids)
    .bind(f.now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Default)]
pub struct UpdateFeed<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub icon: Option<&'a str>,
    pub position: Option<i32>,
    pub publish_role_ids: Option<&'a [i64]>,
    pub visible_role_ids: Option<&'a [i64]>,
}

pub async fn update(pool: &PgPool, id: i64, p: UpdateFeed<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE feeds SET
            name             = COALESCE($2, name),
            description      = COALESCE($3, description),
            icon             = COALESCE($4, icon),
            position         = COALESCE($5, position),
            publish_role_ids = COALESCE($6, publish_role_ids),
            visible_role_ids = COALESCE($7, visible_role_ids)
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(p.name)
    .bind(p.description)
    .bind(p.icon)
    .bind(p.position)
    .bind(p.publish_role_ids)
    .bind(p.visible_role_ids)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM feeds WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
