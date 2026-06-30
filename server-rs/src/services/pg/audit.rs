//! Audit log durability tier. Redis stream (`audit-log`,
//! `audit-log:{server_id}`) is the live tail; this is the long-term
//! archive. A small batcher drains stream → PG every few seconds.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub actor_id: i64,
    pub action: String,
    pub target_type: String,
    pub target_id: i64,
    pub server_id: Option<i64>,
    pub metadata: serde_json::Value,
    pub ip: Option<String>,
    pub created_at_ms: i64,
}

pub async fn insert(pool: &PgPool, r: &AuditRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO audit_entries
            (id, actor_id, action, target_type, target_id, server_id,
             metadata, ip, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
    )
    .bind(r.id)
    .bind(r.actor_id)
    .bind(&r.action)
    .bind(&r.target_type)
    .bind(r.target_id)
    .bind(r.server_id)
    .bind(&r.metadata)
    .bind(&r.ip)
    .bind(r.created_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Batched insert from the Redis-stream drainer. One round trip per
/// drain iteration. Hot-path optimization for high-event servers.
pub async fn insert_batch(pool: &PgPool, rows: &[AuditRow]) -> Result<(), sqlx::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO audit_entries (id, actor_id, action, target_type, target_id, server_id, metadata, ip, created_at_ms) ",
    );
    qb.push_values(rows.iter(), |mut b, r| {
        b.push_bind(r.id)
            .push_bind(r.actor_id)
            .push_bind(&r.action)
            .push_bind(&r.target_type)
            .push_bind(r.target_id)
            .push_bind(r.server_id)
            .push_bind(&r.metadata)
            .push_bind(&r.ip)
            .push_bind(r.created_at_ms);
    });
    qb.build().execute(pool).await?;
    Ok(())
}

/// Server audit log query — newest first, partial index on
/// `(server_id, created_at_ms desc)` covers it.
pub async fn list_for_server(
    pool: &PgPool,
    server_id: i64,
    limit: i64,
    before_ms: Option<i64>,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    let before = before_ms.unwrap_or(i64::MAX);
    sqlx::query_as::<_, AuditRow>(
        r#"
        SELECT * FROM audit_entries
         WHERE server_id = $1 AND created_at_ms < $3
         ORDER BY created_at_ms DESC
         LIMIT $2
        "#,
    )
    .bind(server_id)
    .bind(limit)
    .bind(before)
    .fetch_all(pool)
    .await
}

pub async fn list_for_actor(
    pool: &PgPool,
    actor_id: i64,
    limit: i64,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        r#"
        SELECT * FROM audit_entries
         WHERE actor_id = $1
         ORDER BY created_at_ms DESC
         LIMIT $2
        "#,
    )
    .bind(actor_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}
