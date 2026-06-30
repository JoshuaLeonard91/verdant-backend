//! Login history durability tier. Redis stream `login-history` is the
//! live tail; this archives.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginRow {
    pub id: i64,
    pub user_id: Option<i64>,
    pub session_id: Option<i64>,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub ip: String,
    pub user_agent: Option<String>,
    pub device_hash: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub risk_level: Option<String>,
    pub created_at_ms: i64,
}

pub async fn insert(pool: &PgPool, r: &LoginRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO login_entries
            (id, user_id, session_id, success, failure_reason,
             ip, user_agent, device_hash, city, country, risk_level,
             created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        "#,
    )
    .bind(r.id)
    .bind(r.user_id)
    .bind(r.session_id)
    .bind(r.success)
    .bind(&r.failure_reason)
    .bind(&r.ip)
    .bind(&r.user_agent)
    .bind(&r.device_hash)
    .bind(&r.city)
    .bind(&r.country)
    .bind(&r.risk_level)
    .bind(r.created_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_batch(pool: &PgPool, rows: &[LoginRow]) -> Result<(), sqlx::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO login_entries (id, user_id, session_id, success, failure_reason, ip, user_agent, device_hash, city, country, risk_level, created_at_ms) ",
    );
    qb.push_values(rows.iter(), |mut b, r| {
        b.push_bind(r.id)
            .push_bind(r.user_id)
            .push_bind(r.session_id)
            .push_bind(r.success)
            .push_bind(&r.failure_reason)
            .push_bind(&r.ip)
            .push_bind(&r.user_agent)
            .push_bind(&r.device_hash)
            .push_bind(&r.city)
            .push_bind(&r.country)
            .push_bind(&r.risk_level)
            .push_bind(r.created_at_ms);
    });
    qb.build().execute(pool).await?;
    Ok(())
}

/// Recent login history for a user. Partial index covers it.
pub async fn list_for_user(
    pool: &PgPool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<LoginRow>, sqlx::Error> {
    sqlx::query_as::<_, LoginRow>(
        r#"
        SELECT * FROM login_entries
         WHERE user_id = $1
         ORDER BY created_at_ms DESC
         LIMIT $2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Recent failed attempts (admin / risk dashboards). Partial index on
/// `(created_at_ms DESC) WHERE success = false` covers it.
pub async fn recent_failures(pool: &PgPool, limit: i64) -> Result<Vec<LoginRow>, sqlx::Error> {
    sqlx::query_as::<_, LoginRow>(
        r#"
        SELECT * FROM login_entries
         WHERE success = false
         ORDER BY created_at_ms DESC
         LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}
