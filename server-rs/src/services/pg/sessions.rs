//! Sessions table — auth bearer tokens + sliding-window updates.
//!
//! Mirrors the surface that `services/session.rs` expects.
//! Every method takes `&PgPool` and returns `sqlx::Error` — the
//! caller (services/session.rs) maps to `AppError`.
//!
//! Sliding-window optimization: on every request we update `last_used_at_ms`
//! only when it crosses a threshold
//! (currently 5 minutes). Without this, every authed request becomes a
//! pg row write — burns a connection slot and clobbers the WAL.

use sqlx::PgPool;

/// Single session row. Mirrors the columns in 0001_slice1_auth.sql.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub revoke_token_hash: Option<String>,
    pub verify_token_hash: Option<String>,
    pub expires_at_ms: i64,
    pub verified: bool,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_hash: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub risk_level: Option<String>,
    pub verify_expires_at_ms: Option<i64>,
    pub verify_attempts: i32,
    pub created_at_ms: i64,
    pub last_used_at_ms: i64,
}

/// Insert a fresh session. Caller fills the snowflake id + the
/// already-hashed token. We never see the plaintext token.
pub async fn insert(pool: &PgPool, row: &SessionRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, token_hash, revoke_token_hash, verify_token_hash,
            expires_at_ms, verified, ip, user_agent, device_hash,
            city, region, country, risk_level,
            verify_expires_at_ms, verify_attempts,
            created_at_ms, last_used_at_ms
        )
        VALUES (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9,$10,
            $11,$12,$13,$14,
            $15,$16,
            $17,$18
        )
        "#,
    )
    .bind(row.id)
    .bind(row.user_id)
    .bind(&row.token_hash)
    .bind(&row.revoke_token_hash)
    .bind(&row.verify_token_hash)
    .bind(row.expires_at_ms)
    .bind(row.verified)
    .bind(&row.ip)
    .bind(&row.user_agent)
    .bind(&row.device_hash)
    .bind(&row.city)
    .bind(&row.region)
    .bind(&row.country)
    .bind(&row.risk_level)
    .bind(row.verify_expires_at_ms)
    .bind(row.verify_attempts)
    .bind(row.created_at_ms)
    .bind(row.last_used_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up by primary key.
pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Auth-middleware hot path: resolve a bearer token's hash to the
/// session row. Single index hit on `sessions_token_hash_uniq`.
pub async fn by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

/// Email "this wasn't me" revoke flow.
pub async fn by_revoke_token_hash(
    pool: &PgPool,
    revoke_hash: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE revoke_token_hash = $1")
        .bind(revoke_hash)
        .fetch_optional(pool)
        .await
}

/// Sliding-window update for `last_used_at_ms`. Caller decides whether
/// to fire (e.g. only if delta > 5 min). We also opportunistically
/// refresh ip / user_agent when supplied (NULL skips the field). Keeps
/// session rows from churning on every request.
pub async fn touch_last_used(
    pool: &PgPool,
    id: i64,
    last_used_at_ms: i64,
    new_ip: Option<&str>,
    new_user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE sessions
        SET last_used_at_ms = $2,
            ip              = COALESCE($3, ip),
            user_agent      = COALESCE($4, user_agent)
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(last_used_at_ms)
    .bind(new_ip)
    .bind(new_user_agent)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn rotate_token_hash(
    pool: &PgPool,
    id: i64,
    current_token_hash: &str,
    new_token_hash: &str,
    expires_at_ms: i64,
    last_used_at_ms: i64,
    new_ip: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE sessions
        SET token_hash      = $3,
            expires_at_ms   = $4,
            last_used_at_ms = $5,
            ip              = COALESCE($6, ip)
        WHERE id = $1 AND token_hash = $2
        "#,
    )
    .bind(id)
    .bind(current_token_hash)
    .bind(new_token_hash)
    .bind(expires_at_ms)
    .bind(last_used_at_ms)
    .bind(new_ip)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Mark a session verified (e.g. after email-code success). Clears the
/// pending verify_token_hash + expiry once they've served their purpose.
pub async fn mark_verified(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE sessions
        SET verified                = TRUE,
            verify_token_hash       = NULL,
            verify_expires_at_ms    = NULL,
            verify_attempts         = 0
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Increment the verify attempt counter — used to throttle code-guess
/// attempts (handler enforces the cap).
pub async fn bump_verify_attempts(pool: &PgPool, id: i64) -> Result<i32, sqlx::Error> {
    let row: (i32,) = sqlx::query_as(
        r#"
        UPDATE sessions
        SET verify_attempts = verify_attempts + 1
        WHERE id = $1
        RETURNING verify_attempts
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Set / replace the verify token (e.g. resend code).
pub async fn set_verify_token(
    pool: &PgPool,
    id: i64,
    verify_token_hash: &str,
    verify_expires_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE sessions
        SET verify_token_hash    = $2,
            verify_expires_at_ms = $3,
            verify_attempts      = 0
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(verify_token_hash)
    .bind(verify_expires_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Set the single-use revoke token (issued in the new-device email).
pub async fn set_revoke_token(
    pool: &PgPool,
    id: i64,
    revoke_token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoke_token_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(revoke_token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Clear the revoke token after it's been consumed (don't allow replay).
pub async fn clear_revoke_token(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoke_token_hash = NULL WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Single-session revoke (logout this device).
pub async fn delete_one(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// "Logout everywhere" — wipe every session for a user. Returns the
/// rows that existed so the caller can broadcast revoke events.
pub async fn delete_all_for_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Vec<(i64, String)>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        r#"
        DELETE FROM sessions
        WHERE user_id = $1
        RETURNING id, token_hash
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List a user's sessions for the "active sessions" UI.
pub async fn list_for_user(pool: &PgPool, user_id: i64) -> Result<Vec<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT * FROM sessions
        WHERE user_id = $1
        ORDER BY last_used_at_ms DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Periodic cleanup: drop expired sessions. Call from a maintenance
/// task or directly on an idle connection. Returns the number of rows
/// deleted (useful for stat output).
pub async fn delete_expired(pool: &PgPool, now_ms: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"
        DELETE FROM sessions
        WHERE expires_at_ms > 0 AND expires_at_ms < $1
        "#,
    )
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
