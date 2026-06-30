//! Auth side-tables: invite_codes (signup), password_resets, email_verifications.
//! Sessions live in `pg::sessions`.

use sqlx::PgPool;

// ─── invite_codes ────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct InviteCodeRow {
    pub code: String,
    pub invited_by: i64,
    pub used_by: Option<i64>,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn invite_get(pool: &PgPool, code: &str) -> Result<Option<InviteCodeRow>, sqlx::Error> {
    sqlx::query_as::<_, InviteCodeRow>("SELECT * FROM invite_codes WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await
}

pub async fn invite_insert(
    pool: &PgPool,
    code: &str,
    invited_by: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO invite_codes (code, invited_by, created_at_ms) VALUES ($1,$2,$3)")
        .bind(code)
        .bind(invited_by)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

/// Mark an invite consumed. Idempotent — does nothing if already used.
pub async fn invite_consume(
    pool: &PgPool,
    code: &str,
    used_by: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE invite_codes SET used_by = $2, used_at_ms = $3 WHERE code = $1 AND used_by IS NULL",
    )
    .bind(code)
    .bind(used_by)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn invite_delete(pool: &PgPool, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM invite_codes WHERE code = $1")
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn invite_list_by_user(
    pool: &PgPool,
    invited_by: i64,
) -> Result<Vec<InviteCodeRow>, sqlx::Error> {
    sqlx::query_as::<_, InviteCodeRow>(
        "SELECT * FROM invite_codes WHERE invited_by = $1 ORDER BY created_at_ms DESC",
    )
    .bind(invited_by)
    .fetch_all(pool)
    .await
}

// ─── password_resets ─────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct PasswordResetRow {
    pub id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn password_reset_insert(
    pool: &PgPool,
    id: i64,
    user_id: i64,
    token_hash: &str,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO password_resets (id, user_id, token_hash, expires_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn password_reset_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<PasswordResetRow>, sqlx::Error> {
    sqlx::query_as::<_, PasswordResetRow>("SELECT * FROM password_resets WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn password_reset_consume(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE password_resets SET used_at_ms = $2 WHERE id = $1 AND used_at_ms IS NULL",
    )
    .bind(id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ─── email_verifications ─────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct EmailVerifyRow {
    pub id: i64,
    pub user_id: i64,
    pub email: String,
    pub token_hash: String,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn email_verify_insert(
    pool: &PgPool,
    id: i64,
    user_id: i64,
    email: &str,
    token_hash: &str,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO email_verifications
            (id, user_id, email, token_hash, expires_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(email)
    .bind(token_hash)
    .bind(expires_at_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn email_verify_by_token_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<EmailVerifyRow>, sqlx::Error> {
    sqlx::query_as::<_, EmailVerifyRow>("SELECT * FROM email_verifications WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn email_verify_consume(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE email_verifications SET used_at_ms = $2 WHERE id = $1 AND used_at_ms IS NULL",
    )
    .bind(id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}
