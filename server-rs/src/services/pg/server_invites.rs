//! Server invites — codes for joining servers. (Distinct from
//! `invite_codes` in pg::auth which are signup-time registration codes.)

use sha2::{Digest, Sha256};
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServerInviteRow {
    pub code: String,
    pub server_id: i64,
    pub inviter_id: i64,
    pub max_uses: i32,
    pub uses: i32,
    pub expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub fn code_hash(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

pub async fn by_code(pool: &PgPool, code: &str) -> Result<Option<ServerInviteRow>, sqlx::Error> {
    sqlx::query_as::<_, ServerInviteRow>("SELECT * FROM server_invites WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await
}

pub async fn by_code_hash_for_server(
    pool: &PgPool,
    server_id: i64,
    invite_code_hash: &str,
) -> Result<Option<ServerInviteRow>, sqlx::Error> {
    if !valid_code_hash(invite_code_hash) {
        return Ok(None);
    }
    let invite_code_hash = invite_code_hash.to_ascii_lowercase();
    let rows = sqlx::query_as::<_, ServerInviteRow>(
        "SELECT * FROM server_invites WHERE server_id = $1 ORDER BY created_at_ms DESC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .find(|row| code_hash(&row.code) == invite_code_hash))
}

pub async fn list_for_server(
    pool: &PgPool,
    server_id: i64,
) -> Result<Vec<ServerInviteRow>, sqlx::Error> {
    sqlx::query_as::<_, ServerInviteRow>(
        "SELECT * FROM server_invites WHERE server_id = $1 ORDER BY created_at_ms DESC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await
}

pub async fn insert(
    pool: &PgPool,
    code: &str,
    server_id: i64,
    inviter_id: i64,
    max_uses: i32,
    expires_at_ms: Option<i64>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO server_invites
            (code, server_id, inviter_id, max_uses, expires_at_ms, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(code)
    .bind(server_id)
    .bind(inviter_id)
    .bind(max_uses)
    .bind(expires_at_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomic increment + expiry/cap check. Returns true if the invite was
/// consumed (uses += 1), false if expired or at cap.
pub async fn try_consume(pool: &PgPool, code: &str, now_ms: i64) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        UPDATE server_invites
           SET uses = uses + 1
         WHERE code = $1
           AND (max_uses = 0 OR uses < max_uses)
           AND (expires_at_ms IS NULL OR expires_at_ms > $2)
        "#,
    )
    .bind(code)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn delete(pool: &PgPool, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM server_invites WHERE code = $1")
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

/// Cleanup batch: drop expired invites. Returns count.
pub async fn delete_expired(pool: &PgPool, now_ms: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM server_invites WHERE expires_at_ms IS NOT NULL AND expires_at_ms < $1",
    )
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

fn valid_code_hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_invite_code_hash_is_stable_and_not_plaintext() {
        let hash = code_hash("InviteABC123");

        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
        assert!(!hash.contains("InviteABC123"));
        assert!(valid_code_hash(&hash));
        assert!(!valid_code_hash("InviteABC123"));
    }
}
