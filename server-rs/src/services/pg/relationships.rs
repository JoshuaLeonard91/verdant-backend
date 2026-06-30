//! Relationships — friend graph + blocks. Composite PK (user_id, target_id),
//! rel_type carries the edge kind.

use sqlx::PgPool;

// rel_type values mirror the legacy wire format so the HTTP/WS
// payloads remain identical pre/post migration. Do NOT renumber
// without coordinating a client-side bump.
pub const REL_FRIEND: i16 = 1;
pub const REL_BLOCKED: i16 = 2;
pub const REL_REQUEST_SENT: i16 = 3; // PENDING_OUTGOING on the wire
pub const REL_REQUEST_RECEIVED: i16 = 4; // PENDING_INCOMING on the wire

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RelationshipRow {
    pub user_id: i64,
    pub target_id: i64,
    pub rel_type: i16,
    pub notes: Option<String>,
    pub nickname_color: Option<String>,
    pub created_at_ms: i64,
}

/// Upsert a single edge. Used by both "send friend request" and
/// "accept" (which flips both sides to FRIEND).
pub async fn upsert(
    pool: &PgPool,
    user_id: i64,
    target_id: i64,
    rel_type: i16,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO relationships (user_id, target_id, rel_type, created_at_ms)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, target_id) DO UPDATE
            SET rel_type = EXCLUDED.rel_type
        "#,
    )
    .bind(user_id)
    .bind(target_id)
    .bind(rel_type)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Set notes and/or nickname color for an existing edge.
pub async fn set_metadata(
    pool: &PgPool,
    user_id: i64,
    target_id: i64,
    notes: Option<&str>,
    nickname_color: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE relationships
           SET notes          = COALESCE($3, notes),
               nickname_color = COALESCE($4, nickname_color)
         WHERE user_id = $1 AND target_id = $2
        "#,
    )
    .bind(user_id)
    .bind(target_id)
    .bind(notes)
    .bind(nickname_color)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, user_id: i64, target_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM relationships WHERE user_id = $1 AND target_id = $2")
        .bind(user_id)
        .bind(target_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Read one edge.
pub async fn get(
    pool: &PgPool,
    user_id: i64,
    target_id: i64,
) -> Result<Option<RelationshipRow>, sqlx::Error> {
    sqlx::query_as::<_, RelationshipRow>(
        "SELECT * FROM relationships WHERE user_id = $1 AND target_id = $2",
    )
    .bind(user_id)
    .bind(target_id)
    .fetch_optional(pool)
    .await
}

/// All outgoing edges for a user (READY hot path).
pub async fn list_for_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Vec<RelationshipRow>, sqlx::Error> {
    sqlx::query_as::<_, RelationshipRow>("SELECT * FROM relationships WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await
}

/// "Is A blocked by B" — used in DM-create / message guards.
pub async fn is_blocked(pool: &PgPool, blocker: i64, target: i64) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM relationships
             WHERE user_id = $1 AND target_id = $2 AND rel_type = $3
        )
        "#,
    )
    .bind(blocker)
    .bind(target)
    .bind(REL_BLOCKED)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Bidirectional block check — returns true if either direction is blocked.
pub async fn either_blocks(pool: &PgPool, a: i64, b: i64) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM relationships
             WHERE rel_type = $3
               AND ((user_id = $1 AND target_id = $2) OR (user_id = $2 AND target_id = $1))
        )
        "#,
    )
    .bind(a)
    .bind(b)
    .bind(REL_BLOCKED)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// True when two users are allowed to open or continue a direct message.
///
/// The sender must either be mutual friends with the target or share at least
/// one server. Blocks are checked by callers so they can return a single
/// generic user-facing error for both block and eligibility failures.
pub async fn can_direct_message(pool: &PgPool, a: i64, b: i64) -> Result<bool, sqlx::Error> {
    if a == b {
        return Ok(false);
    }

    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT
            EXISTS(
                SELECT 1
                  FROM relationships
                 WHERE rel_type = $3
                   AND ((user_id = $1 AND target_id = $2)
                     OR (user_id = $2 AND target_id = $1))
            )
            OR
            EXISTS(
                SELECT 1
                  FROM server_members a_member
                  JOIN server_members b_member
                    ON b_member.server_id = a_member.server_id
                 WHERE a_member.user_id = $1
                   AND b_member.user_id = $2
                 LIMIT 1
            )
        "#,
    )
    .bind(a)
    .bind(b)
    .bind(REL_FRIEND)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}
