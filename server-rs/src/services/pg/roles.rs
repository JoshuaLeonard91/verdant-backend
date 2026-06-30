//! Roles + member_roles. The permissions cache reads both at IDENTIFY.

use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub color: i32,
    pub permissions: i64,
    pub position: i32,
    pub color_only: bool,
    pub show_as_section: bool,
    pub color_priority: i32,
    pub created_at_ms: i64,
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<RoleRow>, sqlx::Error> {
    sqlx::query_as::<_, RoleRow>("SELECT * FROM roles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// List server's roles, sorted by position descending — matches the
/// permissions-cache binary-search shape (highest-priority role first).
pub async fn list_for_server(pool: &PgPool, server_id: i64) -> Result<Vec<RoleRow>, sqlx::Error> {
    sqlx::query_as::<_, RoleRow>(
        "SELECT * FROM roles WHERE server_id = $1 ORDER BY position DESC, id ASC",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await
}

pub async fn insert(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    name: &str,
    color: i32,
    permissions: i64,
    position: i32,
    color_only: bool,
    show_as_section: bool,
    color_priority: i32,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO roles (
            id, server_id, name, color, permissions, position,
            color_only, show_as_section, color_priority, created_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(color)
    .bind(permissions)
    .bind(position)
    .bind(color_only)
    .bind(show_as_section)
    .bind(color_priority)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update(
    pool: &PgPool,
    id: i64,
    name: Option<&str>,
    color: Option<i32>,
    permissions: Option<i64>,
    position: Option<i32>,
    color_only: Option<bool>,
    show_as_section: Option<bool>,
    color_priority: Option<i32>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE roles SET
            name            = COALESCE($2, name),
            color           = COALESCE($3, color),
            permissions     = COALESCE($4, permissions),
            position        = COALESCE($5, position),
            color_only      = COALESCE($6, color_only),
            show_as_section = COALESCE($7, show_as_section),
            color_priority  = COALESCE($8, color_priority)
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(color)
    .bind(permissions)
    .bind(position)
    .bind(color_only)
    .bind(show_as_section)
    .bind(color_priority)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn reorder(pool: &PgPool, items: &[(i64, i32)]) -> Result<(), sqlx::Error> {
    if items.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for (id, pos) in items {
        sqlx::query("UPDATE roles SET position = $2 WHERE id = $1")
            .bind(id)
            .bind(pos)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn reorder_display(
    pool: &PgPool,
    position_items: &[(i64, i32)],
    color_items: &[(i64, i32)],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for (id, pos) in position_items {
        sqlx::query("UPDATE roles SET position = $2 WHERE id = $1")
            .bind(id)
            .bind(pos)
            .execute(&mut *tx)
            .await?;
    }
    for (id, priority) in color_items {
        sqlx::query("UPDATE roles SET color_priority = $2 WHERE id = $1")
            .bind(id)
            .bind(priority)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ─── member_roles ────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MemberRoleRow {
    pub user_id: i64,
    pub server_id: i64,
    pub role_id: i64,
}

pub async fn assign(
    pool: &PgPool,
    user_id: i64,
    server_id: i64,
    role_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO member_roles (user_id, server_id, role_id)
        VALUES ($1,$2,$3)
        ON CONFLICT (user_id, server_id, role_id) DO NOTHING
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn unassign(
    pool: &PgPool,
    user_id: i64,
    server_id: i64,
    role_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM member_roles WHERE user_id = $1 AND server_id = $2 AND role_id = $3")
        .bind(user_id)
        .bind(server_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// "What roles does user X have in server Y" — one round trip.
/// Replace the user's cosmetic name-color assignment for a server.
///
/// Color-only roles are stored in member_roles for compatibility with existing
/// READY/member role payloads, but this transaction keeps the cosmetic
/// assignment single-select and leaves permission roles untouched.
pub async fn set_user_name_color(
    pool: &PgPool,
    user_id: i64,
    server_id: i64,
    role_id: Option<i64>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        DELETE FROM member_roles mr
        USING roles r
        WHERE mr.role_id = r.id
          AND mr.user_id = $1
          AND mr.server_id = $2
          AND r.server_id = $2
          AND r.color_only = true
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .execute(&mut *tx)
    .await?;

    if let Some(role_id) = role_id {
        sqlx::query(
            r#"
            INSERT INTO member_roles (user_id, server_id, role_id)
            VALUES ($1,$2,$3)
            ON CONFLICT (user_id, server_id, role_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(server_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await
}

pub async fn list_role_ids(
    pool: &PgPool,
    user_id: i64,
    server_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT role_id FROM member_roles WHERE user_id = $1 AND server_id = $2")
            .bind(user_id)
            .bind(server_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// "List user's role assignments across all servers" — used at IDENTIFY.
pub async fn list_for_user(pool: &PgPool, user_id: i64) -> Result<Vec<MemberRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, MemberRoleRow>("SELECT * FROM member_roles WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await
}

/// Bulk replace: drop all of user's roles for a server, then assign new
/// set. Single transaction so the mid-state is never visible.
pub async fn replace_user_roles_in_server(
    pool: &PgPool,
    user_id: i64,
    server_id: i64,
    role_ids: &[i64],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM member_roles WHERE user_id = $1 AND server_id = $2")
        .bind(user_id)
        .bind(server_id)
        .execute(&mut *tx)
        .await?;
    if !role_ids.is_empty() {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO member_roles (user_id, server_id, role_id) ",
        );
        qb.push_values(role_ids.iter(), |mut b, rid| {
            b.push_bind(user_id).push_bind(server_id).push_bind(rid);
        });
        qb.push(" ON CONFLICT DO NOTHING");
        qb.build().execute(&mut *tx).await?;
    }
    tx.commit().await
}
