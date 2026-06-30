//! Bots + bot_tokens. Token rotation supported via separate rows
//! per active token; revoke sets `revoked_at_ms` rather than deleting.

use crate::services::banner_crop::BannerCrop;
use sqlx::PgPool;

pub const SCOPE_ANNOUNCEMENTS_WRITE: &str = "announcements:write";
pub const SCOPE_FEEDS_READ: &str = "feeds:read";
pub const SCOPE_MESSAGES_WRITE: &str = "messages:write";
pub const SCOPE_MESSAGES_READ: &str = "messages:read";
pub const SCOPE_MESSAGE_CONTENT_READ: &str = "message_content:read";
pub const SCOPE_MEMBERS_READ: &str = "members:read";
pub const SCOPE_AUDIT_READ: &str = "audit:read";
pub const SCOPE_UPLOADS_WRITE: &str = "uploads:write";

pub const ALL_SCOPES: &[&str] = &[
    SCOPE_ANNOUNCEMENTS_WRITE,
    SCOPE_FEEDS_READ,
    SCOPE_MESSAGES_WRITE,
    SCOPE_MESSAGES_READ,
    SCOPE_MESSAGE_CONTENT_READ,
    SCOPE_MEMBERS_READ,
    SCOPE_AUDIT_READ,
    SCOPE_UPLOADS_WRITE,
];

pub fn default_token_scopes() -> Vec<String> {
    vec![
        SCOPE_ANNOUNCEMENTS_WRITE.to_string(),
        SCOPE_FEEDS_READ.to_string(),
        SCOPE_UPLOADS_WRITE.to_string(),
    ]
}

pub fn normalize_scopes(scopes: Option<&[String]>) -> Vec<String> {
    let Some(scopes) = scopes else {
        return default_token_scopes();
    };
    let mut result = Vec::new();
    for scope in scopes {
        let trimmed = scope.trim();
        if ALL_SCOPES.contains(&trimmed) && !result.iter().any(|s| s == trimmed) {
            result.push(trimmed.to_string());
        }
    }
    result
}

pub fn has_scope(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|s| s == scope)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BotRow {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub banner_crop_x: Option<f64>,
    pub banner_crop_y: Option<f64>,
    pub banner_crop_width: Option<f64>,
    pub banner_crop_height: Option<f64>,
    pub avatar_preset: Option<String>,
    pub banner_preset: Option<String>,
    pub created_at_ms: i64,
}

impl BotRow {
    pub fn banner_crop(&self) -> Option<BannerCrop> {
        crate::services::banner_crop::from_parts(
            self.banner_crop_x,
            self.banner_crop_y,
            self.banner_crop_width,
            self.banner_crop_height,
        )
    }
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<BotRow>, sqlx::Error> {
    sqlx::query_as::<_, BotRow>("SELECT * FROM bots WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn by_ids(pool: &PgPool, ids: &[i64]) -> Result<Vec<BotRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, BotRow>("SELECT * FROM bots WHERE id = ANY($1::bigint[])")
        .bind(ids)
        .fetch_all(pool)
        .await
}

pub async fn list_for_server(pool: &PgPool, server_id: i64) -> Result<Vec<BotRow>, sqlx::Error> {
    sqlx::query_as::<_, BotRow>("SELECT * FROM bots WHERE server_id = $1 ORDER BY id ASC")
        .bind(server_id)
        .fetch_all(pool)
        .await
}

pub async fn insert(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    name: &str,
    description: Option<&str>,
    avatar_preset: Option<&str>,
    banner_preset: Option<&str>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO bots
            (id, server_id, name, description, avatar_preset, banner_preset, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(description)
    .bind(avatar_preset)
    .bind(banner_preset)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update(
    pool: &PgPool,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    avatar_url: Option<&str>,
    banner_url: Option<&str>,
    avatar_preset: Option<&str>,
    banner_preset: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE bots SET
            name          = COALESCE($2, name),
            description   = COALESCE($3, description),
            avatar_url    = COALESCE($4, avatar_url),
            banner_url    = COALESCE($5, banner_url),
            avatar_preset = COALESCE($6, avatar_preset),
            banner_preset = COALESCE($7, banner_preset)
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(avatar_url)
    .bind(banner_url)
    .bind(avatar_preset)
    .bind(banner_preset)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_banner_crop(
    pool: &PgPool,
    id: i64,
    crop: Option<BannerCrop>,
) -> Result<(), sqlx::Error> {
    let (x, y, width, height) = match crop {
        Some(c) => (Some(c.x), Some(c.y), Some(c.width), Some(c.height)),
        None => (None, None, None, None),
    };
    sqlx::query(
        r#"
        UPDATE bots SET
            banner_crop_x      = $2,
            banner_crop_y      = $3,
            banner_crop_width  = $4,
            banner_crop_height = $5
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(x)
    .bind(y)
    .bind(width)
    .bind(height)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("UPDATE announcements SET bot_id = NULL WHERE bot_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM bots WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

// ─── bot_tokens ──────────────────────────────────────────────────────

// ─── bot_roles ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BotRoleRow {
    pub bot_id: i64,
    pub server_id: i64,
    pub role_id: i64,
}

pub async fn list_role_ids(
    pool: &PgPool,
    bot_id: i64,
    server_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT role_id FROM bot_roles WHERE bot_id = $1 AND server_id = $2")
            .bind(bot_id)
            .bind(server_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn list_roles_for_server(
    pool: &PgPool,
    server_id: i64,
) -> Result<Vec<BotRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, BotRoleRow>(
        "SELECT bot_id, server_id, role_id FROM bot_roles WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await
}

pub async fn assign_role(
    pool: &PgPool,
    bot_id: i64,
    server_id: i64,
    role_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO bot_roles (bot_id, server_id, role_id, created_at_ms)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (bot_id, server_id, role_id) DO NOTHING
        "#,
    )
    .bind(bot_id)
    .bind(server_id)
    .bind(role_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn unassign_role(
    pool: &PgPool,
    bot_id: i64,
    server_id: i64,
    role_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM bot_roles WHERE bot_id = $1 AND server_id = $2 AND role_id = $3")
        .bind(bot_id)
        .bind(server_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BotTokenRow {
    pub id: i64,
    pub bot_id: i64,
    pub token_hash: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub allowed_feed_ids: Vec<i64>,
    pub allowed_channel_ids: Vec<i64>,
    pub revoked_at_ms: Option<i64>,
    pub last_used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

pub async fn token_by_id(pool: &PgPool, id: i64) -> Result<Option<BotTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, BotTokenRow>("SELECT * FROM bot_tokens WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Bot-auth hot path. Single index hit on `bot_tokens_hash_uniq`.
pub async fn token_by_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<BotTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, BotTokenRow>("SELECT * FROM bot_tokens WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn list_tokens(pool: &PgPool, bot_id: i64) -> Result<Vec<BotTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, BotTokenRow>(
        "SELECT * FROM bot_tokens WHERE bot_id = $1 ORDER BY created_at_ms DESC",
    )
    .bind(bot_id)
    .fetch_all(pool)
    .await
}

pub async fn token_insert(
    pool: &PgPool,
    id: i64,
    bot_id: i64,
    token_hash: &str,
    name: &str,
    scopes: &[String],
    allowed_feed_ids: &[i64],
    allowed_channel_ids: &[i64],
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO bot_tokens
            (id, bot_id, token_hash, name, scopes, allowed_feed_ids,
             allowed_channel_ids, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(id)
    .bind(bot_id)
    .bind(token_hash)
    .bind(name)
    .bind(scopes)
    .bind(allowed_feed_ids)
    .bind(allowed_channel_ids)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn token_revoke(pool: &PgPool, id: i64, now_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE bot_tokens SET revoked_at_ms = $2 WHERE id = $1 AND revoked_at_ms IS NULL")
        .bind(id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn token_touch_last_used(pool: &PgPool, id: i64, now_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE bot_tokens SET last_used_at_ms = $2 WHERE id = $1")
        .bind(id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}
