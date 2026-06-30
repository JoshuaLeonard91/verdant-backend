//! Servers + server_members.

use super::{ms_to_dt, ms_to_dt_opt};
use crate::repo::servers::ServerRow;
use crate::services::banner_crop::{self, BannerCrop};
use sqlx::PgPool;

#[derive(Debug, sqlx::FromRow)]
struct ServerRaw {
    id: i64,
    name: String,
    owner_id: i64,
    icon_url: Option<String>,
    banner_url: Option<String>,
    banner_crop_x: Option<f64>,
    banner_crop_y: Option<f64>,
    banner_crop_width: Option<f64>,
    banner_crop_height: Option<f64>,
    accent_color: Option<String>,
    banner_offset_y: i32,
    voice_bitrate: i32,
    welcome_channel_id: Option<i64>,
    announce_channel_id: Option<i64>,
    welcome_message: Option<String>,
    welcome_screen_description: Option<String>,
    welcome_screen_channels: serde_json::Value,
    emoji_version: i32,
    deleted_at_ms: Option<i64>,
    created_at_ms: i64,
}

impl From<ServerRaw> for ServerRow {
    fn from(r: ServerRaw) -> Self {
        Self {
            id: r.id,
            name: r.name,
            icon_url: r.icon_url,
            owner_id: r.owner_id,
            voice_bitrate: r.voice_bitrate,
            welcome_channel_id: r.welcome_channel_id,
            announce_channel_id: r.announce_channel_id,
            welcome_message: r.welcome_message,
            welcome_screen_description: r.welcome_screen_description,
            welcome_screen_channels: Some(r.welcome_screen_channels),
            emoji_version: r.emoji_version,
            banner_url: r.banner_url,
            banner_crop: banner_crop::from_parts(
                r.banner_crop_x,
                r.banner_crop_y,
                r.banner_crop_width,
                r.banner_crop_height,
            ),
            accent_color: r.accent_color,
            banner_offset_y: r.banner_offset_y,
            created_at: ms_to_dt(r.created_at_ms),
            deleted_at: ms_to_dt_opt(r.deleted_at_ms),
        }
    }
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<ServerRow>, sqlx::Error> {
    let r = sqlx::query_as::<_, ServerRaw>("SELECT * FROM servers WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(r.map(Into::into))
}

pub async fn by_ids(pool: &PgPool, ids: &[i64]) -> Result<Vec<ServerRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rs = sqlx::query_as::<_, ServerRaw>(
        "SELECT * FROM servers WHERE id = ANY($1::bigint[]) AND deleted_at_ms IS NULL",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    Ok(rs.into_iter().map(Into::into).collect())
}

pub async fn insert(
    pool: &PgPool,
    id: i64,
    name: &str,
    owner_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO servers (id, name, owner_id, created_at_ms) VALUES ($1,$2,$3,$4)")
        .bind(id)
        .bind(name)
        .bind(owner_id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Default)]
pub struct UpdateServer<'a> {
    pub name: Option<&'a str>,
    pub icon_url: Option<&'a str>,
    pub banner_url: Option<&'a str>,
    pub accent_color: Option<&'a str>,
    pub banner_offset_y: Option<i32>,
    pub voice_bitrate: Option<i32>,
    pub welcome_channel_id: Option<i64>,
    pub announce_channel_id: Option<i64>,
    pub welcome_message: Option<&'a str>,
    pub welcome_screen_description: Option<&'a str>,
    pub welcome_screen_channels: Option<&'a serde_json::Value>,
    pub emoji_version: Option<i32>,
    pub owner_id: Option<i64>,
}

pub async fn update(pool: &PgPool, id: i64, p: UpdateServer<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE servers SET
            name                       = COALESCE($2,  name),
            icon_url                   = COALESCE($3,  icon_url),
            banner_url                 = COALESCE($4,  banner_url),
            accent_color               = COALESCE($5,  accent_color),
            banner_offset_y            = COALESCE($6,  banner_offset_y),
            voice_bitrate              = COALESCE($7,  voice_bitrate),
            welcome_channel_id         = CASE WHEN $8 IS NULL THEN welcome_channel_id WHEN $8 = 0 THEN NULL ELSE $8 END,
            announce_channel_id        = CASE WHEN $9 IS NULL THEN announce_channel_id WHEN $9 = 0 THEN NULL ELSE $9 END,
            welcome_message            = COALESCE($10, welcome_message),
            welcome_screen_description = COALESCE($11, welcome_screen_description),
            welcome_screen_channels    = COALESCE($12, welcome_screen_channels),
            emoji_version              = COALESCE($13, emoji_version),
            owner_id                   = COALESCE($14, owner_id)
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(p.name)
    .bind(p.icon_url)
    .bind(p.banner_url)
    .bind(p.accent_color)
    .bind(p.banner_offset_y)
    .bind(p.voice_bitrate)
    .bind(p.welcome_channel_id)
    .bind(p.announce_channel_id)
    .bind(p.welcome_message)
    .bind(p.welcome_screen_description)
    .bind(p.welcome_screen_channels)
    .bind(p.emoji_version)
    .bind(p.owner_id)
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
        UPDATE servers SET
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

/// Atomically bump emoji_version and return the new value. Used by
/// the emoji rename/delete fan-out so clients can detect they've
/// fallen out of sync via a monotonic counter.
pub async fn bump_emoji_version(pool: &PgPool, id: i64) -> Result<Option<i32>, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "UPDATE servers SET emoji_version = emoji_version + 1 WHERE id = $1 RETURNING emoji_version",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(v,)| v))
}

pub async fn soft_delete(pool: &PgPool, id: i64, now_ms: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE servers SET deleted_at_ms = $2 WHERE id = $1 AND deleted_at_ms IS NULL")
        .bind(id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── server_members ──────────────────────────────────────────────────

pub async fn add_member(
    pool: &PgPool,
    server_id: i64,
    user_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO server_members (server_id, user_id, joined_at_ms)
        VALUES ($1, $2, $3)
        ON CONFLICT (server_id, user_id) DO NOTHING
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_member(pool: &PgPool, server_id: i64, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn is_member(pool: &PgPool, server_id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// "List user's servers" — uses server_members_user_idx.
pub async fn list_server_ids_for_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT server_id FROM server_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// "List server's members" — uses primary key on (server_id, user_id).
pub async fn list_member_ids_for_server(
    pool: &PgPool,
    server_id: i64,
) -> Result<Vec<i64>, sqlx::Error> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        r#"
        SELECT sm.user_id
          FROM server_members sm
          JOIN users u ON u.id = sm.user_id
         WHERE sm.server_id = $1
           AND u.deleted_at_ms IS NULL
        "#,
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn member_count(pool: &PgPool, server_id: i64) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
          FROM server_members sm
          JOIN users u ON u.id = sm.user_id
         WHERE sm.server_id = $1
           AND u.deleted_at_ms IS NULL
        "#,
    )
    .bind(server_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}
