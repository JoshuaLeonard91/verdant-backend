//! Users — auth identity, profile, prefs, 2FA, subscription state.

use super::{ms_to_dt, ms_to_dt_opt};
use crate::repo::users::UserRow;
use crate::services::banner_crop::{self, BannerCrop};
use sqlx::{PgPool, Postgres, Transaction};

/// Internal raw row mirroring the table columns. Public conversion
/// hop keeps the handler-facing `UserRow` (chrono-typed timestamps,
/// optional fields, `serde_json::Value` for jsonb) decoupled from the
/// PG row layout.
#[derive(Debug, sqlx::FromRow)]
struct UserRaw {
    id: i64,
    email: String,
    password_hash: String,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    banner_url: Option<String>,
    banner_base_color: Option<String>,
    banner_crop_x: Option<f64>,
    banner_crop_y: Option<f64>,
    banner_crop_width: Option<f64>,
    banner_crop_height: Option<f64>,
    member_list_banner_url: Option<String>,
    member_list_banner_crop_x: Option<f64>,
    member_list_banner_crop_y: Option<f64>,
    member_list_banner_crop_width: Option<f64>,
    member_list_banner_crop_height: Option<f64>,
    bio: Option<String>,
    custom_status_text: Option<String>,
    custom_status_emoji: Option<String>,
    status_type: String,
    email_verified: bool,
    username_set: bool,
    server_order: Vec<i64>,
    favorite_order: Vec<i64>,
    preferences: serde_json::Value,
    totp_secret: Option<Vec<u8>>,
    totp_enabled_at_ms: Option<i64>,
    subscription_tier: Option<String>,
    subscription_expires_at_ms: Option<i64>,
    subscribed: bool,
    subscription_ring_style: Option<String>,
    status_auto: bool,
    preferred_status: String,
    deleted_at_ms: Option<i64>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

impl From<UserRaw> for UserRow {
    fn from(r: UserRaw) -> UserRow {
        UserRow {
            id: r.id,
            username: r.username,
            email: r.email,
            password_hash: r.password_hash,
            avatar_url: r.avatar_url,
            // status_type drives both fields in the legacy Row shape.
            status: r.status_type.clone(),
            status_type: r.status_type,
            subscribed: r.subscribed,
            display_name: r.display_name,
            bio: r.bio,
            custom_status_text: r.custom_status_text,
            custom_status_emoji: r.custom_status_emoji,
            created_at: ms_to_dt(r.created_at_ms),
            updated_at: ms_to_dt(r.updated_at_ms),
            // The legacy Row carried the TOTP secret as a base64 string
            // (the encrypted ciphertext was stored as text). With the
            // bytea column it's cleaner to expose the raw bytes; we
            // base64 here so existing call sites that decrypt strings
            // keep working.
            totp_secret: r.totp_secret.as_ref().map(|b| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(b)
            }),
            totp_enabled_at: ms_to_dt_opt(r.totp_enabled_at_ms),
            banner_url: r.banner_url,
            banner_base_color: r.banner_base_color,
            banner_crop: banner_crop::from_parts(
                r.banner_crop_x,
                r.banner_crop_y,
                r.banner_crop_width,
                r.banner_crop_height,
            ),
            member_list_banner_url: r.member_list_banner_url,
            member_list_banner_crop: banner_crop::from_parts(
                r.member_list_banner_crop_x,
                r.member_list_banner_crop_y,
                r.member_list_banner_crop_width,
                r.member_list_banner_crop_height,
            ),
            server_order: serde_json::Value::Array(
                r.server_order
                    .iter()
                    .map(|n| serde_json::Value::String(n.to_string()))
                    .collect(),
            ),
            favorite_order: serde_json::Value::Array(
                r.favorite_order
                    .iter()
                    .map(|n| serde_json::Value::String(n.to_string()))
                    .collect(),
            ),
            email_verified: r.email_verified,
            deleted_at: ms_to_dt_opt(r.deleted_at_ms),
            username_set: r.username_set,
            preferences: r.preferences,
            subscription_tier: r.subscription_tier,
            subscription_expires_at: ms_to_dt_opt(r.subscription_expires_at_ms),
            subscription_ring_style: r.subscription_ring_style,
            status_auto: r.status_auto,
            preferred_status: r.preferred_status,
        }
    }
}

const SELECT_COLS: &str = "
    id, email, password_hash, username, display_name, avatar_url,
    banner_url, banner_base_color, banner_crop_x, banner_crop_y, banner_crop_width, banner_crop_height,
    member_list_banner_url, member_list_banner_crop_x, member_list_banner_crop_y,
    member_list_banner_crop_width, member_list_banner_crop_height,
    bio, custom_status_text, custom_status_emoji,
    status_type, email_verified, username_set,
    server_order, favorite_order, preferences,
    totp_secret, totp_enabled_at_ms,
    subscription_tier, subscription_expires_at_ms, subscribed, subscription_ring_style,
    status_auto, preferred_status,
    deleted_at_ms, created_at_ms, updated_at_ms
";

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<UserRow>, sqlx::Error> {
    let raw =
        sqlx::query_as::<_, UserRaw>(&format!("SELECT {SELECT_COLS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(raw.map(Into::into))
}

/// Batch-fetch by id list. Single round trip via `= ANY($1)`.
pub async fn by_ids(pool: &PgPool, ids: &[i64]) -> Result<Vec<UserRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let raws = sqlx::query_as::<_, UserRaw>(&format!(
        "SELECT {SELECT_COLS} FROM users WHERE id = ANY($1::bigint[])"
    ))
    .bind(ids)
    .fetch_all(pool)
    .await?;
    Ok(raws.into_iter().map(Into::into).collect())
}

/// Login lookup. `lower(email)` indexed for case-insensitive match.
pub async fn by_email_lower(pool: &PgPool, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
    let raw = sqlx::query_as::<_, UserRaw>(&format!(
        "SELECT {SELECT_COLS} FROM users WHERE lower(email) = lower($1)"
    ))
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(raw.map(Into::into))
}

pub async fn by_username_lower(
    pool: &PgPool,
    username: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let raw = sqlx::query_as::<_, UserRaw>(&format!(
        "SELECT {SELECT_COLS} FROM users WHERE lower(username) = lower($1)"
    ))
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(raw.map(Into::into))
}

pub async fn email_exists(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let row: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = lower($1))")
            .bind(email)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

pub async fn email_verified_by_id(pool: &PgPool, id: i64) -> Result<Option<bool>, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(verified,)| verified))
}

pub async fn username_exists(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    let row: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE lower(username) = lower($1))")
            .bind(username)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Initial signup. Snowflake id provided by caller.
pub struct InsertUser<'a> {
    pub id: i64,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub username: &'a str,
    pub display_name: Option<&'a str>,
    pub username_set: bool,
    pub email_verified: bool,
    pub now_ms: i64,
}

pub async fn insert(pool: &PgPool, u: InsertUser<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, username, display_name,
                           username_set, email_verified, status_type,
                           created_at_ms, updated_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'offline',$8,$8)
        "#,
    )
    .bind(u.id)
    .bind(u.email)
    .bind(u.password_hash)
    .bind(u.username)
    .bind(u.display_name)
    .bind(u.username_set)
    .bind(u.email_verified)
    .bind(u.now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Generic patch: each `Some(_)` field is set, `None` skipped. We use
/// `COALESCE($N, col)` to make the SQL identical regardless of which
/// fields are being patched. Cheap and avoids dynamic SQL.
#[derive(Default)]
pub struct UpdateUser<'a> {
    pub display_name: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub banner_url: Option<&'a str>,
    pub banner_base_color: Option<&'a str>,
    pub member_list_banner_url: Option<&'a str>,
    pub bio: Option<&'a str>,
    pub custom_status_text: Option<&'a str>,
    pub custom_status_emoji: Option<&'a str>,
    pub status_type: Option<&'a str>,
    pub username: Option<&'a str>,
    pub email: Option<&'a str>,
    pub password_hash: Option<&'a str>,
    pub email_verified: Option<bool>,
    pub username_set: Option<bool>,
    pub server_order: Option<&'a [i64]>,
    pub favorite_order: Option<&'a [i64]>,
    pub preferences: Option<&'a serde_json::Value>,
}

pub async fn update(pool: &PgPool, id: i64, p: UpdateUser<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users SET
            display_name   = COALESCE($2,  display_name),
            avatar_url     = COALESCE($3,  avatar_url),
            banner_url     = COALESCE($4,  banner_url),
            banner_base_color = COALESCE($5, banner_base_color),
            member_list_banner_url = COALESCE($6, member_list_banner_url),
            bio            = COALESCE($7,  bio),
            custom_status_text  = COALESCE($8,  custom_status_text),
            custom_status_emoji = COALESCE($9,  custom_status_emoji),
            status_type    = COALESCE($10,  status_type),
            username       = COALESCE($11, username),
            email          = COALESCE($12, email),
            password_hash  = COALESCE($13, password_hash),
            email_verified = COALESCE($14, email_verified),
            username_set   = COALESCE($15, username_set),
            server_order   = COALESCE($16, server_order),
            favorite_order = COALESCE($17, favorite_order),
            preferences    = COALESCE($18, preferences),
            updated_at_ms  = $19
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(p.display_name)
    .bind(p.avatar_url)
    .bind(p.banner_url)
    .bind(p.banner_base_color)
    .bind(p.member_list_banner_url)
    .bind(p.bio)
    .bind(p.custom_status_text)
    .bind(p.custom_status_emoji)
    .bind(p.status_type)
    .bind(p.username)
    .bind(p.email)
    .bind(p.password_hash)
    .bind(p.email_verified)
    .bind(p.username_set)
    .bind(p.server_order)
    .bind(p.favorite_order)
    .bind(p.preferences)
    .bind(super::now_ms())
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
        UPDATE users
           SET banner_crop_x      = $2,
               banner_crop_y      = $3,
               banner_crop_width  = $4,
               banner_crop_height = $5,
               updated_at_ms      = $6
         WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(x)
    .bind(y)
    .bind(width)
    .bind(height)
    .bind(super::now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_member_list_banner_crop(
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
        UPDATE users
           SET member_list_banner_crop_x      = $2,
               member_list_banner_crop_y      = $3,
               member_list_banner_crop_width  = $4,
               member_list_banner_crop_height = $5,
               updated_at_ms                  = $6
         WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(x)
    .bind(y)
    .bind(width)
    .bind(height)
    .bind(super::now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

/// Soft-delete: set `deleted_at_ms = now`. Reads everywhere filter
/// the deleted set out via the partial `users_active_idx` index.
pub async fn soft_delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET deleted_at_ms = $2, updated_at_ms = $2 WHERE id = $1 AND deleted_at_ms IS NULL",
    )
    .bind(id)
    .bind(super::now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

/// Hard-delete: cascades through every `ON DELETE CASCADE` FK target
/// (sessions, server_members, member_roles, relationships, …). Use for
/// the GDPR-style purge, not the user-facing "delete account" flow
/// which is soft-delete only.
pub async fn hard_delete(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// 2FA: set encrypted TOTP secret + backup codes.
pub async fn set_totp(
    pool: &PgPool,
    id: i64,
    encrypted_secret: &[u8],
    backup_code_hashes: &[String],
    enabled_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users
           SET totp_secret           = $2,
               backup_code_hashes    = $3,
               totp_enabled_at_ms    = $4,
               updated_at_ms         = $4
         WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(encrypted_secret)
    .bind(backup_code_hashes)
    .bind(enabled_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// 2FA: clear all TOTP state (disable).
pub async fn clear_totp(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users
           SET totp_secret         = NULL,
               backup_code_hashes  = '{}',
               totp_enabled_at_ms  = NULL,
               updated_at_ms       = $2
         WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(super::now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

/// 2FA: consume a backup code (atomic remove from array).
/// Returns `true` if the code was present and removed.
pub async fn consume_backup_code(
    pool: &PgPool,
    id: i64,
    code_hash: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        UPDATE users
           SET backup_code_hashes = array_remove(backup_code_hashes, $2),
               updated_at_ms      = $3
         WHERE id = $1 AND $2 = ANY(backup_code_hashes)
        "#,
    )
    .bind(id)
    .bind(code_hash)
    .bind(super::now_ms())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Subscription: activate / extend.
pub async fn set_subscription(
    pool: &PgPool,
    id: i64,
    tier: Option<&str>,
    expires_at_ms: Option<i64>,
    subscribed: bool,
    ring_style: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users
           SET subscription_tier            = $2,
               subscription_expires_at_ms   = $3,
               subscribed                   = $4,
               subscription_ring_style      = COALESCE($5, subscription_ring_style),
               updated_at_ms                = $6
         WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(tier)
    .bind(expires_at_ms)
    .bind(subscribed)
    .bind(ring_style)
    .bind(super::now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_subscription_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    tier: Option<&str>,
    expires_at_ms: Option<i64>,
    subscribed: bool,
    ring_style: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users
           SET subscription_tier            = $2,
               subscription_expires_at_ms   = $3,
               subscribed                   = $4,
               subscription_ring_style      = COALESCE($5, subscription_ring_style),
               updated_at_ms                = $6
         WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(tier)
    .bind(expires_at_ms)
    .bind(subscribed)
    .bind(ring_style)
    .bind(super::now_ms())
    .execute(&mut **tx)
    .await?;
    Ok(())
}
