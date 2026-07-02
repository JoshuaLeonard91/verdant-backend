//! Users — auth identity, profile, prefs, 2FA, subscription state.

use super::{ms_to_dt, ms_to_dt_opt};
use crate::repo::users::UserRow;
use crate::services::banner_crop::{self, BannerCrop};
use crate::services::field_crypto::{
    EncryptedField, FieldAad, FieldCryptoError, FieldEncryptionKeyring,
};
use sqlx::{PgPool, Postgres, Transaction};

const USER_EMAIL_TABLE: &str = "users";
const USER_EMAIL_COLUMN: &str = "email";

/// Internal raw row mirroring the table columns. Public conversion
/// hop keeps the handler-facing `UserRow` (chrono-typed timestamps,
/// optional fields, `serde_json::Value` for jsonb) decoupled from the
/// PG row layout.
#[derive(Debug, sqlx::FromRow)]
struct UserRaw {
    id: i64,
    email: String,
    email_ciphertext: Option<Vec<u8>>,
    email_nonce: Option<Vec<u8>>,
    email_key_version: Option<i16>,
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
        user_row_from_raw(r, None).expect("plaintext user row conversion cannot fail")
    }
}

fn user_row_from_raw(
    r: UserRaw,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<UserRow, sqlx::Error> {
    let email = match keyring {
        Some(keyring) => decrypt_email_from_raw(keyring, &r)?.unwrap_or_else(|| r.email.clone()),
        None => r.email.clone(),
    };
    Ok(UserRow {
        id: r.id,
        username: r.username,
        email,
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
    })
}

fn decrypt_email_from_raw(
    keyring: &FieldEncryptionKeyring,
    raw: &UserRaw,
) -> Result<Option<String>, sqlx::Error> {
    let (Some(ciphertext), Some(nonce), Some(key_version)) = (
        raw.email_ciphertext.as_ref(),
        raw.email_nonce.as_ref(),
        raw.email_key_version,
    ) else {
        return Ok(None);
    };
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| sqlx::Error::Protocol("invalid encrypted user email nonce".into()))?;
    let encrypted = EncryptedField::from_parts(key_version, nonce, ciphertext.clone())
        .map_err(|_| sqlx::Error::Protocol("invalid encrypted user email metadata".into()))?;
    let bytes = keyring
        .decrypt_bytes(&encrypted, &email_aad(raw.id))
        .map_err(|_| sqlx::Error::Protocol("encrypted user email decryption failed".into()))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| sqlx::Error::Protocol("encrypted user email is not utf-8".into()))
}

fn field_crypto_sql_error(context: &'static str, err: FieldCryptoError) -> sqlx::Error {
    sqlx::Error::Protocol(format!("{context}: {err}"))
}

pub const USER_EMAIL_BACKFILL_CLAIM_SQL: &str = r#"
    SELECT id, email
      FROM users
     WHERE email_ciphertext IS NULL
        OR email_nonce IS NULL
        OR email_key_version IS NULL
        OR email_blind_index IS NULL
     ORDER BY id ASC
     LIMIT $1
     FOR UPDATE SKIP LOCKED
"#;

pub const USER_EMAIL_BACKFILL_UPDATE_SQL: &str = r#"
    UPDATE users
       SET email_ciphertext = $2,
           email_nonce = $3,
           email_key_version = $4,
           email_blind_index = $5,
           updated_at_ms = $6
     WHERE id = $1
"#;

#[derive(Debug, sqlx::FromRow)]
struct UserEmailBackfillCandidate {
    id: i64,
    email: String,
}

const SELECT_COLS: &str = "
    id, email, email_ciphertext, email_nonce, email_key_version,
    password_hash, username, display_name, avatar_url,
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

pub async fn by_id_with_crypto(
    pool: &PgPool,
    id: i64,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<Option<UserRow>, sqlx::Error> {
    let raw =
        sqlx::query_as::<_, UserRaw>(&format!("SELECT {SELECT_COLS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    raw.map(|r| user_row_from_raw(r, keyring)).transpose()
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

pub async fn by_ids_with_crypto(
    pool: &PgPool,
    ids: &[i64],
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<Vec<UserRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let raws = sqlx::query_as::<_, UserRaw>(&format!(
        "SELECT {SELECT_COLS} FROM users WHERE id = ANY($1::bigint[])"
    ))
    .bind(ids)
    .fetch_all(pool)
    .await?;
    raws.into_iter()
        .map(|r| user_row_from_raw(r, keyring))
        .collect()
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

pub async fn by_email_lower_with_crypto(
    pool: &PgPool,
    email: &str,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<Option<UserRow>, sqlx::Error> {
    let raw = if let Some(keyring) = keyring {
        let blind_index = email_blind_index(keyring, email);
        sqlx::query_as::<_, UserRaw>(&format!(
            "SELECT {SELECT_COLS} FROM users
             WHERE email_blind_index = $1
                OR (email_blind_index IS NULL AND lower(email) = lower($2))
             LIMIT 1"
        ))
        .bind(blind_index)
        .bind(email)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as::<_, UserRaw>(&format!(
            "SELECT {SELECT_COLS} FROM users WHERE lower(email) = lower($1)"
        ))
        .bind(email)
        .fetch_optional(pool)
        .await?
    };
    raw.map(|r| user_row_from_raw(r, keyring)).transpose()
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

pub async fn email_exists_with_crypto(
    pool: &PgPool,
    email: &str,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<bool, sqlx::Error> {
    let row: (bool,) = if let Some(keyring) = keyring {
        let blind_index = email_blind_index(keyring, email);
        sqlx::query_as(
            "SELECT EXISTS(
                SELECT 1 FROM users
                 WHERE email_blind_index = $1
                    OR (email_blind_index IS NULL AND lower(email) = lower($2))
             )",
        )
        .bind(blind_index)
        .bind(email)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = lower($1))")
            .bind(email)
            .fetch_one(pool)
            .await?
    };
    Ok(row.0)
}

pub async fn backfill_encrypted_email_batch(
    pool: &PgPool,
    keyring: &FieldEncryptionKeyring,
    requested_limit: i64,
) -> Result<usize, sqlx::Error> {
    let limit = user_email_backfill_batch_limit(requested_limit);
    let mut tx = pool.begin().await?;
    let candidates = sqlx::query_as::<_, UserEmailBackfillCandidate>(USER_EMAIL_BACKFILL_CLAIM_SQL)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

    for candidate in &candidates {
        let encrypted_email = prepare_email_encryption(keyring, candidate.id, &candidate.email)
            .map_err(|err| field_crypto_sql_error("could not encrypt user email", err))?;
        sqlx::query(USER_EMAIL_BACKFILL_UPDATE_SQL)
            .bind(candidate.id)
            .bind(encrypted_email.ciphertext())
            .bind(encrypted_email.nonce().as_slice())
            .bind(encrypted_email.key_version())
            .bind(encrypted_email.blind_index())
            .bind(super::now_ms())
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(candidates.len())
}

fn user_email_backfill_batch_limit(requested_limit: i64) -> i64 {
    requested_limit.clamp(1, 1_000)
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
    insert_with_crypto(pool, u, None).await
}

pub async fn insert_with_crypto(
    pool: &PgPool,
    u: InsertUser<'_>,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_tx(&mut tx, u, keyring).await?;
    tx.commit().await
}

pub async fn insert_tx(
    tx: &mut Transaction<'_, Postgres>,
    u: InsertUser<'_>,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<(), sqlx::Error> {
    let encrypted_email = keyring
        .map(|keyring| prepare_email_encryption(keyring, u.id, u.email))
        .transpose()
        .map_err(|err| field_crypto_sql_error("could not encrypt user email", err))?;
    let email_ciphertext: Option<&[u8]> = encrypted_email.as_ref().map(|v| v.ciphertext());
    let email_nonce: Option<&[u8]> = encrypted_email.as_ref().map(|v| v.nonce().as_slice());
    let email_key_version = encrypted_email.as_ref().map(|v| v.key_version());
    let email_blind_index = encrypted_email.as_ref().map(|v| v.blind_index());

    sqlx::query(
        r#"
        INSERT INTO users (id, email, email_ciphertext, email_nonce, email_key_version,
                           email_blind_index, password_hash, username, display_name,
                           username_set, email_verified, status_type,
                           created_at_ms, updated_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'offline',$12,$12)
        "#,
    )
    .bind(u.id)
    .bind(u.email)
    .bind(email_ciphertext)
    .bind(email_nonce)
    .bind(email_key_version)
    .bind(email_blind_index)
    .bind(u.password_hash)
    .bind(u.username)
    .bind(u.display_name)
    .bind(u.username_set)
    .bind(u.email_verified)
    .bind(u.now_ms)
    .execute(&mut **tx)
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
    update_with_crypto(pool, id, p, None).await
}

pub async fn update_with_crypto(
    pool: &PgPool,
    id: i64,
    p: UpdateUser<'_>,
    keyring: Option<&FieldEncryptionKeyring>,
) -> Result<(), sqlx::Error> {
    let email_changed = p.email.is_some();
    let encrypted_email = match (keyring, p.email) {
        (Some(keyring), Some(email)) => Some(
            prepare_email_encryption(keyring, id, email)
                .map_err(|err| field_crypto_sql_error("could not encrypt user email", err))?,
        ),
        _ => None,
    };
    let email_ciphertext: Option<&[u8]> = encrypted_email.as_ref().map(|v| v.ciphertext());
    let email_nonce: Option<&[u8]> = encrypted_email.as_ref().map(|v| v.nonce().as_slice());
    let email_key_version = encrypted_email.as_ref().map(|v| v.key_version());
    let email_blind_index = encrypted_email.as_ref().map(|v| v.blind_index());

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
            updated_at_ms  = $19,
            email_ciphertext = CASE WHEN $20 THEN $21::bytea ELSE email_ciphertext END,
            email_nonce = CASE WHEN $20 THEN $22::bytea ELSE email_nonce END,
            email_key_version = CASE WHEN $20 THEN $23::smallint ELSE email_key_version END,
            email_blind_index = CASE WHEN $20 THEN $24::text ELSE email_blind_index END
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
    .bind(email_changed)
    .bind(email_ciphertext)
    .bind(email_nonce)
    .bind(email_key_version)
    .bind(email_blind_index)
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

#[derive(Debug, Clone)]
pub struct EncryptedEmailWrite {
    field: EncryptedField,
    blind_index: String,
}

impl EncryptedEmailWrite {
    pub fn key_version(&self) -> i16 {
        self.field.key_version()
    }

    pub fn nonce(&self) -> &[u8; 12] {
        self.field.nonce()
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.field.ciphertext()
    }

    pub fn blind_index(&self) -> &str {
        &self.blind_index
    }
}

fn normalize_email_for_blind_index(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn email_aad(user_id: i64) -> FieldAad {
    FieldAad::new(USER_EMAIL_TABLE, USER_EMAIL_COLUMN, user_id)
}

fn email_blind_index(keyring: &FieldEncryptionKeyring, email: &str) -> String {
    keyring.blind_index_for_field_hex(
        USER_EMAIL_TABLE,
        USER_EMAIL_COLUMN,
        &normalize_email_for_blind_index(email),
    )
}

fn prepare_email_encryption(
    keyring: &FieldEncryptionKeyring,
    user_id: i64,
    email: &str,
) -> Result<EncryptedEmailWrite, FieldCryptoError> {
    let field = keyring.encrypt_bytes(email.as_bytes(), &email_aad(user_id))?;
    Ok(EncryptedEmailWrite {
        field,
        blind_index: email_blind_index(keyring, email),
    })
}

#[cfg(test)]
fn decrypt_email_field(
    keyring: &FieldEncryptionKeyring,
    user_id: i64,
    encrypted: &EncryptedEmailWrite,
) -> Result<String, FieldCryptoError> {
    let bytes = keyring.decrypt_bytes(&encrypted.field, &email_aad(user_id))?;
    String::from_utf8(bytes).map_err(|_| FieldCryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::field_crypto::{FieldAad, FieldEncryptionKeyring};

    const FIELD_KEY: &str = "b55f7f6657f90b0771c71f56ab29a70fd23c9e247a57de9532a53bc55790d251";

    #[test]
    fn user_email_crypto_write_hides_plaintext_and_decrypts_at_service_boundary() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(FIELD_KEY, 1).expect("field key");
        let encrypted =
            prepare_email_encryption(&keyring, 42, "Josh@Example.com").expect("encrypted email");

        assert!(
            !encrypted
                .ciphertext()
                .windows(4)
                .any(|part| part == b"Josh")
        );
        assert_eq!(encrypted.blind_index().len(), 64);

        let plaintext = decrypt_email_field(&keyring, 42, &encrypted).expect("decrypted email");
        assert_eq!(plaintext, "Josh@Example.com");
    }

    #[test]
    fn user_email_blind_index_is_case_insensitive_and_field_scoped() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(FIELD_KEY, 1).expect("field key");

        let mixed = email_blind_index(&keyring, " Josh@Example.com ");
        let lower = email_blind_index(&keyring, "josh@example.com");
        let other_field =
            keyring.blind_index_for_field_hex("users", "username", "josh@example.com");

        assert_eq!(mixed, lower);
        assert_ne!(mixed, other_field);
    }

    #[test]
    fn user_email_decrypt_requires_matching_user_id_aad() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(FIELD_KEY, 1).expect("field key");
        let encrypted =
            prepare_email_encryption(&keyring, 42, "josh@example.com").expect("encrypted email");

        assert!(decrypt_email_field(&keyring, 43, &encrypted).is_err());
    }

    #[test]
    fn user_email_aad_uses_users_email_row_identity() {
        assert_eq!(email_aad(42), FieldAad::new("users", "email", 42));
    }

    #[test]
    fn user_email_backfill_claim_sql_is_bounded_resumable_and_row_locked() {
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("FOR UPDATE SKIP LOCKED"));
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("ORDER BY id ASC"));
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("LIMIT $1"));
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("email_ciphertext IS NULL"));
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("email_nonce IS NULL"));
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("email_key_version IS NULL"));
        assert!(USER_EMAIL_BACKFILL_CLAIM_SQL.contains("email_blind_index IS NULL"));
    }

    #[test]
    fn user_email_backfill_update_sql_writes_encrypted_metadata_only() {
        assert!(USER_EMAIL_BACKFILL_UPDATE_SQL.contains("email_ciphertext = $2"));
        assert!(USER_EMAIL_BACKFILL_UPDATE_SQL.contains("email_nonce = $3"));
        assert!(USER_EMAIL_BACKFILL_UPDATE_SQL.contains("email_key_version = $4"));
        assert!(USER_EMAIL_BACKFILL_UPDATE_SQL.contains("email_blind_index = $5"));
        assert!(USER_EMAIL_BACKFILL_UPDATE_SQL.contains("updated_at_ms = $6"));
        assert!(!USER_EMAIL_BACKFILL_UPDATE_SQL.contains("email ="));
    }

    #[test]
    fn user_email_backfill_batch_limit_is_clamped_to_safe_bounds() {
        assert_eq!(user_email_backfill_batch_limit(0), 1);
        assert_eq!(user_email_backfill_batch_limit(250), 250);
        assert_eq!(user_email_backfill_batch_limit(10_000), 1_000);
    }
}
