//! Shared public-media asset index for custom emojis and stickers.

use sqlx::{PgConnection, PgPool, Postgres, Transaction};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomExpressionAssetRow {
    pub id: i64,
    pub kind: String,
    pub sha256_hex: String,
    pub byte_size: i64,
    pub content_type: String,
    pub extension: String,
    pub storage_key: String,
    pub ref_count: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

pub struct CustomExpressionAssetInput<'a> {
    pub id: i64,
    pub kind: &'a str,
    pub sha256_hex: &'a str,
    pub byte_size: i64,
    pub content_type: &'a str,
    pub extension: &'a str,
    pub storage_key: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomExpressionAssetCleanup {
    pub asset_id: i64,
    pub kind: String,
    pub sha256_hex: String,
    pub storage_key: String,
}

pub fn advisory_lock_key(kind: &str, sha256_hex: &str) -> i64 {
    let prefix = sha256_hex.get(..16).unwrap_or(sha256_hex);
    let digest_prefix = u64::from_str_radix(prefix, 16).unwrap_or_default();
    let kind_discriminator = match kind {
        "emoji" => 0x454d_4f4a_495f_0001_u64,
        "sticker" => 0x5354_4943_4b52_0001_u64,
        _ => 0x4355_5354_4558_0001_u64,
    };
    (digest_prefix ^ kind_discriminator) as i64
}

pub async fn by_kind_hash(
    pool: &PgPool,
    kind: &str,
    sha256_hex: &str,
) -> Result<Option<CustomExpressionAssetRow>, sqlx::Error> {
    sqlx::query_as::<_, CustomExpressionAssetRow>(
        "SELECT * FROM custom_expression_assets WHERE kind = $1 AND sha256_hex = $2",
    )
    .bind(kind)
    .bind(sha256_hex)
    .fetch_optional(pool)
    .await
}

pub async fn by_kind_hash_tx(
    tx: &mut Transaction<'_, Postgres>,
    kind: &str,
    sha256_hex: &str,
) -> Result<Option<CustomExpressionAssetRow>, sqlx::Error> {
    sqlx::query_as::<_, CustomExpressionAssetRow>(
        "SELECT * FROM custom_expression_assets WHERE kind = $1 AND sha256_hex = $2",
    )
    .bind(kind)
    .bind(sha256_hex)
    .fetch_optional(&mut **tx)
    .await
}

pub async fn by_storage_key(
    pool: &PgPool,
    storage_key: &str,
) -> Result<Option<CustomExpressionAssetRow>, sqlx::Error> {
    sqlx::query_as::<_, CustomExpressionAssetRow>(
        "SELECT * FROM custom_expression_assets WHERE storage_key = $1",
    )
    .bind(storage_key)
    .fetch_optional(pool)
    .await
}

pub async fn upsert_and_increment_ref(
    tx: &mut Transaction<'_, Postgres>,
    input: CustomExpressionAssetInput<'_>,
) -> Result<CustomExpressionAssetRow, sqlx::Error> {
    sqlx::query_as::<_, CustomExpressionAssetRow>(
        r#"
        INSERT INTO custom_expression_assets (
            id, kind, sha256_hex, byte_size, content_type, extension,
            storage_key, ref_count, created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$8)
        ON CONFLICT ON CONSTRAINT custom_expression_assets_kind_hash_unique DO UPDATE
           SET ref_count = custom_expression_assets.ref_count + 1,
               updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING *
        "#,
    )
    .bind(input.id)
    .bind(input.kind)
    .bind(input.sha256_hex)
    .bind(input.byte_size)
    .bind(input.content_type)
    .bind(input.extension)
    .bind(input.storage_key)
    .bind(input.now_ms)
    .fetch_one(&mut **tx)
    .await
}

pub async fn decrement_ref(
    tx: &mut Transaction<'_, Postgres>,
    asset_id: i64,
) -> Result<Option<CustomExpressionAssetCleanup>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, String, String, String, i64)>(
        r#"
        UPDATE custom_expression_assets
           SET ref_count = GREATEST(ref_count - 1, 0),
               updated_at_ms = $2
         WHERE id = $1
         RETURNING id, kind, sha256_hex, storage_key, ref_count
        "#,
    )
    .bind(asset_id)
    .bind(chrono::Utc::now().timestamp_millis())
    .fetch_optional(&mut **tx)
    .await?;
    Ok(
        row.and_then(|(asset_id, kind, sha256_hex, storage_key, ref_count)| {
            (ref_count == 0).then_some(CustomExpressionAssetCleanup {
                asset_id,
                kind,
                sha256_hex,
                storage_key,
            })
        }),
    )
}

pub async fn lock_digest_on_connection(
    conn: &mut PgConnection,
    kind: &str,
    sha256_hex: &str,
) -> Result<i64, sqlx::Error> {
    let lock_key = advisory_lock_key(kind, sha256_hex);
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_key)
        .execute(&mut *conn)
        .await?;
    Ok(lock_key)
}

pub async fn unlock_digest_on_connection(
    conn: &mut PgConnection,
    lock_key: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn is_unreferenced_on_connection(
    conn: &mut PgConnection,
    asset_id: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
              FROM custom_expression_assets assets
             WHERE assets.id = $1
               AND assets.ref_count = 0
               AND NOT EXISTS (SELECT 1 FROM emojis WHERE asset_id = $1)
               AND NOT EXISTS (SELECT 1 FROM stickers WHERE asset_id = $1)
        )
        "#,
    )
    .bind(asset_id)
    .fetch_one(&mut *conn)
    .await
}

pub async fn delete_if_unreferenced_on_connection(
    conn: &mut PgConnection,
    asset_id: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM custom_expression_assets assets
         WHERE assets.id = $1
           AND assets.ref_count = 0
           AND NOT EXISTS (SELECT 1 FROM emojis WHERE asset_id = $1)
           AND NOT EXISTS (SELECT 1 FROM stickers WHERE asset_id = $1)
        "#,
    )
    .bind(asset_id)
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete_if_unreferenced(pool: &PgPool, asset_id: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM custom_expression_assets assets
         WHERE assets.id = $1
           AND assets.ref_count = 0
           AND NOT EXISTS (SELECT 1 FROM emojis WHERE asset_id = $1)
           AND NOT EXISTS (SELECT 1 FROM stickers WHERE asset_id = $1)
        "#,
    )
    .bind(asset_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::advisory_lock_key;

    const MIGRATION: &str =
        include_str!("../../../migrations/0031_custom_expression_asset_dedupe.sql");
    const SOURCE: &str = include_str!("custom_expression_assets.rs");

    #[test]
    fn migration_indexes_hashes_without_storing_bytes() {
        assert!(MIGRATION.contains("custom_expression_assets"));
        assert!(MIGRATION.contains("sha256_hex"));
        assert!(MIGRATION.contains("custom_expression_assets_hash_idx"));
        assert!(MIGRATION.contains("asset_id"));
        assert!(MIGRATION.contains("asset_hash"));
        assert!(!MIGRATION.to_ascii_lowercase().contains("bytea"));
    }

    #[test]
    fn upsert_reuses_existing_hash_and_increments_ref_count() {
        assert!(
            SOURCE.contains("ON CONFLICT ON CONSTRAINT custom_expression_assets_kind_hash_unique")
        );
        assert!(SOURCE.contains("ref_count = custom_expression_assets.ref_count + 1"));
        assert!(SOURCE.contains("RETURNING *"));
    }

    #[test]
    fn advisory_lock_key_is_kind_scoped_and_digest_derived() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        assert_eq!(
            advisory_lock_key("emoji", hash),
            advisory_lock_key("emoji", hash)
        );
        assert_ne!(
            advisory_lock_key("emoji", hash),
            advisory_lock_key("sticker", hash)
        );
    }

    #[test]
    fn decrement_ref_returns_cleanup_only_for_last_reference() {
        assert!(SOURCE.contains("RETURNING id, kind, sha256_hex, storage_key, ref_count"));
        assert!(SOURCE.contains("ref_count == 0"));
        assert!(SOURCE.contains("CustomExpressionAssetCleanup"));
    }

    #[test]
    fn asset_metadata_delete_rechecks_catalog_references() {
        assert!(SOURCE.contains("delete_if_unreferenced"));
        assert!(SOURCE.contains("NOT EXISTS (SELECT 1 FROM emojis WHERE asset_id = $1)"));
        assert!(SOURCE.contains("NOT EXISTS (SELECT 1 FROM stickers WHERE asset_id = $1)"));
    }

    #[test]
    fn digest_cleanup_uses_session_advisory_lock() {
        assert!(SOURCE.contains("lock_digest_on_connection"));
        assert!(SOURCE.contains("pg_advisory_lock"));
        assert!(SOURCE.contains("pg_advisory_unlock"));
        assert!(SOURCE.contains("delete_if_unreferenced_on_connection"));
    }
}
