//! Server custom emojis.

use sqlx::{PgPool, Postgres, Transaction};

pub const MAX_SERVER_CUSTOM_EMOJIS: i64 = 100;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmojiRow {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub url: String,
    pub created_by: i64,
    pub created_at_ms: i64,
    pub asset_id: Option<i64>,
    pub asset_hash: Option<String>,
    pub source_peer_id: Option<String>,
    pub source_origin: Option<String>,
    pub source_server_label: Option<String>,
    pub source_expression_name: Option<String>,
    pub imported_by: Option<i64>,
    pub imported_at_ms: Option<i64>,
}

pub struct CustomExpressionSourceInput<'a> {
    pub source_peer_id: Option<&'a str>,
    pub source_origin: Option<&'a str>,
    pub source_server_label: Option<&'a str>,
    pub source_expression_name: Option<&'a str>,
    pub imported_by: Option<i64>,
    pub imported_at_ms: Option<i64>,
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<EmojiRow>, sqlx::Error> {
    sqlx::query_as::<_, EmojiRow>("SELECT * FROM emojis WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_for_server(pool: &PgPool, server_id: i64) -> Result<Vec<EmojiRow>, sqlx::Error> {
    sqlx::query_as::<_, EmojiRow>(
        "SELECT * FROM emojis WHERE server_id = $1 ORDER BY id ASC LIMIT $2",
    )
    .bind(server_id)
    .bind(MAX_SERVER_CUSTOM_EMOJIS)
    .fetch_all(pool)
    .await
}

pub async fn count_for_server(pool: &PgPool, server_id: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM emojis WHERE server_id = $1")
        .bind(server_id)
        .fetch_one(pool)
        .await
}

pub async fn is_at_server_limit(pool: &PgPool, server_id: i64) -> Result<bool, sqlx::Error> {
    count_for_server(pool, server_id)
        .await
        .map(|count| count >= MAX_SERVER_CUSTOM_EMOJIS)
}

pub async fn insert(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    name: &str,
    url: &str,
    created_by: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO emojis (id, server_id, name, url, created_by, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(url)
    .bind(created_by)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_if_below_server_limit(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    name: &str,
    url: &str,
    created_by: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Serializes quota checks per server without holding the lock while the
    // caller reads multipart data or scans/stores media.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(server_id)
        .execute(&mut *tx)
        .await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM emojis WHERE server_id = $1")
        .bind(server_id)
        .fetch_one(&mut *tx)
        .await?;

    if count >= MAX_SERVER_CUSTOM_EMOJIS {
        tx.commit().await?;
        return Ok(false);
    }

    sqlx::query(
        r#"
        INSERT INTO emojis (id, server_id, name, url, created_by, created_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(url)
    .bind(created_by)
    .bind(now_ms)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

pub async fn insert_with_asset_if_below_server_limit(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    name: &str,
    created_by: i64,
    now_ms: i64,
    asset: crate::services::pg::custom_expression_assets::CustomExpressionAssetInput<'_>,
    source: CustomExpressionSourceInput<'_>,
) -> Result<Option<EmojiRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let asset_lock_key = crate::services::pg::custom_expression_assets::advisory_lock_key(
        asset.kind,
        asset.sha256_hex,
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(asset_lock_key)
        .execute(&mut *tx)
        .await?;

    let row = insert_with_asset_if_below_server_limit_tx(
        &mut tx, id, server_id, name, created_by, now_ms, asset, source,
    )
    .await?;

    tx.commit().await?;
    Ok(row)
}

pub async fn insert_with_asset_if_below_server_limit_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    server_id: i64,
    name: &str,
    created_by: i64,
    now_ms: i64,
    asset: crate::services::pg::custom_expression_assets::CustomExpressionAssetInput<'_>,
    source: CustomExpressionSourceInput<'_>,
) -> Result<Option<EmojiRow>, sqlx::Error> {
    // Serializes quota checks per server and keeps the catalog row tied to the
    // shared custom_expression_assets reference in one transaction.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(server_id)
        .execute(&mut **tx)
        .await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM emojis WHERE server_id = $1")
        .bind(server_id)
        .fetch_one(&mut **tx)
        .await?;

    if count >= MAX_SERVER_CUSTOM_EMOJIS {
        return Ok(None);
    }

    let asset_row =
        crate::services::pg::custom_expression_assets::upsert_and_increment_ref(tx, asset).await?;

    let row = sqlx::query_as::<_, EmojiRow>(
        r#"
        INSERT INTO emojis (
            id, server_id, name, url, created_by, created_at_ms,
            asset_id, asset_hash, source_peer_id, source_origin,
            source_server_label, source_expression_name, imported_by, imported_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(name)
    .bind(&asset_row.storage_key)
    .bind(created_by)
    .bind(now_ms)
    .bind(asset_row.id)
    .bind(&asset_row.sha256_hex)
    .bind(source.source_peer_id)
    .bind(source.source_origin)
    .bind(source.source_server_label)
    .bind(source.source_expression_name)
    .bind(source.imported_by)
    .bind(source.imported_at_ms)
    .fetch_one(&mut **tx)
    .await?;

    Ok(Some(row))
}

pub async fn rename(pool: &PgPool, id: i64, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE emojis SET name = $2 WHERE id = $1")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(
    pool: &PgPool,
    id: i64,
) -> Result<
    Option<crate::services::pg::custom_expression_assets::CustomExpressionAssetCleanup>,
    sqlx::Error,
> {
    let mut tx = pool.begin().await?;
    let asset_id =
        sqlx::query_scalar::<_, Option<i64>>("DELETE FROM emojis WHERE id = $1 RETURNING asset_id")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let cleanup = match asset_id {
        Some(Some(asset_id)) => {
            crate::services::pg::custom_expression_assets::decrement_ref(&mut tx, asset_id).await?
        }
        Some(None) | None => None,
    };
    tx.commit().await?;
    Ok(cleanup)
}

#[cfg(test)]
mod tests {
    const SOURCE: &str = include_str!("emojis.rs");

    fn function_source(name: &str) -> &'static str {
        let signature = format!("pub async fn {name}");
        SOURCE
            .split(&signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} should exist"))
            .split("pub async fn")
            .next()
            .expect("function source section should be present")
    }

    #[test]
    fn server_custom_emoji_quota_is_bounded() {
        assert!(SOURCE.contains("pub const MAX_SERVER_CUSTOM_EMOJIS: i64 = 100"));
        assert!(SOURCE.contains("ORDER BY id ASC LIMIT $2"));
    }

    #[test]
    fn quota_insert_uses_server_scoped_advisory_lock() {
        let source = function_source("insert_if_below_server_limit");

        assert!(source.contains("pg_advisory_xact_lock"));
        assert!(source.contains("COUNT(*) FROM emojis WHERE server_id = $1"));
        assert!(source.contains("count >= MAX_SERVER_CUSTOM_EMOJIS"));
        assert!(source.contains("INSERT INTO emojis"));
    }

    #[test]
    fn dedupe_insert_records_asset_reference_without_storing_bytes() {
        let source = function_source("insert_with_asset_if_below_server_limit_tx");

        assert!(source.contains("custom_expression_assets"));
        assert!(source.contains("asset_id"));
        assert!(source.contains("asset_hash"));
        assert!(source.contains("sha256_hex"));
        assert!(!source.contains("bytea"));
    }

    #[test]
    fn dedupe_insert_has_transaction_variant_for_locked_upload_flow() {
        assert!(SOURCE.contains("insert_with_asset_if_below_server_limit_tx"));
        assert!(SOURCE.contains("pg_advisory_xact_lock"));
        assert!(SOURCE.contains("advisory_lock_key"));
    }

    #[test]
    fn delete_returns_last_asset_cleanup_from_single_delete_statement() {
        let source = function_source("delete");

        assert!(source.contains("DELETE FROM emojis WHERE id = $1 RETURNING asset_id"));
        assert!(!source.contains("SELECT asset_id FROM emojis"));
        assert!(source.contains("decrement_ref"));
        assert!(source.contains("Ok(cleanup)"));
    }
}
