//! Federation discovery registry storage.
//!
//! This is metadata-only. It does not participate in runtime message,
//! presence, voice, Redis, NATS, or account-linking flows.

use serde_json::Value;
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FederationInstanceRow {
    pub id: i64,
    pub domain: String,
    pub display_name: String,
    pub api_url: String,
    pub public_url: String,
    pub mode: String,
    pub status: String,
    pub public_discovery: bool,
    pub discovery_description: Option<String>,
    pub invite_url: Option<String>,
    pub server_version: Option<String>,
    pub min_client_version: Option<String>,
    pub upload_policy: Option<String>,
    pub content_scanning: Value,
    pub capabilities: Value,
    pub public_key: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub verification_method: String,
    pub verification_token_hash: String,
    pub verified_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

pub struct InsertFederationInstance<'a> {
    pub id: i64,
    pub domain: &'a str,
    pub display_name: &'a str,
    pub api_url: &'a str,
    pub public_url: &'a str,
    pub mode: &'a str,
    pub status: &'a str,
    pub public_discovery: bool,
    pub discovery_description: Option<&'a str>,
    pub invite_url: Option<&'a str>,
    pub server_version: Option<&'a str>,
    pub min_client_version: Option<&'a str>,
    pub upload_policy: Option<&'a str>,
    pub content_scanning: &'a Value,
    pub capabilities: &'a Value,
    pub public_key: Option<&'a str>,
    pub public_key_fingerprint: Option<&'a str>,
    pub verification_method: &'a str,
    pub verification_token_hash: &'a str,
    pub verified_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub now_ms: i64,
}

pub struct UpdateFederationInstance<'a> {
    pub id: i64,
    pub domain: &'a str,
    pub display_name: &'a str,
    pub api_url: &'a str,
    pub public_url: &'a str,
    pub mode: &'a str,
    pub status: &'a str,
    pub public_discovery: bool,
    pub discovery_description: Option<&'a str>,
    pub invite_url: Option<&'a str>,
    pub server_version: Option<&'a str>,
    pub min_client_version: Option<&'a str>,
    pub upload_policy: Option<&'a str>,
    pub content_scanning: &'a Value,
    pub capabilities: &'a Value,
    pub public_key: Option<&'a str>,
    pub public_key_fingerprint: Option<&'a str>,
    pub verification_method: &'a str,
    pub verification_token_hash: &'a str,
    pub verified_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

pub async fn insert(
    pool: &PgPool,
    input: InsertFederationInstance<'_>,
) -> Result<FederationInstanceRow, sqlx::Error> {
    sqlx::query_as::<_, FederationInstanceRow>(
        r#"
        INSERT INTO federation_instances (
            id, domain, display_name, api_url, public_url, mode, status,
            public_discovery, discovery_description, invite_url, server_version,
            min_client_version, upload_policy, content_scanning, capabilities,
            public_key, public_key_fingerprint, verification_method,
            verification_token_hash, verified_at_ms, revoked_at_ms,
            created_at_ms, updated_at_ms
        )
        VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
            $19,$20,$21,$22,$23
        )
        RETURNING *
        "#,
    )
    .bind(input.id)
    .bind(input.domain)
    .bind(input.display_name)
    .bind(input.api_url)
    .bind(input.public_url)
    .bind(input.mode)
    .bind(input.status)
    .bind(input.public_discovery)
    .bind(input.discovery_description)
    .bind(input.invite_url)
    .bind(input.server_version)
    .bind(input.min_client_version)
    .bind(input.upload_policy)
    .bind(input.content_scanning)
    .bind(input.capabilities)
    .bind(input.public_key)
    .bind(input.public_key_fingerprint)
    .bind(input.verification_method)
    .bind(input.verification_token_hash)
    .bind(input.verified_at_ms)
    .bind(input.revoked_at_ms)
    .bind(input.now_ms)
    .bind(input.now_ms)
    .fetch_one(pool)
    .await
}

pub async fn by_id(pool: &PgPool, id: i64) -> Result<Option<FederationInstanceRow>, sqlx::Error> {
    sqlx::query_as::<_, FederationInstanceRow>("SELECT * FROM federation_instances WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn update(
    pool: &PgPool,
    input: UpdateFederationInstance<'_>,
) -> Result<Option<FederationInstanceRow>, sqlx::Error> {
    sqlx::query_as::<_, FederationInstanceRow>(
        r#"
        UPDATE federation_instances SET
            domain = $2,
            display_name = $3,
            api_url = $4,
            public_url = $5,
            mode = $6,
            status = $7,
            public_discovery = $8,
            discovery_description = $9,
            invite_url = $10,
            server_version = $11,
            min_client_version = $12,
            upload_policy = $13,
            content_scanning = $14,
            capabilities = $15,
            public_key = $16,
            public_key_fingerprint = $17,
            verification_method = $18,
            verification_token_hash = $19,
            verified_at_ms = $20,
            revoked_at_ms = $21,
            updated_at_ms = $22
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(input.id)
    .bind(input.domain)
    .bind(input.display_name)
    .bind(input.api_url)
    .bind(input.public_url)
    .bind(input.mode)
    .bind(input.status)
    .bind(input.public_discovery)
    .bind(input.discovery_description)
    .bind(input.invite_url)
    .bind(input.server_version)
    .bind(input.min_client_version)
    .bind(input.upload_policy)
    .bind(input.content_scanning)
    .bind(input.capabilities)
    .bind(input.public_key)
    .bind(input.public_key_fingerprint)
    .bind(input.verification_method)
    .bind(input.verification_token_hash)
    .bind(input.verified_at_ms)
    .bind(input.revoked_at_ms)
    .bind(input.updated_at_ms)
    .fetch_optional(pool)
    .await
}

pub async fn list_public_discovery(
    pool: &PgPool,
    search: Option<&str>,
    limit: i64,
) -> Result<Vec<FederationInstanceRow>, sqlx::Error> {
    sqlx::query_as::<_, FederationInstanceRow>(
        r#"
        SELECT *
          FROM federation_instances
         WHERE status = 'verified'
           AND public_discovery = true
           AND (
                $1::text IS NULL
                OR domain ILIKE '%' || $1 || '%'
                OR display_name ILIKE '%' || $1 || '%'
           )
         ORDER BY updated_at_ms DESC, id DESC
         LIMIT $2
        "#,
    )
    .bind(search)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn verified_by_audience_host(
    pool: &PgPool,
    audience_host: &str,
) -> Result<Option<FederationInstanceRow>, sqlx::Error> {
    sqlx::query_as::<_, FederationInstanceRow>(
        r#"
        SELECT *
          FROM federation_instances
         WHERE status = 'verified'
           AND revoked_at_ms IS NULL
           AND (
                lower(domain) = lower($1)
                OR lower(split_part(regexp_replace(api_url, '^https://', ''), ':', 1)) = lower($1)
           )
         ORDER BY verified_at_ms DESC NULLS LAST, updated_at_ms DESC, id DESC
         LIMIT 1
        "#,
    )
    .bind(audience_host)
    .fetch_optional(pool)
    .await
}
