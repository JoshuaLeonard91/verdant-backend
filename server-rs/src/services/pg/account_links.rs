//! Account-linking storage.
//!
//! Links are local identity mappings only. They must never be used as local
//! authorization, membership, role, or session state.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountLinkIntentRow {
    pub id: i64,
    pub local_user_id: i64,
    pub issuer_instance_id: String,
    pub audience_instance_id: String,
    pub state_hash: String,
    pub requested_scopes: Vec<String>,
    pub status: String,
    pub expires_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub cancelled_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountLinkRow {
    pub id: i64,
    pub local_user_id: i64,
    pub provider: String,
    pub issuer_instance_id: String,
    pub issuer_user_id: String,
    pub issuer_username: Option<String>,
    pub issuer_display_name: Option<String>,
    pub scopes: Vec<String>,
    pub status: String,
    pub proof_jti_hash: Option<String>,
    pub linked_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub revocation_checked_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IssuedAccountLinkGrantRow {
    pub id: i64,
    pub issuer_user_id: i64,
    pub audience_instance_id: String,
    pub audience_api_origin: String,
    pub proof_jti_hash: String,
    pub scopes: Vec<String>,
    pub status: String,
    pub issued_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

pub struct InsertAccountLinkIntent<'a> {
    pub id: i64,
    pub local_user_id: i64,
    pub issuer_instance_id: &'a str,
    pub audience_instance_id: &'a str,
    pub state_hash: &'a str,
    pub requested_scopes: &'a [String],
    pub expires_at_ms: i64,
    pub now_ms: i64,
}

pub struct InsertAccountLink<'a> {
    pub id: i64,
    pub local_user_id: i64,
    pub provider: &'a str,
    pub issuer_instance_id: &'a str,
    pub issuer_user_id: &'a str,
    pub issuer_username: Option<&'a str>,
    pub issuer_display_name: Option<&'a str>,
    pub scopes: &'a [String],
    pub proof_jti_hash: Option<&'a str>,
    pub now_ms: i64,
}

pub struct InsertIssuedAccountLinkGrant<'a> {
    pub id: i64,
    pub issuer_user_id: i64,
    pub audience_instance_id: &'a str,
    pub audience_api_origin: &'a str,
    pub proof_jti_hash: &'a str,
    pub scopes: &'a [String],
    pub now_ms: i64,
}

pub async fn create_intent(
    pool: &PgPool,
    input: InsertAccountLinkIntent<'_>,
) -> Result<AccountLinkIntentRow, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkIntentRow>(
        r#"
        INSERT INTO account_link_intents (
            id, local_user_id, issuer_instance_id, audience_instance_id,
            state_hash, requested_scopes, status, expires_at_ms,
            created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$8)
        RETURNING *
        "#,
    )
    .bind(input.id)
    .bind(input.local_user_id)
    .bind(input.issuer_instance_id)
    .bind(input.audience_instance_id)
    .bind(input.state_hash)
    .bind(input.requested_scopes)
    .bind(input.expires_at_ms)
    .bind(input.now_ms)
    .fetch_one(pool)
    .await
}

pub async fn list_for_user(
    pool: &PgPool,
    local_user_id: i64,
) -> Result<Vec<AccountLinkRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        SELECT *
          FROM account_links
         WHERE local_user_id = $1
         ORDER BY updated_at_ms DESC, id DESC
        "#,
    )
    .bind(local_user_id)
    .fetch_all(pool)
    .await
}

pub async fn pending_intent_by_state_for_update(
    tx: &mut Transaction<'_, Postgres>,
    local_user_id: i64,
    state_hash: &str,
) -> Result<Option<AccountLinkIntentRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkIntentRow>(
        r#"
        SELECT *
          FROM account_link_intents
         WHERE local_user_id = $1
           AND state_hash = $2
           AND status = 'pending'
         FOR UPDATE
        "#,
    )
    .bind(local_user_id)
    .bind(state_hash)
    .fetch_optional(&mut **tx)
    .await
}

pub async fn mark_intent_completed(
    tx: &mut Transaction<'_, Postgres>,
    intent_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE account_link_intents
           SET status = 'completed',
               completed_at_ms = $2,
               updated_at_ms = $2
         WHERE id = $1
        "#,
    )
    .bind(intent_id)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn mark_intent_expired(
    tx: &mut Transaction<'_, Postgres>,
    intent_id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE account_link_intents
           SET status = 'expired',
               updated_at_ms = $2
         WHERE id = $1
           AND status = 'pending'
        "#,
    )
    .bind(intent_id)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn revoke_active_conflicts(
    tx: &mut Transaction<'_, Postgres>,
    local_user_id: i64,
    provider: &str,
    issuer_instance_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE account_links
           SET status = 'revoked',
               revoked_at_ms = $4,
               revocation_checked_at_ms = COALESCE(revocation_checked_at_ms, $4),
               updated_at_ms = $4
         WHERE provider = $2
           AND issuer_instance_id = $3
           AND revoked_at_ms IS NULL
           AND local_user_id = $1
        "#,
    )
    .bind(local_user_id)
    .bind(provider)
    .bind(issuer_instance_id)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn insert_link(
    tx: &mut Transaction<'_, Postgres>,
    input: InsertAccountLink<'_>,
) -> Result<AccountLinkRow, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        INSERT INTO account_links (
            id, local_user_id, provider, issuer_instance_id, issuer_user_id,
            issuer_username, issuer_display_name, scopes, status, proof_jti_hash,
            linked_at_ms, created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'linked',$9,$10,$10,$10)
        RETURNING *
        "#,
    )
    .bind(input.id)
    .bind(input.local_user_id)
    .bind(input.provider)
    .bind(input.issuer_instance_id)
    .bind(input.issuer_user_id)
    .bind(input.issuer_username)
    .bind(input.issuer_display_name)
    .bind(input.scopes)
    .bind(input.proof_jti_hash)
    .bind(input.now_ms)
    .fetch_one(&mut **tx)
    .await
}

pub async fn list_revocation_sync_candidates_for_user(
    pool: &PgPool,
    local_user_id: i64,
    provider: &str,
) -> Result<Vec<AccountLinkRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        SELECT *
          FROM account_links
         WHERE local_user_id = $1
           AND provider = $2
           AND proof_jti_hash IS NOT NULL
           AND revoked_at_ms IS NULL
           AND status IN ('linked', 'stale')
         ORDER BY updated_at_ms DESC, id DESC
         LIMIT 50
        "#,
    )
    .bind(local_user_id)
    .bind(provider)
    .fetch_all(pool)
    .await
}

pub async fn mark_link_revocation_checked(
    pool: &PgPool,
    id: i64,
    local_user_id: i64,
    now_ms: i64,
) -> Result<Option<AccountLinkRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        UPDATE account_links
           SET status = 'linked',
               revocation_checked_at_ms = $3,
               updated_at_ms = CASE WHEN status <> 'linked' THEN $3 ELSE updated_at_ms END
         WHERE id = $1
           AND local_user_id = $2
           AND revoked_at_ms IS NULL
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(local_user_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

pub async fn mark_link_stale_from_official_sync(
    pool: &PgPool,
    id: i64,
    local_user_id: i64,
    now_ms: i64,
) -> Result<Option<AccountLinkRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        UPDATE account_links
           SET status = 'stale',
               revocation_checked_at_ms = $3,
               updated_at_ms = $3
         WHERE id = $1
           AND local_user_id = $2
           AND revoked_at_ms IS NULL
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(local_user_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

pub async fn mark_link_revoked_from_official_sync(
    pool: &PgPool,
    id: i64,
    local_user_id: i64,
    revoked_at_ms: i64,
    now_ms: i64,
) -> Result<Option<AccountLinkRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        UPDATE account_links
           SET status = 'revoked',
               revoked_at_ms = COALESCE(revoked_at_ms, $3),
               revocation_checked_at_ms = $4,
               updated_at_ms = $4
         WHERE id = $1
           AND local_user_id = $2
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(local_user_id)
    .bind(revoked_at_ms)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

pub async fn revoke_for_user(
    pool: &PgPool,
    id: i64,
    local_user_id: i64,
    now_ms: i64,
) -> Result<Option<AccountLinkRow>, sqlx::Error> {
    sqlx::query_as::<_, AccountLinkRow>(
        r#"
        UPDATE account_links
           SET status = 'revoked',
               revoked_at_ms = COALESCE(revoked_at_ms, $3),
               revocation_checked_at_ms = COALESCE(revocation_checked_at_ms, $3),
               updated_at_ms = $3
         WHERE id = $1
           AND local_user_id = $2
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(local_user_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

pub async fn insert_issued_grant(
    pool: &PgPool,
    input: InsertIssuedAccountLinkGrant<'_>,
) -> Result<IssuedAccountLinkGrantRow, sqlx::Error> {
    sqlx::query_as::<_, IssuedAccountLinkGrantRow>(
        r#"
        INSERT INTO account_link_issued_grants (
            id, issuer_user_id, audience_instance_id, audience_api_origin,
            proof_jti_hash, scopes, status, issued_at_ms, created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$7,$7)
        RETURNING *
        "#,
    )
    .bind(input.id)
    .bind(input.issuer_user_id)
    .bind(input.audience_instance_id)
    .bind(input.audience_api_origin)
    .bind(input.proof_jti_hash)
    .bind(input.scopes)
    .bind(input.now_ms)
    .fetch_one(pool)
    .await
}

pub async fn list_issued_grants_for_user(
    pool: &PgPool,
    issuer_user_id: i64,
) -> Result<Vec<IssuedAccountLinkGrantRow>, sqlx::Error> {
    sqlx::query_as::<_, IssuedAccountLinkGrantRow>(
        r#"
        SELECT *
          FROM account_link_issued_grants
         WHERE issuer_user_id = $1
         ORDER BY updated_at_ms DESC, id DESC
        "#,
    )
    .bind(issuer_user_id)
    .fetch_all(pool)
    .await
}

pub async fn revoke_issued_grant_for_user(
    pool: &PgPool,
    id: i64,
    issuer_user_id: i64,
    now_ms: i64,
) -> Result<Option<IssuedAccountLinkGrantRow>, sqlx::Error> {
    sqlx::query_as::<_, IssuedAccountLinkGrantRow>(
        r#"
        UPDATE account_link_issued_grants
           SET status = 'revoked',
               revoked_at_ms = COALESCE(revoked_at_ms, $3),
               updated_at_ms = $3
         WHERE id = $1
           AND issuer_user_id = $2
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(issuer_user_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
}

pub async fn issued_grants_by_proof_hashes(
    pool: &PgPool,
    proof_jti_hashes: &[String],
) -> Result<Vec<IssuedAccountLinkGrantRow>, sqlx::Error> {
    sqlx::query_as::<_, IssuedAccountLinkGrantRow>(
        r#"
        SELECT *
          FROM account_link_issued_grants
         WHERE proof_jti_hash = ANY($1)
        "#,
    )
    .bind(proof_jti_hashes)
    .fetch_all(pool)
    .await
}

pub fn scopes_to_json(scopes: &[String]) -> Value {
    Value::Array(scopes.iter().cloned().map(Value::String).collect())
}
