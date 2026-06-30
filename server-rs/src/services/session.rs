//! Session service — Postgres-backed.
//!
//! Tables (see `migrations/0001_slice1_auth.sql`):
//!   - `sessions` — primary row keyed by id; carries every metadata
//!     field the WS connection needs (token_hash, ip, ua, geo, verify
//!     state, revoke token, sliding-window timestamps).
//!   - Unique index on token_hash for the auth-middleware hot path.
//!   - Unique partial index on revoke_token_hash for the email-revoke flow.
//!   - Index on user_id for "list / revoke all sessions".
//!
//! Sliding-window optimization: `last_used_at_ms` is only written when
//! it crosses a five-minute threshold. That avoids one PG row write per
//! authenticated request — which would otherwise dominate the WAL on a
//! chat-app workload.

use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::services::crypto::{generate_session_token, generate_verification_code, hash_token};
use crate::services::device::DeviceInfo;
use crate::services::pg::sessions as pg_sessions;
use crate::services::risk::RiskLevel;
use crate::snowflake::SnowflakeGenerator;

const MAX_SESSIONS_PER_USER: usize = 10;
const SESSION_LIFETIME_DAYS: i64 = 7;
const VERIFY_CODE_EXPIRY_MINUTES: i64 = 15;
const MAX_VERIFY_ATTEMPTS: i32 = 5;
/// Only write `last_used_at_ms` if the previous value is older than this.
/// 5 minutes — keeps session row churn under control without losing
/// any meaningful "last seen" granularity.
const SLIDING_UPDATE_THRESHOLD_MS: i64 = 5 * 60 * 1000;

/// Geo lookup result. Plumbed through from the rate-limit / login
/// pipeline; populated by the GeoIP service when an IP is available.
pub struct GeoResult {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
}

impl Default for GeoResult {
    fn default() -> Self {
        Self {
            city: None,
            region: None,
            country: None,
        }
    }
}

pub struct CreateSessionResult {
    pub token: String,
    pub session_id: i64,
    pub risk_level: RiskLevel,
    pub verified: bool,
}

/// Create a fresh session. Evicts the oldest sessions when over the
/// per-user cap so a flood of new logins doesn't blow up the table.
pub async fn create_session(
    pool: &PgPool,
    snowflake: &SnowflakeGenerator,
    user_id: i64,
    ip: &str,
    user_agent: Option<&str>,
    device: &DeviceInfo,
    geo: &GeoResult,
    risk_level: RiskLevel,
) -> Result<CreateSessionResult, crate::error::AppError> {
    let token = generate_session_token();
    let token_hash = hash_token(&token);
    let verified = risk_level != RiskLevel::High;

    // Per-user cap eviction. Read the user's existing sessions, drop
    // the surplus oldest. Single-row deletes — under cap most users
    // won't ever take this path.
    let existing = pg_sessions::list_for_user(pool, user_id)
        .await
        .map_err(map_err)?;
    if existing.len() >= MAX_SESSIONS_PER_USER {
        let mut by_age: Vec<&pg_sessions::SessionRow> = existing.iter().collect();
        by_age.sort_by_key(|s| s.created_at_ms);
        let to_delete = existing.len().saturating_sub(MAX_SESSIONS_PER_USER - 1);
        for s in by_age.iter().take(to_delete) {
            let _ = pg_sessions::delete_one(pool, s.id).await;
        }
    }

    let session_id = snowflake.next_id();
    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let expires_at_ms = (now + Duration::days(SESSION_LIFETIME_DAYS)).timestamp_millis();

    let row = pg_sessions::SessionRow {
        id: session_id,
        user_id,
        token_hash: token_hash.clone(),
        revoke_token_hash: None,
        verify_token_hash: None,
        expires_at_ms,
        verified,
        ip: Some(ip.to_string()),
        user_agent: user_agent.map(str::to_string),
        device_hash: Some(device.device_hash.clone()),
        city: geo.city.clone(),
        region: geo.region.clone(),
        country: geo.country.clone(),
        risk_level: Some(risk_level.as_str().to_string()),
        verify_expires_at_ms: None,
        verify_attempts: 0,
        created_at_ms: now_ms,
        last_used_at_ms: now_ms,
    };

    pg_sessions::insert(pool, &row).await.map_err(|e| {
        tracing::error!(error = %e, "create_session: PG insert failed");
        crate::error::AppError::Internal
    })?;

    Ok(CreateSessionResult {
        token,
        session_id,
        risk_level,
        verified,
    })
}

/// Result of a successful session validation.
pub struct ValidatedSession {
    pub user_id: i64,
    pub session_id: i64,
}

pub struct RotatedSession {
    pub user_id: i64,
    pub session_id: i64,
    pub token: String,
}

/// Validate a session token: check expiry, verified, and refresh the
/// sliding window. Drops expired rows on the spot.
pub async fn validate_session(
    pool: &PgPool,
    token: &str,
    ip: &str,
    geo: &GeoResult,
) -> Result<Option<ValidatedSession>, crate::error::AppError> {
    let token_hash = hash_token(token);
    let Some(session) = pg_sessions::by_token_hash(pool, &token_hash)
        .await
        .map_err(map_err)?
    else {
        return Ok(None);
    };

    let now_ms = Utc::now().timestamp_millis();

    // Expired — purge and report none.
    if session.expires_at_ms <= now_ms {
        let _ = pg_sessions::delete_one(pool, session.id).await;
        return Ok(None);
    }

    // High-risk session that hasn't completed email verification.
    if !session.verified {
        return Ok(None);
    }

    // Sliding window — only write through if the gap is meaningful,
    // and only refresh ip/geo when we're already writing.
    if now_ms - session.last_used_at_ms >= SLIDING_UPDATE_THRESHOLD_MS {
        let _ = pg_sessions::touch_last_used(
            pool,
            session.id,
            now_ms,
            Some(ip),
            // We don't bind user_agent on every refresh — it shouldn't
            // change for the same session. ip + last_used is enough.
            None,
        )
        .await;
        // Best-effort geo refresh (only if we have a value, only on a
        // touch). Run as a separate query so the touch above remains
        // atomic and small.
        if geo.city.is_some() || geo.country.is_some() {
            let _ = sqlx::query(
                "UPDATE sessions SET city = COALESCE($2, city), region = COALESCE($3, region), country = COALESCE($4, country) WHERE id = $1",
            )
            .bind(session.id)
            .bind(geo.city.as_deref())
            .bind(geo.region.as_deref())
            .bind(geo.country.as_deref())
            .execute(pool)
            .await;
        }
        // Slide expiry forward. Cheap.
        let new_expires = (Utc::now() + Duration::days(SESSION_LIFETIME_DAYS)).timestamp_millis();
        let _ = sqlx::query("UPDATE sessions SET expires_at_ms = $2 WHERE id = $1")
            .bind(session.id)
            .bind(new_expires)
            .execute(pool)
            .await;
    }

    Ok(Some(ValidatedSession {
        user_id: session.user_id,
        session_id: session.id,
    }))
}

pub async fn rotate_session(
    pool: &PgPool,
    token: &str,
    ip: &str,
    geo: &GeoResult,
) -> Result<Option<RotatedSession>, crate::error::AppError> {
    let token_hash = hash_token(token);
    let Some(session) = pg_sessions::by_token_hash(pool, &token_hash)
        .await
        .map_err(map_err)?
    else {
        return Ok(None);
    };

    let now_ms = Utc::now().timestamp_millis();
    if session.expires_at_ms <= now_ms {
        let _ = pg_sessions::delete_one(pool, session.id).await;
        return Ok(None);
    }
    if !session.verified {
        return Ok(None);
    }

    let rotated_token = generate_session_token();
    let rotated_token_hash = hash_token(&rotated_token);
    let expires_at_ms = (Utc::now() + Duration::days(SESSION_LIFETIME_DAYS)).timestamp_millis();
    let rotated = pg_sessions::rotate_token_hash(
        pool,
        session.id,
        &token_hash,
        &rotated_token_hash,
        expires_at_ms,
        now_ms,
        Some(ip),
    )
    .await
    .map_err(map_err)?;
    if !rotated {
        return Ok(None);
    }

    if geo.city.is_some() || geo.country.is_some() {
        let _ = sqlx::query(
            "UPDATE sessions SET city = COALESCE($2, city), region = COALESCE($3, region), country = COALESCE($4, country) WHERE id = $1 AND token_hash = $5",
        )
        .bind(session.id)
        .bind(geo.city.as_deref())
        .bind(geo.region.as_deref())
        .bind(geo.country.as_deref())
        .bind(&rotated_token_hash)
        .execute(pool)
        .await;
    }

    Ok(Some(RotatedSession {
        user_id: session.user_id,
        session_id: session.id,
        token: rotated_token,
    }))
}

/// Revoke a session by its raw bearer token (logout).
pub async fn revoke_session(pool: &PgPool, token: &str) -> Result<(), crate::error::AppError> {
    let token_hash = hash_token(token);
    if let Some(s) = pg_sessions::by_token_hash(pool, &token_hash)
        .await
        .map_err(map_err)?
    {
        let _ = pg_sessions::delete_one(pool, s.id).await;
    }
    Ok(())
}

/// "This wasn't me" email-link revoke — looks up by the revoke token.
pub async fn revoke_session_by_revoke_token(
    pool: &PgPool,
    revoke_token: &str,
) -> Result<bool, crate::error::AppError> {
    let revoke_hash = hash_token(revoke_token);
    let Some(s) = pg_sessions::by_revoke_token_hash(pool, &revoke_hash)
        .await
        .map_err(map_err)?
    else {
        return Ok(false);
    };
    let _ = pg_sessions::delete_one(pool, s.id).await;
    Ok(true)
}

/// Issue a 6-digit verification code for an existing session. Stores
/// the code's hash + an expiry on the session row.
pub async fn create_verification_token(
    pool: &PgPool,
    session_id: i64,
) -> Result<String, crate::error::AppError> {
    let code = generate_verification_code();
    let code_hash = hash_token(&code);
    let expires_at_ms =
        (Utc::now() + Duration::minutes(VERIFY_CODE_EXPIRY_MINUTES)).timestamp_millis();
    pg_sessions::set_verify_token(pool, session_id, &code_hash, expires_at_ms)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create_verification_token: PG update failed");
            crate::error::AppError::Internal
        })?;
    Ok(code)
}

/// Verify a session with a 6-digit code. Returns `Some(user_id)` on
/// success. Idempotent if the session is already verified.
pub async fn verify_session_code(
    pool: &PgPool,
    session_token: &str,
    code: &str,
) -> Result<Option<i64>, crate::error::AppError> {
    let token_hash = hash_token(session_token);
    let Some(session) = pg_sessions::by_token_hash(pool, &token_hash)
        .await
        .map_err(map_err)?
    else {
        return Ok(None);
    };

    let now_ms = Utc::now().timestamp_millis();

    // Expired? Drop and bail.
    if session.expires_at_ms <= now_ms {
        let _ = pg_sessions::delete_one(pool, session.id).await;
        return Ok(None);
    }

    // Already verified — idempotent success.
    if session.verified {
        return Ok(Some(session.user_id));
    }

    // Too many attempts — kill the session.
    if session.verify_attempts >= MAX_VERIFY_ATTEMPTS {
        let _ = pg_sessions::delete_one(pool, session.id).await;
        return Ok(None);
    }

    // No active verification challenge or expired.
    let Some(verify_hash) = session.verify_token_hash.as_ref() else {
        return Ok(None);
    };
    if session
        .verify_expires_at_ms
        .map(|exp| exp <= now_ms)
        .unwrap_or(true)
    {
        return Ok(None);
    }

    let candidate_hash = hash_token(code);
    if &candidate_hash != verify_hash {
        // Wrong code: bump attempt counter, drop session if over cap.
        let attempts = pg_sessions::bump_verify_attempts(pool, session.id)
            .await
            .map_err(map_err)?;
        if attempts >= MAX_VERIFY_ATTEMPTS {
            let _ = pg_sessions::delete_one(pool, session.id).await;
        }
        return Ok(None);
    }

    // Match — flip verified and clear pending state.
    pg_sessions::mark_verified(pool, session.id)
        .await
        .map_err(map_err)?;
    Ok(Some(session.user_id))
}

/// Revoke every session for a user (e.g. password reset). Returns
/// `(session_id, token_hash)` pairs so the caller can broadcast revoke
/// events to active WS connections.
pub async fn revoke_all_user_sessions(
    pool: &PgPool,
    user_id: i64,
) -> Result<Vec<(i64, String)>, crate::error::AppError> {
    pg_sessions::delete_all_for_user(pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "revoke_all_user_sessions: PG delete failed");
            crate::error::AppError::Internal
        })
}

/// Issue a single-use revoke token for an existing session — used by
/// the new-device email "this wasn't me" link.
pub async fn set_revoke_token_for_session(
    pool: &PgPool,
    session_id: i64,
    revoke_token_hash: &str,
) -> Result<(), crate::error::AppError> {
    pg_sessions::set_revoke_token(pool, session_id, revoke_token_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "set_revoke_token_for_session: PG update failed");
            crate::error::AppError::Internal
        })
}

#[inline]
fn map_err(e: sqlx::Error) -> crate::error::AppError {
    tracing::error!(error = %e, "session: pg error");
    crate::error::AppError::Internal
}
