pub const FEDERATION_RUNTIME_MIGRATION: &str =
    include_str!("../../migrations/0028_federation_runtime_foundation.sql");

use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;

use super::auth::FederationPeerKey;
use super::client::FederationPeerEndpoint;
use super::identity::{REMOTE_PRINCIPAL_PASSWORD_HASH, remote_principal_projection};
use super::producer::{FederationPeerRoute, FederationProducerPeer, FederationRouteScope};
use super::protocol::FederationEventKind;

const REPLAY_NONCE_TTL_MS: i64 = 10 * 60 * 1000;
const OUTBOUND_RETRY_BASE_MS: i64 = 1_000;
const OUTBOUND_RETRY_MAX_MS: i64 = 30_000;
const OUTBOUND_MAX_ATTEMPTS: i32 = 8;
const OUTBOUND_MAX_ERROR_CODE_CHARS: usize = 96;
pub const REPLAY_NONCE_PRUNE_BATCH_LIMIT: i64 = 10_000;

pub const REMOTE_PRINCIPAL_UPSERT_SQL: &str = r#"
INSERT INTO users (id, email, password_hash, username, display_name,
                   username_set, email_verified, status_type,
                   created_at_ms, updated_at_ms)
VALUES ($1,$2,$3,$4,$5,true,false,'offline',$6,$6)
ON CONFLICT DO NOTHING;

SELECT id FROM users WHERE lower(email) = lower($1);

INSERT INTO federation_remote_principals (
    id, home_peer_id, remote_user_id, local_user_id, remote_username,
    display_name, avatar_url, status, created_at_ms, updated_at_ms
)
VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)
ON CONFLICT ON CONSTRAINT federation_remote_principals_unique_remote DO UPDATE
   SET local_user_id = COALESCE(federation_remote_principals.local_user_id, EXCLUDED.local_user_id),
       remote_username = EXCLUDED.remote_username,
       display_name = EXCLUDED.display_name,
       avatar_url = EXCLUDED.avatar_url,
       status = 'active',
       updated_at_ms = EXCLUDED.updated_at_ms
RETURNING local_user_id;
"#;

pub const INBOUND_EVENT_INSERT_SQL: &str = r#"
INSERT INTO federation_inbound_events (
    id, source_peer_id, remote_event_id, event_kind, protocol_version,
    payload_hash, status, accepted_at_ms, created_at_ms, updated_at_ms
)
VALUES ($1,$2,$3,$4,1,$5,'received',NULL,$6,$6)
ON CONFLICT ON CONSTRAINT federation_inbound_events_unique_remote DO NOTHING
"#;

pub const INBOUND_EVENT_ACCEPT_SQL: &str = r#"
UPDATE federation_inbound_events
   SET status = 'accepted',
       accepted_at_ms = $3,
       updated_at_ms = $3
 WHERE source_peer_id = $1
   AND remote_event_id = $2
"#;

pub const OUTBOUND_EVENT_CLAIM_SQL: &str = r#"
WITH due AS (
    SELECT id
      FROM federation_outbound_events
     WHERE status IN ('pending','failed')
       AND next_attempt_at_ms <= $1
     ORDER BY next_attempt_at_ms ASC, id ASC
     LIMIT $2
     FOR UPDATE SKIP LOCKED
)
UPDATE federation_outbound_events outbox
   SET status = 'sending',
       updated_at_ms = $1
  FROM due
 WHERE outbox.id = due.id
RETURNING outbox.id,
          outbox.destination_peer_id,
          outbox.event_id,
          outbox.event_kind,
          outbox.payload_hash,
          outbox.event_body_json,
          outbox.attempt_count
"#;

pub const OUTBOUND_EVENT_SENT_SQL: &str = r#"
UPDATE federation_outbound_events
   SET status = 'sent',
       updated_at_ms = $2
 WHERE id = $1
"#;

pub const OUTBOUND_EVENT_FAILED_SQL: &str = r#"
UPDATE federation_outbound_events
   SET status = $2,
       attempt_count = $3,
       next_attempt_at_ms = $4,
       last_error_code = $5,
       updated_at_ms = $6
 WHERE id = $1
"#;

pub const OUTBOUND_EVENT_DEAD_SQL: &str = r#"
UPDATE federation_outbound_events
   SET status = 'dead',
       attempt_count = $2,
       next_attempt_at_ms = NULL,
       last_error_code = $3,
       updated_at_ms = $4
 WHERE id = $1
"#;

pub const PEER_ROUTES_FOR_SCOPE_SQL: &str = r#"
SELECT DISTINCT routes.peer_id, routes.scope_type, routes.scope_id
  FROM federation_peer_routes routes
  JOIN federation_peer_keys keys
    ON keys.peer_id = routes.peer_id
   AND keys.status = 'active'
 WHERE routes.status = 'active'
   AND routes.scope_type = $1
   AND routes.scope_id = $2
 ORDER BY routes.peer_id ASC
"#;

pub const PEER_ROUTE_UPSERT_SQL: &str = r#"
INSERT INTO federation_peer_routes (
    id, peer_id, scope_type, scope_id, status, created_at_ms, updated_at_ms
)
VALUES ($1,$2,$3,$4,'active',$5,$5)
ON CONFLICT ON CONSTRAINT federation_peer_routes_unique_scope DO UPDATE
   SET status = 'active',
       updated_at_ms = EXCLUDED.updated_at_ms
"#;

pub const PEER_ROUTE_REVOKE_SQL: &str = r#"
UPDATE federation_peer_routes
   SET status = 'revoked',
       updated_at_ms = $4
 WHERE peer_id = $1
   AND scope_type = $2
   AND scope_id = $3
"#;

pub const PEER_ENDPOINT_FOR_PEER_SQL: &str = r#"
SELECT api_origin
  FROM federation_peer_keys
 WHERE peer_id = $1
   AND status = 'active'
 ORDER BY valid_until_ms NULLS LAST, updated_at_ms DESC
 LIMIT 1
"#;

pub const REPLAY_NONCE_PRUNE_SQL: &str = r#"
WITH expired AS (
    SELECT id
      FROM federation_replay_nonces
     WHERE expires_at_ms < $1
     ORDER BY expires_at_ms ASC, id ASC
     LIMIT $2
)
DELETE FROM federation_replay_nonces nonces
 USING expired
 WHERE nonces.id = expired.id
"#;

#[derive(Debug, sqlx::FromRow)]
struct FederationPeerKeyRow {
    peer_id: String,
    key_id: String,
    public_key_ed25519: Vec<u8>,
    valid_after_ms: Option<i64>,
    valid_until_ms: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct FederationPeerRouteRow {
    peer_id: String,
    scope_type: String,
    scope_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventInsertResult {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone)]
pub struct InsertInboundFederationEvent<'a> {
    pub id: i64,
    pub source_peer_id: &'a str,
    pub remote_event_id: &'a str,
    pub event_kind: FederationEventKind,
    pub payload_hash: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct InsertOutboundFederationEvent<'a> {
    pub id: i64,
    pub destination_peer_id: &'a str,
    pub event_id: &'a str,
    pub event_kind: FederationEventKind,
    pub payload_hash: &'a str,
    pub event_body_json: &'a Value,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFailurePlan {
    pub status: &'static str,
    pub attempt_count: i32,
    pub next_attempt_at_ms: Option<i64>,
    pub last_error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ClaimedOutboundFederationEvent {
    pub id: i64,
    pub destination_peer_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub payload_hash: String,
    pub event_body_json: Value,
    pub attempt_count: i32,
}

#[derive(Debug, Clone)]
pub struct UpsertRemotePrincipal<'a> {
    pub principal_id: i64,
    pub local_user_id: i64,
    pub home_peer_id: &'a str,
    pub remote_user_id: &'a str,
    pub remote_username: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePrincipalUpsertResult {
    pub local_user_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePrincipalIdentity {
    pub local_user_id: i64,
    pub home_peer_id: String,
    pub remote_user_id: String,
    pub remote_username: Option<String>,
}

pub fn next_retry_at_ms(now_ms: i64, attempt_count: i32) -> i64 {
    let shift = attempt_count.clamp(0, 5) as u32;
    let delay = OUTBOUND_RETRY_BASE_MS
        .saturating_mul(1_i64 << shift)
        .min(OUTBOUND_RETRY_MAX_MS);
    now_ms.saturating_add(delay)
}

pub fn next_outbound_failure_plan(
    now_ms: i64,
    previous_attempt_count: i32,
    error_code: &str,
) -> OutboundFailurePlan {
    let attempt_count = previous_attempt_count.saturating_add(1).max(1);
    let dead = attempt_count >= OUTBOUND_MAX_ATTEMPTS;
    OutboundFailurePlan {
        status: if dead { "dead" } else { "failed" },
        attempt_count,
        next_attempt_at_ms: (!dead).then(|| next_retry_at_ms(now_ms, previous_attempt_count)),
        last_error_code: sanitize_outbound_error_code(error_code),
    }
}

fn sanitize_outbound_error_code(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(OUTBOUND_MAX_ERROR_CODE_CHARS));
    let mut last_was_sep = false;
    for ch in value.chars() {
        if out.len() >= OUTBOUND_MAX_ERROR_CODE_CHARS {
            break;
        }
        let next = if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            last_was_sep = false;
            ch
        } else if !last_was_sep {
            last_was_sep = true;
            '_'
        } else {
            continue;
        };
        out.push(next);
    }

    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "UNSPECIFIED_DELIVERY_FAILURE".to_string()
    } else {
        trimmed.to_string()
    }
}

pub async fn upsert_remote_principal(
    pool: &PgPool,
    principal: UpsertRemotePrincipal<'_>,
) -> Result<RemotePrincipalUpsertResult, sqlx::Error> {
    let projection = remote_principal_projection(principal.home_peer_id, principal.remote_user_id)
        .map_err(|err| sqlx::Error::Protocol(format!("invalid remote principal: {err}")))?;
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, username, display_name,
                           username_set, email_verified, status_type,
                           created_at_ms, updated_at_ms)
        VALUES ($1,$2,$3,$4,$5,true,false,'offline',$6,$6)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(principal.local_user_id)
    .bind(&projection.email)
    .bind(projection.password_hash)
    .bind(&projection.username)
    .bind(principal.display_name)
    .bind(principal.now_ms)
    .execute(&mut *tx)
    .await?;

    let (local_user_id,): (i64,) =
        sqlx::query_as("SELECT id FROM users WHERE lower(email) = lower($1)")
            .bind(&projection.email)
            .fetch_one(&mut *tx)
            .await?;

    sqlx::query(
        r#"
        UPDATE users
           SET display_name = $2,
               password_hash = $3,
               updated_at_ms = $4
         WHERE id = $1
           AND password_hash = $3
        "#,
    )
    .bind(local_user_id)
    .bind(principal.display_name)
    .bind(REMOTE_PRINCIPAL_PASSWORD_HASH)
    .bind(principal.now_ms)
    .execute(&mut *tx)
    .await?;

    let (mapped_local_user_id,): (i64,) = sqlx::query_as(
        r#"
        INSERT INTO federation_remote_principals (
            id, home_peer_id, remote_user_id, local_user_id, remote_username,
            display_name, avatar_url, status, created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)
        ON CONFLICT ON CONSTRAINT federation_remote_principals_unique_remote DO UPDATE
           SET local_user_id = COALESCE(federation_remote_principals.local_user_id, EXCLUDED.local_user_id),
               remote_username = EXCLUDED.remote_username,
               display_name = EXCLUDED.display_name,
               avatar_url = EXCLUDED.avatar_url,
               status = 'active',
               updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING local_user_id
        "#,
    )
    .bind(principal.principal_id)
    .bind(principal.home_peer_id)
    .bind(principal.remote_user_id)
    .bind(local_user_id)
    .bind(principal.remote_username)
    .bind(principal.display_name)
    .bind(principal.avatar_url)
    .bind(principal.now_ms)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(RemotePrincipalUpsertResult {
        local_user_id: mapped_local_user_id,
    })
}

pub async fn local_user_id_for_remote_principal(
    pool: &PgPool,
    home_peer_id: &str,
    remote_user_id: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT local_user_id
          FROM federation_remote_principals
         WHERE home_peer_id = $1
           AND remote_user_id = $2
           AND status = 'active'
        "#,
    )
    .bind(home_peer_id)
    .bind(remote_user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(id,)| id))
}

pub async fn remote_principals_for_local_user_ids(
    pool: &PgPool,
    local_user_ids: &[i64],
) -> Result<HashMap<i64, RemotePrincipalIdentity>, sqlx::Error> {
    if local_user_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT local_user_id, home_peer_id, remote_user_id, remote_username
          FROM federation_remote_principals
         WHERE local_user_id = ANY($1)
           AND status = 'active'
        "#,
    )
    .bind(local_user_ids)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(local_user_id, home_peer_id, remote_user_id, remote_username)| {
                (
                    local_user_id,
                    RemotePrincipalIdentity {
                        local_user_id,
                        home_peer_id,
                        remote_user_id,
                        remote_username,
                    },
                )
            },
        )
        .collect())
}

pub async fn peer_key_by_peer_and_key(
    pool: &PgPool,
    peer_id: &str,
    key_id: &str,
) -> Result<Option<FederationPeerKey>, sqlx::Error> {
    let Some(row) = sqlx::query_as::<_, FederationPeerKeyRow>(
        r#"
        SELECT peer_id, key_id, public_key_ed25519, valid_after_ms, valid_until_ms
          FROM federation_peer_keys
         WHERE peer_id = $1
           AND key_id = $2
           AND status = 'active'
         LIMIT 1
        "#,
    )
    .bind(peer_id)
    .bind(key_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let public_key = row
        .public_key_ed25519
        .try_into()
        .map_err(|_| sqlx::Error::Protocol("invalid federation peer key length".into()))?;

    Ok(Some(FederationPeerKey {
        peer_id: row.peer_id,
        key_id: row.key_id,
        public_key,
        valid_after_ms: row.valid_after_ms,
        valid_until_ms: row.valid_until_ms,
    }))
}

pub async fn peer_endpoint_by_peer_id(
    pool: &PgPool,
    peer_id: &str,
) -> Result<Option<FederationPeerEndpoint>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(PEER_ENDPOINT_FOR_PEER_SQL)
        .bind(peer_id)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|(api_origin,)| FederationPeerEndpoint {
        peer_id: peer_id.to_string(),
        api_origin,
    }))
}

pub async fn producer_peers_for_scope(
    pool: &PgPool,
    scope: FederationRouteScope,
) -> Result<Vec<FederationProducerPeer>, sqlx::Error> {
    let (scope_type, scope_id) = scope_query_parts(scope);
    let rows = sqlx::query_as::<_, FederationPeerRouteRow>(PEER_ROUTES_FOR_SCOPE_SQL)
        .bind(scope_type)
        .bind(scope_id)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let route = peer_route_from_row(&row.scope_type, row.scope_id)?;
            Ok(FederationProducerPeer {
                peer_id: row.peer_id,
                routes: vec![route],
                active: true,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?)
}

pub async fn upsert_peer_route(
    pool: &PgPool,
    id: i64,
    peer_id: &str,
    scope: FederationRouteScope,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let (scope_type, scope_id) = scope_query_parts(scope);
    sqlx::query(PEER_ROUTE_UPSERT_SQL)
        .bind(id)
        .bind(peer_id)
        .bind(scope_type)
        .bind(scope_id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_peer_route(
    pool: &PgPool,
    peer_id: &str,
    scope: FederationRouteScope,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let (scope_type, scope_id) = scope_query_parts(scope);
    sqlx::query(PEER_ROUTE_REVOKE_SQL)
        .bind(peer_id)
        .bind(scope_type)
        .bind(scope_id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

fn scope_query_parts(scope: FederationRouteScope) -> (&'static str, i64) {
    match scope {
        FederationRouteScope::Server { server_id } => ("server", server_id),
        FederationRouteScope::Channel { channel_id } => ("channel", channel_id),
        FederationRouteScope::Dm { channel_id } => ("dm", channel_id),
        FederationRouteScope::Principal { user_id } => ("principal", user_id),
    }
}

fn peer_route_from_row(
    scope_type: &str,
    scope_id: i64,
) -> Result<FederationPeerRoute, sqlx::Error> {
    match scope_type {
        "server" => Ok(FederationPeerRoute::Server {
            server_id: scope_id,
        }),
        "channel" => Ok(FederationPeerRoute::Channel {
            channel_id: scope_id,
        }),
        "dm" => Ok(FederationPeerRoute::Dm {
            channel_id: scope_id,
        }),
        "principal" => Ok(FederationPeerRoute::Principal { user_id: scope_id }),
        _ => Err(sqlx::Error::Protocol(format!(
            "invalid federation peer route scope type: {scope_type}"
        ))),
    }
}

pub async fn reserve_replay_nonce(
    pool: &PgPool,
    id: i64,
    source_peer_id: &str,
    key_id: &str,
    nonce: &str,
    request_timestamp_ms: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let expires_at_ms = now_ms.saturating_add(REPLAY_NONCE_TTL_MS);
    let result = sqlx::query(
        r#"
        INSERT INTO federation_replay_nonces (
            id, source_peer_id, key_id, nonce, request_timestamp_ms, expires_at_ms, created_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT ON CONSTRAINT federation_replay_nonces_unique_nonce DO NOTHING
        "#,
    )
    .bind(id)
    .bind(source_peer_id)
    .bind(key_id)
    .bind(nonce)
    .bind(request_timestamp_ms)
    .bind(expires_at_ms)
    .bind(now_ms)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}

pub async fn prune_expired_replay_nonces(
    pool: &PgPool,
    now_ms: i64,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(REPLAY_NONCE_PRUNE_SQL)
        .bind(now_ms)
        .bind(limit.clamp(1, REPLAY_NONCE_PRUNE_BATCH_LIMIT))
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn insert_inbound_event(
    pool: &PgPool,
    event: InsertInboundFederationEvent<'_>,
) -> Result<EventInsertResult, sqlx::Error> {
    let result = sqlx::query(INBOUND_EVENT_INSERT_SQL)
        .bind(event.id)
        .bind(event.source_peer_id)
        .bind(event.remote_event_id)
        .bind(event.event_kind.as_str())
        .bind(event.payload_hash)
        .bind(event.now_ms)
        .execute(pool)
        .await?;

    if result.rows_affected() == 1 {
        Ok(EventInsertResult::Inserted)
    } else {
        Ok(EventInsertResult::Duplicate)
    }
}

pub async fn mark_inbound_event_accepted(
    pool: &PgPool,
    source_peer_id: &str,
    remote_event_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(INBOUND_EVENT_ACCEPT_SQL)
        .bind(source_peer_id)
        .bind(remote_event_id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_outbound_event(
    pool: &PgPool,
    event: InsertOutboundFederationEvent<'_>,
) -> Result<EventInsertResult, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO federation_outbound_events (
            id, destination_peer_id, event_id, event_kind, protocol_version,
            payload_hash, event_body_json, status, attempt_count, next_attempt_at_ms,
            created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,1,$5,$6,'pending',0,$7,$7,$7)
        ON CONFLICT ON CONSTRAINT federation_outbound_events_unique_remote DO NOTHING
        "#,
    )
    .bind(event.id)
    .bind(event.destination_peer_id)
    .bind(event.event_id)
    .bind(event.event_kind.as_str())
    .bind(event.payload_hash)
    .bind(event.event_body_json)
    .bind(event.now_ms)
    .execute(pool)
    .await?;

    if result.rows_affected() == 1 {
        Ok(EventInsertResult::Inserted)
    } else {
        Ok(EventInsertResult::Duplicate)
    }
}

pub async fn claim_due_outbound_events(
    pool: &PgPool,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<ClaimedOutboundFederationEvent>, sqlx::Error> {
    let limit = limit.clamp(1, 100);
    sqlx::query_as::<_, ClaimedOutboundFederationEvent>(OUTBOUND_EVENT_CLAIM_SQL)
        .bind(now_ms)
        .bind(limit)
        .fetch_all(pool)
        .await
}

pub async fn mark_outbound_event_sent(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(OUTBOUND_EVENT_SENT_SQL)
        .bind(id)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_outbound_event_failed(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
    previous_attempt_count: i32,
    error_code: &str,
) -> Result<OutboundFailurePlan, sqlx::Error> {
    let plan = next_outbound_failure_plan(now_ms, previous_attempt_count, error_code);
    sqlx::query(OUTBOUND_EVENT_FAILED_SQL)
        .bind(id)
        .bind(plan.status)
        .bind(plan.attempt_count)
        .bind(plan.next_attempt_at_ms)
        .bind(&plan.last_error_code)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(plan)
}

pub async fn mark_outbound_event_dead(
    pool: &PgPool,
    id: i64,
    now_ms: i64,
    previous_attempt_count: i32,
    error_code: &str,
) -> Result<OutboundFailurePlan, sqlx::Error> {
    let attempt_count = previous_attempt_count.saturating_add(1).max(1);
    let plan = OutboundFailurePlan {
        status: "dead",
        attempt_count,
        next_attempt_at_ms: None,
        last_error_code: sanitize_outbound_error_code(error_code),
    };
    sqlx::query(OUTBOUND_EVENT_DEAD_SQL)
        .bind(id)
        .bind(plan.attempt_count)
        .bind(&plan.last_error_code)
        .bind(now_ms)
        .execute(pool)
        .await?;
    Ok(plan)
}
