use serde_json::{Value, json};
use sqlx::PgPool;

use crate::error::{AppError, AppResult};
use crate::services::cdn;

pub const FEDERATED_MEMBERSHIP_CAPABILITY_PATH: &str = "/api/federation/invites/capability";
pub const FEDERATION_CLIENT_MEMBERSHIP_MIGRATION: &str =
    include_str!("../../migrations/0029_federation_client_memberships.sql");

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct FederatedClientMembershipRecord {
    pub id: i64,
    pub home_user_id: i64,
    pub target_peer_id: String,
    pub target_api_origin: String,
    pub target_server_id: i64,
    pub remote_user_id: String,
    pub invite_code_hash: String,
    pub status: String,
    pub server_name: Option<String>,
    pub server_icon_url: Option<String>,
    pub server_banner_url: Option<String>,
    pub last_capability_status: Option<String>,
    pub last_error_code: Option<String>,
    pub last_refreshed_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl FederatedClientMembershipRecord {
    pub fn to_client_json(&self) -> Value {
        json!({
            "id": self.id.to_string(),
            "targetPeerId": self.target_peer_id,
            "targetApiOrigin": self.target_api_origin,
            "targetServerId": self.target_server_id.to_string(),
            "status": self.status,
            "server": {
                "id": self.target_server_id.to_string(),
                "name": self.server_name,
                "iconUrl": cdn::resolve(self.server_icon_url.as_deref()),
                "bannerUrl": cdn::resolve(self.server_banner_url.as_deref()),
            },
            "lastCapabilityStatus": self.last_capability_status,
            "lastErrorCode": self.last_error_code,
            "lastRefreshedAtMs": self.last_refreshed_at_ms,
            "createdAtMs": self.created_at_ms,
            "updatedAtMs": self.updated_at_ms,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UpsertFederatedClientMembership<'a> {
    pub id: i64,
    pub home_user_id: i64,
    pub target_peer_id: &'a str,
    pub target_api_origin: &'a str,
    pub target_server_id: i64,
    pub remote_user_id: &'a str,
    pub invite_code_hash: &'a str,
    pub server_name: Option<&'a str>,
    pub server_icon_url: Option<&'a str>,
    pub server_banner_url: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedMembershipServerSnapshot {
    pub target_server_id: i64,
    pub server_name: Option<String>,
    pub server_icon_url: Option<String>,
    pub server_banner_url: Option<String>,
}

pub fn build_federated_membership_capability_body(
    remote_user_id: &str,
    target_server_id: i64,
    invite_code_hash: &str,
) -> AppResult<Value> {
    if !is_valid_remote_user_id(remote_user_id)
        || target_server_id <= 0
        || !is_valid_invite_code_hash(invite_code_hash)
    {
        return Err(AppError::Validation(
            "Invalid federated membership pointer".into(),
        ));
    }
    Ok(json!({
        "remoteUserId": remote_user_id,
        "serverId": target_server_id.to_string(),
        "inviteCodeHash": invite_code_hash,
    }))
}

pub fn server_scope_from_capability_response(
    upstream: &Value,
) -> AppResult<Vec<FederatedMembershipServerSnapshot>> {
    let Some(raw_scope) = upstream.get("serverScope") else {
        return Ok(Vec::new());
    };
    let scope = raw_scope.as_array().ok_or(AppError::Internal)?;
    if scope.len() > 64 {
        return Err(AppError::Internal);
    }

    let mut snapshots = Vec::with_capacity(scope.len());
    for raw in scope {
        let object = raw.as_object().ok_or(AppError::Internal)?;
        let target_server_id = object
            .get("id")
            .and_then(server_id_value)
            .ok_or(AppError::Internal)?;
        snapshots.push(FederatedMembershipServerSnapshot {
            target_server_id,
            server_name: optional_trimmed_string(object.get("name"), 120)?,
            server_icon_url: optional_trimmed_string(object.get("iconUrl"), 2048)?,
            server_banner_url: optional_trimmed_string(object.get("bannerUrl"), 2048)?,
        });
    }
    Ok(snapshots)
}

pub fn sanitize_capability_response_for_client(path: &str, upstream: Value) -> AppResult<Value> {
    if path != FEDERATED_MEMBERSHIP_CAPABILITY_PATH {
        return Err(AppError::Internal);
    }
    let object = upstream.as_object().ok_or(AppError::Internal)?;
    match object.get("status").and_then(Value::as_str) {
        Some("pending") => Ok(json!({
            "status": "pending",
            "reason": object.get("reason").and_then(Value::as_str).unwrap_or("pending"),
        })),
        Some("ready") => {
            let token_type = object
                .get("tokenType")
                .and_then(Value::as_str)
                .filter(|value| *value == "federated_client")
                .ok_or(AppError::Internal)?;
            let access_token = object
                .get("accessToken")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or(AppError::Internal)?;
            let expires_at = object
                .get("expiresAt")
                .and_then(Value::as_str)
                .ok_or(AppError::Internal)?;
            let server_id = object
                .get("serverId")
                .and_then(Value::as_str)
                .ok_or(AppError::Internal)?;
            let user = object.get("user").cloned().ok_or(AppError::Internal)?;
            Ok(json!({
                "status": "ready",
                "tokenType": token_type,
                "accessToken": access_token,
                "expiresAt": expires_at,
                "serverId": server_id,
                "user": user,
            }))
        }
        _ => Err(AppError::Internal),
    }
}

fn server_id_value(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| {
            value
                .as_str()
                .and_then(|raw| raw.trim().parse::<i64>().ok())
        })
        .filter(|id| *id > 0)
}

fn optional_trimmed_string(value: Option<&Value>, max_len: usize) -> AppResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(raw) = value.as_str() else {
        return Err(AppError::Internal);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > max_len {
        return Err(AppError::Internal);
    }
    Ok(Some(trimmed.to_string()))
}

pub async fn upsert_client_membership(
    pool: &PgPool,
    input: UpsertFederatedClientMembership<'_>,
) -> Result<FederatedClientMembershipRecord, sqlx::Error> {
    sqlx::query_as::<_, FederatedClientMembershipRecord>(
        r#"
        INSERT INTO federation_client_memberships (
            id, home_user_id, target_peer_id, target_api_origin, target_server_id,
            remote_user_id, invite_code_hash, status, server_name, server_icon_url,
            server_banner_url, last_capability_status, last_error_code,
            last_refreshed_at_ms, created_at_ms, updated_at_ms
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,NULL,NULL,NULL,$11,$11)
        ON CONFLICT ON CONSTRAINT federation_client_memberships_unique_remote_server DO UPDATE
           SET target_api_origin = EXCLUDED.target_api_origin,
               remote_user_id = EXCLUDED.remote_user_id,
               invite_code_hash = EXCLUDED.invite_code_hash,
               status = 'active',
               server_name = COALESCE(EXCLUDED.server_name, federation_client_memberships.server_name),
               server_icon_url = COALESCE(EXCLUDED.server_icon_url, federation_client_memberships.server_icon_url),
               server_banner_url = COALESCE(EXCLUDED.server_banner_url, federation_client_memberships.server_banner_url),
               updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING id, home_user_id, target_peer_id, target_api_origin, target_server_id,
                  remote_user_id, invite_code_hash, status, server_name, server_icon_url,
                  server_banner_url, last_capability_status, last_error_code,
                  last_refreshed_at_ms, created_at_ms, updated_at_ms
        "#,
    )
    .bind(input.id)
    .bind(input.home_user_id)
    .bind(input.target_peer_id)
    .bind(input.target_api_origin)
    .bind(input.target_server_id)
    .bind(input.remote_user_id)
    .bind(input.invite_code_hash)
    .bind(input.server_name)
    .bind(input.server_icon_url)
    .bind(input.server_banner_url)
    .bind(input.now_ms)
    .fetch_one(pool)
    .await
}

pub async fn list_client_memberships_for_user(
    pool: &PgPool,
    home_user_id: i64,
) -> Result<Vec<FederatedClientMembershipRecord>, sqlx::Error> {
    sqlx::query_as::<_, FederatedClientMembershipRecord>(
        r#"
        SELECT id, home_user_id, target_peer_id, target_api_origin, target_server_id,
               remote_user_id, invite_code_hash, status, server_name, server_icon_url,
               server_banner_url, last_capability_status, last_error_code,
               last_refreshed_at_ms, created_at_ms, updated_at_ms
          FROM federation_client_memberships
         WHERE home_user_id = $1
           AND status IN ('active','pending','revoked','removed')
         ORDER BY updated_at_ms DESC, id DESC
        "#,
    )
    .bind(home_user_id)
    .fetch_all(pool)
    .await
}

pub async fn client_membership_for_user(
    pool: &PgPool,
    membership_id: i64,
    home_user_id: i64,
) -> Result<Option<FederatedClientMembershipRecord>, sqlx::Error> {
    sqlx::query_as::<_, FederatedClientMembershipRecord>(
        r#"
        SELECT id, home_user_id, target_peer_id, target_api_origin, target_server_id,
               remote_user_id, invite_code_hash, status, server_name, server_icon_url,
               server_banner_url, last_capability_status, last_error_code,
               last_refreshed_at_ms, created_at_ms, updated_at_ms
          FROM federation_client_memberships
         WHERE id = $1
           AND home_user_id = $2
        "#,
    )
    .bind(membership_id)
    .bind(home_user_id)
    .fetch_optional(pool)
    .await
}

pub async fn mark_client_membership_capability_status(
    pool: &PgPool,
    membership_id: i64,
    status: &'static str,
    error_code: Option<&str>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE federation_client_memberships
           SET last_capability_status = $2,
               last_error_code = $3,
               last_refreshed_at_ms = $4,
               updated_at_ms = $4
         WHERE id = $1
        "#,
    )
    .bind(membership_id)
    .bind(status)
    .bind(error_code)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

fn is_valid_remote_user_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn is_valid_invite_code_hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_server_scope_parser_accepts_minimal_server_metadata() {
        let value = json!({
            "status": "ready",
            "serverScope": [
                {
                    "id": "10",
                    "name": "Verdant",
                    "iconUrl": "https://cdn.example.com/server-icons/10.webp",
                    "bannerUrl": null
                },
                {
                    "id": 20,
                    "name": " Self Host ",
                    "iconUrl": "",
                    "bannerUrl": "https://cdn.example.com/server-banners/20.webp"
                }
            ]
        });

        let scope = server_scope_from_capability_response(&value).expect("valid scope");

        assert_eq!(scope.len(), 2);
        assert_eq!(scope[0].target_server_id, 10);
        assert_eq!(scope[0].server_name.as_deref(), Some("Verdant"));
        assert_eq!(
            scope[0].server_icon_url.as_deref(),
            Some("https://cdn.example.com/server-icons/10.webp")
        );
        assert_eq!(scope[0].server_banner_url, None);
        assert_eq!(scope[1].target_server_id, 20);
        assert_eq!(scope[1].server_name.as_deref(), Some("Self Host"));
        assert_eq!(scope[1].server_icon_url, None);
        assert_eq!(
            scope[1].server_banner_url.as_deref(),
            Some("https://cdn.example.com/server-banners/20.webp")
        );
    }

    #[test]
    fn capability_server_scope_parser_is_backward_compatible_when_absent() {
        let value = json!({"status": "ready"});

        let scope = server_scope_from_capability_response(&value).expect("missing scope is ok");

        assert!(scope.is_empty());
    }

    #[test]
    fn capability_server_scope_parser_rejects_invalid_scope() {
        let value = json!({
            "status": "ready",
            "serverScope": [{"id": "not-a-server"}]
        });

        assert!(server_scope_from_capability_response(&value).is_err());
    }

    #[test]
    fn sanitize_capability_response_for_client_omits_server_scope() {
        let value = json!({
            "status": "ready",
            "tokenType": "federated_client",
            "accessToken": "target-access",
            "expiresAt": "2026-06-23T00:00:00Z",
            "serverId": "10",
            "serverScope": [{"id": "10", "name": "Verdant"}],
            "user": {"id": "42"}
        });

        let sanitized =
            sanitize_capability_response_for_client(FEDERATED_MEMBERSHIP_CAPABILITY_PATH, value)
                .expect("valid response");

        assert!(sanitized.get("serverScope").is_none());
        assert_eq!(
            sanitized.get("serverId").and_then(Value::as_str),
            Some("10")
        );
    }
}
