use axum::{
    Json,
    body::to_bytes,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use validator::Validate;

use crate::config::InstanceMode;
use crate::error::{AppError, AppResult};
use crate::federation::auth::{
    FederationRequestIdentity, FederationRequestVerifier, InMemoryNonceStore, StaticPeerKeyStore,
    VerifyError,
};
use crate::federation::client_membership::{
    UpsertFederatedClientMembership, upsert_client_membership,
};
use crate::middleware::{auth::UserId, rate_limit};
use crate::repo::servers::ServerRow;
use crate::services::permissions::bits;
use crate::services::{banner_crop, cdn};
use crate::state::AppState;
use crate::ws::{events, topics};

use super::{extract_client_ip, parse_id};

const MAX_MEMBERS_PER_SERVER: i64 = 10_000;
const CHANNEL_TYPE_SERVER_TEXT: i32 = 0;
const MAX_INVITE_USES: i32 = 100;
const MAX_INVITE_EXPIRES_IN_SECS: i64 = 30 * 24 * 60 * 60;
const FEDERATED_INVITE_CAPABILITY_BODY_LIMIT_BYTES: usize = 16 * 1024;
// Federated client credentials are short-lived target-backend capabilities.
// Durable joined-server persistence comes from the home-backed federated
// membership record, which can re-mint this scoped bearer without invite rejoin.
const FEDERATED_CLIENT_ACCESS_TOKEN_MINUTES: i64 = 60;

async fn configured_server_text_channel_exists(
    state: &AppState,
    server_id: i64,
    channel_id: i64,
    purpose: &'static str,
) -> bool {
    match crate::services::pg::channels::by_id(&state.pg, channel_id).await {
        Ok(Some(channel))
            if channel.server_id == Some(server_id)
                && channel.r#type == CHANNEL_TYPE_SERVER_TEXT =>
        {
            true
        }
        Ok(Some(channel)) => {
            tracing::warn!(
                server_id,
                channel_id,
                purpose,
                channel_server_id = ?channel.server_id,
                channel_type = channel.r#type,
                "Skipping configured channel outside this server or non-text channel"
            );
            false
        }
        Ok(None) => {
            tracing::warn!(
                server_id,
                channel_id,
                purpose,
                "Skipping missing configured channel"
            );
            false
        }
        Err(e) => {
            tracing::warn!(server_id, channel_id, purpose, error = %e, "Failed to validate configured channel");
            false
        }
    }
}

/// Generate a 16-char alphanumeric invite code using rejection sampling
/// to eliminate modulo bias (256 % 62 = 8 would bias the first 8 chars).
fn generate_invite_code() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const MAX_UNBIASED: usize = (256 / CHARS.len()) * CHARS.len(); // 248
    let mut result = String::with_capacity(16);
    let mut buf = [0u8; 20];
    getrandom::fill(&mut buf).expect("getrandom failed");
    let mut i = 0;
    while result.len() < 16 {
        if i >= buf.len() {
            getrandom::fill(&mut buf).expect("getrandom failed");
            i = 0;
        }
        let b = buf[i] as usize;
        i += 1;
        if b < MAX_UNBIASED {
            result.push(CHARS[b % CHARS.len()] as char);
        }
    }
    result
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteRequest {
    #[validate(range(min = 0))]
    pub max_uses: Option<i32>,
    #[validate(range(min = 60))] // Minimum 60 seconds; use None for never-expires
    pub expires_in: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedInviteJoinRequest {
    pub target_api_origin: String,
    pub target_peer_id: String,
    pub server_id: String,
    pub code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedInviteCapabilityRequest {
    pub remote_user_id: String,
    pub server_id: String,
    pub invite_code_hash: String,
}

// ─── POST /api/servers/:serverId/invites ────────────────────────────

fn invite_code_preview(code: &str) -> String {
    code.chars().take(8).collect()
}

fn is_valid_invite_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 64 && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn federation_invite_preview_enabled(mode: InstanceMode) -> bool {
    matches!(mode, InstanceMode::Official | InstanceMode::Federated)
}

fn federation_invite_join_enabled(mode: InstanceMode) -> bool {
    matches!(mode, InstanceMode::Official | InstanceMode::Federated)
}

fn federated_invite_preview_rate_limit_key(client_ip: &str) -> String {
    format!("ip:{client_ip}")
}

fn federation_invite_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> AppError {
    AppError::WithCode {
        status,
        code,
        message: message.into(),
    }
}

fn federation_verify_error(error: VerifyError) -> AppError {
    match error {
        VerifyError::MissingHeader | VerifyError::MalformedHeader => federation_invite_error(
            StatusCode::UNAUTHORIZED,
            "FEDERATION_SIGNATURE_REQUIRED",
            "Federation signature is required",
        ),
        VerifyError::Replay => federation_invite_error(
            StatusCode::UNAUTHORIZED,
            "FEDERATION_SIGNATURE_REPLAYED",
            "Federation signature was already used",
        ),
        _ => federation_invite_error(
            StatusCode::UNAUTHORIZED,
            "FEDERATION_SIGNATURE_INVALID",
            "Federation signature was invalid",
        ),
    }
}

fn normalize_invite_limits(
    body: &CreateInviteRequest,
    can_manage_server: bool,
) -> AppResult<(i32, Option<i64>)> {
    let max_uses = body.max_uses.unwrap_or(0);
    if max_uses < 0 || max_uses > MAX_INVITE_USES {
        return Err(AppError::Validation(format!(
            "Invites can have at most {MAX_INVITE_USES} uses"
        )));
    }

    if let Some(expires_in) = body.expires_in {
        if !(60..=MAX_INVITE_EXPIRES_IN_SECS).contains(&expires_in) {
            return Err(AppError::Validation(
                "Invite expiry must be between 60 seconds and 30 days".into(),
            ));
        }
    }

    if !can_manage_server && (max_uses == 0 || body.expires_in.is_none()) {
        return Err(AppError::Validation(
            "Invite must have limited uses and an expiry".into(),
        ));
    }

    Ok((max_uses, body.expires_in))
}

pub async fn create_invite(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<CreateInviteRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!(
        "POST /api/servers/{}/invites user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::INVITE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;
    let perms = state
        .permissions
        .resolve_server_permissions(user_id.0, server_id)
        .await?;
    let can_manage_server = bits::has(perms, bits::MANAGE_SERVER);
    if !can_manage_server && !bits::has(perms, bits::CREATE_INVITE) {
        return Err(AppError::MissingPermission);
    }

    let (max_uses, expires_in) = normalize_invite_limits(&body, can_manage_server)?;

    let code = generate_invite_code();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let expires_at_ms: Option<i64> = if let Some(secs) = expires_in {
        let millis = secs.checked_mul(1000).ok_or_else(|| {
            AppError::Validation("Invite expiry must be between 60 seconds and 30 days".into())
        })?;
        Some(now_ms.checked_add(millis).ok_or_else(|| {
            AppError::Validation("Invite expiry must be between 60 seconds and 30 days".into())
        })?)
    } else {
        None
    };

    crate::services::pg::server_invites::insert(
        &state.pg,
        &code,
        server_id,
        user_id.0,
        max_uses,
        expires_at_ms,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "create_invite: PG write failed");
        AppError::Internal
    })?;

    // Resolve the inviter's username so the response shape matches
    // the legacy JOIN-on-users query.
    let username = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .ok()
        .flatten()
        .map(|u| u.username);

    tracing::info!(
        "Invite created code={}… server={} by={}",
        invite_code_preview(&code),
        server_id,
        user_id.0
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "code": code,
            "serverId": server_id_str,
            "inviterId": user_id.0.to_string(),
            "inviterUsername": username,
            "maxUses": if max_uses == 0 { Value::Null } else { json!(max_uses) },
            "uses": 0,
            "expiresAt": expires_at_ms
                .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
                .map(|t| Value::String(t.to_rfc3339()))
                .unwrap_or(Value::Null),
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        })),
    )
        .into_response())
}

// ─── GET /api/servers/:serverId/invites ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("invites.rs");

    fn invite(max_uses: Option<i32>, expires_in: Option<i64>) -> CreateInviteRequest {
        CreateInviteRequest {
            max_uses,
            expires_in,
        }
    }

    #[test]
    fn non_manager_invite_requires_use_limit_and_expiry() {
        assert!(normalize_invite_limits(&invite(None, Some(3600)), false).is_err());
        assert!(normalize_invite_limits(&invite(Some(0), Some(3600)), false).is_err());
        assert!(normalize_invite_limits(&invite(Some(10), None), false).is_err());
    }

    #[test]
    fn non_manager_bounded_invite_is_allowed() {
        let limits = normalize_invite_limits(&invite(Some(10), Some(7 * 24 * 60 * 60)), false)
            .expect("bounded invite should be valid");
        assert_eq!(limits, (10, Some(7 * 24 * 60 * 60)));
    }

    #[test]
    fn manager_can_create_unlimited_never_expiring_invite() {
        let limits = normalize_invite_limits(&invite(None, None), true)
            .expect("manager unlimited invite should be valid");
        assert_eq!(limits, (0, None));
    }

    #[test]
    fn invite_limits_are_capped() {
        assert!(
            normalize_invite_limits(&invite(Some(MAX_INVITE_USES + 1), Some(3600)), true).is_err()
        );
        assert!(
            normalize_invite_limits(
                &invite(Some(10), Some(MAX_INVITE_EXPIRES_IN_SECS + 1)),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn local_invite_accept_ban_lookup_does_not_fail_open() {
        let handler = SOURCE
            .split("\npub async fn accept_invite")
            .nth(1)
            .expect("accept_invite handler source should exist")
            .split("// Already a member?")
            .next()
            .expect("already-member check follows ban lookup");

        assert!(
            !handler.contains(".unwrap_or(false)"),
            "local invite accept must not treat ban-store errors as not banned"
        );
    }
}

fn millis_opt_to_rfc3339_or_null(millis: Option<i64>) -> Value {
    millis
        .and_then(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms))
        .map(|t| Value::String(t.to_rfc3339()))
        .unwrap_or(Value::Null)
}

pub async fn list_invites(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/invites user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let records = crate::services::pg::server_invites::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_invites: PG read failed");
            AppError::Internal
        })?;

    // Batch-fetch inviter usernames. Typically only a handful of
    // distinct inviters per server — n+1 is fine.
    let mut result: Vec<Value> = Vec::with_capacity(records.len());
    for r in &records {
        let inviter_username = crate::services::pg::users::by_id(&state.pg, r.inviter_id)
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_default();
        result.push(json!({
            "code": r.code,
            "serverId": r.server_id.to_string(),
            "inviterId": r.inviter_id.to_string(),
            "inviterUsername": inviter_username,
            "maxUses": if r.max_uses == 0 { Value::Null } else { json!(r.max_uses) },
            "uses": r.uses,
            "expiresAt": millis_opt_to_rfc3339_or_null(r.expires_at_ms),
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.created_at_ms)
                .map(|t| Value::String(t.to_rfc3339()))
                .unwrap_or(Value::Null),
        }));
    }

    tracing::info!("Listed {} invites for server={}", result.len(), server_id);
    Ok(Json(json!(result)))
}

// ─── DELETE /api/servers/:serverId/invites/:code ────────────────────

pub async fn revoke_invite(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, code)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    let code_preview = invite_code_preview(&code);
    tracing::info!(
        "DELETE /api/servers/{}/invites/{} user_id={}",
        server_id_str,
        code_preview,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::INVITE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state
        .require_membership(user_id.0, server_id)
        .await
        .map_err(|_| AppError::NotFound("invite"))?;

    let invite = crate::services::pg::server_invites::by_code(&state.pg, &code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "revoke_invite: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;
    if invite.server_id != server_id {
        return Err(AppError::NotFound("invite"));
    }

    // Must be invite creator or have MANAGE_SERVER
    if invite.inviter_id != user_id.0 {
        state
            .permissions
            .check_server_permission(user_id.0, server_id, bits::MANAGE_SERVER)
            .await?;
    }

    crate::services::pg::server_invites::delete(&state.pg, &code)
        .await
        .map_err(|e| {
            tracing::error!(code = %code_preview, error = %e, "revoke_invite: PG delete failed");
            AppError::Internal
        })?;

    tracing::info!(
        "Invite revoked code={} server={} by={}",
        code_preview,
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── GET /api/invites/:code — preview ───────────────────────────────

pub async fn preview_invite(
    State(state): State<AppState>,
    user_id: UserId,
    Path(code): Path<String>,
) -> AppResult<Json<Value>> {
    let code_preview = invite_code_preview(&code);
    tracing::info!("GET /api/invites/{} (preview)", code_preview);
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;

    let invite = crate::services::pg::server_invites::by_code(&state.pg, &code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "preview_invite: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Some(exp) = invite.expires_at_ms {
        if exp < now_ms {
            return Err(AppError::NotFound("invite"));
        }
    }
    if invite.max_uses != 0 && invite.uses >= invite.max_uses {
        return Err(AppError::NotFound("invite"));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, invite.server_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "preview_invite: PG server read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;
    if server.deleted_at.is_some() {
        return Err(AppError::NotFound("invite"));
    }

    let inviter_username = crate::services::pg::users::by_id(&state.pg, invite.inviter_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_default();

    let is_member = crate::services::pg::servers::is_member(&state.pg, invite.server_id, user_id.0)
        .await
        .unwrap_or(false);

    let member_count = crate::services::pg::servers::member_count(&state.pg, invite.server_id)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "code": invite.code,
        "server": {
            "id": invite.server_id.to_string(),
            "name": server.name,
            "iconUrl": cdn::resolve(server.icon_url.as_deref()),
            "bannerUrl": cdn::resolve(server.banner_url.as_deref()),
            "bannerCrop": banner_crop::to_json(server.banner_crop),
            "memberCount": member_count,
        },
        "inviterUsername": inviter_username,
        "expiresAt": millis_opt_to_rfc3339_or_null(invite.expires_at_ms),
        "isMember": is_member,
    })))
}

// Public federated invite preview. This intentionally returns only the same
// minimal invite card metadata as the authenticated preview and never computes
// target-backend membership from a home-backend user.
pub async fn preview_federated_invite(
    State(state): State<AppState>,
    Path(code): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let code_preview = invite_code_preview(&code);
    tracing::info!(
        code = %code_preview,
        instance_mode = %state.config.instance_mode.as_str(),
        "GET /api/federation/invites/{code}/preview"
    );

    if !federation_invite_preview_enabled(state.config.instance_mode) {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "FEDERATION_INVITES_DISABLED",
            message: "Federated invite previews are not enabled on this backend".into(),
        });
    }

    if !is_valid_invite_code(&code) {
        return Err(AppError::NotFound("invite"));
    }

    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));
    let rate_limit_key = federated_invite_preview_rate_limit_key(&client_ip);
    rate_limit::enforce(
        &state,
        &rate_limit::FEDERATION_INVITE_PREVIEW_LIMIT,
        &rate_limit_key,
    )
    .await?;

    let invite = crate::services::pg::server_invites::by_code(&state.pg, &code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "preview_federated_invite: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Some(exp) = invite.expires_at_ms {
        if exp < now_ms {
            return Err(AppError::NotFound("invite"));
        }
    }
    if invite.max_uses != 0 && invite.uses >= invite.max_uses {
        return Err(AppError::NotFound("invite"));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, invite.server_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "preview_federated_invite: PG server read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;
    if server.deleted_at.is_some() {
        return Err(AppError::NotFound("invite"));
    }

    let inviter_username = crate::services::pg::users::by_id(&state.pg, invite.inviter_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_default();

    let member_count = crate::services::pg::servers::member_count(&state.pg, invite.server_id)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "code": invite.code,
        "server": {
            "id": invite.server_id.to_string(),
            "name": server.name,
            "iconUrl": cdn::resolve(server.icon_url.as_deref()),
            "bannerUrl": cdn::resolve(server.banner_url.as_deref()),
            "bannerCrop": banner_crop::to_json(server.banner_crop),
            "memberCount": member_count,
        },
        "inviterUsername": inviter_username,
        "expiresAt": millis_opt_to_rfc3339_or_null(invite.expires_at_ms),
        "isMember": false,
        "federated": true,
        "instance": {
            "id": state.config.instance_id.as_str(),
            "mode": state.config.instance_mode.as_str(),
        },
    })))
}

pub async fn join_federated_invite(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<FederatedInviteJoinRequest>,
) -> AppResult<Response> {
    let code = body.code.trim().to_string();
    tracing::info!(
        user_id = user_id.0,
        instance_mode = %state.config.instance_mode.as_str(),
        "POST /api/federation/invites/join"
    );

    if !federation_invite_join_enabled(state.config.instance_mode) {
        return Err(federation_invite_error(
            StatusCode::FORBIDDEN,
            "FEDERATION_INVITES_DISABLED",
            "Federated invite joins are not enabled on this backend",
        ));
    }
    if !is_valid_invite_code(&code) {
        return Err(AppError::NotFound("invite"));
    }

    rate_limit::enforce(&state, &rate_limit::INVITE_LIMIT, &user_id.0.to_string()).await?;

    let server_id = parse_id(body.server_id.trim())?;
    let target_peer_id = body.target_peer_id.trim().to_string();
    if target_peer_id.is_empty() || target_peer_id == state.config.instance_id {
        return Err(federation_invite_error(
            StatusCode::BAD_REQUEST,
            "FEDERATION_INVITE_JOIN_INVALID_TARGET",
            "Federated invite target was invalid",
        ));
    }

    let target_api_origin =
        crate::federation::invite_join::normalize_federated_invite_target_origin(
            &target_peer_id,
            &body.target_api_origin,
        )
        .map_err(|_| {
            federation_invite_error(
                StatusCode::BAD_REQUEST,
                "FEDERATION_INVITE_JOIN_INVALID_TARGET",
                "Federated invite target was invalid",
            )
        })?;

    let peer_endpoint =
        crate::federation::storage::peer_endpoint_by_peer_id(&state.pg, &target_peer_id)
            .await
            .map_err(|error| {
                tracing::warn!(
                    error = %error,
                    target_peer_id = %target_peer_id,
                    "Federated invite join peer endpoint lookup failed"
                );
                AppError::Internal
            })?
            .ok_or_else(|| {
                federation_invite_error(
                    StatusCode::FORBIDDEN,
                    "FEDERATION_PEER_UNTRUSTED",
                    "Federated invite target is not trusted by this backend",
                )
            })?;
    let trusted_api_origin =
        crate::federation::invite_join::normalize_federated_invite_target_origin(
            &peer_endpoint.peer_id,
            &peer_endpoint.api_origin,
        )
        .map_err(|_| {
            tracing::warn!(
                target_peer_id = %target_peer_id,
                "Federated invite join trusted peer endpoint is invalid"
            );
            federation_invite_error(
                StatusCode::FORBIDDEN,
                "FEDERATION_PEER_INVALID_ENDPOINT",
                "Federated invite target is not trusted by this backend",
            )
        })?;
    if trusted_api_origin != target_api_origin {
        tracing::warn!(
            target_peer_id = %target_peer_id,
            requested_api_origin = %target_api_origin,
            trusted_api_origin = %trusted_api_origin,
            "Federated invite join target origin did not match trusted peer endpoint"
        );
        return Err(federation_invite_error(
            StatusCode::FORBIDDEN,
            "FEDERATION_PEER_ORIGIN_MISMATCH",
            "Federated invite target did not match a trusted peer",
        ));
    }

    if state
        .config
        .federation_s2s_key_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .is_none()
        || state.config.federation_s2s_signing_seed.is_none()
    {
        return Err(federation_invite_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "FEDERATION_S2S_SIGNING_NOT_CONFIGURED",
            "Federated invite join signing is not configured",
        ));
    }

    let (username, avatar_url, display_name) = state
        .user_profiles
        .get_or_fetch_vdb(&state, user_id.0)
        .await;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let report = crate::federation::invite_join::enqueue_federated_invite_join(
        &state,
        &target_peer_id,
        server_id,
        user_id.0,
        &code,
        Some(username),
        display_name,
        avatar_url,
        now_ms,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            error = %error,
            target_peer_id = %target_peer_id,
            server_id,
            user_id = user_id.0,
            "Federated invite join enqueue failed"
        );
        federation_invite_error(
            StatusCode::BAD_REQUEST,
            "FEDERATION_INVITE_JOIN_FAILED",
            "Federated invite join could not be queued",
        )
    })?;
    let remote_user_id = user_id.0.to_string();
    let invite_code_hash = crate::federation::invite_join::federated_invite_code_hash(&code);
    let membership = upsert_client_membership(
        &state.pg,
        UpsertFederatedClientMembership {
            id: state.snowflake.next_id(),
            home_user_id: user_id.0,
            target_peer_id: &target_peer_id,
            target_api_origin: &target_api_origin,
            target_server_id: server_id,
            remote_user_id: &remote_user_id,
            invite_code_hash: &invite_code_hash,
            server_name: None,
            server_icon_url: None,
            server_banner_url: None,
            now_ms,
        },
    )
    .await
    .map_err(|error| {
        tracing::error!(
            error = %error,
            target_peer_id = %target_peer_id,
            target_api_origin = %target_api_origin,
            server_id,
            user_id = user_id.0,
            "Failed to persist federated client membership pointer"
        );
        AppError::Internal
    })?;

    tracing::info!(
        target_peer_id = %target_peer_id,
        target_api_origin = %target_api_origin,
        server_id,
        user_id = user_id.0,
        membership_id = membership.id,
        queued_events = report.queued_events,
        duplicate_events = report.duplicate_events,
        "Federated invite join queued and membership pointer persisted"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": report.status,
            "queuedEvents": report.queued_events,
            "duplicateEvents": report.duplicate_events,
            "targetPeerId": target_peer_id,
            "targetApiOrigin": target_api_origin,
            "serverId": server_id.to_string(),
            "membership": membership.to_client_json(),
        })),
    )
        .into_response())
}

// ─── POST /api/invites/:code/accept ─────────────────────────────────

pub async fn issue_federated_invite_capability(
    State(state): State<AppState>,
    request: Request,
) -> AppResult<Response> {
    if !federation_invite_join_enabled(state.config.instance_mode) {
        return Err(federation_invite_error(
            StatusCode::FORBIDDEN,
            "FEDERATION_INVITES_DISABLED",
            "Federated invite joins are not enabled on this backend",
        ));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let body_bytes = to_bytes(body, FEDERATED_INVITE_CAPABILITY_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| {
            federation_invite_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "FEDERATION_INVITE_CAPABILITY_BODY_TOO_LARGE",
                "Federated invite capability request was too large",
            )
        })?;
    let verified =
        verify_federated_invite_capability_signature(&state, &headers, &body_bytes).await?;
    rate_limit::enforce(
        &state,
        &rate_limit::FEDERATION_EVENT_LIMIT,
        &verified.source_peer_id,
    )
    .await?;

    let body: FederatedInviteCapabilityRequest =
        serde_json::from_slice(&body_bytes).map_err(|_| {
            federation_invite_error(
                StatusCode::BAD_REQUEST,
                "FEDERATION_INVITE_CAPABILITY_INVALID",
                "Federated invite capability request was invalid",
            )
        })?;
    if !is_valid_remote_user_id(&body.remote_user_id)
        || !is_valid_invite_code_hash(&body.invite_code_hash)
    {
        return Err(federation_invite_error(
            StatusCode::BAD_REQUEST,
            "FEDERATION_INVITE_CAPABILITY_INVALID",
            "Federated invite capability request was invalid",
        ));
    }
    let server_id = parse_id(body.server_id.trim())?;

    let Some(local_user_id) = crate::federation::storage::local_user_id_for_remote_principal(
        &state.pg,
        &verified.source_peer_id,
        &body.remote_user_id,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            source_peer_id = %verified.source_peer_id,
            remote_user_id = %body.remote_user_id,
            error = %error,
            "Federated invite capability remote principal lookup failed"
        );
        AppError::Internal
    })?
    else {
        return Ok(federated_invite_capability_pending_response(
            "projected_principal_pending",
        ));
    };

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|error| {
            tracing::warn!(
                server_id,
                error = %error,
                "Federated invite capability server lookup failed"
            );
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;
    if server.deleted_at.is_some() {
        return Err(AppError::NotFound("server"));
    }

    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, local_user_id)
        .await
        .map_err(|error| {
            tracing::warn!(
                server_id,
                local_user_id,
                error = %error,
                "Federated invite capability membership check failed"
            );
            AppError::Internal
        })?;
    if !is_member {
        return Ok(federated_invite_capability_pending_response(
            "membership_pending",
        ));
    }

    let user = crate::services::pg::users::by_id(&state.pg, local_user_id)
        .await
        .map_err(|error| {
            tracing::warn!(
                local_user_id,
                error = %error,
                "Federated invite capability user lookup failed"
            );
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;

    let server_scope =
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, local_user_id)
            .await
            .map_err(|error| {
                tracing::warn!(
                    source_peer_id = %verified.source_peer_id,
                    remote_user_id = %body.remote_user_id,
                    local_user_id,
                    server_id,
                    error = %error,
                    "Federated invite capability membership scope lookup failed"
                );
                AppError::Internal
            })?;
    let server_scope =
        federated_client_token_server_scope(server_scope, server_id).map_err(|error| {
            tracing::warn!(
                source_peer_id = %verified.source_peer_id,
                remote_user_id = %body.remote_user_id,
                local_user_id,
                server_id,
                error = ?error,
                "Federated invite capability membership scope rejected"
            );
            error
        })?;
    let scoped_server_rows = crate::services::pg::servers::by_ids(&state.pg, &server_scope)
        .await
        .map_err(|error| {
            tracing::warn!(
                source_peer_id = %verified.source_peer_id,
                remote_user_id = %body.remote_user_id,
                local_user_id,
                server_id,
                error = %error,
                "Federated invite capability server scope metadata lookup failed"
            );
            AppError::Internal
        })?;
    let scoped_server_rows_by_id: HashMap<i64, ServerRow> = scoped_server_rows
        .into_iter()
        .map(|row| (row.id, row))
        .collect();
    if !scoped_server_rows_by_id.contains_key(&server_id) {
        tracing::warn!(
            source_peer_id = %verified.source_peer_id,
            remote_user_id = %body.remote_user_id,
            local_user_id,
            server_id,
            "Federated invite capability required server missing from metadata scope"
        );
        return Err(AppError::Internal);
    }
    let server_scope_json = server_scope
        .iter()
        .filter_map(|server_id| scoped_server_rows_by_id.get(server_id))
        .map(server_to_federated_capability_json)
        .collect::<Vec<_>>();

    let expires_at =
        chrono::Utc::now() + chrono::Duration::minutes(FEDERATED_CLIENT_ACCESS_TOKEN_MINUTES);
    let access_token = crate::services::crypto::generate_federated_client_access_token(
        local_user_id,
        &state.config.jwt_secret,
        &state.config.instance_id,
        &verified.source_peer_id,
        &body.remote_user_id,
        &server_scope,
        chrono::Duration::minutes(FEDERATED_CLIENT_ACCESS_TOKEN_MINUTES),
    )?;

    tracing::info!(
        source_peer_id = %verified.source_peer_id,
        remote_user_id = %body.remote_user_id,
        local_user_id,
        server_id,
        scoped_server_count = server_scope.len(),
        scoped_server_metadata_count = server_scope_json.len(),
        "Federated invite client capability issued"
    );
    Ok(Json(json!({
        "status": "ready",
        "tokenType": "federated_client",
        "accessToken": access_token,
        "expiresAt": expires_at.to_rfc3339(),
        "serverId": server_id.to_string(),
        "serverScope": server_scope_json,
        "user": user_to_federated_capability_json(&user),
    }))
    .into_response())
}

async fn verify_federated_invite_capability_signature(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    body_bytes: &[u8],
) -> AppResult<crate::federation::auth::VerifiedFederationRequest> {
    let identity =
        FederationRequestIdentity::from_headers(headers).map_err(federation_verify_error)?;
    let Some(peer_key) = crate::federation::storage::peer_key_by_peer_and_key(
        &state.pg,
        &identity.source_peer_id,
        &identity.key_id,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            source_peer_id = %identity.source_peer_id,
            key_id = %identity.key_id,
            error = %error,
            "Federated invite capability peer key lookup failed"
        );
        AppError::Internal
    })?
    else {
        return Err(federation_verify_error(VerifyError::UnknownPeerKey));
    };
    let mut key_store = StaticPeerKeyStore::default();
    key_store.insert(peer_key);
    let verifier = FederationRequestVerifier::new(
        state.config.instance_id.clone(),
        key_store,
        InMemoryNonceStore::default(),
    );
    let verified = verifier
        .verify_signature(
            "POST",
            crate::federation::invite_join::FEDERATED_INVITE_CAPABILITY_PATH,
            headers,
            body_bytes,
        )
        .map_err(federation_verify_error)?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let nonce_reserved = crate::federation::storage::reserve_replay_nonce(
        &state.pg,
        state.snowflake.next_id(),
        &verified.source_peer_id,
        &verified.key_id,
        &verified.nonce,
        verified.timestamp_ms,
        now_ms,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            source_peer_id = %verified.source_peer_id,
            key_id = %verified.key_id,
            error = %error,
            "Federated invite capability replay nonce reservation failed"
        );
        AppError::Internal
    })?;
    if !nonce_reserved {
        return Err(federation_verify_error(VerifyError::Replay));
    }
    Ok(verified)
}

fn federated_invite_capability_pending_response(reason: &'static str) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "pending",
            "reason": reason,
        })),
    )
        .into_response()
}

fn federated_client_token_server_scope(
    mut server_ids: Vec<i64>,
    required_server_id: i64,
) -> AppResult<Vec<i64>> {
    if required_server_id <= 0 {
        return Err(AppError::Internal);
    }

    server_ids.retain(|server_id| *server_id > 0);
    server_ids.sort_unstable();
    server_ids.dedup();

    if server_ids.binary_search(&required_server_id).is_err() || server_ids.len() > 64 {
        return Err(AppError::Internal);
    }

    Ok(server_ids)
}

fn server_to_federated_capability_json(server: &ServerRow) -> Value {
    json!({
        "id": server.id.to_string(),
        "name": server.name,
        "iconUrl": cdn::resolve(server.icon_url.as_deref()),
        "bannerUrl": cdn::resolve(server.banner_url.as_deref()),
    })
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

fn user_to_federated_capability_json(user: &crate::repo::users::UserRow) -> Value {
    json!({
        "id": user.id.to_string(),
        "username": user.username,
        "displayName": user.display_name,
        "email": "",
        "avatarUrl": cdn::resolve(user.avatar_url.as_deref()),
        "bannerUrl": cdn::resolve(user.banner_url.as_deref()),
        "bannerCrop": banner_crop::to_json(user.banner_crop),
        "memberListBannerUrl": Value::Null,
        "memberListBannerCrop": Value::Null,
        "bio": Value::Null,
        "status": user.status_type,
        "usernameSet": true,
        "emailVerified": true,
        "totpEnabled": false,
    })
}

#[cfg(test)]
mod federated_invite_preview_tests {
    use super::*;

    #[test]
    fn federated_invite_preview_is_mode_gated() {
        assert!(federation_invite_preview_enabled(InstanceMode::Official));
        assert!(federation_invite_preview_enabled(InstanceMode::Federated));
        assert!(!federation_invite_preview_enabled(InstanceMode::Linked));
        assert!(!federation_invite_preview_enabled(InstanceMode::Standalone));
    }

    #[test]
    fn federated_invite_preview_rejects_non_code_inputs() {
        assert!(is_valid_invite_code("AbC123"));
        assert!(!is_valid_invite_code(""));
        assert!(!is_valid_invite_code("abc/123"));
        assert!(!is_valid_invite_code("abc-123"));
        assert!(!is_valid_invite_code(&"a".repeat(65)));
    }

    #[test]
    fn federated_invite_preview_rate_limit_key_is_client_scoped() {
        let key = federated_invite_preview_rate_limit_key("203.0.113.10");

        assert_eq!(key, "ip:203.0.113.10");
        assert!(!key.contains("invite"));
        assert!(!key.contains("AbC12345"));
    }

    #[test]
    fn federated_client_scope_uses_all_current_memberships_after_invite_join() {
        let scope = federated_client_token_server_scope(vec![10, 20, 10, 30], 20)
            .expect("joined invite target should produce a token scope");

        assert_eq!(scope, vec![10, 20, 30]);
    }

    #[test]
    fn federated_client_scope_rejects_missing_invite_membership() {
        let error = federated_client_token_server_scope(vec![10, 30], 20)
            .expect_err("token must not be issued before the invite target membership exists");

        assert!(matches!(error, AppError::Internal));
    }

    #[test]
    fn federated_client_access_token_ttl_is_short_lived() {
        let ttl = chrono::Duration::minutes(FEDERATED_CLIENT_ACCESS_TOKEN_MINUTES);

        assert!(
            ttl <= chrono::Duration::hours(1),
            "federated client target bearers must stay short-lived; durable membership refresh preserves joined-server persistence"
        );
        assert!(
            ttl >= chrono::Duration::minutes(15),
            "federated client target bearers should allow normal workspace hydration before home-backed refresh"
        );
    }

    #[test]
    fn federated_capability_user_json_omits_local_auth_fields() {
        let now = chrono::Utc::now();
        let row = crate::repo::users::UserRow {
            id: 42,
            username: "fed_projection".into(),
            email: "private@example.com".into(),
            password_hash: "!disabled!".into(),
            avatar_url: Some("avatars/42.webp".into()),
            status: "online".into(),
            status_type: "online".into(),
            subscribed: false,
            display_name: Some("Remote User".into()),
            bio: Some("private bio".into()),
            custom_status_text: None,
            custom_status_emoji: None,
            created_at: now,
            updated_at: now,
            totp_secret: Some("secret".into()),
            totp_enabled_at: Some(now),
            banner_url: None,
            banner_base_color: None,
            banner_crop: None,
            member_list_banner_url: None,
            member_list_banner_crop: None,
            server_order: serde_json::Value::Null,
            favorite_order: serde_json::Value::Null,
            email_verified: false,
            deleted_at: None,
            username_set: false,
            preferences: serde_json::Value::Null,
            subscription_tier: None,
            subscription_expires_at: None,
            subscription_ring_style: None,
            status_auto: false,
            preferred_status: "online".into(),
        };

        let value = user_to_federated_capability_json(&row);

        assert_eq!(value["id"], "42");
        assert_eq!(value["username"], "fed_projection");
        assert_eq!(value["displayName"], "Remote User");
        assert_eq!(value["email"], "");
        assert_eq!(value["emailVerified"], true);
        assert_eq!(value["totpEnabled"], false);
        assert_eq!(value["usernameSet"], true);
        assert_eq!(value["bio"], serde_json::Value::Null);
    }
}

pub async fn accept_invite(
    State(state): State<AppState>,
    user_id: UserId,
    Path(code): Path<String>,
) -> AppResult<Response> {
    let code_preview = invite_code_preview(&code);
    tracing::info!(
        "POST /api/invites/{}/accept user_id={}",
        code_preview,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::INVITE_LIMIT, &user_id.0.to_string()).await?;

    let invite = crate::services::pg::server_invites::by_code(&state.pg, &code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "accept_invite: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;

    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();
    if let Some(exp) = invite.expires_at_ms {
        if exp < now_ms {
            return Err(AppError::NotFound("invite"));
        }
    }
    if invite.max_uses != 0 && invite.uses >= invite.max_uses {
        return Err(AppError::NotFound("invite"));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, invite.server_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "accept_invite: PG server read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("invite"))?;
    if server.deleted_at.is_some() {
        return Err(AppError::NotFound("invite"));
    }

    // Ban check via Redis set `banned:{server_id}` — defense-in-depth;
    // moderation.rs writes to the same key on ban.
    use fred::interfaces::SetsInterface;
    let ban_key = format!("banned:{}", invite.server_id);
    let banned: bool = state
        .redis
        .sismember(&ban_key, user_id.0.to_string())
        .await
        .map_err(|e| {
            tracing::error!(
                server_id = invite.server_id,
                user_id = user_id.0,
                error = %e,
                "accept_invite: Redis ban lookup failed"
            );
            AppError::Internal
        })?;
    if banned {
        tracing::warn!(
            "Banned user {} tried to accept invite code={}",
            user_id.0,
            code_preview
        );
        return Err(AppError::NotFound("invite"));
    }

    // Already a member? Short-circuit and return the server payload.
    let already_member =
        crate::services::pg::servers::is_member(&state.pg, invite.server_id, user_id.0)
            .await
            .unwrap_or(false);
    if already_member {
        return Ok(Json(server_to_legacy_json(&server)).into_response());
    }

    // Soft cap on members. Best-effort — race window between count
    // and insert is OK at solo-prod traffic; full atomic enforcement
    // would require a CHECK-INSERT-or-fail pattern in pg::servers.
    let member_count = crate::services::pg::servers::member_count(&state.pg, invite.server_id)
        .await
        .unwrap_or(0);
    if member_count >= MAX_MEMBERS_PER_SERVER {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "SERVER_FULL",
            message: format!("Server has reached the {MAX_MEMBERS_PER_SERVER}-member cap"),
        });
    }

    // Atomic uses++ with cap+expiry guard. If the row drifted between
    // the read above and now (concurrent claims), this is the actual
    // gate that prevents over-consumption.
    let consumed = crate::services::pg::server_invites::try_consume(&state.pg, &code, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(code = %code_preview, error = %e, "accept_invite: PG try_consume failed");
            AppError::Internal
        })?;
    if !consumed {
        return Err(AppError::NotFound("invite"));
    }

    crate::services::pg::servers::add_member(&state.pg, invite.server_id, user_id.0, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, server_id = invite.server_id, error = %e, "accept_invite: PG add_member failed");
            AppError::Internal
        })?;

    // Update permission cache
    state
        .permissions
        .add_user_server(user_id.0, invite.server_id);

    // Broadcast MEMBER_JOIN to all server members
    let (username, avatar_url, display_name) = state
        .user_profiles
        .get_or_fetch_vdb(&state, user_id.0)
        .await;
    let uid_str = user_id.0.to_string();
    let server_id_str = invite.server_id.to_string();

    let presence_topic = topics::presence_topic(invite.server_id);
    let join_json = events::member_join_json(
        &server_id_str,
        &uid_str,
        &username,
        display_name.as_deref(),
        avatar_url.as_deref(),
        &now.to_rfc3339(),
    );
    let join_proto = events::member_join_proto(
        server_id_str.clone(),
        uid_str.clone(),
        username.clone(),
        display_name.clone(),
        avatar_url.clone(),
        now.to_rfc3339(),
    );
    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_JOIN,
            server_id: Some(invite.server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(user_id.0),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str.clone(),
                "userId": uid_str.clone(),
                "username": username,
                "displayName": display_name,
                "avatarUrl": avatar_url,
                "joinedAt": now.to_rfc3339(),
            }),
        },
    );
    topics::publish(&state, &presence_topic, &join_json, &join_proto).await;

    // Insert system join message in welcome channel (if configured).
    if let Some(welcome_ch_id) = server.welcome_channel_id {
        if !configured_server_text_channel_exists(
            &state,
            invite.server_id,
            welcome_ch_id,
            "welcome_channel_id",
        )
        .await
        {
            tracing::warn!(
                server_id = invite.server_id,
                channel_id = welcome_ch_id,
                "Skipped welcome message for invalid configured channel"
            );
        } else {
            let msg_id = state.snowflake.next_id();
            let welcome_msg = server
                .welcome_message
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "{user} joined the server!".to_string());
            let content = welcome_msg
                .replace("{user}", &username)
                .replace("{server}", &server.name)
                .replace("{count}", &(member_count + 1).to_string());

            let row = crate::services::pg::messages::MessageRow {
                id: msg_id,
                channel_id: welcome_ch_id,
                author_id: user_id.0,
                r#type: 1,
                flags: 0,
                content: content.clone(),
                reply_to: None,
                edited_at_ms: None,
                created_at_ms: now_ms,
            };
            if let Err(e) = crate::services::pg::messages::insert(&state.pg, &row).await {
                tracing::warn!(error = %e, "accept_invite: PG join message insert failed");
            } else {
                let ch_topic = topics::channel_live_topic(welcome_ch_id);
                let join_msg = json!({
                    "id": msg_id.to_string(),
                    "channelId": welcome_ch_id.to_string(),
                    "authorId": uid_str.clone(),
                    "author": {
                        "id": uid_str.clone(),
                        "username": username.clone(),
                        "displayName": display_name.clone(),
                        "avatarUrl": avatar_url.clone(),
                    },
                    "content": content,
                    "type": 1,
                    "edited": false,
                    "editedAt": null,
                    "createdAt": now.to_rfc3339(),
                    "updatedAt": now.to_rfc3339(),
                    "reactions": [],
                    "attachments": [],
                });
                let json_text = events::message_create_json(&join_msg);
                let proto_msg = events::message_create_proto(crate::proto::Message {
                    id: msg_id.to_string(),
                    channel_id: welcome_ch_id.to_string(),
                    author_id: uid_str.clone(),
                    author: Some(crate::proto::MessageAuthor {
                        id: uid_str.clone(),
                        username: username.clone(),
                        avatar_url: avatar_url.clone(),
                        display_name: display_name.clone(),
                    }),
                    content: content.clone(),
                    r#type: 1,
                    edited: false,
                    created_at: now.to_rfc3339(),
                    updated_at: now.to_rfc3339(),
                    nonce: None,
                    attachments: vec![],
                    reactions: vec![],
                    reply_to: None,
                    edited_at: None,
                });
                topics::publish(&state, &ch_topic, &json_text, &proto_msg).await;
                let welcome_ch_id_str = welcome_ch_id.to_string();
                let server_id_str = invite.server_id.to_string();
                let msg_id_str = msg_id.to_string();
                let unread_json = events::channel_unread_signal_json(
                    &welcome_ch_id_str,
                    Some(&server_id_str),
                    &msg_id_str,
                    &uid_str,
                    &now.to_rfc3339(),
                    false,
                    false,
                );
                let unread_proto = events::channel_unread_signal_proto(
                    welcome_ch_id_str,
                    Some(server_id_str),
                    msg_id_str,
                    uid_str.clone(),
                    now.to_rfc3339(),
                    false,
                    false,
                );
                topics::publish(
                    &state,
                    &topics::channel_notify_topic(welcome_ch_id),
                    &unread_json,
                    &unread_proto,
                )
                .await;
            }
        }
    }

    tracing::info!(
        "Invite accepted code={} server={} by={}",
        code_preview,
        invite.server_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(server_to_legacy_json(&server))).into_response())
}

/// Render a ServerRow into the legacy ServerResponse JSON shape.
/// Minimal — only the fields the client reads from this response.
fn server_to_legacy_json(s: &ServerRow) -> Value {
    json!({
        "id": s.id.to_string(),
        "name": s.name,
        "ownerId": s.owner_id.to_string(),
        "iconUrl": cdn::resolve(s.icon_url.as_deref()),
        "welcomeChannelId": s.welcome_channel_id.map(|id| Value::String(id.to_string())).unwrap_or(Value::Null),
        "announceChannelId": s.announce_channel_id.map(|id| Value::String(id.to_string())).unwrap_or(Value::Null),
        "welcomeMessage": s.welcome_message.as_ref().filter(|m| !m.is_empty()).map(|m| Value::String(m.clone())).unwrap_or(Value::Null),
        "voiceBitrate": s.voice_bitrate,
        "emojiVersion": s.emoji_version,
    })
}
