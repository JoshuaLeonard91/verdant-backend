use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::Method;
use serde_json::{Value, json};
use std::time::Duration;

use crate::{
    error::{AppError, AppResult},
    federation::{
        auth::FederationRequestSigner,
        client::FederationHttpClient,
        client_membership::{
            FEDERATED_MEMBERSHIP_CAPABILITY_PATH, FederatedClientMembershipRecord,
            FederatedMembershipServerSnapshot, UpsertFederatedClientMembership,
            build_federated_membership_capability_body, client_membership_for_user,
            list_client_memberships_for_user, mark_client_membership_capability_status,
            sanitize_capability_response_for_client, server_scope_from_capability_response,
            upsert_client_membership,
        },
        invite_join::normalize_federated_invite_target_origin,
        storage::peer_endpoint_by_peer_id,
    },
    handlers::parse_id,
    middleware::{auth::UserId, rate_limit},
    state::AppState,
};

const FEDERATED_MEMBERSHIP_CAPABILITY_RESPONSE_LIMIT_BYTES: usize = 128 * 1024;
const FEDERATED_MEMBERSHIP_CAPABILITY_HTTP_TIMEOUT_SECS: u64 = 10;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_federated_memberships))
        .route(
            "/{membershipId}/capability",
            post(refresh_federated_membership_capability),
        )
}

pub async fn list_federated_memberships(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(
        &state,
        &rate_limit::FEDERATION_EVENT_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;

    let stored_memberships = list_client_memberships_for_user(&state.pg, user_id.0)
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                user_id = user_id.0,
                "Failed to list federated client memberships"
            );
            AppError::Internal
        })?;
    let membership_count = stored_memberships.len();
    let active_count = stored_memberships
        .iter()
        .filter(|membership| membership.status == "active")
        .count();
    let pending_count = stored_memberships
        .iter()
        .filter(|membership| membership.status == "pending")
        .count();
    let inactive_count = membership_count
        .saturating_sub(active_count)
        .saturating_sub(pending_count);
    tracing::info!(
        user_id = user_id.0,
        membership_count,
        active_count,
        pending_count,
        inactive_count,
        "Federated client memberships listed"
    );

    let memberships = stored_memberships
        .into_iter()
        .map(|membership| membership.to_client_json())
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "memberships": memberships,
    })))
}

pub async fn refresh_federated_membership_capability(
    State(state): State<AppState>,
    user_id: UserId,
    Path(membership_id): Path<String>,
) -> AppResult<Response> {
    rate_limit::enforce(
        &state,
        &rate_limit::FEDERATION_EVENT_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;

    let membership_id = parse_id(&membership_id)?;
    let membership = client_membership_for_user(&state.pg, membership_id, user_id.0)
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                membership_id,
                user_id = user_id.0,
                "Failed to load federated client membership"
            );
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("federated membership"))?;

    if !matches!(membership.status.as_str(), "active" | "pending") {
        tracing::info!(
            membership_id,
            user_id = user_id.0,
            target_peer_id = %membership.target_peer_id,
            target_api_origin = %membership.target_api_origin,
            target_server_id = membership.target_server_id,
            status = %membership.status,
            "Federated membership capability refresh skipped for inactive membership"
        );
        return Err(federated_membership_error(
            StatusCode::CONFLICT,
            "FEDERATED_MEMBERSHIP_INACTIVE",
            "Federated membership is not active",
        ));
    }

    let peer_endpoint = peer_endpoint_by_peer_id(&state.pg, &membership.target_peer_id)
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                membership_id,
                target_peer_id = %membership.target_peer_id,
                "Failed to load federated membership peer endpoint"
            );
            AppError::Internal
        })?
        .ok_or_else(|| {
            federated_membership_error(
                StatusCode::FORBIDDEN,
                "FEDERATION_PEER_UNTRUSTED",
                "Federated membership target is not trusted by this backend",
            )
        })?;

    tracing::info!(
        membership_id,
        user_id = user_id.0,
        target_peer_id = %membership.target_peer_id,
        target_api_origin = %membership.target_api_origin,
        target_server_id = membership.target_server_id,
        "Federated membership capability refresh started"
    );

    let trusted_origin =
        normalize_federated_invite_target_origin(&peer_endpoint.peer_id, &peer_endpoint.api_origin)
            .map_err(|_| {
                tracing::warn!(
                    membership_id,
                    target_peer_id = %membership.target_peer_id,
                    "Federated membership peer endpoint failed validation"
                );
                federated_membership_error(
                    StatusCode::FORBIDDEN,
                    "FEDERATION_PEER_INVALID_ENDPOINT",
                    "Federated membership target is not trusted by this backend",
                )
            })?;
    if trusted_origin != membership.target_api_origin {
        tracing::warn!(
            membership_id,
            target_peer_id = %membership.target_peer_id,
            target_api_origin = %membership.target_api_origin,
            target_server_id = membership.target_server_id,
            "Federated membership target origin mismatch"
        );
        return Err(federated_membership_error(
            StatusCode::FORBIDDEN,
            "FEDERATION_PEER_ORIGIN_MISMATCH",
            "Federated membership target no longer matches a trusted peer",
        ));
    }

    let key_id = state
        .config
        .federation_s2s_key_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            federated_membership_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "FEDERATION_S2S_SIGNING_NOT_CONFIGURED",
                "Federated membership refresh signing is not configured",
            )
        })?;
    let signing_seed = state.config.federation_s2s_signing_seed.ok_or_else(|| {
        federated_membership_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "FEDERATION_S2S_SIGNING_NOT_CONFIGURED",
            "Federated membership refresh signing is not configured",
        )
    })?;

    let payload = build_federated_membership_capability_body(
        &membership.remote_user_id,
        membership.target_server_id,
        &membership.invite_code_hash,
    )?;
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| AppError::Internal)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let signer =
        FederationRequestSigner::from_seed(&state.config.instance_id, key_id, signing_seed)
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    membership_id,
                    target_peer_id = %membership.target_peer_id,
                    "Failed to build federated membership S2S signer"
                );
                AppError::Internal
            })?;
    let s2s_client = FederationHttpClient::with_timeout(
        Duration::from_secs(FEDERATED_MEMBERSHIP_CAPABILITY_HTTP_TIMEOUT_SECS),
        signer,
    )
    .map_err(|error| {
        tracing::error!(
            error = %error,
            membership_id,
            "Failed to build federated membership HTTP client"
        );
        AppError::Internal
    })?;
    let nonce = format!("fedmem-{}", uuid::Uuid::new_v4().simple());
    let upstream = s2s_client
        .send_signed_json_request(
            Method::POST,
            &peer_endpoint,
            FEDERATED_MEMBERSHIP_CAPABILITY_PATH,
            payload_bytes,
            now_ms,
            &nonce,
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                membership_id,
                target_peer_id = %membership.target_peer_id,
                target_api_origin = %membership.target_api_origin,
                target_server_id = membership.target_server_id,
                "Federated membership capability refresh delivery failed"
            );
            AppError::WithCode {
                status: StatusCode::BAD_GATEWAY,
                code: "FEDERATION_CAPABILITY_DELIVERY_FAILED",
                message: "Federated membership refresh could not reach the target backend".into(),
            }
        });

    let upstream = match upstream {
        Ok(response) => response,
        Err(error) => {
            mark_membership_refresh(&state, membership_id, "failed", Some(error_code(&error)))
                .await?;
            return Err(error);
        }
    };

    let upstream_status = upstream.status();
    let response_bytes = read_limited_response(
        upstream,
        FEDERATED_MEMBERSHIP_CAPABILITY_RESPONSE_LIMIT_BYTES,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            error = %error,
            membership_id,
            target_peer_id = %membership.target_peer_id,
            target_api_origin = %membership.target_api_origin,
            target_server_id = membership.target_server_id,
            "Federated membership capability refresh response failed validation"
        );
        error
    });

    let response_bytes = match response_bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            mark_membership_refresh(&state, membership_id, "failed", Some(error_code(&error)))
                .await?;
            return Err(error);
        }
    };

    if !upstream_status.is_success() {
        tracing::warn!(
            membership_id,
            target_peer_id = %membership.target_peer_id,
            target_api_origin = %membership.target_api_origin,
            target_server_id = membership.target_server_id,
            upstream_status = upstream_status.as_u16(),
            "Federated membership capability refresh was rejected by target backend"
        );
        let error = federated_membership_error(
            StatusCode::BAD_GATEWAY,
            "FEDERATION_CAPABILITY_REJECTED",
            "Federated membership refresh was rejected by the target backend",
        );
        mark_membership_refresh(&state, membership_id, "failed", Some(error_code(&error))).await?;
        return Err(error);
    }

    let upstream_value: Value = serde_json::from_slice(&response_bytes).map_err(|_| {
        federated_membership_error(
            StatusCode::BAD_GATEWAY,
            "FEDERATION_CAPABILITY_INVALID_RESPONSE",
            "Federated membership refresh returned an invalid response",
        )
    })?;
    let scoped_servers = server_scope_from_capability_response(&upstream_value).map_err(|_| {
        federated_membership_error(
            StatusCode::BAD_GATEWAY,
            "FEDERATION_CAPABILITY_INVALID_RESPONSE",
            "Federated membership refresh returned an invalid response",
        )
    })?;
    let response = sanitize_capability_response_for_client(
        FEDERATED_MEMBERSHIP_CAPABILITY_PATH,
        upstream_value,
    )
    .map_err(|_| {
        federated_membership_error(
            StatusCode::BAD_GATEWAY,
            "FEDERATION_CAPABILITY_INVALID_RESPONSE",
            "Federated membership refresh returned an invalid response",
        )
    });

    let response = match response {
        Ok(value) => value,
        Err(error) => {
            mark_membership_refresh(&state, membership_id, "failed", Some(error_code(&error)))
                .await?;
            return Err(error);
        }
    };

    let capability_status = match response.get("status").and_then(Value::as_str) {
        Some("ready") => "ready",
        Some("pending") => "pending",
        _ => "failed",
    };
    if capability_status == "ready" && !scoped_servers.is_empty() {
        sync_membership_server_scope(
            &state,
            user_id.0,
            &membership,
            &scoped_servers,
            chrono::Utc::now().timestamp_millis(),
        )
        .await?;
    }
    mark_membership_refresh(&state, membership_id, capability_status, None).await?;

    tracing::info!(
        membership_id,
        target_peer_id = %membership.target_peer_id,
        target_api_origin = %membership.target_api_origin,
        target_server_id = membership.target_server_id,
        capability_status,
        scoped_server_count = scoped_servers.len(),
        "Federated membership capability refresh completed"
    );

    Ok(Json(response).into_response())
}

async fn read_limited_response(response: reqwest::Response, max_bytes: usize) -> AppResult<Bytes> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(federated_membership_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "FEDERATION_CAPABILITY_RESPONSE_TOO_LARGE",
            "Federated membership refresh response was too large",
        ));
    }

    let mut stream = response.bytes_stream();
    let mut received = 0usize;
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            federated_membership_error(
                StatusCode::BAD_GATEWAY,
                "FEDERATION_CAPABILITY_DELIVERY_FAILED",
                "Federated membership refresh response could not be read",
            )
        })?;
        received = received.checked_add(chunk.len()).ok_or_else(|| {
            federated_membership_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "FEDERATION_CAPABILITY_RESPONSE_TOO_LARGE",
                "Federated membership refresh response was too large",
            )
        })?;
        if received > max_bytes {
            return Err(federated_membership_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "FEDERATION_CAPABILITY_RESPONSE_TOO_LARGE",
                "Federated membership refresh response was too large",
            ));
        }
        chunks.push(chunk);
    }

    let mut bytes = Vec::with_capacity(received);
    for chunk in chunks {
        bytes.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(bytes))
}

async fn sync_membership_server_scope(
    state: &AppState,
    home_user_id: i64,
    membership: &FederatedClientMembershipRecord,
    scoped_servers: &[FederatedMembershipServerSnapshot],
    now_ms: i64,
) -> AppResult<()> {
    let mut upserted_count = 0usize;
    for server in scoped_servers {
        let record = upsert_client_membership(
            &state.pg,
            UpsertFederatedClientMembership {
                id: state.snowflake.next_id(),
                home_user_id,
                target_peer_id: &membership.target_peer_id,
                target_api_origin: &membership.target_api_origin,
                target_server_id: server.target_server_id,
                remote_user_id: &membership.remote_user_id,
                invite_code_hash: &membership.invite_code_hash,
                server_name: server.server_name.as_deref(),
                server_icon_url: server.server_icon_url.as_deref(),
                server_banner_url: server.server_banner_url.as_deref(),
                now_ms,
            },
        )
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                membership_id = membership.id,
                home_user_id,
                target_peer_id = %membership.target_peer_id,
                target_api_origin = %membership.target_api_origin,
                target_server_id = server.target_server_id,
                "Failed to upsert federated membership server scope row"
            );
            AppError::Internal
        })?;
        tracing::debug!(
            membership_id = membership.id,
            scoped_membership_id = record.id,
            home_user_id,
            target_peer_id = %membership.target_peer_id,
            target_api_origin = %membership.target_api_origin,
            target_server_id = server.target_server_id,
            has_server_name = server.server_name.is_some(),
            has_server_icon = server.server_icon_url.is_some(),
            has_server_banner = server.server_banner_url.is_some(),
            "Federated membership server scope row synced"
        );
        upserted_count += 1;
    }
    tracing::info!(
        membership_id = membership.id,
        home_user_id,
        target_peer_id = %membership.target_peer_id,
        target_api_origin = %membership.target_api_origin,
        scoped_server_count = scoped_servers.len(),
        upserted_count,
        "Federated membership server scope synced"
    );
    Ok(())
}

async fn mark_membership_refresh(
    state: &AppState,
    membership_id: i64,
    status: &'static str,
    code: Option<&str>,
) -> AppResult<()> {
    mark_client_membership_capability_status(
        &state.pg,
        membership_id,
        status,
        code,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(|error| {
        tracing::error!(
            error = %error,
            membership_id,
            status,
            "Failed to update federated membership refresh status"
        );
        AppError::Internal
    })
}

fn federated_membership_error(
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

fn error_code(error: &AppError) -> &'static str {
    match error {
        AppError::WithCode { code, .. } => code,
        AppError::RateLimited => "RATE_LIMITED",
        AppError::Validation(_) => "VALIDATION_FAILED",
        AppError::NotFound(_) => "NOT_FOUND",
        AppError::Forbidden => "PERMISSION_MISSING",
        _ => "INTERNAL_ERROR",
    }
}
