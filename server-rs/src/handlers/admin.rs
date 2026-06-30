use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::net::SocketAddr;

use super::extract_client_ip;
use crate::error::{AppError, AppResult};
use crate::middleware::rate_limit;
use crate::state::AppState;
use crate::ws::{events, topics};

type HmacSha256 = Hmac<Sha256>;

/// Maximum clock skew allowed for HMAC-signed requests (5 minutes).
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
const MAX_SCOPED_TIMESTAMP_SKEW_SECS: i64 = 60;
const MIN_ADMIN_NONCE_CHARS: usize = 16;
const MAX_ADMIN_NONCE_CHARS: usize = 128;

/// Verify HMAC-SHA256 signature on an admin request.
///
/// Expected headers:
///   X-Signature: <hex-encoded HMAC-SHA256(timestamp + "." + body)>
///   X-Timestamp: <unix seconds>
///
/// The signature covers `"<timestamp>.<raw_body>"` so replay attacks with
/// different bodies or stale timestamps are rejected.
pub(crate) fn verify_admin_signature(
    headers: &HeaderMap,
    body_bytes: &[u8],
    secret: &str,
) -> Result<(), AppError> {
    verify_admin_signature_inner(headers, body_bytes, secret, None, MAX_TIMESTAMP_SKEW_SECS)
}

/// Verify an admin request whose signature is bound to a one-time nonce,
/// method, path, timestamp, and raw body.
pub(crate) fn verify_admin_signature_scoped(
    headers: &HeaderMap,
    body_bytes: &[u8],
    secret: &str,
    method: &str,
    path: &str,
) -> Result<(), AppError> {
    verify_admin_signature_inner(
        headers,
        body_bytes,
        secret,
        Some((method, path)),
        MAX_SCOPED_TIMESTAMP_SKEW_SECS,
    )
}

pub(crate) fn admin_signature_nonce(headers: &HeaderMap) -> Result<&str, AppError> {
    let nonce = headers
        .get("x-nonce")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let valid = (MIN_ADMIN_NONCE_CHARS..=MAX_ADMIN_NONCE_CHARS).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "ADMIN_INVALID_NONCE",
            message: "Missing or invalid X-Nonce header".into(),
        });
    }
    Ok(nonce)
}

fn verify_admin_signature_inner(
    headers: &HeaderMap,
    body_bytes: &[u8],
    secret: &str,
    scope: Option<(&str, &str)>,
    max_skew_secs: i64,
) -> Result<(), AppError> {
    let sig_hex = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let timestamp_str = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Validate timestamp
    let timestamp: i64 = timestamp_str.parse().map_err(|_| AppError::WithCode {
        status: StatusCode::UNAUTHORIZED,
        code: "ADMIN_INVALID_TIMESTAMP",
        message: "Missing or invalid X-Timestamp header".into(),
    })?;

    let now = chrono::Utc::now().timestamp();
    let skew = (now - timestamp).abs();
    if skew > max_skew_secs {
        tracing::warn!(
            "Admin request rejected: timestamp skew {}s (max {}s)",
            skew,
            max_skew_secs
        );
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "ADMIN_TIMESTAMP_EXPIRED",
            message: "Request timestamp too old or too far in the future".into(),
        });
    }

    // Decode provided signature
    let provided = hex::decode(sig_hex).map_err(|_| AppError::WithCode {
        status: StatusCode::UNAUTHORIZED,
        code: "ADMIN_INVALID_SIGNATURE",
        message: "Invalid signature format".into(),
    })?;

    // Compute expected HMAC: sign "<timestamp>.<body>"
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp_str.as_bytes());
    mac.update(b".");
    if let Some((method, path)) = scope {
        let nonce = admin_signature_nonce(headers)?;
        mac.update(nonce.as_bytes());
        mac.update(b".");
        mac.update(method.as_bytes());
        mac.update(b".");
        mac.update(path.as_bytes());
        mac.update(b".");
    }
    mac.update(body_bytes);

    // Constant-time verification (built into hmac crate)
    mac.verify_slice(&provided).map_err(|_| {
        tracing::warn!("Admin request rejected: HMAC signature mismatch");
        AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "UNAUTHORIZED",
            message: "Unauthorized".into(),
        }
    })
}

#[derive(Deserialize)]
pub struct NotifyUpdateRequest {
    pub version: String,
    pub notes: Option<String>,
}

// ─── POST /api/admin/notify-update ──────────────────────────────────
// Broadcast UPDATE_AVAILABLE to all WS clients.
// Protected by HMAC-SHA256 request signing (not user auth).

pub async fn notify_update(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> AppResult<Json<Value>> {
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::ADMIN_LIMIT, &ip).await?;

    let secret = state.config.update_notify_secret.as_deref();

    match secret {
        None | Some("") => {
            return Err(AppError::WithCode {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "UPDATE_NOT_CONFIGURED",
                message: "Update notifications not configured".into(),
            });
        }
        Some(key) => {
            verify_admin_signature(&headers, &body_bytes, key)?;
        }
    }

    // Parse body
    let body: NotifyUpdateRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError::Validation(format!("Invalid request body: {e}")))?;

    tracing::info!("POST /api/admin/notify-update version={}", body.version);

    // Strict semver-like validation: only digits, dots, hyphens, plus signs
    if body.version.is_empty()
        || body.version.len() > 32
        || !body
            .version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
    {
        return Err(AppError::Validation("Invalid version".into()));
    }

    // Broadcast UPDATE_AVAILABLE via system topic
    let notes = body.notes.as_deref().unwrap_or("");
    let topic = topics::system_topic();
    let json_text = events::update_available_json(&body.version, notes);
    let proto_msg = events::update_available_proto(body.version.clone(), notes.to_string());
    topics::publish(&state, &topic, &json_text, &proto_msg).await;

    tracing::info!("Broadcast UPDATE_AVAILABLE v{}", body.version);
    Ok(Json(json!({ "ok": true, "version": body.version })))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::{admin_signature_nonce, verify_admin_signature, verify_admin_signature_scoped};

    type HmacSha256 = Hmac<Sha256>;

    fn headers_for(secret: &str, timestamp: i64, payload_parts: &[&[u8]]) -> HeaderMap {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        for (index, part) in payload_parts.iter().enumerate() {
            if index > 0 {
                mac.update(b".");
            }
            mac.update(part);
        }
        let signature = hex::encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-timestamp", timestamp.to_string().parse().unwrap());
        headers.insert("x-signature", signature.parse().unwrap());
        headers
    }

    fn headers_for_scoped(
        secret: &str,
        timestamp: i64,
        nonce: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> HeaderMap {
        let timestamp_string = timestamp.to_string();
        let mut headers = headers_for(
            secret,
            timestamp,
            &[
                timestamp_string.as_bytes(),
                nonce.as_bytes(),
                method.as_bytes(),
                path.as_bytes(),
                body,
            ],
        );
        headers.insert("x-nonce", nonce.parse().unwrap());
        headers
    }

    #[test]
    fn legacy_admin_signature_uses_timestamp_and_body_only() {
        let secret = "random-admin-secret-32-characters";
        let timestamp = chrono::Utc::now().timestamp();
        let body = br#"{"version":"1.2.3"}"#;
        let timestamp_string = timestamp.to_string();
        let headers = headers_for(secret, timestamp, &[timestamp_string.as_bytes(), body]);

        verify_admin_signature(&headers, body, secret).unwrap();
    }

    #[test]
    fn scoped_admin_signature_binds_method_and_path() {
        let secret = "random-admin-secret-32-characters";
        let timestamp = chrono::Utc::now().timestamp();
        let body = br#"{"status":"verified","publicDiscovery":true}"#;
        let nonce = "01HV6N6MJ2KTZ02C6RG8BN0KTE";
        let method = "PATCH";
        let path = "/api/admin/federation/instances/42";
        let headers = headers_for_scoped(secret, timestamp, nonce, method, path, body);

        verify_admin_signature_scoped(&headers, body, secret, method, path).unwrap();
        assert!(
            verify_admin_signature_scoped(
                &headers,
                body,
                secret,
                method,
                "/api/admin/federation/instances/43",
            )
            .is_err()
        );
        assert!(verify_admin_signature(&headers, body, secret).is_err());
    }

    #[test]
    fn scoped_admin_signature_requires_nonce() {
        let secret = "random-admin-secret-32-characters";
        let timestamp = chrono::Utc::now().timestamp();
        let body = br#"{"status":"verified"}"#;
        let method = "PATCH";
        let path = "/api/admin/federation/instances/42";
        let timestamp_string = timestamp.to_string();
        let headers = headers_for(
            secret,
            timestamp,
            &[
                timestamp_string.as_bytes(),
                method.as_bytes(),
                path.as_bytes(),
                body,
            ],
        );

        assert!(admin_signature_nonce(&headers).is_err());
        assert!(verify_admin_signature_scoped(&headers, body, secret, method, path).is_err());
    }

    #[test]
    fn scoped_admin_signature_binds_nonce() {
        let secret = "random-admin-secret-32-characters";
        let timestamp = chrono::Utc::now().timestamp();
        let body = br#"{"status":"verified"}"#;
        let method = "PATCH";
        let path = "/api/admin/federation/instances/42";
        let mut headers = headers_for_scoped(
            secret,
            timestamp,
            "01HV6N6MJ2KTZ02C6RG8BN0KTE",
            method,
            path,
            body,
        );

        verify_admin_signature_scoped(&headers, body, secret, method, path).unwrap();
        headers.insert("x-nonce", "01HV6N6MJ2KTZ02C6RG8BN0KTF".parse().unwrap());
        assert!(verify_admin_signature_scoped(&headers, body, secret, method, path).is_err());
    }

    #[test]
    fn scoped_admin_signature_uses_shorter_timestamp_window() {
        let secret = "random-admin-secret-32-characters";
        let timestamp = chrono::Utc::now().timestamp() - 61;
        let body = br#"{"status":"verified"}"#;
        let method = "PATCH";
        let path = "/api/admin/federation/instances/42";
        let headers = headers_for_scoped(
            secret,
            timestamp,
            "01HV6N6MJ2KTZ02C6RG8BN0KTE",
            method,
            path,
            body,
        );

        assert!(verify_admin_signature_scoped(&headers, body, secret, method, path).is_err());
    }
}
