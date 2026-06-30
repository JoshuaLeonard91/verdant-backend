use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;

use super::extract_client_ip;
use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::crypto::{generate_session_token, hash_token};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Consume an email verification token and mark the user as verified.
/// Returns the user_id on success, or None if the token is invalid.
async fn consume_email_verification_token(state: &AppState, token: &str) -> Option<i64> {
    use fred::interfaces::KeysInterface;
    let token_hash = hash_token(token);
    let key = format!("emailverify:{token_hash}");
    let uid_str: Option<String> = state.redis.get(&key).await.ok().flatten();
    let user_id = uid_str.and_then(|s| s.parse::<i64>().ok())?;

    // Single-use: atomic DEL returns 1 if we won the race.
    let deleted: i64 = state.redis.del(&key).await.unwrap_or(0);
    if deleted == 0 {
        return None;
    }

    // Flip email_verified on the user row.
    if let Err(e) = crate::services::pg::users::update(
        &state.pg,
        user_id,
        crate::services::pg::users::UpdateUser {
            email_verified: Some(true),
            ..Default::default()
        },
    )
    .await
    {
        tracing::error!(user_id, error = %e, "email_verify: PG update failed");
        return None;
    }

    if let Err(e) = crate::services::registration::auto_join_default_server(state, user_id).await {
        tracing::error!(user_id, error = %e, "email_verify: default server auto-join failed");
    }

    Some(user_id)
}

/// POST /api/auth/verify-email — verify email with token (public, no auth required)
pub async fn verify_email(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VerifyEmailRequest>,
) -> AppResult<Json<Value>> {
    // Rate limit by IP
    let ip = extract_client_ip(&headers, &axum::extract::ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;

    let user_id = consume_email_verification_token(&state, &body.token)
        .await
        .ok_or_else(|| AppError::Validation("Invalid or expired verification link".into()))?;

    tracing::info!("Email verified for user_id={}", user_id);
    Ok(Json(json!({ "verified": true })))
}

/// POST /api/auth/resend-verification — resend email verification (authenticated)
pub async fn resend_verification(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<Value>> {
    // Rate limit per user
    let key = format!("resend-verify:{}", user_id.0);
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &key).await?;

    let user = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "resend_verification: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("user"))?;

    if user.email_verified {
        return Ok(Json(json!({ "message": "Email already verified" })));
    }
    let email = user.email.clone();

    if !state.config.email_delivery_configured() {
        tracing::error!(
            user_id = user_id.0,
            "resend_verification: email delivery is not configured"
        );
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            code: "EMAIL_DELIVERY_UNAVAILABLE",
            message: "Email verification is temporarily unavailable".into(),
        });
    }

    // Generate new token and store the hash in Redis with a 24-hour
    // TTL. The key pattern mirrors the password-reset layout.
    use fred::interfaces::KeysInterface;
    use fred::types::Expiration;
    let token = generate_session_token();
    let token_hash = hash_token(&token);
    let key = format!("emailverify:{token_hash}");
    state
        .redis
        .set::<(), _, _>(
            &key,
            user_id.0.to_string(),
            Some(Expiration::EX(24 * 60 * 60)),
            None,
            false,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                user_id = user_id.0,
                error = %e,
                "resend_verification: token write failed"
            );
            AppError::Internal
        })?;

    // Send email (best-effort)
    if let Some(ref email_service) = state.email {
        let t = token.clone();
        let svc = email_service.clone();
        let addr = email.clone();
        tokio::spawn(async move {
            if let Err(e) = svc.send_email_verification(&addr, &t).await {
                tracing::error!("Failed to send verification email: {e}");
            }
        });
    } else {
        tracing::warn!(
            user_id = user_id.0,
            "resend_verification: email service not configured; verification email not sent"
        );
    }

    Ok(Json(json!({ "sent": true })))
}

// ─── GET /verify-email?token=... — browser-accessible verification link ──────

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    pub token: Option<String>,
}

// CSP hash for the static inline style block below (SHA-256, base64).
// Regenerate with: printf '<style-content>' | openssl dgst -sha256 -binary | openssl base64 -A
const VERIFY_STYLE_HASH: &str = "sha256-ZBP61yAfBryTWM+/nAciXJsMU8BMZs+1Tm180PC8Qh4=";

fn verification_page(title: &str, message: &str, success: bool) -> impl IntoResponse {
    let (icon, color) = if success {
        ("&#10003;", "#22c55e")
    } else {
        ("&#10007;", "#ef4444")
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — Verdant</title>
  <style>
    body {{ margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0a0a0f; color: #e4e4e7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}
    .card {{ text-align: center; max-width: 420px; padding: 48px 32px; }}
    .icon {{ font-size: 48px; margin-bottom: 16px; }}
    h1 {{ font-size: 24px; margin: 0 0 12px; }}
    p {{ color: #a1a1aa; font-size: 15px; line-height: 1.5; margin: 0; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon" style="color:{color}">{icon}</div>
    <h1>{title}</h1>
    <p>{message}</p>
  </div>
</body>
</html>"#,
    );

    let csp = format!(
        "default-src 'none'; style-src '{}'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        VERIFY_STYLE_HASH
    );

    axum::response::Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_SECURITY_POLICY, csp)
        .body(axum::body::Body::from(html))
        .unwrap()
}

/// GET /verify-email?token=... — clicked from email link, verifies and shows result page
pub async fn verify_email_page(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<VerifyEmailQuery>,
) -> impl IntoResponse {
    // Rate limit by IP
    let ip = extract_client_ip(&headers, &axum::extract::ConnectInfo(addr));
    if rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip)
        .await
        .is_err()
    {
        return verification_page(
            "Too Many Requests",
            "Please wait a moment and try again.",
            false,
        )
        .into_response();
    }
    if crate::services::app_bans::ensure_ip_not_banned(&state, &ip)
        .await
        .is_err()
    {
        return verification_page(
            "Access Restricted",
            "This verification link cannot be used from this network right now.",
            false,
        )
        .into_response();
    }

    let Some(token) = query.token else {
        return verification_page(
            "Invalid Link",
            "This verification link is missing the token. Please request a new verification email from your account settings.",
            false,
        ).into_response();
    };

    let Some(user_id) = consume_email_verification_token(&state, &token).await else {
        return verification_page(
            "Invalid or Expired Link",
            "This verification link is no longer valid or has expired. Please request a new verification email from your account settings.",
            false,
        ).into_response();
    };

    tracing::info!("Email verified via link for user_id={}", user_id);

    verification_page(
        "Email Verified",
        "Your email has been verified successfully. You can close this page and return to Verdant.",
        true,
    )
    .into_response()
}
