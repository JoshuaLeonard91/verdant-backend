use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use fred::interfaces::KeysInterface;
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::rate_limit;
use crate::repo::users::{self, UserResponse};
use crate::services::{
    crypto::{self, blacklist_access_token, generate_access_token, hash_token},
    device::parse_device,
    hash_service,
    login_log::{self, LogLoginParams},
    risk::{self, RiskLevel},
    session::{self, GeoResult},
    totp,
};
use crate::state::AppState;

/// Cookie name depends on secure mode:
/// - Production (HTTPS): `__Host-session` — enforces Secure, no Domain, Path=/
/// - Dev (HTTP): `__session` — `__Host-` prefix requires Secure flag
fn cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-session"
    } else {
        "__session"
    }
}

// Account lockout
const MAX_LOGIN_ATTEMPTS: u64 = 5;
const TERMS_VERSION: &str = "2026-05-15";
const PRIVACY_VERSION: &str = "2026-05-15";
const LEGAL_ACCEPTANCE_SOURCE: &str = "client_signup";

/// Build the `UserResponse`-shaped JSON directly from a VdbUser
/// record. Mirrors the field set that `UserResponse::from(&UserRow)`
/// emits — used by every auth handler that returns the current user
/// after a session mutation.
fn member_list_banner_visible_for_user(state: &AppState, u: &crate::repo::users::UserRow) -> bool {
    let official_subscription_active =
        crate::services::entitlements::official_subscription_active_from_db(
            u.subscribed,
            u.subscription_expires_at,
        );
    crate::services::entitlements::member_list_banner_visible(
        &state.config,
        official_subscription_active,
    )
}

fn pg_user_to_user_response_json(
    state: &AppState,
    u: &crate::repo::users::UserRow,
    status: &str,
) -> Value {
    let member_list_banner_visible = member_list_banner_visible_for_user(state, u);
    json!({
        "id": u.id.to_string(),
        "username": u.username,
        "displayName": u.display_name,
        "email": u.email,
        "avatarUrl": crate::services::cdn::resolve(u.avatar_url.as_deref()),
        "bannerUrl": crate::services::cdn::resolve(u.banner_url.as_deref()),
        "bannerCrop": crate::services::banner_crop::to_json(u.banner_crop),
        "memberListBannerUrl": if member_list_banner_visible { crate::services::cdn::resolve(u.member_list_banner_url.as_deref()) } else { None },
        "memberListBannerCrop": if member_list_banner_visible { crate::services::banner_crop::to_json(u.member_list_banner_crop) } else { serde_json::Value::Null },
        "bio": normalize_optional_text(u.bio.as_deref()),
        "customStatusText": normalize_optional_text(u.custom_status_text.as_deref()),
        "customStatusEmoji": normalize_optional_text(u.custom_status_emoji.as_deref()),
        "status": status,
        "subscribed": u.subscribed,
        "usernameSet": u.username_set,
        "emailVerified": u.email_verified,
        "totpEnabled": u.totp_enabled_at.is_some(),
    })
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// Look up GeoIP data for an IP address, falling back to empty result.
fn geo_lookup(state: &AppState, ip: &str) -> GeoResult {
    state
        .geoip
        .as_ref()
        .map_or_else(GeoResult::default, |g| g.lookup(ip))
}
const LOGIN_LOCKOUT_SECS: i64 = 900; // 15 min

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginVerificationDelivery {
    Email,
    None,
}

fn login_verification_delivery(email_available: bool) -> LoginVerificationDelivery {
    if email_available {
        LoginVerificationDelivery::Email
    } else {
        LoginVerificationDelivery::None
    }
}

fn send_login_verification_code(state: &AppState, email: String, code: String) {
    match login_verification_delivery(state.email.is_some()) {
        LoginVerificationDelivery::Email => {
            if let Some(ref email_service) = state.email {
                let svc = email_service.clone();
                tokio::spawn(async move {
                    if let Err(e) = svc.send_login_verification(&email, &code).await {
                        tracing::error!("Failed to send login verification email: {e}");
                    }
                });
            }
        }
        LoginVerificationDelivery::None => {
            tracing::warn!("Email service not configured; login verification email not sent");
        }
    }
}

// ─── Request types ──────────────────────────────────────────────────

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    pub registration_key: Option<String>,
    #[serde(default)]
    pub terms_accepted: bool,
    #[serde(default)]
    pub privacy_accepted: bool,
}

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

#[derive(Deserialize, Validate, Default)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    /// Session token from body (Tauri clients). Web clients send it via cookie instead.
    pub session_token: Option<String>,
}

#[derive(Deserialize, Validate, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    /// Session token from body (Tauri clients). Web clients send it via cookie instead.
    pub session_token: Option<String>,
    pub access_token: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct RevokeSessionRequest {
    #[validate(length(min = 1))]
    pub token: String,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct VerifySessionRequest {
    /// Session token from body (Tauri clients). Web clients send it via cookie instead.
    pub session_token: Option<String>,
    #[validate(length(min = 1))]
    pub code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendSessionCodeRequest {
    pub session_token: Option<String>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Login2faRequest {
    #[validate(length(min = 1))]
    pub two_factor_ticket: String,
    #[validate(length(min = 1))]
    pub code: String,
}

// ─── Helpers ────────────────────────────────────────────────────────

use super::extract_client_ip;

fn extract_ua(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn truncate_for_audit(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.map(|s| s.chars().take(max_chars).collect())
}

/// Build a Set-Cookie header value for the session cookie.
/// Uses `__Host-` prefix in production (Secure) for subdomain injection protection.
/// `SameSite=Strict` is safe because cookies are only consumed by same-origin fetch().
/// `Path=/` is required by the `__Host-` prefix spec.
fn session_cookie(token: &str, secure: bool) -> String {
    let name = cookie_name(secure);
    if secure {
        format!("{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800; Secure")
    } else {
        format!("{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800")
    }
}

/// Build a Set-Cookie header that clears the session cookie.
fn clear_session_cookie(secure: bool) -> String {
    let name = cookie_name(secure);
    if secure {
        format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Secure")
    } else {
        format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
    }
}

/// Returns true when the request is browser-shaped and must keep session tokens
/// behind the HttpOnly cookie boundary. `X-Client-Version` is settable by
/// browser JavaScript, so browser Fetch Metadata or Origin headers always win.
/// Native clients that need body session tokens must send `X-Client-Version`
/// without browser-only headers.
fn is_browser_request(headers: &HeaderMap) -> bool {
    if headers.get(header::ORIGIN).is_some()
        || headers.get("sec-fetch-dest").is_some()
        || headers.get("sec-fetch-mode").is_some()
        || headers.get("sec-fetch-site").is_some()
        || headers.get("sec-fetch-user").is_some()
    {
        return true;
    }
    headers.get("x-client-version").is_none()
}

/// Extract session token from Cookie header.
/// Checks both `__Host-session` (production) and `__session` (dev) names.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|pair| {
                let pair = pair.trim();
                // Try __Host-session first (production), then __session (dev)
                pair.strip_prefix("__Host-session=")
                    .or_else(|| pair.strip_prefix("__session="))
                    .map(|v| v.to_string())
            })
        })
}

// ─── POST /api/auth/register ────────────────────────────────────────

fn session_token_from_body_or_cookie(
    headers: &HeaderMap,
    body_session_token: Option<String>,
) -> Option<(String, bool)> {
    if let Some(session_token) = body_session_token.filter(|s| !s.is_empty()) {
        return Some((session_token, true));
    }
    extract_session_cookie(headers).map(|session_token| (session_token, false))
}

fn refresh_response_payload(
    access_token: String,
    session_token: &str,
    include_session_token: bool,
) -> Value {
    let mut response = json!({ "accessToken": access_token });
    if include_session_token {
        response["sessionToken"] = json!(session_token);
    }
    response
}

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!("POST /api/auth/register");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::REGISTER_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;

    if !body.terms_accepted || !body.privacy_accepted {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "LEGAL_ACCEPTANCE_REQUIRED",
            message: "You must accept the Terms of Service and Privacy Policy".into(),
        });
    }

    let ua = extract_ua(&headers);
    let audit_ua = truncate_for_audit(ua.as_deref(), 512);
    let email_lower = crate::services::email_validation::normalize_routable_email(&body.email)?;
    let registration_key = body
        .registration_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if registration_key.is_none() && !state.config.public_registration_enabled {
        tracing::warn!(
            "Register failed: missing registration key while public registration is disabled"
        );
        return Err(AppError::RegistrationFailed(
            "Invalid registration key".into(),
        ));
    }

    let email_verification_required = state.config.email_verification_required();
    if email_verification_required && !state.config.email_delivery_configured() {
        tracing::error!(
            "Register blocked: email verification is required but no email delivery is configured"
        );
        return Err(AppError::WithCode {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "EMAIL_DELIVERY_UNAVAILABLE",
            message: "Email verification is temporarily unavailable".into(),
        });
    }

    // Check for existing email (generic error, no enumeration).
    if crate::services::pg::users::by_email_lower(&state.pg, &email_lower)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "register: PG email check failed");
            AppError::Internal
        })?
        .is_some()
    {
        tracing::warn!("Register failed: email already taken");
        return Err(AppError::RegistrationFailed("Registration failed".into()));
    }

    // Hash password locally with Argon2 through hash_service's blocking thread pool.
    let password_hash = hash_service::hash_password(&state, body.password.clone()).await?;

    let user_id = state.snowflake.next_id();
    let temp_username = format!("user_{user_id}");

    let now_millis = chrono::Utc::now().timestamp_millis();
    let mut tx = state.pg.begin().await.map_err(|e| {
        tracing::error!(error = %e, "register: PG transaction begin failed");
        AppError::Internal
    })?;

    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, username, display_name,
                           username_set, email_verified, status_type,
                           created_at_ms, updated_at_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'offline',$8,$8)
        "#,
    )
    .bind(user_id)
    .bind(&email_lower)
    .bind(&password_hash)
    .bind(&temp_username)
    .bind(Option::<&str>::None)
    .bind(false)
    .bind(false)
    .bind(now_millis)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "register: PG primary write failed");
        AppError::RegistrationFailed("Registration failed".into())
    })?;

    let legal_acceptance_id = state.snowflake.next_id();
    sqlx::query(
        r#"
        INSERT INTO user_legal_acceptances
            (id, user_id, terms_version, privacy_version, accepted_at_ms, accepted_ip, user_agent, source)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(legal_acceptance_id)
    .bind(user_id)
    .bind(TERMS_VERSION)
    .bind(PRIVACY_VERSION)
    .bind(now_millis)
    .bind(&ip)
    .bind(audit_ua.as_deref())
    .bind(LEGAL_ACCEPTANCE_SOURCE)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(user_id, error = %e, "register: legal acceptance write failed");
        AppError::RegistrationFailed("Registration failed".into())
    })?;

    if let Some(key) = registration_key {
        // The invite code references `users(id)` through `used_by`, so the
        // user row must exist before this update. Keeping both statements in
        // one transaction preserves single-use semantics: if the key is
        // missing or already claimed, the user insert rolls back.
        let consume = sqlx::query(
            "UPDATE invite_codes SET used_by = $2, used_at_ms = $3 WHERE code = $1 AND used_by IS NULL",
        )
        .bind(key)
        .bind(user_id)
        .bind(now_millis)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "register: invite consume failed");
            AppError::Internal
        })?;

        if consume.rows_affected() != 1 {
            let _ = tx.rollback().await;
            tracing::warn!("Register failed: invalid registration key");
            return Err(AppError::RegistrationFailed(
                "Invalid registration key".into(),
            ));
        }
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(user_id, error = %e, "register: PG transaction commit failed");
        AppError::Internal
    })?;

    // Legacy shim for downstream functions that still expect UserRow.
    let user = users::UserRow {
        id: user_id,
        username: temp_username.clone(),
        email: email_lower.clone(),
        password_hash,
        status: String::new(),
        status_type: "offline".to_string(),
        avatar_url: None,
        banner_url: None,
        banner_base_color: None,
        banner_crop: None,
        member_list_banner_url: None,
        member_list_banner_crop: None,
        display_name: None,
        bio: None,
        custom_status_text: None,
        custom_status_emoji: None,
        totp_enabled_at: None,
        totp_secret: None,
        deleted_at: None,
        email_verified: false,
        subscription_tier: None,
        subscription_expires_at: None,
        subscription_ring_style: None,
        subscribed: false,
        username_set: false,
        status_auto: false,
        preferred_status: "online".to_string(),
        server_order: serde_json::Value::Array(Vec::new()),
        favorite_order: serde_json::Value::Array(Vec::new()),
        preferences: serde_json::Value::Object(Default::default()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Create session
    let device = parse_device(ua.as_deref());
    let geo = geo_lookup(&state, &ip);
    let session_result = session::create_session(
        &state.pg,
        &state.snowflake,
        user_id,
        &ip,
        ua.as_deref(),
        &device,
        &geo,
        RiskLevel::None,
    )
    .await?;

    // Log login (fire-and-forget)
    let log_id = state.snowflake.next_id();
    let redis_log = state.redis.clone();
    let log_ip = ip.clone();
    let log_ua = ua.clone();
    let log_dh = device.device_hash.clone();
    let log_sid = session_result.session_id;
    let log_vdb = state.pg.clone();
    tokio::spawn(async move {
        login_log::log_login(
            &redis_log,
            LogLoginParams {
                id: log_id,
                user_id: Some(user_id),
                session_id: Some(log_sid),
                ip: log_ip,
                user_agent: log_ua,
                device_hash: Some(log_dh),
                city: None,
                country: None,
                success: true,
                risk_level: RiskLevel::None,
                failure_reason: None,
            },
            log_vdb,
        )
        .await;
    });

    let access_token = generate_access_token(
        user_id,
        &state.config.jwt_secret,
        Some(session_result.session_id),
    )?;

    if !email_verification_required {
        if let Err(e) =
            crate::services::registration::auto_join_default_server(&state, user_id).await
        {
            tracing::error!(user_id, error = %e, "register: default server auto-join failed");
        }
    }

    // Send email verification.
    // Stores the token hash in Redis with a 24-hour TTL under the
    // same `emailverify:{hash}` key the verify_email handler reads.
    if email_verification_required {
        let verify_token = crypto::generate_session_token();
        let verify_hash = hash_token(&verify_token);
        use fred::interfaces::KeysInterface;
        use fred::types::Expiration;
        let key = format!("emailverify:{verify_hash}");
        state
            .redis
            .set::<(), _, _>(
                &key,
                user_id.to_string(),
                Some(Expiration::EX(24 * 60 * 60)),
                None,
                false,
            )
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "register: email verification token write failed");
                AppError::Internal
            })?;
        if let Some(ref email_service) = state.email {
            let svc = email_service.clone();
            let addr = email_lower.clone();
            tokio::spawn(async move {
                if let Err(e) = svc.send_email_verification(&addr, &verify_token).await {
                    tracing::error!("Failed to send verification email: {e}");
                }
            });
        } else {
            tracing::error!(
                user_id,
                "register: email verification required but sender disappeared"
            );
            return Err(AppError::WithCode {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "EMAIL_DELIVERY_UNAVAILABLE",
                message: "Email verification is temporarily unavailable".into(),
            });
        }
    }

    tracing::info!("Registration successful user_id={}", user_id);

    let mut body = json!({
        "user": UserResponse::from_with_member_list_banner_visibility(
            &user,
            member_list_banner_visible_for_user(&state, &user),
        ),
        "accessToken": access_token,
        "emailVerificationRequired": email_verification_required,
    });
    // Only include sessionToken for non-browser clients (Tauri sends it in body).
    // Browsers use the httpOnly cookie instead — never expose the token in JSON.
    if !is_browser_request(&headers) {
        body["sessionToken"] = json!(session_result.token);
    }

    Ok((
        StatusCode::CREATED,
        [(
            header::SET_COOKIE,
            session_cookie(&session_result.token, state.config.secure_cookies),
        )],
        Json(body),
    )
        .into_response())
}

// ─── POST /api/auth/login ───────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!("POST /api/auth/login");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;

    let ua = extract_ua(&headers);
    let device = parse_device(ua.as_deref());
    let geo = geo_lookup(&state, &ip);

    // Account lockout check
    let email_hash = hash_token(&body.email.to_lowercase());
    let lock_key = format!("login-lock:{email_hash}");
    let lock_count: u64 = state
        .redis
        .get::<Option<String>, _>(&lock_key)
        .await
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if lock_count >= MAX_LOGIN_ATTEMPTS {
        let log_id = state.snowflake.next_id();
        let redis_log = state.redis.clone();
        let log_ip = ip.clone();
        let log_ua = ua.clone();
        let log_vdb = state.pg.clone();
        tokio::spawn(async move {
            login_log::log_login(
                &redis_log,
                LogLoginParams {
                    id: log_id,
                    user_id: None,
                    session_id: None,
                    ip: log_ip,
                    user_agent: log_ua,
                    device_hash: None,
                    city: None,
                    country: None,
                    success: false,
                    risk_level: RiskLevel::None,
                    failure_reason: Some("account_locked".into()),
                },
                log_vdb,
            )
            .await;
        });
        tracing::warn!("Login rejected: account locked ip={}", ip);
        return Err(AppError::WithCode {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "AUTH_ACCOUNT_LOCKED",
            message: "Account temporarily locked".into(),
        });
    }

    let user = crate::services::pg::users::by_email_lower(&state.pg, &body.email)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "login: PG by_email_lower failed");
            AppError::Internal
        })?;

    let Some(user) = user else {
        // Timing-safe: still run password verify against dummy
        let _ = hash_service::verify_password(
            &state,
            hash_service::DUMMY_HASH.into(),
            body.password.clone(),
        )
        .await;
        increment_lockout(&state, &lock_key).await;
        log_failed_login(&state, None, &ip, &ua, None);
        tracing::warn!("Login failed: user not found");
        return Err(AppError::InvalidCredentials);
    };

    // Verify password. If hashing fails, return the same outward-facing
    // InvalidCredentials response as the dummy path to avoid differential
    // auth errors that could help user enumeration.
    let valid = match hash_service::verify_password(
        &state,
        user.password_hash.clone(),
        body.password.clone(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Login: hash service error user_id={}: {e}", user.id);
            return Err(AppError::InvalidCredentials);
        }
    };

    if !valid {
        increment_lockout(&state, &lock_key).await;
        log_failed_login(&state, Some(user.id), &ip, &ua, Some(&device.device_hash));
        tracing::warn!("Login failed: invalid password user_id={}", user.id);
        return Err(AppError::InvalidCredentials);
    }

    // Clear lockout on success
    let _: Result<(), _> = KeysInterface::del(&state.redis, &lock_key).await;
    crate::services::app_bans::ensure_user_not_banned(&state, user.id).await?;

    // Account restoration: if soft-deleted, check grace period
    let mut account_restored = false;
    if let Some(deleted_at) = user.deleted_at {
        let days_since = (chrono::Utc::now() - deleted_at).num_days();
        if days_since >= 30 {
            // Past grace period — treat as invalid credentials (account should be purged)
            tracing::warn!(
                "Login rejected: account past 30-day grace period user_id={}",
                user.id
            );
            return Err(AppError::InvalidCredentials);
        }
        // Within grace period — clear the user's deleted_at column.
        let _ =
            sqlx::query("UPDATE users SET deleted_at_ms = NULL, updated_at_ms = $2 WHERE id = $1")
                .bind(user.id)
                .bind(chrono::Utc::now().timestamp_millis())
                .execute(&state.pg)
                .await;

        // Also restore any owned servers that were soft-deleted when
        // the account was deleted. Single UPDATE clears the flag.
        let _ = sqlx::query("UPDATE servers SET deleted_at_ms = NULL WHERE owner_id = $1 AND deleted_at_ms IS NOT NULL")
            .bind(user.id)
            .execute(&state.pg)
            .await;

        account_restored = true;
        tracing::info!("Account restored on login user_id={}", user.id);
    }

    // 2FA check
    if user.totp_enabled_at.is_some() {
        tracing::info!("Login requires 2FA user_id={}", user.id);
        let ticket = uuid::Uuid::new_v4().to_string();
        let ticket_hash = hash_token(&ticket);
        let key = format!("2fa-ticket:{ticket_hash}");
        let _: Result<(), _> = KeysInterface::set(
            &state.redis,
            &key,
            user.id.to_string(),
            Some(fred::types::Expiration::EX(300)),
            None,
            false,
        )
        .await;

        return Ok(Json(json!({
            "requiresTwoFactor": true,
            "twoFactorTicket": ticket,
        }))
        .into_response());
    }

    // Assess risk
    let risk_level = risk::assess_login_risk(
        &state.pg,
        user.id,
        &device.device_hash,
        geo.country.as_deref(),
    )
    .await;

    // Create session
    let session_result = session::create_session(
        &state.pg,
        &state.snowflake,
        user.id,
        &ip,
        ua.as_deref(),
        &device,
        &geo,
        risk_level,
    )
    .await?;

    // Log login
    let log_id = state.snowflake.next_id();
    let redis_log = state.redis.clone();
    let log_ip = ip.clone();
    let log_ua = ua.clone();
    let log_dh = device.device_hash.clone();
    let log_sid = session_result.session_id;
    let log_uid = user.id;
    let log_vdb = state.pg.clone();
    tokio::spawn(async move {
        login_log::log_login(
            &redis_log,
            LogLoginParams {
                id: log_id,
                user_id: Some(log_uid),
                session_id: Some(log_sid),
                ip: log_ip,
                user_agent: log_ua,
                device_hash: Some(log_dh),
                city: None,
                country: None,
                success: true,
                risk_level,
                failure_reason: None,
            },
            log_vdb,
        )
        .await;
    });

    // High risk: require verification
    if risk_level == RiskLevel::High && !session_result.verified {
        tracing::info!(
            "Login requires verification (high risk) user_id={}",
            user.id
        );
        let code = session::create_verification_token(&state.pg, session_result.session_id).await?;

        send_login_verification_code(&state, user.email.clone(), code);

        let mut body = json!({ "requiresVerification": true });
        if !is_browser_request(&headers) {
            body["sessionToken"] = json!(session_result.token);
        }

        // Set cookie so web clients can complete verification via cookie
        return Ok((
            [(
                header::SET_COOKIE,
                session_cookie(&session_result.token, state.config.secure_cookies),
            )],
            Json(body),
        )
            .into_response());
    }

    let access_token = generate_access_token(
        user.id,
        &state.config.jwt_secret,
        Some(session_result.session_id),
    )?;

    tracing::info!("Login successful user_id={}", user.id);

    let mut response = json!({
        "user": UserResponse::from_with_member_list_banner_visibility(
            &user,
            member_list_banner_visible_for_user(&state, &user),
        ),
        "accessToken": access_token,
    });
    if !is_browser_request(&headers) {
        response["sessionToken"] = json!(session_result.token);
    }
    if account_restored {
        response["accountRestored"] = json!(true);
    }

    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&session_result.token, state.config.secure_cookies),
        )],
        Json(response),
    )
        .into_response())
}

// ─── POST /api/auth/refresh ─────────────────────────────────────────

pub async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RefreshRequest>,
) -> AppResult<Response> {
    tracing::info!("POST /api/auth/refresh");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;
    let geo = geo_lookup(&state, &ip);

    // Try body first (native), then cookie (web browser). Only body-sourced
    // refreshes may receive the rotated session token in the JSON response.
    let (session_token, include_session_token) =
        session_token_from_body_or_cookie(&headers, body.session_token).ok_or_else(|| {
            tracing::warn!("Refresh failed: no session token in body or cookie");
            AppError::TokenRevoked
        })?;

    let rotated = session::rotate_session(&state.pg, &session_token, &ip, &geo)
        .await?
        .ok_or_else(|| {
            tracing::warn!("Refresh failed: session invalid or revoked");
            AppError::TokenRevoked
        })?;
    crate::services::app_bans::ensure_user_not_banned(&state, rotated.user_id).await?;

    let access_token = generate_access_token(
        rotated.user_id,
        &state.config.jwt_secret,
        Some(rotated.session_id),
    )?;

    tracing::info!("Refresh successful user_id={}", rotated.user_id);

    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&rotated.token, state.config.secure_cookies),
        )],
        Json(refresh_response_payload(
            access_token,
            &rotated.token,
            include_session_token,
        )),
    )
        .into_response())
}

// ─── POST /api/auth/logout ──────────────────────────────────────────

pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LogoutRequest>,
) -> AppResult<Response> {
    tracing::info!("POST /api/auth/logout");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;

    // Extract fields before moving body
    let body_access_token = body.access_token;

    // Try body first (Tauri), then cookie (web browser)
    let session_token = body
        .session_token
        .filter(|s| !s.is_empty())
        .or_else(|| extract_session_cookie(&headers));

    if let Some(ref session_token) = session_token {
        // Validate session ownership: look up the session token to get user_id.
        let session_user_id = {
            let token_hash = crypto::hash_token(session_token);
            crate::services::pg::sessions::by_token_hash(&state.pg, &token_hash)
                .await
                .ok()
                .flatten()
                .map(|s| s.user_id)
        };

        // If an access token is provided, verify it matches the session owner
        let token_to_blacklist = body_access_token.or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        });

        if let Some(ref token) = token_to_blacklist {
            if let Ok(claims) = crypto::decode_access_token(token, &state.config.jwt_secret) {
                if let Some(sess_uid) = session_user_id {
                    if claims.sub != sess_uid {
                        tracing::warn!(
                            "Logout: access token user {} doesn't match session user {}",
                            claims.sub,
                            sess_uid
                        );
                    } else {
                        blacklist_access_token(token, &state.config.jwt_secret, &state.redis).await;
                    }
                }
            }
        }

        session::revoke_session(&state.pg, session_token).await?;
    }

    tracing::info!("Logout successful");

    Ok((
        [(
            header::SET_COOKIE,
            clear_session_cookie(state.config.secure_cookies),
        )],
        Json(json!({ "success": true })),
    )
        .into_response())
}

// ─── POST /api/auth/revoke-session ──────────────────────────────────

pub async fn revoke_session_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RevokeSessionRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("POST /api/auth/revoke-session");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;
    session::revoke_session_by_revoke_token(&state.pg, &body.token).await?;
    tracing::info!("Session revoked via revoke token");
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/auth/verify-session ──────────────────────────────────

// ─── POST /api/auth/resend-session-code ─────────────────────────────

/// Resend the 6-digit session verification code via email.
pub async fn resend_session_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ResendSessionCodeRequest>,
) -> AppResult<Json<Value>> {
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;

    let session_token = body
        .session_token
        .filter(|s| !s.is_empty())
        .or_else(|| extract_session_cookie(&headers))
        .ok_or(AppError::TokenRevoked)?;

    let token_hash = crypto::hash_token(&session_token);
    let session = crate::services::pg::sessions::by_token_hash(&state.pg, &token_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "resend_session_code: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::TokenRevoked)?;
    crate::services::app_bans::ensure_user_not_banned(&state, session.user_id).await?;

    if session.verified {
        return Ok(Json(json!({ "success": true })));
    }

    let user = crate::services::pg::users::by_id(&state.pg, session.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "resend_session_code: user read failed");
            AppError::Internal
        })?
        .ok_or(AppError::TokenRevoked)?;

    // Generate new code (replaces old one)
    let code = session::create_verification_token(&state.pg, session.id).await?;

    send_login_verification_code(&state, user.email.clone(), code);

    tracing::info!(
        "Session verification code resent user_id={}",
        session.user_id
    );
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod login_verification_delivery_tests {
    use super::{LoginVerificationDelivery, login_verification_delivery};

    #[test]
    fn configured_email_service_is_used_for_login_verification() {
        assert_eq!(
            login_verification_delivery(true),
            LoginVerificationDelivery::Email
        );
    }

    #[test]
    fn missing_email_service_skips_login_verification_send() {
        assert_eq!(
            login_verification_delivery(false),
            LoginVerificationDelivery::None
        );
    }
}

pub async fn verify_session(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VerifySessionRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("POST /api/auth/verify-session");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;

    // Try body first (native), then cookie (web browser). Only body-sourced
    // verification may receive the session token in the JSON response.
    let (session_token, include_session_token) =
        session_token_from_body_or_cookie(&headers, body.session_token).ok_or_else(|| {
            tracing::warn!("Verify-session failed: no session token in body or cookie");
            AppError::TokenRevoked
        })?;

    let user_id = session::verify_session_code(&state.pg, &session_token, &body.code)
        .await?
        .ok_or_else(|| {
            tracing::warn!("Session verification failed: invalid code");
            AppError::WithCode {
                status: StatusCode::UNAUTHORIZED,
                code: "AUTH_2FA_INVALID_CODE",
                message: "Invalid verification code".into(),
            }
        })?;
    crate::services::app_bans::ensure_user_not_banned(&state, user_id).await?;

    // Look up session_id for the JWT sid claim.
    let session_id = {
        let token_hash = crypto::hash_token(&session_token);
        crate::services::pg::sessions::by_token_hash(&state.pg, &token_hash)
            .await
            .ok()
            .flatten()
            .map(|s| s.id)
    };

    let user_rec = crate::services::pg::users::by_id(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "verify_session: user read failed");
            AppError::Internal
        })?
        .ok_or_else(|| {
            tracing::error!("Session verification: user not found user_id={}", user_id);
            AppError::NotFound("user")
        })?;

    let access_token = generate_access_token(user_id, &state.config.jwt_secret, session_id)?;

    tracing::info!("Session verified user_id={}", user_id);

    let mut body = json!({
        "user": pg_user_to_user_response_json(
            &state,
            &user_rec,
            &crate::services::presence::effective_status(&state.redis, user_id).await,
        ),
        "accessToken": access_token,
    });
    if include_session_token {
        body["sessionToken"] = json!(session_token);
    }

    Ok(Json(body))
}

// ─── POST /api/auth/login/2fa ──────────────────────────────────────

const MAX_2FA_ATTEMPTS_PER_TICKET: u64 = 5;

pub async fn login_2fa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Login2faRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!("POST /api/auth/login/2fa");
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &ip).await?;
    crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;

    let ua = extract_ua(&headers);

    let ticket_hash = hash_token(&body.two_factor_ticket);
    let ticket_key = format!("2fa-ticket:{ticket_hash}");

    // Look up ticket → userId
    let user_id_str: Option<String> = state.redis.get(&ticket_key).await.ok().flatten();

    let Some(user_id_str) = user_id_str else {
        tracing::warn!("2FA login failed: invalid or expired ticket");
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTH_2FA_TICKET_INVALID",
            message: "Invalid or expired two-factor ticket".into(),
        });
    };

    let user_id: i64 = user_id_str.parse().map_err(|_| AppError::Internal)?;
    crate::services::app_bans::ensure_user_not_banned(&state, user_id).await?;

    // Atomic attempt counter
    let attempts_key = format!("2fa-attempts:{ticket_hash}");
    let attempts: u64 = KeysInterface::incr_by(&state.redis, &attempts_key, 1i64)
        .await
        .unwrap_or(1) as u64;
    if attempts == 1 {
        let _: Result<(), _> = KeysInterface::expire(&state.redis, &attempts_key, 300, None).await;
    }

    if attempts > MAX_2FA_ATTEMPTS_PER_TICKET {
        let _: Result<(), _> = KeysInterface::del(&state.redis, &ticket_key).await;
        let _: Result<(), _> = KeysInterface::del(&state.redis, &attempts_key).await;
        tracing::warn!("2FA login failed: too many attempts user_id={}", user_id);
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTH_2FA_TOO_MANY_ATTEMPTS",
            message: "Too many failed attempts. Please log in again.".into(),
        });
    }

    // Fetch user with TOTP secret.
    let user_row = crate::services::pg::users::by_id(&state.pg, user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "login_2fa: PG user read failed");
            AppError::Internal
        })?
        .ok_or(AppError::Internal)?;

    let totp_secret_opt = user_row.totp_secret.clone();
    if totp_secret_opt.as_deref().map_or(true, str::is_empty) {
        tracing::warn!("2FA login failed: TOTP not configured user_id={}", user_id);
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTH_2FA_INVALID",
            message: "Invalid verification".into(),
        });
    }
    let totp_secret = totp_secret_opt.as_deref().unwrap_or("");
    let user = user_row;

    let totp_enc_key = state.config.totp_encryption_key.as_deref().ok_or_else(|| {
        tracing::error!("TOTP_ENCRYPTION_KEY not configured");
        AppError::Internal
    })?;
    let secret = totp::decrypt_secret(totp_secret, totp_enc_key).map_err(|e| {
        tracing::error!("TOTP decrypt failed: {e}");
        AppError::Internal
    })?;

    let mut code_valid = false;

    // Try TOTP code first (6 digits)
    if body.code.len() == 6 && body.code.chars().all(|c| c.is_ascii_digit()) {
        // Replay prevention
        let replay_key = format!("totp-used:{user_id}:{}", body.code);
        let already_used: Option<String> = state.redis.get(&replay_key).await.ok().flatten();

        if already_used.is_none() {
            if let Ok(valid) = totp::verify_code(&secret, &body.code, &user.username) {
                if valid {
                    code_valid = true;
                    let _: Result<(), _> = KeysInterface::set(
                        &state.redis,
                        &replay_key,
                        "1",
                        Some(fred::types::Expiration::EX(90)),
                        None,
                        false,
                    )
                    .await;
                }
            }
        }
    }

    // If TOTP didn't match, try as backup code. Post-rip backup code
    // hashes live on the VdbUser record (`backup_code_hashes` field).
    // Consuming a code = RMW the user record, remove the matching
    // hash, dual_write. This is race-safe enough for the 2FA path
    // (single user, at most one login at a time) without needing a
    // dedicated atomic wire op.
    if !code_valid {
        let normalized = body.code.replace('-', "").to_uppercase();
        let code_hash = crypto::hmac_hash(&normalized, totp_enc_key);

        match crate::services::pg::users::consume_backup_code(&state.pg, user_id, &code_hash).await
        {
            Ok(true) => {
                code_valid = true;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!(user_id, error = %e, "login_2fa: PG backup-code consume write failed");
                return Err(AppError::Internal);
            }
        }
    }

    if !code_valid {
        tracing::warn!("2FA login failed: invalid code user_id={}", user_id);
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTH_2FA_INVALID_CODE",
            message: "Invalid two-factor code".into(),
        });
    }

    // Success — consume the ticket
    let _: Result<(), _> = KeysInterface::del(&state.redis, &ticket_key).await;
    let _: Result<(), _> = KeysInterface::del(&state.redis, &attempts_key).await;

    // Create session with risk assessment
    let device = parse_device(ua.as_deref());
    let geo = geo_lookup(&state, &ip);
    let risk_level = risk::assess_login_risk(
        &state.pg,
        user_id,
        &device.device_hash,
        geo.country.as_deref(),
    )
    .await;
    let session_result = session::create_session(
        &state.pg,
        &state.snowflake,
        user_id,
        &ip,
        ua.as_deref(),
        &device,
        &geo,
        risk_level,
    )
    .await?;

    // Log login
    let log_id = state.snowflake.next_id();
    let redis_log = state.redis.clone();
    let log_ip = ip.clone();
    let log_ua = ua.clone();
    let log_dh = device.device_hash.clone();
    let log_sid = session_result.session_id;
    let log_vdb = state.pg.clone();
    tokio::spawn(async move {
        login_log::log_login(
            &redis_log,
            LogLoginParams {
                id: log_id,
                user_id: Some(user_id),
                session_id: Some(log_sid),
                ip: log_ip,
                user_agent: log_ua,
                device_hash: Some(log_dh),
                city: None,
                country: None,
                success: true,
                risk_level,
                failure_reason: None,
            },
            log_vdb,
        )
        .await;
    });

    // 2FA proves identity — auto-verify even high-risk sessions.
    if risk_level == RiskLevel::High && !session_result.verified {
        let _ = crate::services::pg::sessions::mark_verified(&state.pg, session_result.session_id)
            .await;
    }

    // Low risk: send notification email
    if risk_level == RiskLevel::Low {
        if let Some(ref email_svc) = state.email {
            let email_svc = email_svc.clone();
            let email = user.email.clone();
            let label = device.device_label.clone();
            tokio::spawn(async move {
                let _ = email_svc
                    .send_login_notification(&email, &label, "Unknown", None)
                    .await;
            });
        }
    }

    let access_token = generate_access_token(
        user_id,
        &state.config.jwt_secret,
        Some(session_result.session_id),
    )?;

    tracing::info!("2FA login successful user_id={}", user_id);

    let mut body = json!({
        "user": UserResponse::from_with_member_list_banner_visibility(
            &user,
            member_list_banner_visible_for_user(&state, &user),
        ),
        "accessToken": access_token,
    });
    if !is_browser_request(&headers) {
        body["sessionToken"] = json!(session_result.token);
    }

    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&session_result.token, state.config.secure_cookies),
        )],
        Json(body),
    )
        .into_response())
}

// ─── Helpers ────────────────────────────────────────────────────────

async fn increment_lockout(state: &AppState, lock_key: &str) {
    let count: Result<i64, _> = KeysInterface::incr_by(&state.redis, lock_key, 1i64).await;
    if let Ok(1) = count {
        let _: Result<(), _> =
            KeysInterface::expire(&state.redis, lock_key, LOGIN_LOCKOUT_SECS, None).await;
    }
}

fn log_failed_login(
    state: &AppState,
    user_id: Option<i64>,
    ip: &str,
    ua: &Option<String>,
    device_hash: Option<&str>,
) {
    let log_id = state.snowflake.next_id();
    let redis_log = state.redis.clone();
    let ip = ip.to_string();
    let ua = ua.clone();
    let dh = device_hash.map(|s| s.to_string());
    let log_vdb = state.pg.clone();
    tokio::spawn(async move {
        login_log::log_login(
            &redis_log,
            LogLoginParams {
                id: log_id,
                user_id,
                session_id: None,
                ip,
                user_agent: ua,
                device_hash: dh,
                city: None,
                country: None,
                success: false,
                risk_level: RiskLevel::None,
                failure_reason: Some("invalid_credentials".into()),
            },
            log_vdb,
        )
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn register_request_defaults_legal_acceptance_to_false() {
        let request: RegisterRequest = serde_json::from_value(json!({
            "email": "new-user@example.com",
            "password": "correct horse battery staple",
        }))
        .expect("register request should deserialize with defaulted legal fields");

        assert!(!request.terms_accepted);
        assert!(!request.privacy_accepted);
    }

    #[test]
    fn register_request_accepts_explicit_legal_acceptance() {
        let request: RegisterRequest = serde_json::from_value(json!({
            "email": "new-user@example.com",
            "password": "correct horse battery staple",
            "termsAccepted": true,
            "privacyAccepted": true,
        }))
        .expect("register request should accept explicit legal fields");

        assert!(request.terms_accepted);
        assert!(request.privacy_accepted);
    }

    #[test]
    fn browser_fetch_metadata_wins_over_forged_native_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://app.verdant.chat".parse().unwrap());
        headers.insert("x-client-version", "forged-browser-js".parse().unwrap());
        headers.insert("sec-fetch-dest", "empty".parse().unwrap());
        headers.insert("sec-fetch-mode", "cors".parse().unwrap());

        assert!(is_browser_request(&headers));
    }

    #[test]
    fn native_client_version_without_browser_headers_is_not_browser() {
        let mut headers = HeaderMap::new();
        headers.insert("x-client-version", "verdant-flutter-test".parse().unwrap());

        assert!(!is_browser_request(&headers));
    }

    #[test]
    fn missing_native_header_defaults_to_browser_for_session_token_responses() {
        let headers = HeaderMap::new();

        assert!(is_browser_request(&headers));
    }

    #[test]
    fn legal_audit_truncation_preserves_char_boundaries() {
        let value = "ab🌿cd";

        assert_eq!(truncate_for_audit(Some(value), 3).as_deref(), Some("ab🌿"));
        assert_eq!(truncate_for_audit(None, 3), None);
    }

    #[test]
    fn refresh_payload_includes_rotated_session_token_for_native_clients() {
        let payload = refresh_response_payload("fresh-access".to_string(), "rotated-session", true);

        assert_eq!(payload["accessToken"], "fresh-access");
        assert_eq!(payload["sessionToken"], "rotated-session");
    }

    #[test]
    fn refresh_payload_omits_session_token_for_browser_clients() {
        let payload =
            refresh_response_payload("fresh-access".to_string(), "rotated-session", false);

        assert_eq!(payload["accessToken"], "fresh-access");
        assert!(payload.get("sessionToken").is_none());
    }

    #[test]
    fn cookie_refresh_does_not_return_session_token_when_native_header_is_forged() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-session=cookie-session".parse().unwrap(),
        );
        headers.insert("x-client-version", "forged-browser-js".parse().unwrap());
        headers.insert("sec-fetch-dest", "empty".parse().unwrap());

        let (session_token, include_session_token) =
            session_token_from_body_or_cookie(&headers, None)
                .expect("cookie token should be accepted");
        let payload = refresh_response_payload(
            "fresh-access".to_string(),
            "rotated-session",
            include_session_token,
        );

        assert_eq!(session_token, "cookie-session");
        assert!(!include_session_token);
        assert_eq!(payload["accessToken"], "fresh-access");
        assert!(payload.get("sessionToken").is_none());
    }

    #[test]
    fn cookie_verify_session_does_not_return_session_token_when_native_header_is_forged() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-session=cookie-session".parse().unwrap(),
        );
        headers.insert("x-client-version", "forged-browser-js".parse().unwrap());
        headers.insert("sec-fetch-dest", "empty".parse().unwrap());

        let (session_token, include_session_token) =
            session_token_from_body_or_cookie(&headers, None)
                .expect("cookie token should be accepted");
        let mut payload = json!({ "accessToken": "fresh-access" });
        if include_session_token {
            payload["sessionToken"] = json!(session_token);
        }

        assert!(!include_session_token);
        assert_eq!(payload["accessToken"], "fresh-access");
        assert!(payload.get("sessionToken").is_none());
    }

    #[test]
    fn refresh_cookie_uses_rotated_session_token() {
        let cookie = session_cookie("rotated-session", true);

        assert!(cookie.starts_with("__Host-session=rotated-session;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
    }
}
