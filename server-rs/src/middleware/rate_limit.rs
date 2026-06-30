use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::middleware::auth::UserId;
use crate::state::AppState;

/// In-memory rate limit entry for fallback when Redis is down.
struct LocalRateLimitEntry {
    count: AtomicU64,
    window: u64,
    /// Absolute expiry time (seconds since UNIX epoch). Used for cleanup.
    expires_at: u64,
}

/// Local in-memory rate limiter that activates when Redis is unavailable.
/// Not distributed across instances, but prevents single-instance brute-force.
pub struct LocalRateLimiter {
    entries: DashMap<String, LocalRateLimitEntry>,
}

/// Cleanup interval: evict stale entries every 60 seconds. Short enough that
/// a Redis outage can't let the local fallback accumulate unbounded entries.
const CLEANUP_INTERVAL_SECS: u64 = 60;

impl LocalRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Spawn a background task that evicts stale rate limit entries every 5 minutes.
    pub fn start_cleanup_task(self: &std::sync::Arc<Self>) {
        let limiter = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let before = limiter.entries.len();
                limiter.cleanup(now_secs);
                let after = limiter.entries.len();
                if before > after {
                    tracing::debug!(
                        "Rate limiter cleanup: evicted {} stale entries",
                        before - after
                    );
                }
            }
        });
    }

    /// Increment and check rate limit locally. Returns current count.
    pub fn check_public(&self, key: &str, window: u64, window_secs: u64) -> u64 {
        self.check(key, window, window_secs)
    }

    /// Internal check implementation.
    fn check(&self, key: &str, window: u64, window_secs: u64) -> u64 {
        let expires_at = (window + 1) * window_secs;
        let entry = self
            .entries
            .entry(key.to_string())
            .or_insert_with(|| LocalRateLimitEntry {
                count: AtomicU64::new(0),
                window,
                expires_at,
            });

        // If window changed, reset counter
        if entry.window != window {
            // Remove stale entry and insert fresh
            drop(entry);
            self.entries.remove(key);
            let entry =
                self.entries
                    .entry(key.to_string())
                    .or_insert_with(|| LocalRateLimitEntry {
                        count: AtomicU64::new(0),
                        window,
                        expires_at,
                    });
            entry.count.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            entry.count.fetch_add(1, Ordering::Relaxed) + 1
        }
    }

    /// Periodically clean up stale entries (call from a background task).
    /// `now_secs` is the current time in seconds since UNIX epoch.
    pub fn cleanup(&self, now_secs: u64) {
        self.entries.retain(|_, entry| entry.expires_at > now_secs);
    }
}

/// Configuration for a rate limiter.
#[derive(Clone)]
pub struct RateLimitConfig {
    pub window_secs: u64,
    pub max: u64,
    pub prefix: &'static str,
}

/// Apply rate limiting based on config. Returns an error response if over limit.
///
/// # Multi-Instance Safety
///
/// Uses Redis INCR as the primary counter — all API instances share the same
/// counters. A user hitting instance A 5 times and instance B 5 times correctly
/// sees a total of 10 against their limit.
///
/// If Redis is unavailable, falls back to an in-memory DashMap per instance.
/// This degrades gracefully: rate limiting becomes per-instance (less strict)
/// rather than failing all requests.
///
/// # How It Works
///
/// 1. Build key: `"{prefix}:{userId_or_IP}:{window_number}"`
/// 2. Redis INCR the key (atomic counter)
/// 3. If count > max → reject with 429 + Retry-After header
/// 4. First increment sets a TTL so keys auto-expire after the window
pub async fn check_rate_limit(
    state: &AppState,
    req: &Request<Body>,
    config: &RateLimitConfig,
    ip: &str,
) -> Result<(), Response> {
    // Identify requester: userId if authed, else IP
    let identifier = req
        .extensions()
        .get::<UserId>()
        .map(|u| u.0.to_string())
        .unwrap_or_else(|| ip.to_string());

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let window = now_secs / config.window_secs;
    let key = format!("{}:{}:{}", config.prefix, identifier, window);

    let current: u64 = match fred::interfaces::KeysInterface::incr_by::<i64, _>(
        &state.redis,
        &key,
        1i64,
    )
    .await
    {
        Ok(val) => val as u64,
        Err(e) => {
            // Redis unavailable — fall back to in-memory rate limiter
            tracing::warn!(prefix = config.prefix, error = %e, "Rate limiter Redis error — using local fallback");
            state
                .local_rate_limiter
                .check(&key, window, config.window_secs)
        }
    };

    // Set TTL on first increment
    if current == 1 {
        let _: Result<(), _> = fred::interfaces::KeysInterface::expire(
            &state.redis,
            &key,
            config.window_secs as i64,
            None,
        )
        .await;
    }

    if current > config.max {
        let remaining = config
            .window_secs
            .saturating_sub(now_secs % config.window_secs);
        let body = json!({
            "error": "Rate limited",
            "code": "RATE_LIMITED",
            "retryAfter": remaining,
        });
        let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
        if let Ok(val) = HeaderValue::from_str(&remaining.to_string()) {
            resp.headers_mut().insert("retry-after", val);
        }
        return Err(resp);
    }

    Ok(())
}

// ─── Predefined rate limit configurations ─────────────────────────

pub const AUTH_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 5,
    prefix: "rl:auth",
};

pub const REGISTER_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 300,
    max: 3,
    prefix: "rl:register",
};

pub const MESSAGE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 10,
    max: 10,
    prefix: "rl:message",
};

pub const REACTION_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:reaction",
};

pub const TYPING_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 10,
    max: 20,
    prefix: "rl:typing",
};

pub const READ_STATE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 60,
    prefix: "rl:read_state",
};

pub const PRESENCE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:presence",
};

pub const WS_NAV_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 10,
    max: 30,
    prefix: "rl:ws_nav",
};

pub const VOICE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 10,
    max: 8,
    prefix: "rl:voice",
};

pub const API_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 10,
    max: 20,
    prefix: "rl:api",
};

pub const INVITE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 5,
    prefix: "rl:invite",
};

pub const CHANNEL_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:channel",
};

pub const CATEGORY_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:category",
};

pub const SERVER_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 10,
    prefix: "rl:server",
};

pub const DM_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 5,
    max: 5,
    prefix: "rl:dm",
};

pub const RELATIONSHIP_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 10,
    prefix: "rl:relationship",
};

pub const EMOJI_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 10,
    prefix: "rl:emoji",
};

pub const ROLE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:role",
};

pub const UPLOAD_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 10,
    prefix: "rl:upload",
};

pub const MODERATION_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 10,
    prefix: "rl:moderation",
};

pub const PASSWORD_RESET_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 300,
    max: 3,
    prefix: "rl:pwreset",
};

/// Per-user IDENTIFY rate limit. The IDENTIFY handler triggers
/// `query_ready_full` which is the most expensive composer in the
/// engine — a power user with 100+ servers can produce a multi-MB
/// payload that fans out to 500+ engine table_get calls.
///
/// At 10 IDENTIFYs per minute (one every 6s) we still allow legit
/// reconnect storms after a network blip, but a malicious or
/// runaway client can't hammer the composer.
pub const IDENTIFY_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 10,
    prefix: "rl:identify",
};

pub const ADMIN_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 5,
    prefix: "rl:admin",
};

pub const UPDATE_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 30,
    prefix: "rl:update",
};

pub const MEDIA_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 60,
    prefix: "rl:media",
};

pub const ATTACHMENT_MEDIA_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 240,
    prefix: "rl:attachment_media",
};

pub const SEARCH_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:search",
};

pub const LINK_PREVIEW_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:link_preview",
};

pub const REPORT_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 5,
    prefix: "rl:report",
};

pub const BUG_REPORT_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 5,
    prefix: "rl:bugreport",
};

pub const STRIPE_WEBHOOK_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 120,
    prefix: "rl:stripe_webhook",
};

pub const FEDERATION_EVENT_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 120,
    prefix: "rl:federation_event",
};

pub const FEDERATION_INVITE_PREVIEW_LIMIT: RateLimitConfig = RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:federation_invite_preview",
};

/// Rate limit info returned on successful requests for response headers.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitInfo {
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: u64,
}

impl RateLimitInfo {
    /// Attach X-RateLimit-* headers to a response.
    pub fn apply_headers(&self, resp: &mut Response) {
        let headers = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&self.limit.to_string()) {
            headers.insert("x-ratelimit-limit", v);
        }
        if let Ok(v) = HeaderValue::from_str(&self.remaining.to_string()) {
            headers.insert("x-ratelimit-remaining", v);
        }
        if let Ok(v) = HeaderValue::from_str(&self.reset_at.to_string()) {
            headers.insert("x-ratelimit-reset", v);
        }
    }
}

/// Check if a request carries a valid stress test bypass header.
/// Returns true if STRESS_TEST_KEY is configured AND the request has
/// `X-Stress-Test: <matching key>`. Used to skip rate limits during load testing.
pub fn is_stress_test_bypass(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    if let Some(ref key) = state.config.stress_test_key {
        if let Some(header) = headers.get("x-stress-test").and_then(|v| v.to_str().ok()) {
            return header == key;
        }
    }
    false
}

/// Check if a request carries a valid loadtest secret header.
/// Returns true if LOADTEST_SECRET is configured AND the request has
/// `X-Loadtest-Secret: <matching key>`. Constant-time comparison.
pub fn is_loadtest_bypass(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let expected = match state.config.loadtest_secret.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    let provided = match headers
        .get("x-loadtest-secret")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v,
        None => return false,
    };
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Rate limit check that also accepts headers for stress test bypass.
/// If the request carries a valid `X-Stress-Test` header, rate limiting is skipped.
pub async fn enforce_opt_bypass(
    state: &AppState,
    config: &RateLimitConfig,
    identifier: &str,
    headers: Option<&axum::http::HeaderMap>,
) -> Result<RateLimitInfo, crate::error::AppError> {
    if let Some(h) = headers {
        if is_stress_test_bypass(state, h) {
            return Ok(RateLimitInfo {
                limit: u64::MAX,
                remaining: u64::MAX,
                reset_at: 0,
            });
        }
    }
    enforce(state, config, identifier).await
}

/// Inline rate limit check for use inside handlers.
/// Takes a user_id or IP as identifier.
///
/// Bypass is header-gated only. Callers that want stress-test bypass must use
/// `enforce_opt_bypass()` and pass the request headers; a request that doesn't
/// carry a valid `X-Stress-Test: <key>` header is always rate-limited, even if
/// `STRESS_TEST_KEY` is configured on the server. This prevents a prod .env
/// containing a stray `STRESS_TEST_KEY` from silently relaxing every limit.
pub async fn enforce(
    state: &AppState,
    config: &RateLimitConfig,
    identifier: &str,
) -> Result<RateLimitInfo, crate::error::AppError> {
    enforce_inner(state, config, identifier).await
}

async fn enforce_inner(
    state: &AppState,
    config: &RateLimitConfig,
    identifier: &str,
) -> Result<RateLimitInfo, crate::error::AppError> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let window = now_secs / config.window_secs;
    let key = format!("{}:{}:{}", config.prefix, identifier, window);

    let current: u64 = match fred::interfaces::KeysInterface::incr_by::<i64, _>(
        &state.redis,
        &key,
        1i64,
    )
    .await
    {
        Ok(val) => val as u64,
        Err(e) => {
            // Redis unavailable — fall back to in-memory rate limiter
            tracing::warn!(prefix = config.prefix, error = %e, "Rate limiter Redis error — using local fallback");
            state
                .local_rate_limiter
                .check(&key, window, config.window_secs)
        }
    };

    if current == 1 {
        let _: Result<(), _> = fred::interfaces::KeysInterface::expire(
            &state.redis,
            &key,
            config.window_secs as i64,
            None,
        )
        .await;
    }

    let reset_at = (window + 1) * config.window_secs;

    if current > config.max {
        return Err(crate::error::AppError::RateLimited);
    }

    Ok(RateLimitInfo {
        limit: config.max,
        remaining: config.max.saturating_sub(current),
        reset_at,
    })
}
