//! Redis-backed presence layer.
//!
//! Presence is **ephemeral** — stored in Redis with TTL, not durable storage.
//! The source of truth is "who is connected and what did they last tell us."
//!
//! Key format: `presence:{user_id}` → `"{status}"` (e.g. `"online"`, `"idle"`)
//! TTL: 90s, refreshed by WS heartbeat (~41s interval).
//! Missing key = offline.

use fred::prelude::*;

/// TTL for presence keys. 2× heartbeat interval gives one missed beat as grace.
const PRESENCE_TTL_SECS: i64 = 90;

/// Redis key for a user's presence.
fn key(user_id: i64) -> String {
    format!("presence:{user_id}")
}

/// Set a user's presence status with TTL.
pub async fn set(redis: &Client, user_id: i64, status: &str) {
    let k = key(user_id);
    let _: Result<(), _> = redis
        .set(
            &k,
            status,
            Some(Expiration::EX(PRESENCE_TTL_SECS)),
            None,
            false,
        )
        .await;
}

/// Refresh TTL on an existing presence key (called on WS heartbeat).
pub async fn refresh(redis: &Client, user_id: i64) {
    let k = key(user_id);
    let _: Result<bool, _> = redis.expire(&k, PRESENCE_TTL_SECS, None).await;
}

/// Remove a user's presence (clean disconnect).
pub async fn remove(redis: &Client, user_id: i64) {
    let k = key(user_id);
    let _: Result<i64, _> = redis.del(&k).await;
}

/// Get a single user's presence. Returns None if offline (key missing/expired).
pub async fn get(redis: &Client, user_id: i64) -> Option<String> {
    let k = key(user_id);
    redis.get::<Option<String>, _>(&k).await.ok().flatten()
}

/// Batch-get presence for multiple users. Returns a vec of (user_id, status)
/// for users who are online. Offline users (missing keys) are omitted.
pub async fn batch_get(redis: &Client, user_ids: &[i64]) -> Vec<(i64, String)> {
    if user_ids.is_empty() {
        return Vec::new();
    }
    // Build individual gets — fred's mget wants MultipleKeys which is awkward
    // with dynamic vecs. Individual gets are fine for presence (small N per call).
    let mut results = Vec::new();
    for uid in user_ids {
        if let Some(status) = get(redis, *uid).await {
            results.push((*uid, status));
        }
    }
    results
}

/// Resolve a single user's effective status: Redis presence if connected,
/// otherwise "offline".
pub async fn effective_status(redis: &Client, user_id: i64) -> String {
    get(redis, user_id)
        .await
        .unwrap_or_else(|| "offline".to_string())
}
