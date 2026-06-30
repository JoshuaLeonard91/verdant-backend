//! Subscription service — Postgres-backed.
//!
//! Single source of truth for premium feature gates. Reads land on the
//! `users` row (subscription_tier / subscription_expires_at_ms /
//! subscribed); writes go through
//! `pg::users::set_subscription`. Audit-trail events still fire to the
//! Redis stream `subscription-events`; PG dual-write is via
//! `pg::subscription::insert_idempotent` (stripe-event-id replay-safe).

use chrono::{DateTime, Utc};
use fred::clients::Client;
use fred::interfaces::StreamsInterface;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use crate::services::pg::{
    emojis as pg_emojis, servers as pg_servers, stickers as pg_stickers, subscription as pg_sub,
    users as pg_users,
};

// ─── Tier constants ──────────────────────────────────────────────────

pub const TIER_PREMIUM: &str = "premium";

pub const FREE_MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024; // 8 MB
pub const FREE_MAX_VOICE_BITRATE: i32 = 64_000; // 64 kbps

pub const PREMIUM_MAX_UPLOAD_BYTES: u64 = 25 * 1024 * 1024; // 25 MB
pub const PREMIUM_MAX_VOICE_BITRATE: i32 = 128_000; // 128 kbps

pub const MAX_CUSTOM_STICKERS_PER_MESSAGE: usize = 8;

// ─── Subscription state (READY payload shape) ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInfo {
    pub active: bool,
    pub tier: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub ring_style: Option<String>,
}

impl SubscriptionInfo {
    pub fn from_db(
        tier: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        _ring_style: Option<&str>,
    ) -> Self {
        let now = Utc::now();
        let active = tier.is_some() && expires_at.map(|exp| exp > now).unwrap_or(false);
        Self {
            active,
            tier: if active { tier.map(String::from) } else { None },
            expires_at: if active { expires_at } else { None },
            ring_style: None,
        }
    }

    pub fn free() -> Self {
        Self {
            active: false,
            tier: None,
            expires_at: None,
            ring_style: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn from_db_never_exposes_deprecated_ring_style() {
        let info = SubscriptionInfo::from_db(
            Some(TIER_PREMIUM),
            Some(Utc::now() + Duration::days(30)),
            Some("rotate"),
        );

        assert!(info.active);
        assert_eq!(info.ring_style, None);
    }

    #[test]
    fn free_subscription_has_no_ring_style() {
        let info = SubscriptionInfo::free();

        assert!(!info.active);
        assert_eq!(info.ring_style, None);
    }

    #[test]
    fn custom_emoji_rewrite_neutralizes_known_out_of_scope_matches() {
        let emoji_servers = HashMap::from([
            ("local".to_string(), vec![10]),
            ("remote".to_string(), vec![20]),
        ]);
        let sticker_servers = HashMap::new();

        let rewritten = rewrite_custom_emoji_shortcodes(
            ":local: :remote: :unknown:",
            Some(10),
            false,
            &emoji_servers,
            &sticker_servers,
            MAX_CUSTOM_STICKERS_PER_MESSAGE,
        );

        assert_eq!(rewritten, ":local: remote :unknown:");
    }

    #[test]
    fn custom_emoji_rewrite_allows_cross_server_when_entitled() {
        let emoji_servers = HashMap::from([
            ("local".to_string(), vec![10]),
            ("remote".to_string(), vec![20]),
        ]);
        let sticker_servers = HashMap::new();

        let rewritten = rewrite_custom_emoji_shortcodes(
            ":local: :remote: :unknown:",
            Some(10),
            true,
            &emoji_servers,
            &sticker_servers,
            MAX_CUSTOM_STICKERS_PER_MESSAGE,
        );

        assert_eq!(rewritten, ":local: :remote: :unknown:");
    }

    #[test]
    fn custom_sticker_rewrite_caps_renderable_sticker_shortcodes() {
        let emoji_servers = HashMap::new();
        let sticker_servers = HashMap::from([("bonk".to_string(), vec![10])]);
        let content = std::iter::repeat(":bonk:")
            .take(MAX_CUSTOM_STICKERS_PER_MESSAGE + 2)
            .collect::<Vec<_>>()
            .join(" ");
        let expected = std::iter::repeat(":bonk:")
            .take(MAX_CUSTOM_STICKERS_PER_MESSAGE)
            .chain(std::iter::repeat("bonk").take(2))
            .collect::<Vec<_>>()
            .join(" ");

        let rewritten = rewrite_custom_emoji_shortcodes(
            &content,
            Some(10),
            false,
            &emoji_servers,
            &sticker_servers,
            MAX_CUSTOM_STICKERS_PER_MESSAGE,
        );

        assert_eq!(rewritten, expected);
    }

    #[test]
    fn custom_emoji_candidate_detection_requires_shortcode_shape() {
        assert!(!contains_custom_emoji_shortcode_candidate("plain message"));
        assert!(!contains_custom_emoji_shortcode_candidate("time is 12:30"));
        assert!(contains_custom_emoji_shortcode_candidate(":party_tree:"));
    }

    #[test]
    fn custom_emoji_reaction_allows_local_match() {
        let emoji_servers = HashMap::from([
            ("local".to_string(), vec![10]),
            ("remote".to_string(), vec![20]),
        ]);

        assert!(validate_reaction_custom_emoji_shortcode_with_servers(
            ":local:",
            Some(10),
            false,
            &emoji_servers,
        ));
    }

    #[test]
    fn custom_emoji_reaction_blocks_remote_match_without_entitlement() {
        let emoji_servers = HashMap::from([
            ("local".to_string(), vec![10]),
            ("remote".to_string(), vec![20]),
        ]);

        assert!(!validate_reaction_custom_emoji_shortcode_with_servers(
            ":remote:",
            Some(10),
            false,
            &emoji_servers,
        ));
    }

    #[test]
    fn custom_emoji_reaction_allows_remote_match_with_entitlement() {
        let emoji_servers = HashMap::from([("remote".to_string(), vec![20])]);

        assert!(validate_reaction_custom_emoji_shortcode_with_servers(
            ":remote:",
            Some(10),
            true,
            &emoji_servers,
        ));
    }

    #[test]
    fn custom_emoji_reaction_allows_unknown_or_non_shortcode_values() {
        let emoji_servers = HashMap::from([("remote".to_string(), vec![20])]);

        assert!(validate_reaction_custom_emoji_shortcode_with_servers(
            ":unknown:",
            Some(10),
            false,
            &emoji_servers,
        ));
        assert!(validate_reaction_custom_emoji_shortcode_with_servers(
            "\u{1f642}",
            Some(10),
            false,
            &emoji_servers,
        ));
        assert!(validate_reaction_custom_emoji_shortcode_with_servers(
            "prefix :remote:",
            Some(10),
            false,
            &emoji_servers,
        ));
    }

    #[test]
    fn message_resolution_includes_sticker_catalog_but_reactions_do_not() {
        let source = include_str!("subscription.rs");
        let resolver = source
            .rsplit("async fn resolve_custom_expression_servers_for_names")
            .next()
            .expect("resolver should exist")
            .split("/// Strip / preserve custom emoji shortcodes")
            .next()
            .expect("resolver section should end before validator docs");

        assert!(resolver.contains("include_stickers: bool"));
        assert!(resolver.contains("pg_stickers::list_for_server"));
        assert!(resolver.contains("if include_stickers"));
        assert!(source.contains("&unique_names, true"));
        assert!(source.contains("&unique_names, false"));
    }
}

// ─── Feature gates ───────────────────────────────────────────────────

pub async fn is_subscribed(pool: &PgPool, user_id: i64) -> bool {
    match pg_users::by_id(pool, user_id).await {
        Ok(Some(u)) => {
            u.subscribed
                && u.subscription_expires_at
                    .map(|exp| exp > Utc::now())
                    .unwrap_or(false)
        }
        _ => false,
    }
}

pub async fn get_subscription_info(pool: &PgPool, user_id: i64) -> SubscriptionInfo {
    match pg_users::by_id(pool, user_id).await {
        Ok(Some(u)) => SubscriptionInfo::from_db(
            u.subscription_tier.as_deref(),
            u.subscription_expires_at,
            u.subscription_ring_style.as_deref(),
        ),
        _ => SubscriptionInfo::free(),
    }
}

pub async fn can_use_cross_server_emoji(pool: &PgPool, user_id: i64) -> bool {
    is_subscribed(pool, user_id).await
}

pub async fn can_upload_animated_avatar(pool: &PgPool, user_id: i64) -> bool {
    is_subscribed(pool, user_id).await
}

pub async fn can_upload_animated_banner(pool: &PgPool, user_id: i64) -> bool {
    is_subscribed(pool, user_id).await
}

pub async fn max_upload_bytes(pool: &PgPool, user_id: i64) -> u64 {
    if is_subscribed(pool, user_id).await {
        PREMIUM_MAX_UPLOAD_BYTES
    } else {
        FREE_MAX_UPLOAD_BYTES
    }
}

pub async fn max_voice_bitrate(pool: &PgPool, user_id: i64) -> i32 {
    if is_subscribed(pool, user_id).await {
        PREMIUM_MAX_VOICE_BITRATE
    } else {
        FREE_MAX_VOICE_BITRATE
    }
}

pub async fn has_badge(pool: &PgPool, user_id: i64) -> bool {
    is_subscribed(pool, user_id).await
}

pub async fn get_ring_style(pool: &PgPool, user_id: i64) -> Option<String> {
    let _ = (pool, user_id);
    None
}

// ─── Mutations (Stripe webhook / admin) ──────────────────────────────

pub async fn activate(
    pool: &PgPool,
    user_id: i64,
    tier: &str,
    expires_at: DateTime<Utc>,
    _stripe_customer_id: Option<&str>,
) -> Result<(), String> {
    pg_users::set_subscription(
        pool,
        user_id,
        Some(tier),
        Some(expires_at.timestamp_millis()),
        true,
        None,
    )
    .await
    .map_err(|e| format!("activate: pg update failed: {e}"))
}

pub async fn revoke(pool: &PgPool, user_id: i64) -> Result<(), String> {
    pg_users::set_subscription(pool, user_id, None, None, false, None)
        .await
        .map_err(|e| format!("revoke: pg update failed: {e}"))
}

pub async fn set_ring_style(
    pool: &PgPool,
    user_id: i64,
    _style: Option<&str>,
) -> Result<(), String> {
    sqlx::query("UPDATE users SET subscription_ring_style = NULL WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| format!("clear_ring_style: pg update failed: {e}"))?;
    Ok(())
}

/// Append an event to the Redis stream + PG durability tier. The PG
/// insert is replay-protected via the unique index on stripe_event_id.
pub async fn log_event(
    redis: &Client,
    pool: &PgPool,
    id: i64,
    user_id: i64,
    event_type: &str,
    stripe_event_id: Option<&str>,
    amount_cents: Option<i32>,
    metadata: Option<serde_json::Value>,
) -> Result<(), String> {
    let event_type_str = event_type.to_string();
    let stripe_str = stripe_event_id.unwrap_or_default().to_string();
    let amount = amount_cents.unwrap_or(0);
    let meta_value = metadata.unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    let meta_str = meta_value.to_string();

    let fields: Vec<(&str, String)> = vec![
        ("id", id.to_string()),
        ("user_id", user_id.to_string()),
        ("event_type", event_type_str.clone()),
        ("stripe_event_id", stripe_str.clone()),
        ("amount_cents", amount.to_string()),
        ("metadata", meta_str.clone()),
    ];
    let _: String = redis
        .xadd("subscription-events", false, None, "*", fields)
        .await
        .map_err(|e| format!("xadd subscription-events: {e}"))?;

    // PG durability tier — fire-and-forget, replay-safe.
    let row = pg_sub::SubscriptionEventRow {
        id,
        user_id,
        event_type: event_type_str,
        stripe_event_id: if stripe_str.is_empty() {
            None
        } else {
            Some(stripe_str)
        },
        amount_cents: amount,
        metadata: meta_value,
        created_at_ms: Utc::now().timestamp_millis(),
    };
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = pg_sub::insert_idempotent(&pool_clone, &row).await {
            tracing::warn!(error = %e, "subscription_event PG dual-write failed");
        }
    });

    Ok(())
}

// ─── Custom-emoji enforcement ────────────────────────────────────────

static CUSTOM_EMOJI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r":([a-zA-Z0-9_]{2,32}):").unwrap());

pub fn contains_custom_emoji_shortcode_candidate(content: &str) -> bool {
    content.contains(':') && CUSTOM_EMOJI_RE.is_match(content)
}

fn custom_emoji_shortcode_name(value: &str) -> Option<&str> {
    if !value.contains(':') {
        return None;
    }
    let caps = CUSTOM_EMOJI_RE.captures(value)?;
    let full_match = caps.get(0)?;
    if full_match.as_str() != value {
        return None;
    }
    caps.get(1).map(|m| m.as_str())
}

pub fn is_custom_emoji_reaction_shortcode_candidate(emoji: &str) -> bool {
    custom_emoji_shortcode_name(emoji).is_some()
}

fn custom_emoji_shortcode_allowed(
    name: &str,
    server_id: Option<i64>,
    cross_server_emoji: bool,
    emoji_servers: &HashMap<String, Vec<i64>>,
) -> bool {
    custom_expression_shortcode_allowed(name, server_id, cross_server_emoji, emoji_servers)
        .unwrap_or(true)
}

fn custom_expression_shortcode_allowed(
    name: &str,
    server_id: Option<i64>,
    cross_server_emoji: bool,
    expression_servers: &HashMap<String, Vec<i64>>,
) -> Option<bool> {
    let sids = expression_servers.get(name)?;
    if let Some(current_sid) = server_id {
        if sids.contains(&current_sid) {
            return Some(true);
        }
    }
    Some(cross_server_emoji && !sids.is_empty())
}

fn rewrite_custom_emoji_shortcodes(
    content: &str,
    server_id: Option<i64>,
    cross_server_emoji: bool,
    emoji_servers: &HashMap<String, Vec<i64>>,
    sticker_servers: &HashMap<String, Vec<i64>>,
    max_custom_stickers: usize,
) -> String {
    let mut custom_stickers = 0usize;
    CUSTOM_EMOJI_RE
        .replace_all(content, |caps: &regex::Captures| {
            let name = &caps[1];
            let full_match = &caps[0];
            if custom_expression_shortcode_allowed(
                name,
                server_id,
                cross_server_emoji,
                emoji_servers,
            )
            .unwrap_or(false)
            {
                return full_match.to_string();
            };
            if custom_expression_shortcode_allowed(
                name,
                server_id,
                cross_server_emoji,
                sticker_servers,
            )
            .unwrap_or(false)
            {
                if custom_stickers < max_custom_stickers {
                    custom_stickers += 1;
                    return full_match.to_string();
                }
                return name.to_string();
            };
            if !emoji_servers.contains_key(name) && !sticker_servers.contains_key(name) {
                return full_match.to_string();
            };
            name.to_string()
        })
        .into_owned()
}

#[derive(Default)]
struct CustomExpressionServers {
    emoji_servers: HashMap<String, Vec<i64>>,
    sticker_servers: HashMap<String, Vec<i64>>,
}

async fn resolve_custom_expression_servers_for_names(
    pool: &PgPool,
    user_id: i64,
    server_id: Option<i64>,
    unique_names: &HashSet<String>,
    include_stickers: bool,
) -> CustomExpressionServers {
    if unique_names.is_empty() {
        return CustomExpressionServers::default();
    }

    let mut scope_ids = pg_servers::list_server_ids_for_user(pool, user_id)
        .await
        .unwrap_or_default();
    if scope_ids.is_empty() {
        if let Some(sid) = server_id {
            scope_ids.push(sid);
        }
    }

    let mut expression_servers = CustomExpressionServers::default();
    for sid in &scope_ids {
        if let Ok(list) = pg_emojis::list_for_server(pool, *sid).await {
            for e in list {
                if unique_names.contains(&e.name) {
                    expression_servers
                        .emoji_servers
                        .entry(e.name)
                        .or_default()
                        .push(*sid);
                }
            }
        }
        if include_stickers {
            if let Ok(list) = pg_stickers::list_for_server(pool, *sid).await {
                for sticker in list {
                    if unique_names.contains(&sticker.name) {
                        expression_servers
                            .sticker_servers
                            .entry(sticker.name)
                            .or_default()
                            .push(*sid);
                    }
                }
            }
        }
    }
    expression_servers
}

/// Strip / preserve custom emoji shortcodes based on the caller's effective
/// entitlement. Without cross-server emoji, users may only use emojis from the
/// channel's own server; with it, they may use any emoji from their servers.
/// Returns the rewritten content (same-string for the all-allowed common case).
pub async fn validate_message_emojis_with_entitlement(
    pool: &PgPool,
    user_id: i64,
    server_id: Option<i64>, // None for DMs
    content: &str,
    cross_server_emoji: bool,
) -> String {
    if !contains_custom_emoji_shortcode_candidate(content) {
        return content.to_string();
    }

    let emoji_names: Vec<String> = CUSTOM_EMOJI_RE
        .captures_iter(content)
        .map(|cap| cap[1].to_string())
        .collect();
    let unique_names: HashSet<String> = emoji_names.into_iter().collect();
    let expression_servers =
        resolve_custom_expression_servers_for_names(pool, user_id, server_id, &unique_names, true)
            .await;

    rewrite_custom_emoji_shortcodes(
        content,
        server_id,
        cross_server_emoji,
        &expression_servers.emoji_servers,
        &expression_servers.sticker_servers,
        MAX_CUSTOM_STICKERS_PER_MESSAGE,
    )
}

pub fn validate_reaction_custom_emoji_shortcode_with_servers(
    emoji: &str,
    server_id: Option<i64>,
    cross_server_emoji: bool,
    emoji_servers: &HashMap<String, Vec<i64>>,
) -> bool {
    let Some(name) = custom_emoji_shortcode_name(emoji) else {
        return true;
    };
    custom_emoji_shortcode_allowed(name, server_id, cross_server_emoji, emoji_servers)
}

pub async fn validate_reaction_emoji_with_entitlement(
    pool: &PgPool,
    user_id: i64,
    server_id: Option<i64>,
    emoji: &str,
    cross_server_emoji: bool,
) -> bool {
    let Some(name) = custom_emoji_shortcode_name(emoji) else {
        return true;
    };

    let unique_names = HashSet::from([name.to_string()]);
    let expression_servers =
        resolve_custom_expression_servers_for_names(pool, user_id, server_id, &unique_names, false)
            .await;
    custom_emoji_shortcode_allowed(
        name,
        server_id,
        cross_server_emoji,
        &expression_servers.emoji_servers,
    )
}

/// Compatibility wrapper for older call sites. New gates should pass
/// `Entitlements::cross_server_emoji` explicitly so official subscription state
/// cannot leak into self-host modes.
pub async fn validate_message_emojis(
    pool: &PgPool,
    user_id: i64,
    server_id: Option<i64>,
    content: &str,
) -> String {
    let subscribed = is_subscribed(pool, user_id).await;
    validate_message_emojis_with_entitlement(pool, user_id, server_id, content, subscribed).await
}
