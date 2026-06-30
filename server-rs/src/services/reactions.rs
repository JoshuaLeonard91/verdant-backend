//! Redis-backed reaction service.
//!
//! Post-PG-rip the `reactions` table has been replaced with two
//! Redis sets per message:
//!
//! - `reactions:{msg_id}:{emoji}` — SET of user_ids that have
//!   reacted with this emoji.
//! - `reactions-emojis:{msg_id}` — SET of distinct emoji strings
//!   that have reactions on this message. Used to enforce the
//!   `MAX_UNIQUE_REACTIONS_PER_MESSAGE` cap.
//!
//! The add operation is a single Lua script so the "exists +
//! check cap + insert" sequence is atomic. The read path
//! (list_reactions_for_messages) does a BATCH read via
//! `SMEMBERS` fan-out; the messages-per-page limit bounds the
//! fan-out to ~50 keys.

use fred::clients::Client;
use fred::interfaces::{LuaInterface, SetsInterface};
use std::collections::HashMap;

/// Matches the postgres schema's unique-reaction cap (20).
pub const MAX_UNIQUE_REACTIONS_PER_MESSAGE: usize = 20;

/// Result of an add-reaction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddReactionResult {
    /// First time this user reacted with this emoji — caller
    /// broadcasts REACTION_ADD.
    Added,
    /// The user had already reacted with the same emoji.
    AlreadyPresent,
    /// The message already has the cap on unique emojis and the
    /// requested emoji is new — caller returns 403.
    LimitReached,
}

fn members_key(message_id: i64, emoji: &str) -> String {
    format!("reactions:{message_id}:{emoji}")
}

fn emojis_key(message_id: i64) -> String {
    format!("reactions-emojis:{message_id}")
}

/// Lua script: atomic `add_reaction`. Returns:
///   1  — added a brand-new user/emoji pair
///   0  — user already reacted with this emoji
///   -1 — unique-emoji cap hit (emoji was new and would exceed cap)
const ADD_REACTION_LUA: &str = r#"
local member_key = KEYS[1]
local emojis_key = KEYS[2]
local user_id = ARGV[1]
local max_unique = tonumber(ARGV[2])
local emoji = ARGV[3]

if redis.call('SISMEMBER', member_key, user_id) == 1 then
    return 0
end

local emoji_exists = redis.call('SISMEMBER', emojis_key, emoji) == 1
if not emoji_exists then
    local current = redis.call('SCARD', emojis_key)
    if current >= max_unique then
        return -1
    end
end

redis.call('SADD', member_key, user_id)
if not emoji_exists then
    redis.call('SADD', emojis_key, emoji)
end
return 1
"#;

/// Atomically record that `user_id` reacted with `emoji` on
/// `message_id`. Enforces the unique-emoji cap inside the
/// script so there's no TOCTOU race between the check and the
/// insert.
pub async fn add_reaction(
    redis: &Client,
    message_id: i64,
    emoji: &str,
    user_id: i64,
) -> Result<AddReactionResult, String> {
    let keys = vec![members_key(message_id, emoji), emojis_key(message_id)];
    let args = vec![
        user_id.to_string(),
        MAX_UNIQUE_REACTIONS_PER_MESSAGE.to_string(),
        emoji.to_string(),
    ];
    let result: i64 = redis
        .eval(ADD_REACTION_LUA, keys, args)
        .await
        .map_err(|e| format!("add_reaction: redis eval failed: {e}"))?;
    Ok(match result {
        1 => AddReactionResult::Added,
        0 => AddReactionResult::AlreadyPresent,
        -1 => AddReactionResult::LimitReached,
        other => return Err(format!("add_reaction: unexpected script result {other}")),
    })
}

/// Lua script: atomic `remove_reaction`. Returns:
///   1 — removed the last reference to this emoji for this user
///   0 — the user had not reacted with this emoji
const REMOVE_REACTION_LUA: &str = r#"
local member_key = KEYS[1]
local emojis_key = KEYS[2]
local user_id = ARGV[1]
local emoji = ARGV[2]

local removed = redis.call('SREM', member_key, user_id)
if removed == 0 then
    return 0
end

-- If no users remain on this emoji, drop it from the emojis
-- set so the cap check resets.
if redis.call('SCARD', member_key) == 0 then
    redis.call('DEL', member_key)
    redis.call('SREM', emojis_key, emoji)
end
return 1
"#;

/// Atomically remove `user_id`'s reaction of `emoji` on
/// `message_id`. If they weren't reacting, returns `false` so
/// the caller can skip the broadcast + return 404.
pub async fn remove_reaction(
    redis: &Client,
    message_id: i64,
    emoji: &str,
    user_id: i64,
) -> Result<bool, String> {
    let keys = vec![members_key(message_id, emoji), emojis_key(message_id)];
    let args = vec![user_id.to_string(), emoji.to_string()];
    let result: i64 = redis
        .eval(REMOVE_REACTION_LUA, keys, args)
        .await
        .map_err(|e| format!("remove_reaction: redis eval failed: {e}"))?;
    Ok(result == 1)
}

/// Aggregated reaction view for a single message.
#[derive(Debug, Clone, Default)]
pub struct MessageReactions {
    /// Per-emoji user id set.
    pub by_emoji: HashMap<String, Vec<i64>>,
}

/// Read every reaction on `message_id`. For the listing / cache
/// backfill path — called infrequently and bounded by the
/// unique-emoji cap (≤20 SMEMBERS per message).
pub async fn list_reactions(redis: &Client, message_id: i64) -> Result<MessageReactions, String> {
    let emojis: Vec<String> = SetsInterface::smembers(redis, emojis_key(message_id))
        .await
        .map_err(|e| format!("list_reactions: emojis smembers failed: {e}"))?;
    let mut by_emoji = HashMap::with_capacity(emojis.len());
    for emoji in emojis {
        let users: Vec<String> = SetsInterface::smembers(redis, members_key(message_id, &emoji))
            .await
            .map_err(|e| format!("list_reactions: member smembers failed: {e}"))?;
        let parsed: Vec<i64> = users.into_iter().filter_map(|s| s.parse().ok()).collect();
        if !parsed.is_empty() {
            by_emoji.insert(emoji, parsed);
        }
    }
    Ok(MessageReactions { by_emoji })
}

/// Batch-read reactions for many messages. Bounded fan-out: one
/// SMEMBERS per emoji per message. For a typical page of 50
/// messages with ~3 distinct reactions each that's 150 round
/// trips — use the per-message path when possible.
pub async fn list_reactions_batch(
    redis: &Client,
    message_ids: &[i64],
) -> Result<HashMap<i64, MessageReactions>, String> {
    let mut out = HashMap::with_capacity(message_ids.len());
    for mid in message_ids {
        out.insert(*mid, list_reactions(redis, *mid).await?);
    }
    Ok(out)
}

/// Batch-read reactions from Redis. Post-PG migration Redis is the
/// authoritative reaction store; there is no secondary tier. The
/// `_with_fallback` suffix is preserved for source-compat with the
/// existing call sites.
pub async fn list_reactions_batch_with_fallback(
    redis: &Client,
    _legacy_vdb: Option<()>,
    message_ids: &[i64],
) -> HashMap<i64, MessageReactions> {
    list_reactions_batch(redis, message_ids)
        .await
        .unwrap_or_default()
}

/// Cascade-delete every reaction on a message. Called when a
/// message is hard-deleted or a moderator wipes reactions.
/// Tombstones keep reactions for audit; hard-delete paths can use this cleanup.
#[allow(dead_code)]
pub async fn delete_all_reactions(redis: &Client, message_id: i64) -> Result<(), String> {
    use fred::interfaces::KeysInterface;
    let emojis: Vec<String> = SetsInterface::smembers(redis, emojis_key(message_id))
        .await
        .unwrap_or_default();
    for emoji in &emojis {
        let _: Result<i64, _> = KeysInterface::del(redis, members_key(message_id, emoji)).await;
    }
    let _: Result<i64, _> = KeysInterface::del(redis, emojis_key(message_id)).await;
    Ok(())
}
