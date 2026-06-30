use fred::clients::Client;
use fred::interfaces::KeysInterface;
use fred::interfaces::LuaInterface;
use fred::types::Expiration;
use prost::Message as ProstMessage;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::proto::{Attachment, CachedMessage, CachedReaction, MessageAuthor, ReplySnapshot};
use crate::services::cdn;

const MAX_CACHED_MESSAGES: i64 = 500;
const CACHE_TTL_SECS: i64 = 86400; // 24 hours

/// Lua script: read messages from ZSET+HASH in one roundtrip.
/// KEYS[1] = msgcache:{channel_id}:idx (ZSET)
/// KEYS[2] = msgcache:{channel_id}:data (HASH)
/// KEYS[3] = msgcache:{channel_id}:warm (warm marker)
/// ARGV[1] = count to fetch
/// ARGV[2] = max score (before cursor), "+inf" if none
/// ARGV[3] = TTL seconds
///
/// Returns: array of protobuf byte strings (one per message), newest first.
const LUA_READ: &str = r#"
local idx_key = KEYS[1]
local data_key = KEYS[2]
local warm_key = KEYS[3]
local count = tonumber(ARGV[1])
local max_score = ARGV[2]

local ids
if max_score == "+inf" then
    ids = redis.call('ZREVRANGE', idx_key, 0, count - 1)
else
    ids = redis.call('ZREVRANGEBYSCORE', idx_key, '(' .. max_score, '-inf', 'LIMIT', 0, count)
end

if #ids == 0 then
    return {}
end

-- Refresh TTL on access (including warm marker)
redis.call('EXPIRE', idx_key, ARGV[3])
redis.call('EXPIRE', data_key, ARGV[3])
redis.call('EXPIRE', warm_key, ARGV[3])

local values = redis.call('HMGET', data_key, unpack(ids))
local result = {}
for i, v in ipairs(values) do
    if v then
        result[#result + 1] = v
    end
end
return result
"#;

/// Lua script: write a single message + trim to max size.
/// KEYS[1] = msgcache:{channel_id}:idx (ZSET)
/// KEYS[2] = msgcache:{channel_id}:data (HASH)
/// ARGV[1] = message ID (string, used as ZSET member and HASH field)
/// ARGV[2] = message ID as score (numeric snowflake)
/// ARGV[3] = protobuf bytes
/// ARGV[4] = max entries
/// ARGV[5] = TTL seconds
const LUA_WRITE: &str = r#"
local idx_key = KEYS[1]
local data_key = KEYS[2]
local msg_id = ARGV[1]
local score = ARGV[2]
local data = ARGV[3]
local max_entries = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

redis.call('ZADD', idx_key, score, msg_id)
redis.call('HSET', data_key, msg_id, data)

-- Trim: remove oldest entries if over limit
local count = redis.call('ZCARD', idx_key)
if count > max_entries then
    local to_remove = redis.call('ZRANGE', idx_key, 0, count - max_entries - 1)
    if #to_remove > 0 then
        redis.call('ZREM', idx_key, unpack(to_remove))
        redis.call('HDEL', data_key, unpack(to_remove))
    end
end

redis.call('EXPIRE', idx_key, ttl)
redis.call('EXPIRE', data_key, ttl)
return 1
"#;

pub struct MessageCache {
    redis: Client,
}

impl MessageCache {
    pub fn new(redis: Client) -> Arc<Self> {
        Arc::new(Self { redis })
    }

    fn idx_key(channel_id: i64) -> String {
        format!("msgcache:{}:idx", channel_id)
    }

    fn data_key(channel_id: i64) -> String {
        format!("msgcache:{}:data", channel_id)
    }

    fn warm_key(channel_id: i64) -> String {
        format!("msgcache:{}:warm", channel_id)
    }

    fn latest_complete_key(channel_id: i64) -> String {
        format!("msgcache:{}:latest_complete", channel_id)
    }

    /// Read cached messages. Returns `None` on miss or error so callers use storage.
    ///
    /// The cache is only trusted when a **warm marker** exists for the channel.
    /// The warm marker is set by `backfill()` after a successful storage read +
    /// cache population. Single message writes (`cache_message`) extend an
    /// existing warm cache but don't establish warmness on their own.
    ///
    /// On hit: decodes protobuf CachedMessages, resolves per-user `me` flag on reactions,
    /// converts to JSON Values matching the existing API response format.
    pub async fn get_messages(
        &self,
        channel_id: i64,
        before: Option<i64>,
        limit: i64,
        user_id: &str,
        api_url: &str,
    ) -> Option<Vec<Value>> {
        // If the warm marker is absent, force a storage read and backfill.
        let warm_exists: i64 = self
            .redis
            .exists(Self::warm_key(channel_id))
            .await
            .unwrap_or(0);
        if warm_exists == 0 {
            tracing::info!(
                "Message cache NOT WARM channel={} — forcing storage read",
                channel_id
            );
            return None;
        }

        let latest_page_complete = self.latest_page_complete(channel_id).await;
        let idx_key = Self::idx_key(channel_id);
        let data_key = Self::data_key(channel_id);
        let warm_key = Self::warm_key(channel_id);
        let max_score = before
            .map(|id| id.to_string())
            .unwrap_or_else(|| "+inf".to_string());

        let raw: Vec<Vec<u8>> = match self
            .redis
            .eval(
                LUA_READ,
                vec![idx_key, data_key, warm_key],
                vec![limit.to_string(), max_score, CACHE_TTL_SECS.to_string()],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Message cache read error channel={}: {}", channel_id, e);
                return None;
            }
        };

        if raw.is_empty() {
            // Warm but empty for this cursor range — legitimate end-of-history
            // for pagination, or the channel truly has no messages cached in
            // this range when the latest page is known complete. Return empty
            // rather than falling through to storage in those complete cases.
            if cached_empty_page_satisfies_request(before, latest_page_complete) {
                tracing::info!(
                    "Message cache HIT (empty page) channel={} before={:?}",
                    channel_id,
                    before
                );
                return Some(vec![]);
            }
            tracing::info!(
                "Message cache MISS channel={} before={:?} limit={}",
                channel_id,
                before,
                limit
            );
            return None;
        }

        if !cached_page_satisfies_request(raw.len(), limit, latest_page_complete) {
            tracing::info!(
                "Message cache PARTIAL channel={} count={} requested={} before={:?}; forcing storage read",
                channel_id,
                raw.len(),
                limit,
                before
            );
            return None;
        }

        let mut messages = Vec::with_capacity(raw.len());
        for bytes in &raw {
            let cached = match CachedMessage::decode(bytes.as_slice()) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Message cache decode error channel={}: {}", channel_id, e);
                    // Corrupted entry — invalidate entire channel cache
                    self.invalidate_channel(channel_id).await;
                    return None;
                }
            };
            messages.push(cached_to_json(&cached, user_id, api_url));
        }

        tracing::info!(
            "Message cache HIT channel={} count={} before={:?}",
            channel_id,
            messages.len(),
            before
        );
        Some(messages)
    }

    /// Write a single message to cache + trim to MAX_CACHED_MESSAGES.
    /// Fire-and-forget — errors are logged and swallowed.
    pub async fn cache_message(
        &self,
        channel_id: i64,
        message_id: i64,
        cached_msg: &CachedMessage,
    ) {
        let idx_key = Self::idx_key(channel_id);
        let data_key = Self::data_key(channel_id);
        let bytes = cached_msg.encode_to_vec();
        let msg_id_str = message_id.to_string();

        let result: Result<i64, _> = self
            .redis
            .eval(
                LUA_WRITE,
                vec![idx_key, data_key],
                vec![
                    fred::types::Value::Bytes(msg_id_str.as_bytes().to_vec().into()),
                    fred::types::Value::Bytes(msg_id_str.as_bytes().to_vec().into()),
                    fred::types::Value::Bytes(bytes.into()),
                    fred::types::Value::Bytes(MAX_CACHED_MESSAGES.to_string().into_bytes().into()),
                    fred::types::Value::Bytes(CACHE_TTL_SECS.to_string().into_bytes().into()),
                ],
            )
            .await;

        match result {
            Ok(_) => {
                tracing::info!(
                    "Message cache WRITE channel={} message={}",
                    channel_id,
                    message_id
                );
                // Refresh warm marker TTL if it exists (don't create — only
                // backfill establishes warmness). EXPIRE on a non-existent
                // key returns false, which is fine.
                let _: Result<bool, _> = self
                    .redis
                    .expire(Self::warm_key(channel_id), CACHE_TTL_SECS, None)
                    .await;
                let _: Result<bool, _> = self
                    .redis
                    .expire(Self::latest_complete_key(channel_id), CACHE_TTL_SECS, None)
                    .await;
            }
            Err(e) => {
                tracing::warn!(
                    "Message cache write error channel={} message={}: {} — invalidating channel to force re-backfill",
                    channel_id,
                    message_id,
                    e
                );
                // Drop warm+idx+data so the next read backfills from storage.
                self.invalidate_channel(channel_id).await;
            }
        }
    }

    /// Backfill cache from DB results after a miss (latest page only).
    /// Fire-and-forget — errors are logged and swallowed.
    pub async fn backfill(
        &self,
        channel_id: i64,
        messages: Vec<CachedMessage>,
        latest_page_complete: bool,
    ) {
        if messages.is_empty() {
            self.mark_warm(channel_id, latest_page_complete).await;
            tracing::info!(
                "Message cache BACKFILL channel={} count=0 (warm marker set)",
                channel_id
            );
            return;
        }

        let idx_key = Self::idx_key(channel_id);
        let data_key = Self::data_key(channel_id);

        // Use pipeline: ZADD + HSET for each message, then EXPIRE
        // We'll use a Lua script to batch this atomically
        let mut zadd_args: Vec<String> = Vec::with_capacity(messages.len() * 2);
        let mut hset_fields: Vec<Vec<u8>> = Vec::with_capacity(messages.len() * 2);

        for msg in &messages {
            zadd_args.push(msg.id.clone()); // score (snowflake ID = numeric string)
            zadd_args.push(msg.id.clone()); // member

            let bytes = msg.encode_to_vec();
            hset_fields.push(msg.id.as_bytes().to_vec());
            hset_fields.push(bytes);
        }

        // Build a Lua script for bulk backfill
        let lua = r#"
local idx_key = KEYS[1]
local data_key = KEYS[2]
local ttl = tonumber(ARGV[1])
local max_entries = tonumber(ARGV[2])
local n = tonumber(ARGV[3])

-- ZADD pairs start at ARGV[4]: score, member, score, member...
for i = 0, n - 1 do
    local base = 4 + i * 2
    local score = ARGV[base]
    local member = ARGV[base + 1]
    redis.call('ZADD', idx_key, 'NX', score, member)
end

-- HSET pairs are in KEYS[3..]: but we can't use KEYS for data.
-- Instead they follow ZADD args: at ARGV[4 + n*2] onward
local hbase = 4 + n * 2
for i = 0, n - 1 do
    local field = ARGV[hbase + i * 2]
    local val = ARGV[hbase + i * 2 + 1]
    redis.call('HSETNX', data_key, field, val)
end

-- Trim
local count = redis.call('ZCARD', idx_key)
if count > max_entries then
    local to_remove = redis.call('ZRANGE', idx_key, 0, count - max_entries - 1)
    if #to_remove > 0 then
        redis.call('ZREM', idx_key, unpack(to_remove))
        redis.call('HDEL', data_key, unpack(to_remove))
    end
end

redis.call('EXPIRE', idx_key, ttl)
redis.call('EXPIRE', data_key, ttl)
return 1
"#;

        // Build args: TTL, max_entries, n, then ZADD pairs, then HSET pairs
        let n = messages.len();
        let mut args: Vec<fred::types::Value> = Vec::with_capacity(3 + n * 4);
        args.push(fred::types::Value::Bytes(
            CACHE_TTL_SECS.to_string().into_bytes().into(),
        ));
        args.push(fred::types::Value::Bytes(
            MAX_CACHED_MESSAGES.to_string().into_bytes().into(),
        ));
        args.push(fred::types::Value::Bytes(n.to_string().into_bytes().into()));

        // ZADD pairs (score, member)
        for pair in zadd_args.chunks(2) {
            args.push(fred::types::Value::Bytes(
                pair[0].as_bytes().to_vec().into(),
            ));
            args.push(fred::types::Value::Bytes(
                pair[1].as_bytes().to_vec().into(),
            ));
        }

        // HSET pairs (field, value — value is raw protobuf bytes)
        for pair in hset_fields.chunks(2) {
            args.push(fred::types::Value::Bytes(pair[0].clone().into()));
            args.push(fred::types::Value::Bytes(pair[1].clone().into()));
        }

        let result: Result<i64, _> = self.redis.eval(lua, vec![idx_key, data_key], args).await;

        match result {
            Ok(_) => {
                self.mark_warm(channel_id, latest_page_complete).await;
                tracing::info!(
                    "Message cache BACKFILL channel={} count={} (warm marker set)",
                    channel_id,
                    n
                );
            }
            Err(e) => {
                tracing::warn!("Message cache backfill error channel={}: {}", channel_id, e);
            }
        }
    }

    /// Invalidate the entire channel cache (for edits, corruption, full reset).
    /// Deletes cached messages and the warm marker so the next read backfills.
    /// Fire-and-forget.
    pub async fn invalidate_channel(&self, channel_id: i64) {
        let idx_key = Self::idx_key(channel_id);
        let data_key = Self::data_key(channel_id);
        let warm_key = Self::warm_key(channel_id);
        let latest_complete_key = Self::latest_complete_key(channel_id);

        let result: Result<i64, _> = self
            .redis
            .del(vec![idx_key, data_key, warm_key, latest_complete_key])
            .await;

        match result {
            Ok(_) => {
                tracing::info!(
                    "Message cache INVALIDATE channel={} (warm marker cleared)",
                    channel_id
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Message cache invalidate error channel={}: {}",
                    channel_id,
                    e
                );
            }
        }
    }

    /// Surgically remove a single message from the cache (for deletes).
    /// Keeps the warm marker intact — the cache is still warm, just
    /// missing one entry. Fire-and-forget.
    pub async fn remove_single_message(&self, channel_id: i64, message_id: i64) {
        let idx_key = Self::idx_key(channel_id);
        let data_key = Self::data_key(channel_id);
        let msg_id_str = message_id.to_string();

        // Atomic ZREM + HDEL
        let lua = r#"
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
return 1
"#;
        let result: Result<i64, _> = self
            .redis
            .eval(lua, vec![idx_key, data_key], vec![msg_id_str])
            .await;

        match result {
            Ok(_) => {
                tracing::info!(
                    "Message cache REMOVE channel={} message={}",
                    channel_id,
                    message_id
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Message cache remove error channel={} message={}: {} — invalidating channel",
                    channel_id,
                    message_id,
                    e
                );
                // A failed remove could leave a tombstone visible; fully invalidate.
                self.invalidate_channel(channel_id).await;
            }
        }
    }

    async fn latest_page_complete(&self, channel_id: i64) -> bool {
        let exists: i64 = self
            .redis
            .exists(Self::latest_complete_key(channel_id))
            .await
            .unwrap_or(0);
        exists != 0
    }

    async fn mark_warm(&self, channel_id: i64, latest_page_complete: bool) {
        let _: Result<(), _> = self
            .redis
            .set(
                Self::warm_key(channel_id),
                "1",
                Some(Expiration::EX(CACHE_TTL_SECS)),
                None,
                false,
            )
            .await;
        if latest_page_complete {
            let _: Result<(), _> = self
                .redis
                .set(
                    Self::latest_complete_key(channel_id),
                    "1",
                    Some(Expiration::EX(CACHE_TTL_SECS)),
                    None,
                    false,
                )
                .await;
        } else {
            let _: Result<i64, _> = self.redis.del(Self::latest_complete_key(channel_id)).await;
        }
    }
}

fn cached_page_satisfies_request(
    cached_count: usize,
    requested_limit: i64,
    latest_page_complete: bool,
) -> bool {
    requested_limit <= 0 || cached_count as i64 >= requested_limit || latest_page_complete
}

fn cached_empty_page_satisfies_request(before: Option<i64>, latest_page_complete: bool) -> bool {
    before.is_some() || latest_page_complete
}

/// Convert a CachedMessage to API-compatible JSON Value, resolving the per-user `me` flag.
fn cached_attachment_url(attachment: &Attachment, api_url: &str) -> String {
    attachment
        .id
        .parse::<i64>()
        .ok()
        .map(|id| crate::handlers::uploads::attachment_media_url(api_url, id))
        .unwrap_or_default()
}

fn cached_to_json(cached: &CachedMessage, user_id: &str, api_url: &str) -> Value {
    let reactions: Vec<Value> = cached
        .reactions
        .iter()
        .map(|r| {
            json!({
                "emoji": r.emoji,
                "emojiId": r.emoji_id,
                "count": r.count,
                "me": r.user_ids.iter().any(|uid| uid == user_id),
            })
        })
        .collect();

    let attachments: Vec<Value> = cached
        .attachments
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "messageId": a.message_id,
                "filename": a.filename,
                "url": cached_attachment_url(a, api_url),
                "contentType": a.content_type,
                "size": a.size,
            })
        })
        .collect();

    let reply_to = cached.reply_to.as_ref().map(|r| {
        json!({
            "id": r.id,
            "content": r.content,
            "author": r.author.as_ref().map(|a| json!({
                "id": a.id,
                "username": a.username,
                "displayName": a.display_name,
                "avatarUrl": cdn::resolve(a.avatar_url.as_deref()),
            })),
        })
    });

    let author = cached.author.as_ref().map(|a| {
        json!({
            "id": a.id,
            "username": a.username,
            "displayName": a.display_name,
            "avatarUrl": cdn::resolve(a.avatar_url.as_deref()),
        })
    });

    json!({
        "id": cached.id,
        "channelId": cached.channel_id,
        "authorId": cached.author_id,
        "author": author,
        "content": cached.content,
        "type": cached.r#type,
        "edited": cached.edited,
        "editedAt": cached.edited_at,
        "createdAt": cached.created_at,
        "updatedAt": cached.updated_at,
        "reactions": reactions,
        "attachments": attachments,
        "replyTo": reply_to.unwrap_or(Value::Null),
    })
}

// ─── Conversion helpers (used by handlers to build CachedMessages) ──────

/// Build a CachedMessage from handler data for a new message.
pub fn build_cached_message_new(
    id_str: String,
    channel_id_str: String,
    author_id_str: String,
    author_username: String,
    author_avatar: Option<String>,
    author_display_name: Option<String>,
    content: String,
    msg_type: i32,
    created_at: String,
    reply_to: Option<ReplySnapshot>,
    attachments: Vec<Attachment>,
) -> CachedMessage {
    CachedMessage {
        id: id_str,
        channel_id: channel_id_str,
        author_id: author_id_str.clone(),
        author: Some(MessageAuthor {
            id: author_id_str,
            username: author_username,
            avatar_url: author_avatar,
            display_name: author_display_name,
        }),
        content,
        attachments,
        reactions: vec![],
        edited: false,
        created_at: created_at.clone(),
        updated_at: created_at,
        nonce: None,
        r#type: msg_type,
        reply_to,
        edited_at: None,
    }
}

/// Build a CachedMessage from query data used for backfill.
pub fn build_cached_message_from_vdb(
    id: i64,
    channel_id: i64,
    author_id: i64,
    author_username: String,
    author_avatar_url: Option<String>,
    author_display_name: Option<String>,
    content: String,
    flags: u16,
    reply_to: Option<ReplySnapshot>,
    reactions: Vec<CachedReaction>,
    attachments: Vec<Attachment>,
) -> CachedMessage {
    let edited = (flags & 0x02) != 0;
    let created_at_millis = (id >> 22) + 1_735_689_600_000;
    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(created_at_millis)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();

    CachedMessage {
        id: id.to_string(),
        channel_id: channel_id.to_string(),
        author_id: author_id.to_string(),
        author: Some(MessageAuthor {
            id: author_id.to_string(),
            username: author_username,
            avatar_url: author_avatar_url,
            display_name: author_display_name,
        }),
        content,
        attachments,
        reactions,
        edited,
        created_at: created_at.clone(),
        updated_at: created_at,
        nonce: None,
        r#type: 0,
        reply_to,
        edited_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached_message_with_attachment(attachment: Attachment) -> CachedMessage {
        CachedMessage {
            id: "100".to_string(),
            channel_id: "200".to_string(),
            author_id: "300".to_string(),
            author: Some(MessageAuthor {
                id: "300".to_string(),
                username: "user".to_string(),
                avatar_url: None,
                display_name: None,
            }),
            content: "hello".to_string(),
            attachments: vec![attachment],
            reactions: vec![],
            edited: false,
            created_at: "2026-05-20T00:00:00Z".to_string(),
            updated_at: "2026-05-20T00:00:00Z".to_string(),
            nonce: None,
            r#type: 0,
            reply_to: None,
            edited_at: None,
        }
    }

    #[test]
    fn cached_attachments_ignore_legacy_public_urls() {
        let cached = cached_message_with_attachment(Attachment {
            id: "42".to_string(),
            message_id: "100".to_string(),
            filename: "private.png".to_string(),
            url: "https://cdn.example.test/attachments/private.png".to_string(),
            content_type: "image/png".to_string(),
            size: 123,
        });

        let value = cached_to_json(&cached, "300", "https://api.example.test/");

        assert_eq!(
            value["attachments"][0]["url"],
            "https://api.example.test/api/media/attachments/42"
        );
    }

    #[test]
    fn invalid_cached_attachment_ids_do_not_emit_legacy_urls() {
        let cached = cached_message_with_attachment(Attachment {
            id: "not-a-snowflake".to_string(),
            message_id: "100".to_string(),
            filename: "private.png".to_string(),
            url: "https://cdn.example.test/attachments/private.png".to_string(),
            content_type: "image/png".to_string(),
            size: 123,
        });

        let value = cached_to_json(&cached, "300", "https://api.example.test/");

        assert_eq!(value["attachments"][0]["url"], "");
    }

    #[test]
    fn cached_page_smaller_than_requested_is_not_trusted() {
        assert!(!cached_page_satisfies_request(1, 50, false));
        assert!(cached_page_satisfies_request(50, 50, false));
        assert!(cached_page_satisfies_request(60, 50, false));
    }

    #[test]
    fn complete_short_latest_page_is_trusted() {
        assert!(cached_page_satisfies_request(1, 50, true));
        assert!(cached_page_satisfies_request(0, 50, true));
    }

    #[test]
    fn empty_latest_page_is_trusted_only_when_known_complete() {
        assert!(!cached_empty_page_satisfies_request(None, false));
        assert!(cached_empty_page_satisfies_request(None, true));
        assert!(cached_empty_page_satisfies_request(Some(123), false));
    }
}
