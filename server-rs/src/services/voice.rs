use crate::config::LiveKitNodeConfig;
use fred::clients::Client;
use fred::interfaces::HashesInterface;
use fred::interfaces::KeysInterface;
use fred::interfaces::LuaInterface;
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// Shared HTTP client for LiveKit API calls (reused across requests).
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

/// Soft-launch voice rooms are intentionally small.
///
/// This is enforced twice:
/// - server-rs rejects new join tokens once Redis already has this many
///   participants in the channel
/// - LiveKit receives the same room cap so concurrent joins cannot exceed the
///   media-server limit
pub const LIVEKIT_ROOM_MAX_PARTICIPANTS: usize = 5;

/// Result of an atomic voice join.
#[derive(Debug, Clone)]
pub struct VoiceJoinResult {
    pub state: VoiceState,
    pub previous: Option<VoiceState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceJoinError {
    ChannelFull,
    Redis,
    Serialize,
    UnexpectedResult,
}

/// Redis script for a capped voice join.
///
/// KEYS[1] = new channel hash, KEYS[2] = user -> channel key
/// ARGV[1] = user id, ARGV[2] = channel id, ARGV[3] = serialized state,
/// ARGV[4] = max participants, ARGV[5] = TTL seconds.
///
/// Returns:
///   1  = joined
///  -1  = target channel is full
const VOICE_JOIN_CAPPED_LUA: &str = r#"
local new_channel_key = KEYS[1]
local user_key = KEYS[2]
local user_id = ARGV[1]
local channel_id = ARGV[2]
local state_json = ARGV[3]
local max_participants = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local old_channel_id = redis.call('GET', user_key)
if old_channel_id == channel_id then
    redis.call('HSET', new_channel_key, user_id, state_json)
    redis.call('EXPIRE', new_channel_key, ttl)
    redis.call('SET', user_key, channel_id, 'EX', ttl)
    return 1
end

if redis.call('HLEN', new_channel_key) >= max_participants then
    return -1
end

if old_channel_id then
    local old_channel_key = 'voice:channel:' .. old_channel_id
    redis.call('HDEL', old_channel_key, user_id)
    if redis.call('HLEN', old_channel_key) == 0 then
        redis.call('DEL', old_channel_key)
    end
end

redis.call('HSET', new_channel_key, user_id, state_json)
redis.call('EXPIRE', new_channel_key, ttl)
redis.call('SET', user_key, channel_id, 'EX', ttl)
return 1
"#;

/// Voice state for a single user in a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceState {
    pub user_id: i64,
    pub channel_id: i64,
    pub server_id: i64,
    pub self_mute: bool,
    pub self_deaf: bool,
    pub server_mute: bool,
    pub server_deaf: bool,
}

impl VoiceState {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "userId": self.user_id.to_string(),
            "channelId": self.channel_id.to_string(),
            "serverId": self.server_id.to_string(),
            "selfMute": self.self_mute,
            "selfDeaf": self.self_deaf,
            "serverMute": self.server_mute,
            "serverDeaf": self.server_deaf,
        })
    }
}

/// Redis-primary voice state tracker.
///
/// All state lives in Redis so multiple API instances share one voice view.
///
/// # Redis Key Schema
///
/// ```text
/// voice:channel:{channel_id}  → HSET { "user_id" → JSON VoiceState }
/// voice:user:{user_id}        → STRING channel_id (reverse lookup)
/// ```
///
/// Both keys have 1-hour TTL as a crash safety net. If the server restarts,
/// stale voice states auto-expire rather than persisting forever.
///
/// # READY Integration
///
/// On WS connect, the READY handler (`ws/handlers.rs`) queries Redis for
/// voice participants in all voice channels the user has access to. This
/// populates the client's voice state immediately — no REST call needed.
///
/// # Multi-Instance Safety
///
/// - `join()` / `leave()` / `update_state()` all go through Redis atomically
/// - `get_participants()` reads from Redis (not local memory)
/// - Any number of API instances can run simultaneously
/// - Rate limiting is also Redis-backed (see `middleware/rate_limit.rs`)
pub struct VoiceService;

impl VoiceService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    /// Add a user to a voice channel.
    pub async fn join(
        &self,
        redis: &Client,
        user_id: i64,
        channel_id: i64,
        server_id: i64,
    ) -> Result<VoiceState, String> {
        self.join_capped(redis, user_id, channel_id, server_id, usize::MAX)
            .await
            .map(|result| result.state)
            .map_err(|e| match e {
                VoiceJoinError::ChannelFull => "voice channel is full".to_string(),
                VoiceJoinError::Redis => "redis voice join failed".to_string(),
                VoiceJoinError::Serialize => "voice state serialization failed".to_string(),
                VoiceJoinError::UnexpectedResult => "unexpected voice join result".to_string(),
            })
    }

    /// Add a user to a voice channel while enforcing the participant cap
    /// inside Redis. The cap check and membership write must be atomic because
    /// join tokens can be requested concurrently from multiple app servers.
    pub async fn join_capped(
        &self,
        redis: &Client,
        user_id: i64,
        channel_id: i64,
        server_id: i64,
        max_participants: usize,
    ) -> Result<VoiceJoinResult, VoiceJoinError> {
        let previous = self.get_user_state(redis, user_id).await;
        let state = VoiceState {
            user_id,
            channel_id,
            server_id,
            self_mute: false,
            self_deaf: false,
            server_mute: false,
            server_deaf: false,
        };

        let value = serde_json::to_string(&state).map_err(|_| VoiceJoinError::Serialize)?;
        let channel_key = format!("voice:channel:{channel_id}");
        let user_key = format!("voice:user:{user_id}");
        let args = vec![
            user_id.to_string(),
            channel_id.to_string(),
            value,
            max_participants.to_string(),
            "3600".to_string(),
        ];

        let result: i64 = redis
            .eval(VOICE_JOIN_CAPPED_LUA, vec![channel_key, user_key], args)
            .await
            .map_err(|e| {
                tracing::error!(user_id, channel_id, error = %e, "voice join Redis script failed");
                VoiceJoinError::Redis
            })?;

        match result {
            1 => Ok(VoiceJoinResult {
                state,
                previous: previous.filter(|p| p.channel_id != channel_id),
            }),
            -1 => Err(VoiceJoinError::ChannelFull),
            _ => Err(VoiceJoinError::UnexpectedResult),
        }
    }

    /// Remove a user from a specific voice channel.
    pub async fn leave(
        &self,
        redis: &Client,
        user_id: i64,
        channel_id: i64,
    ) -> Result<Option<VoiceState>, String> {
        // Read the state before removing
        let channel_key = format!("voice:channel:{channel_id}");
        let state_json: Option<String> = redis
            .hget(&channel_key, user_id.to_string())
            .await
            .map_err(|e| e.to_string())?;

        let removed = state_json.and_then(|json| serde_json::from_str::<VoiceState>(&json).ok());

        // Remove from channel hash
        let _: () = redis
            .hdel(&channel_key, user_id.to_string())
            .await
            .map_err(|e| e.to_string())?;

        // Clean up empty channel key
        let remaining: i64 = redis.hlen(&channel_key).await.map_err(|e| e.to_string())?;
        if remaining == 0 {
            let _: () = redis.del(&channel_key).await.map_err(|e| e.to_string())?;
        }

        // Clean up user key
        let user_key = format!("voice:user:{user_id}");
        let _: () = redis.del(&user_key).await.map_err(|e| e.to_string())?;

        Ok(removed)
    }

    /// Remove a user from ALL voice channels (e.g., on disconnect).
    pub async fn leave_all(
        &self,
        redis: &Client,
        user_id: i64,
    ) -> Result<Option<VoiceState>, String> {
        let user_key = format!("voice:user:{user_id}");
        let channel_id_str: Option<String> =
            redis.get(&user_key).await.map_err(|e| e.to_string())?;

        if let Some(ch_str) = channel_id_str {
            if let Ok(channel_id) = ch_str.parse::<i64>() {
                return self.leave(redis, user_id, channel_id).await;
            }
        }

        Ok(None)
    }

    /// Update a user's self-mute/deaf state.
    pub async fn update_state(
        &self,
        redis: &Client,
        user_id: i64,
        self_mute: Option<bool>,
        self_deaf: Option<bool>,
    ) -> Result<Option<VoiceState>, String> {
        // Find the user's current channel
        let user_key = format!("voice:user:{user_id}");
        let channel_id_str: Option<String> =
            redis.get(&user_key).await.map_err(|e| e.to_string())?;

        let channel_id = match channel_id_str {
            Some(s) => s.parse::<i64>().map_err(|e| e.to_string())?,
            None => return Ok(None),
        };

        // Read current state from Redis
        let channel_key = format!("voice:channel:{channel_id}");
        let state_json: Option<String> = redis
            .hget(&channel_key, user_id.to_string())
            .await
            .map_err(|e| e.to_string())?;

        let mut state = match state_json {
            Some(json) => serde_json::from_str::<VoiceState>(&json).map_err(|e| e.to_string())?,
            None => return Ok(None),
        };

        // Apply updates
        if let Some(mute) = self_mute {
            state.self_mute = mute;
        }
        if let Some(deaf) = self_deaf {
            state.self_deaf = deaf;
        }

        // Write back to Redis
        let value = serde_json::to_string(&state).map_err(|e| e.to_string())?;
        let _: () = redis
            .hset(&channel_key, (user_id.to_string(), value.as_str()))
            .await
            .map_err(|e| e.to_string())?;
        let _: () = KeysInterface::expire(redis, &channel_key, 3600, None)
            .await
            .map_err(|e| e.to_string())?;
        let _: () = KeysInterface::expire(redis, &user_key, 3600, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Some(state))
    }

    /// Set server-mute or server-deaf on a user (moderation).
    pub async fn set_server_state(
        &self,
        redis: &Client,
        user_id: i64,
        channel_id: i64,
        server_mute: Option<bool>,
        server_deaf: Option<bool>,
    ) -> Result<Option<VoiceState>, String> {
        let channel_key = format!("voice:channel:{channel_id}");
        let state_json: Option<String> = redis
            .hget(&channel_key, user_id.to_string())
            .await
            .map_err(|e| e.to_string())?;

        let mut state = match state_json {
            Some(json) => serde_json::from_str::<VoiceState>(&json).map_err(|e| e.to_string())?,
            None => return Ok(None),
        };

        if let Some(mute) = server_mute {
            state.server_mute = mute;
        }
        if let Some(deaf) = server_deaf {
            state.server_deaf = deaf;
        }

        let value = serde_json::to_string(&state).map_err(|e| e.to_string())?;
        let _: () = redis
            .hset(&channel_key, (user_id.to_string(), value.as_str()))
            .await
            .map_err(|e| e.to_string())?;
        let _: () = KeysInterface::expire(redis, &channel_key, 3600, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Some(state))
    }

    /// Get all participants in a voice channel.
    pub async fn get_participants(&self, redis: &Client, channel_id: i64) -> Vec<VoiceState> {
        let channel_key = format!("voice:channel:{channel_id}");
        let entries: std::collections::HashMap<String, String> =
            match redis.hgetall(&channel_key).await {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };

        entries
            .values()
            .filter_map(|json| serde_json::from_str::<VoiceState>(json).ok())
            .collect()
    }

    /// Get a user's current voice state (if in a channel).
    pub async fn get_user_state(&self, redis: &Client, user_id: i64) -> Option<VoiceState> {
        let user_key = format!("voice:user:{user_id}");
        let channel_id_str: Option<String> = redis.get(&user_key).await.ok()?;
        let channel_id = channel_id_str?.parse::<i64>().ok()?;

        let channel_key = format!("voice:channel:{channel_id}");
        let state_json: Option<String> =
            redis.hget(&channel_key, user_id.to_string()).await.ok()?;
        state_json.and_then(|json| serde_json::from_str::<VoiceState>(&json).ok())
    }
}

// ─── LiveKit Integration ─────────────────────────────────────────────

/// Deterministic LiveKit room name from server + channel IDs.
pub fn livekit_room_name(server_id: i64, channel_id: i64) -> String {
    format!("verdant:{server_id}:{channel_id}")
}

const LIVEKIT_RR_KEY: &str = "voice:livekit:rr";
const LIVEKIT_ROOM_NODE_TTL_SECS: i64 = 24 * 60 * 60;
const LIVEKIT_NODE_REGISTRY_KEY: &str = "voice:livekit:nodes:v1";
const LIVEKIT_NODE_HEARTBEAT_PREFIX: &str = "voice:livekit:heartbeat:v1:";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveKitRoomPlacement {
    node: String,
    region: Option<String>,
    url: String,
    created_at: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
struct LiveKitRegistryNodeRecord {
    name: String,
    url: String,
    #[serde(alias = "api_url")]
    api_url: String,
    region: Option<String>,
    weight: Option<u32>,
}

fn livekit_room_node_key(room_name: &str) -> String {
    format!("voice:livekit:room_node:{room_name}")
}

fn livekit_node_heartbeat_key(name: &str) -> String {
    format!("{LIVEKIT_NODE_HEARTBEAT_PREFIX}{name}")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn livekit_total_weight(nodes: &[LiveKitNodeConfig]) -> u64 {
    nodes
        .iter()
        .map(|node| node.weight as u64)
        .sum::<u64>()
        .max(1)
}

fn livekit_weighted_index(nodes: &[LiveKitNodeConfig], value: u64) -> usize {
    let total = livekit_total_weight(nodes);
    let mut slot = value % total;
    for (index, node) in nodes.iter().enumerate() {
        let weight = node.weight as u64;
        if slot < weight {
            return index;
        }
        slot = slot.saturating_sub(weight);
    }
    0
}

fn livekit_hash_index(nodes: &[LiveKitNodeConfig], room_name: &str) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(room_name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    livekit_weighted_index(nodes, u64::from_be_bytes(bytes))
}

fn livekit_node_by_name(nodes: &[LiveKitNodeConfig], name: &str) -> Option<LiveKitNodeConfig> {
    nodes.iter().find(|node| node.name == name).cloned()
}

fn livekit_registry_node_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn livekit_region_is_valid(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 32
        && region
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn livekit_public_host_is_allowed(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    host == "voice.verdant.chat" || (host.starts_with("voice-") && host.ends_with(".verdant.chat"))
}

fn private_api_ip_is_allowed(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_private(),
        Ok(IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            (first & 0xfe00) == 0xfc00
        }
        Err(_) => false,
    }
}

fn assert_no_registry_url_credentials(
    parsed: &Url,
    field: &str,
    node_name: &str,
) -> Result<(), String> {
    if parsed.username().is_empty() && parsed.password().is_none() {
        Ok(())
    } else {
        Err(format!(
            "{field} for LiveKit registry node '{node_name}' must not include credentials"
        ))
    }
}

fn livekit_node_from_registry_record(
    key_name: &str,
    value: &str,
) -> Result<LiveKitNodeConfig, String> {
    let raw: LiveKitRegistryNodeRecord =
        serde_json::from_str(value).map_err(|e| format!("invalid node JSON: {e}"))?;
    let name = raw.name.trim().to_string();
    if name != key_name {
        return Err(format!(
            "node key '{key_name}' does not match node payload name '{name}'"
        ));
    }
    if !livekit_registry_node_name_is_valid(&name) {
        return Err(format!("invalid LiveKit registry node name '{name}'"));
    }

    let url = raw.url.trim().trim_end_matches('/').to_string();
    let parsed_url = Url::parse(&url).map_err(|e| format!("invalid public URL: {e}"))?;
    assert_no_registry_url_credentials(&parsed_url, "url", &name)?;
    if parsed_url.scheme() != "wss" {
        return Err("LiveKit registry public URL must use wss://".to_string());
    }
    if parsed_url.query().is_some() || parsed_url.fragment().is_some() {
        return Err("LiveKit registry public URL must not include query or fragment".to_string());
    }
    let public_host = parsed_url
        .host_str()
        .ok_or_else(|| "LiveKit registry public URL must include a host".to_string())?;
    if !livekit_public_host_is_allowed(public_host) {
        return Err(format!(
            "LiveKit registry public host '{public_host}' is not an allowed Verdant voice host"
        ));
    }

    let api_url = raw.api_url.trim().trim_end_matches('/').to_string();
    let parsed_api_url = Url::parse(&api_url).map_err(|e| format!("invalid API URL: {e}"))?;
    assert_no_registry_url_credentials(&parsed_api_url, "apiUrl", &name)?;
    if !matches!(parsed_api_url.scheme(), "http" | "https") {
        return Err("LiveKit registry API URL must use http:// or https://".to_string());
    }
    if parsed_api_url.query().is_some() || parsed_api_url.fragment().is_some() {
        return Err("LiveKit registry API URL must not include query or fragment".to_string());
    }
    let api_host = parsed_api_url
        .host_str()
        .ok_or_else(|| "LiveKit registry API URL must include a host".to_string())?;
    if !private_api_ip_is_allowed(api_host) {
        return Err(format!(
            "LiveKit registry API host '{api_host}' is not a private VPC IP"
        ));
    }

    let weight = raw.weight.unwrap_or(1);
    if !(1..=1000).contains(&weight) {
        return Err(format!(
            "LiveKit registry node '{name}' weight must be between 1 and 1000"
        ));
    }

    let region = raw.region.and_then(|region| {
        let region = region.trim().to_ascii_lowercase();
        if region.is_empty() {
            None
        } else {
            Some(region)
        }
    });
    if let Some(region) = &region {
        if !livekit_region_is_valid(region) {
            return Err(format!(
                "LiveKit registry node '{name}' has invalid region '{region}'"
            ));
        }
    }

    Ok(LiveKitNodeConfig {
        name,
        url,
        api_url,
        region,
        weight,
    })
}

fn livekit_nodes_from_registry_records(
    records: &HashMap<String, String>,
    healthy_names: &HashSet<String>,
) -> Vec<LiveKitNodeConfig> {
    let mut names = records.keys().cloned().collect::<Vec<_>>();
    names.sort();

    names
        .into_iter()
        .filter(|name| healthy_names.contains(name))
        .filter_map(|name| match records.get(&name) {
            Some(value) => match livekit_node_from_registry_record(&name, value) {
                Ok(node) => Some(node),
                Err(e) => {
                    tracing::warn!(
                        node = %name,
                        error = %e,
                        "Ignoring invalid LiveKit registry node"
                    );
                    None
                }
            },
            None => None,
        })
        .collect()
}

async fn livekit_nodes_from_registry(redis: &Client) -> Result<Vec<LiveKitNodeConfig>, String> {
    let records: HashMap<String, String> = redis
        .hgetall(LIVEKIT_NODE_REGISTRY_KEY)
        .await
        .map_err(|e| format!("read LiveKit registry: {e}"))?;
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let mut healthy_names = HashSet::new();
    for name in records.keys() {
        let exists: i64 = redis
            .exists(livekit_node_heartbeat_key(name))
            .await
            .map_err(|e| format!("read LiveKit heartbeat for {name}: {e}"))?;
        if exists > 0 {
            healthy_names.insert(name.clone());
        }
    }

    Ok(livekit_nodes_from_registry_records(
        &records,
        &healthy_names,
    ))
}

async fn resolve_livekit_nodes(
    redis: &Client,
    fallback_nodes: &[LiveKitNodeConfig],
) -> Vec<LiveKitNodeConfig> {
    match livekit_nodes_from_registry(redis).await {
        Ok(nodes) if !nodes.is_empty() => nodes,
        Ok(_) => fallback_nodes.to_vec(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "LiveKit registry read failed; falling back to configured nodes"
            );
            fallback_nodes.to_vec()
        }
    }
}

fn livekit_room_placement_for_node(node: &LiveKitNodeConfig) -> LiveKitRoomPlacement {
    LiveKitRoomPlacement {
        node: node.name.clone(),
        region: node.region.clone(),
        url: node.url.clone(),
        created_at: unix_now_secs(),
    }
}

fn parse_livekit_room_placement_node(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('{') {
        serde_json::from_str::<LiveKitRoomPlacement>(trimmed)
            .ok()
            .map(|placement| placement.node)
    } else {
        Some(trimmed.to_string())
    }
}

fn livekit_node_from_placement_value(
    nodes: &[LiveKitNodeConfig],
    value: &str,
) -> Option<LiveKitNodeConfig> {
    parse_livekit_room_placement_node(value).and_then(|name| livekit_node_by_name(nodes, &name))
}

async fn persist_livekit_room_node(redis: &Client, room_name: &str, node: &LiveKitNodeConfig) {
    let key = livekit_room_node_key(room_name);
    let payload = serde_json::to_string(&livekit_room_placement_for_node(node))
        .unwrap_or_else(|_| node.name.clone());
    let _: Result<(), _> = redis
        .set::<(), _, _>(
            &key,
            payload,
            Some(fred::types::Expiration::EX(LIVEKIT_ROOM_NODE_TTL_SECS)),
            None,
            false,
        )
        .await;
}

async fn persist_livekit_room_node_if_absent(
    redis: &Client,
    room_name: &str,
    node: &LiveKitNodeConfig,
) -> Result<bool, fred::error::Error> {
    let key = livekit_room_node_key(room_name);
    let payload = serde_json::to_string(&livekit_room_placement_for_node(node))
        .unwrap_or_else(|_| node.name.clone());
    KeysInterface::set(
        redis,
        &key,
        payload,
        Some(fred::types::Expiration::EX(LIVEKIT_ROOM_NODE_TTL_SECS)),
        Some(fred::types::SetOptions::NX),
        false,
    )
    .await
}

/// Choose a LiveKit signaling/API node for a Verdant voice room.
///
/// Selection is round-robin per room creation, then sticky per room through
/// Redis so multiple app-server instances keep returning the same preferred
/// node for the same voice channel. LiveKit Redis clustering is still required
/// for true multi-node SFU routing; this selector only chooses the signaling
/// endpoint and RoomService API target.
pub async fn select_livekit_node(
    redis: &Client,
    nodes: &[LiveKitNodeConfig],
    room_name: &str,
) -> Result<LiveKitNodeConfig, String> {
    if nodes.is_empty() {
        return Err("No LiveKit nodes configured".to_string());
    }

    let room_key = livekit_room_node_key(room_name);
    match redis.get::<Option<String>, _>(&room_key).await {
        Ok(Some(value)) => {
            if let Some(node) = livekit_node_from_placement_value(nodes, &value) {
                return Ok(node);
            }
            tracing::warn!(
                room = %room_name,
                "Ignoring stale LiveKit room-node mapping"
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                error = %e,
                room = %room_name,
                "LiveKit node selection Redis read failed; using deterministic fallback"
            );
            return Ok(nodes[livekit_hash_index(nodes, room_name)].clone());
        }
    }

    let idx = match KeysInterface::incr_by::<i64, _>(redis, LIVEKIT_RR_KEY, 1i64).await {
        Ok(counter) => livekit_weighted_index(nodes, counter.saturating_sub(1) as u64),
        Err(e) => {
            tracing::warn!(
                error = %e,
                room = %room_name,
                "LiveKit node selection Redis counter failed; using deterministic fallback"
            );
            livekit_hash_index(nodes, room_name)
        }
    };

    let selected = nodes[idx].clone();
    match persist_livekit_room_node_if_absent(redis, room_name, &selected).await {
        Ok(true) => Ok(selected),
        Ok(false) => match redis.get::<Option<String>, _>(&room_key).await {
            Ok(Some(value)) => {
                if let Some(node) = livekit_node_from_placement_value(nodes, &value) {
                    Ok(node)
                } else {
                    tracing::warn!(
                        room = %room_name,
                        "LiveKit room-node mapping changed to an unknown node; using local selection"
                    );
                    Ok(selected)
                }
            }
            Ok(None) => Ok(selected),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    room = %room_name,
                    "LiveKit node selection Redis reread failed after placement race"
                );
                Ok(selected)
            }
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                room = %room_name,
                "LiveKit room placement Redis write failed; using local selection"
            );
            Ok(selected)
        }
    }
}

/// Create a LiveKit room on the selected cluster endpoint, failing over to
/// other configured nodes if the selected endpoint is temporarily unavailable.
pub async fn create_livekit_room_on_cluster(
    redis: &Client,
    configured_nodes: &[LiveKitNodeConfig],
    api_key: &str,
    api_secret: &str,
    room_name: &str,
) -> Result<LiveKitNodeConfig, String> {
    let nodes = resolve_livekit_nodes(redis, configured_nodes).await;
    let preferred = select_livekit_node(redis, &nodes, room_name).await?;
    let mut attempts = Vec::with_capacity(nodes.len());
    attempts.push(preferred.clone());
    attempts.extend(
        nodes
            .iter()
            .filter(|node| node.name != preferred.name)
            .cloned(),
    );

    let mut errors = Vec::new();
    for node in attempts {
        match create_livekit_room(&node.api_url, api_key, api_secret, room_name).await {
            Ok(()) => {
                if node.name != preferred.name {
                    persist_livekit_room_node(redis, room_name, &node).await;
                    tracing::warn!(
                        preferred = %preferred.name,
                        fallback = %node.name,
                        room = %room_name,
                        "LiveKit room creation succeeded on fallback node"
                    );
                }
                return Ok(node);
            }
            Err(e) => {
                tracing::warn!(
                    node = %node.name,
                    room = %room_name,
                    error = %e,
                    "LiveKit room creation failed on node"
                );
                errors.push(format!("{}: {e}", node.name));
            }
        }
    }

    Err(format!(
        "LiveKit CreateRoom failed on all configured nodes ({})",
        errors.join("; ")
    ))
}

/// LiveKit JWT claims matching the server SDK format.
#[derive(Debug, Serialize)]
struct LiveKitClaims {
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    iat: u64,
    nbf: u64,
    exp: u64,
    video: LiveKitVideoGrant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LiveKitVideoGrant {
    #[serde(skip_serializing_if = "Option::is_none")]
    room: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    room_join: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    room_create: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    room_list: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    room_admin: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_publish: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_subscribe: bool,
    #[serde(skip_serializing_if = "is_false")]
    can_publish_data: bool,
}

fn is_false(v: &bool) -> bool {
    !v
}

/// Generate a LiveKit access token for a participant.
pub fn generate_livekit_token(
    api_key: &str,
    api_secret: &str,
    room_name: &str,
    participant_identity: &str,
) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let claims = LiveKitClaims {
        iss: api_key.to_string(),
        sub: Some(participant_identity.to_string()),
        iat: now,
        nbf: now,
        exp: now + 600, // 10 minutes
        video: LiveKitVideoGrant {
            room: Some(room_name.to_string()),
            room_join: true,
            room_create: false,
            room_list: false,
            room_admin: false,
            can_publish: true,
            can_subscribe: true,
            can_publish_data: false,
        },
    };

    let key = EncodingKey::from_secret(api_secret.as_bytes());
    jsonwebtoken::encode(&Header::default(), &claims, &key).map_err(|e| e.to_string())
}

/// Generate a service-level JWT for LiveKit Room Service API calls.
fn generate_service_token(api_key: &str, api_secret: &str) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let claims = LiveKitClaims {
        iss: api_key.to_string(),
        sub: None,
        iat: now,
        nbf: now,
        exp: now + 60,
        video: LiveKitVideoGrant {
            room: None,
            room_join: false,
            room_create: true,
            room_list: true,
            room_admin: true,
            can_publish: false,
            can_subscribe: false,
            can_publish_data: false,
        },
    };

    let key = EncodingKey::from_secret(api_secret.as_bytes());
    jsonwebtoken::encode(&Header::default(), &claims, &key).map_err(|e| e.to_string())
}

/// Create a LiveKit room via the Room Service API.
/// Ignores "already exists" errors.
pub async fn create_livekit_room(
    api_url: &str,
    api_key: &str,
    api_secret: &str,
    room_name: &str,
) -> Result<(), String> {
    let token = generate_service_token(api_key, api_secret)?;

    let url = format!(
        "{}/twirp/livekit.RoomService/CreateRoom",
        api_url.trim_end_matches('/')
    );

    let resp = HTTP_CLIENT
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "name": room_name,
            "empty_timeout": 300,
            "max_participants": LIVEKIT_ROOM_MAX_PARTICIPANTS,
            // Low-latency audio: minimize jitter buffer on the receiver side.
            // min_playout_delay=0 tells LiveKit to play audio ASAP with minimal
            // buffering. max_playout_delay caps the adaptive buffer at 150ms
            // instead of the default ~400ms, reducing end-to-end latency for
            // voice chat at the cost of slightly less robustness to jitter.
            "min_playout_delay": 0,
            "max_playout_delay": 150,
        }))
        .send()
        .await
        .map_err(|e| format!("LiveKit API request failed: {e}"))?;

    if resp.status().is_success() || resp.status().as_u16() == 409 {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        // "already exists" is fine
        if body.contains("already exists") {
            Ok(())
        } else {
            Err(format!("LiveKit CreateRoom failed ({status}): {body}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LiveKitNodeConfig, livekit_hash_index, livekit_node_from_placement_value,
        livekit_nodes_from_registry_records, livekit_room_name, livekit_room_placement_for_node,
        livekit_weighted_index,
    };
    use std::collections::{HashMap, HashSet};

    fn node(name: &str, weight: u32) -> LiveKitNodeConfig {
        LiveKitNodeConfig {
            name: name.to_string(),
            url: format!("wss://{name}.verdant.chat"),
            api_url: format!("http://10.0.0.{weight}:7880"),
            region: Some("nyc1".to_string()),
            weight,
        }
    }

    #[test]
    fn livekit_room_names_are_channel_scoped() {
        assert_eq!(livekit_room_name(10, 20), "verdant:10:20");
    }

    #[test]
    fn livekit_weighted_index_respects_weights() {
        let nodes = vec![node("a", 2), node("b", 1)];
        assert_eq!(livekit_weighted_index(&nodes, 0), 0);
        assert_eq!(livekit_weighted_index(&nodes, 1), 0);
        assert_eq!(livekit_weighted_index(&nodes, 2), 1);
        assert_eq!(livekit_weighted_index(&nodes, 3), 0);
    }

    #[test]
    fn livekit_hash_index_is_stable_for_room() {
        let nodes = vec![node("a", 1), node("b", 1), node("c", 1)];
        let first = livekit_hash_index(&nodes, "verdant:1:2");
        let second = livekit_hash_index(&nodes, "verdant:1:2");
        assert_eq!(first, second);
        assert!(first < nodes.len());
    }

    #[test]
    fn livekit_room_placement_accepts_json_and_legacy_node_names() {
        let nodes = vec![node("a", 1), node("b", 1)];
        let placement = serde_json::to_string(&livekit_room_placement_for_node(&nodes[1]))
            .expect("placement should serialize");

        assert_eq!(
            livekit_node_from_placement_value(&nodes, &placement)
                .expect("json placement should resolve")
                .name,
            "b"
        );
        assert_eq!(
            livekit_node_from_placement_value(&nodes, "a")
                .expect("legacy placement should resolve")
                .name,
            "a"
        );
        assert!(livekit_node_from_placement_value(&nodes, "missing").is_none());
    }

    #[test]
    fn livekit_registry_uses_only_healthy_valid_nodes() {
        let mut records = HashMap::new();
        records.insert(
            "livekit-nyc1-01".to_string(),
            serde_json::json!({
                "name": "livekit-nyc1-01",
                "url": "wss://voice.verdant.chat",
                "apiUrl": "http://10.116.0.6:7880",
                "region": "nyc1",
                "weight": 1
            })
            .to_string(),
        );
        records.insert(
            "livekit-nyc1-02".to_string(),
            serde_json::json!({
                "name": "livekit-nyc1-02",
                "url": "wss://voice-nyc1-02.verdant.chat",
                "apiUrl": "http://10.116.0.7:7880",
                "region": "nyc1",
                "weight": 1
            })
            .to_string(),
        );
        let healthy = HashSet::from(["livekit-nyc1-01".to_string()]);

        let nodes = livekit_nodes_from_registry_records(&records, &healthy);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "livekit-nyc1-01");
        assert_eq!(nodes[0].url, "wss://voice.verdant.chat");
        assert_eq!(nodes[0].api_url, "http://10.116.0.6:7880");
    }

    #[test]
    fn livekit_registry_rejects_untrusted_routes() {
        let mut records = HashMap::new();
        records.insert(
            "mismatch".to_string(),
            serde_json::json!({
                "name": "different",
                "url": "wss://voice.verdant.chat",
                "apiUrl": "http://10.116.0.6:7880"
            })
            .to_string(),
        );
        records.insert(
            "external-api".to_string(),
            serde_json::json!({
                "name": "external-api",
                "url": "wss://voice.verdant.chat",
                "apiUrl": "http://example.com:7880"
            })
            .to_string(),
        );
        records.insert(
            "bad-public-url".to_string(),
            serde_json::json!({
                "name": "bad-public-url",
                "url": "wss://evil.example.com",
                "apiUrl": "http://10.116.0.6:7880"
            })
            .to_string(),
        );
        records.insert(
            "metadata-ip".to_string(),
            serde_json::json!({
                "name": "metadata-ip",
                "url": "wss://voice-nyc1-03.verdant.chat",
                "apiUrl": "http://169.254.169.254:80"
            })
            .to_string(),
        );
        let healthy = records.keys().cloned().collect();

        let nodes = livekit_nodes_from_registry_records(&records, &healthy);

        assert!(nodes.is_empty());
    }
}
