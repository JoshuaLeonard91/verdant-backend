use fred::interfaces::{EventInterface, KeysInterface, PubsubInterface};
use fred::types::Expiration;
use prost::Message;
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::Ordering;

use crate::proto::WsMessage;
use crate::state::{AppState, NodeRuntimeInfo};

use super::connection::OutboundMsg;

const OPS_DRAIN_TOPIC: &str = "ops:drain";
const DEFAULT_DRAIN_CLOSE_AFTER_MS: u64 = 750;
const MAX_DRAIN_DELAY_MS: u64 = 30_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrainCommand {
    #[serde(default)]
    pub target_node_id: Option<String>,
    #[serde(default)]
    pub target_droplet_id: Option<String>,
    #[serde(default)]
    pub target_public_ip: Option<String>,
    #[serde(default)]
    pub target_name: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub reconnect_after_ms: Option<u64>,
    #[serde(default)]
    pub close_after_ms: Option<u64>,
}

/// Topic naming conventions (matches the TS implementation).
pub fn channel_topic(channel_id: i64) -> String {
    format!("channel:{channel_id}")
}

pub fn channel_live_topic(channel_id: i64) -> String {
    format!("channel_live:{channel_id}")
}

pub fn channel_notify_topic(channel_id: i64) -> String {
    format!("channel_notify:{channel_id}")
}

pub fn voice_topic(channel_id: i64) -> String {
    format!("voice:{channel_id}")
}

pub fn focused_channel_topics(channel_id: i64) -> [String; 2] {
    [
        channel_live_topic(channel_id),
        channel_notify_topic(channel_id),
    ]
}

pub fn all_channel_topics(channel_id: i64) -> Vec<String> {
    vec![
        channel_topic(channel_id),
        channel_live_topic(channel_id),
        channel_notify_topic(channel_id),
        voice_topic(channel_id),
    ]
}

pub fn presence_topic(server_id: i64) -> String {
    format!("presence:{server_id}")
}

pub fn user_topic(user_id: i64) -> String {
    format!("user:{user_id}")
}

pub fn system_topic() -> String {
    "broadcast:system".to_string()
}

fn is_realtime_scope_topic(topic: &str) -> bool {
    topic.starts_with("channel:")
        || topic.starts_with("channel_live:")
        || topic.starts_with("channel_notify:")
        || topic.starts_with("voice:")
        || topic.starts_with("presence:")
        || topic.starts_with("user:")
}

pub fn server_draining_json(reason: &str, reconnect_after_ms: u64, close_after_ms: u64) -> String {
    json!({
        "op": "SERVER_DRAINING",
        "d": {
            "reason": reason,
            "reconnectAfterMs": reconnect_after_ms,
            "closeAfterMs": close_after_ms,
        }
    })
    .to_string()
}

fn sanitize_drain_reason(reason: Option<&str>) -> String {
    let cleaned = reason
        .unwrap_or("zdt")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .take(64)
        .collect::<String>();
    if cleaned.trim().is_empty() {
        "zdt".to_string()
    } else {
        cleaned
    }
}

fn drain_targets_node(node_id: &str, node: &NodeRuntimeInfo, cmd: &DrainCommand) -> bool {
    let mut has_target = false;

    if let Some(target) = cmd.target_node_id.as_deref() {
        has_target = true;
        if target == node_id {
            return true;
        }
    }
    if let Some(target) = cmd.target_droplet_id.as_deref() {
        has_target = true;
        if node.droplet_id.as_deref() == Some(target) {
            return true;
        }
    }
    if let Some(target) = cmd.target_public_ip.as_deref() {
        has_target = true;
        if node.public_ip.as_deref() == Some(target) {
            return true;
        }
    }
    if let Some(target) = cmd.target_name.as_deref() {
        has_target = true;
        if node.name.as_deref() == Some(target) {
            return true;
        }
    }

    if !has_target {
        tracing::warn!("Ignoring untargeted drain command");
    }
    false
}

fn command_targets_node(state: &AppState, cmd: &DrainCommand) -> bool {
    drain_targets_node(&state.node_id, &state.node, cmd)
}

async fn handle_drain_command(state: AppState, cmd: DrainCommand) {
    if !command_targets_node(&state, &cmd) {
        tracing::debug!(node_id = %state.node_id, command = ?cmd, "Ignoring drain command for another node");
        return;
    }

    if state.draining.swap(true, Ordering::AcqRel) {
        tracing::info!(node_id = %state.node_id, "Drain command ignored: node is already draining");
        return;
    }

    let reconnect_after_ms = cmd.reconnect_after_ms.unwrap_or(0).min(5_000);
    let close_after_ms = cmd
        .close_after_ms
        .unwrap_or(DEFAULT_DRAIN_CLOSE_AFTER_MS)
        .clamp(100, MAX_DRAIN_DELAY_MS);
    let reason = sanitize_drain_reason(cmd.reason.as_deref());
    let event =
        OutboundMsg::Text(server_draining_json(&reason, reconnect_after_ms, close_after_ms).into());

    let conn_ids = state.ws.all_conn_ids();
    let connection_count = conn_ids.len();
    for conn_id in &conn_ids {
        state.ws.send_to(*conn_id, event.clone());
    }
    tracing::info!(
        node_id = %state.node_id,
        connection_count,
        reconnect_after_ms,
        close_after_ms,
        "Sent planned drain event to local WebSocket clients"
    );

    tokio::time::sleep(std::time::Duration::from_millis(close_after_ms)).await;

    for conn_id in conn_ids {
        state.ws.send_to(
            conn_id,
            OutboundMsg::Close(1001, "Server draining".to_string()),
        );
    }
    tracing::info!(
        node_id = %state.node_id,
        connection_count,
        "Closed local WebSocket clients for planned drain"
    );
}

/// Encode a WsMessage to protobuf bytes.
fn encode_proto(msg: &WsMessage) -> Vec<u8> {
    msg.encode_to_vec()
}

/// Build a binary Redis envelope: [node_id_len (1 byte)][node_id bytes][proto bytes]
/// This avoids JSON serialization for cross-instance message delivery.
fn redis_proto_envelope(node_id: &str, proto_bytes: &[u8]) -> Vec<u8> {
    let node_bytes = node_id.as_bytes();
    let mut buf = Vec::with_capacity(1 + node_bytes.len() + proto_bytes.len());
    buf.push(node_bytes.len() as u8);
    buf.extend_from_slice(node_bytes);
    buf.extend_from_slice(proto_bytes);
    buf
}

/// Parse a binary Redis envelope, returning (node_id, proto_bytes).
fn parse_redis_proto_envelope(data: &[u8]) -> Option<(&str, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let node_len = data[0] as usize;
    if data.len() < 1 + node_len {
        return None;
    }
    let node_id = std::str::from_utf8(&data[1..1 + node_len]).ok()?;
    let proto_bytes = &data[1 + node_len..];
    Some((node_id, proto_bytes))
}

/// Legacy JSON envelope for events that don't have proto definitions.
fn redis_json_envelope(node_id: &str, json: &str) -> String {
    format!("{node_id}\n{json}")
}

/// Parse a legacy JSON envelope.
fn parse_json_envelope(payload: &str) -> (&str, &str) {
    match payload.split_once('\n') {
        Some((node_id, json)) => (node_id, json),
        None => ("", payload),
    }
}

/// Publish a message to a topic via sharded broadcast + Redis for cross-instance.
///
/// Uses the `BroadcastService` worker pool for parallel fan-out to local
/// subscribers, replacing the sequential `publish_local_proto_first` loop.
/// Proto bytes are built once and shared (via Arc) across all workers.
/// JSON text is only used if a connection uses JSON encoding.
pub async fn publish(state: &AppState, topic: &str, json_text: &str, proto_msg: &WsMessage) {
    let proto_bytes = encode_proto(proto_msg);

    // Parallel fan-out via sharded worker pool (replaces sequential publish_local)
    let local_count = state
        .broadcast
        .publish(&state.ws, topic, &proto_bytes, json_text)
        .await;
    tracing::debug!(topic, local_count, "Published to topic (sharded broadcast)");

    // Redis cross-instance: send proto bytes (not JSON)
    let envelope = redis_proto_envelope(&state.node_id, &proto_bytes);

    // Cross-region relay: same envelope bytes go over NATS, so the
    // peer region's Redis sees a payload shaped identically to a
    // local publish (embedded remote node_id survives the trip).
    if let Some(bridge) = state.nats_bridge.as_ref() {
        bridge.publish_xr(topic, &envelope);
    }

    let redis = state.redis.clone();
    let topic_owned = topic.to_string();
    tokio::spawn(async move {
        if let Err(e) = redis
            .publish::<i64, _, _>(topic_owned.clone(), envelope)
            .await
        {
            tracing::warn!(topic = %topic_owned, error = %e, "Redis cross-instance publish failed");
        }
    });
}

/// Publish JSON-only to a topic (no protobuf variant available for this event).
/// Used for events like TYPING_START, PRESENCE_UPDATE that don't have proto defs.
pub async fn publish_json(state: &AppState, topic: &str, json_text: &str) {
    let json_out = OutboundMsg::Text(json_text.into());
    let local_count = state.ws.publish_local(topic, &json_out, None);
    tracing::debug!(topic, local_count, "Published JSON-only to topic");

    // JSON-only events still use the legacy JSON envelope over Redis
    let redis_payload = redis_json_envelope(&state.node_id, json_text);
    let redis = state.redis.clone();
    let topic_owned = topic.to_string();
    tokio::spawn(async move {
        if let Err(e) = redis
            .publish::<i64, _, _>(topic_owned.clone(), redis_payload)
            .await
        {
            tracing::warn!(topic = %topic_owned, error = %e, "Redis cross-instance JSON publish failed");
        }
    });
}

/// Publish the same event to multiple topics.
pub async fn publish_to_topics(
    state: &AppState,
    topics: &[String],
    json_text: &str,
    proto_msg: &WsMessage,
) {
    for topic in topics {
        publish(state, topic, json_text, proto_msg).await;
    }
}

/// Publish to a server's presence topic (convenience wrapper).
pub async fn publish_to_presence(
    state: &AppState,
    server_id: i64,
    json_text: &str,
    proto_msg: &WsMessage,
) {
    let topic = presence_topic(server_id);
    publish(state, &topic, json_text, proto_msg).await;
}

/// Publish a feed/announcement event scoped by the feed's
/// `visible_role_ids`. If the feed is unrestricted (empty list), this
/// behaves identically to `publish_to_presence` — everyone in the
/// server can see it. If the feed is role-gated, the event is
/// delivered only to entitled online members (admins / owners / role
/// holders) via their per-user topic, so non-entitled members never
/// learn that a restricted feed exists or was updated.
///
/// Delivery model: entitled users are looked up via the permission
/// cache (which only tracks online users). Offline users refetch via
/// IDENTIFY on reconnect, and IDENTIFY now applies the same
/// visibility filter — so they can't back-door the feed.
pub async fn publish_feed_scoped(
    state: &AppState,
    server_id: i64,
    visible_role_ids: &[i64],
    json_text: &str,
    proto_msg: &WsMessage,
) {
    if visible_role_ids.is_empty() {
        publish(state, &presence_topic(server_id), json_text, proto_msg).await;
        return;
    }
    let allowed: std::collections::HashSet<i64> = visible_role_ids.iter().copied().collect();
    let entitled = state
        .permissions
        .collect_entitled_online_members(server_id, &allowed);
    if entitled.is_empty() {
        return;
    }
    for user_id in entitled {
        publish(state, &user_topic(user_id), json_text, proto_msg).await;
    }
}

/// Publish to a topic, excluding a specific connection (e.g., the sender).
pub async fn publish_except(
    state: &AppState,
    topic: &str,
    json_text: &str,
    proto_msg: &WsMessage,
    exclude_conn: u64,
) {
    let proto_bytes = encode_proto(proto_msg);
    let json_out = OutboundMsg::Text(json_text.into());

    // Local routing with exclusion
    let local_count =
        state
            .ws
            .publish_local_except(topic, &json_out, Some(&proto_bytes), exclude_conn);
    tracing::debug!(
        topic,
        local_count,
        exclude_conn,
        "Published to topic (with exclusion)"
    );

    // Redis: proto envelope
    let envelope = redis_proto_envelope(&state.node_id, &proto_bytes);

    // Cross-region relay (see note in `publish` above).
    if let Some(bridge) = state.nats_bridge.as_ref() {
        bridge.publish_xr(topic, &envelope);
    }

    let redis = state.redis.clone();
    let topic_owned = topic.to_string();
    tokio::spawn(async move {
        if let Err(e) = redis
            .publish::<i64, _, _>(topic_owned.clone(), envelope)
            .await
        {
            tracing::warn!(topic = %topic_owned, error = %e, "Redis cross-instance publish failed");
        }
    });
}

/// Start the Redis subscriber listener that bridges Redis pub/sub to local connections.
/// Handles both binary proto envelopes (new) and legacy JSON envelopes (backward compat).
///
/// If the Redis subscriber disconnects, the bridge will retry with exponential
/// backoff (1s → 2s → 4s → ... → 30s max). Cross-instance messages are lost
/// during the disconnection window, but local delivery is unaffected.
pub async fn start_redis_subscriber(state: AppState) {
    let mut attempts = 0u32;
    loop {
        attempts = attempts.saturating_add(1);
        match state.redis_sub.subscribe(OPS_DRAIN_TOPIC).await {
            Ok(()) => {
                tracing::info!(
                    topic = OPS_DRAIN_TOPIC,
                    attempts,
                    "Redis drain topic subscribed"
                );
                break;
            }
            Err(e) => {
                tracing::warn!(
                    topic = OPS_DRAIN_TOPIC,
                    attempts,
                    error = %e,
                    "Redis drain topic subscribe failed; retrying"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    let state = state.clone();

    tokio::spawn(async move {
        let mut backoff_secs = 1u64;
        let mut total_lagged: u64 = 0;
        loop {
            let mut rx = state.redis_sub.message_rx();
            tracing::info!("Redis pub/sub bridge started");
            let mut received_since_subscribe = false;

            // Inner loop: process messages until the receiver is closed.
            // We distinguish `Lagged(n)` (buffer overflowed — those n
            // messages are dropped but the connection is healthy and we
            // should keep going) from `Closed` (subscriber actually
            // dropped — break out and reconnect with backoff). The
            // previous `while let Ok(msg) = rx.recv().await` collapsed
            // both into "disconnected", which fired hundreds of times at
            // 1000+ WS clients whenever the broadcast buffer briefly
            // overflowed under broadcast burst pressure.
            let bridge_closed = loop {
                match rx.recv().await {
                    Ok(msg) => {
                        if !received_since_subscribe {
                            received_since_subscribe = true;
                            backoff_secs = 1;
                        }

                        let topic = msg.channel.to_string();

                        let raw_bytes: Vec<u8> = match msg.value.convert::<Vec<u8>>() {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        if topic == OPS_DRAIN_TOPIC {
                            match serde_json::from_slice::<DrainCommand>(&raw_bytes) {
                                Ok(cmd) => {
                                    let state = state.clone();
                                    tokio::spawn(async move {
                                        handle_drain_command(state, cmd).await;
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Invalid Redis drain command");
                                }
                            }
                            continue;
                        }

                        // Try binary proto envelope first (new format: [len][node_id][proto])
                        if let Some((origin_node, proto_bytes)) =
                            parse_redis_proto_envelope(&raw_bytes)
                        {
                            if origin_node == state.node_id {
                                continue;
                            }

                            let looks_like_proto = !proto_bytes.is_empty() && raw_bytes[0] == 16;

                            if looks_like_proto {
                                tracing::debug!(
                                    topic = %topic,
                                    origin = %origin_node,
                                    "Redis proto from remote"
                                );
                                let proto_arc: std::sync::Arc<[u8]> =
                                    std::sync::Arc::from(proto_bytes);
                                if let Some(conns) = state.ws.topic_subscribers.get(&topic) {
                                    for &conn_id in conns.iter() {
                                        if let Some(info) = state.ws.conn_info.get(&conn_id) {
                                            let _ = info
                                                .0
                                                .try_send(OutboundMsg::Binary(proto_arc.clone()));
                                        }
                                    }
                                }
                                continue;
                            }
                        }

                        // Fallback: legacy JSON envelope (node_id\njson_payload)
                        if let Ok(raw_str) = std::str::from_utf8(&raw_bytes) {
                            let (origin_node, json_payload) = parse_json_envelope(raw_str);
                            if origin_node == state.node_id {
                                continue;
                            }
                            tracing::debug!(
                                topic = %topic,
                                origin = %origin_node,
                                "Redis JSON from remote"
                            );
                            let out = OutboundMsg::Text(json_payload.into());
                            state.ws.publish_local(&topic, &out, None);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        total_lagged = total_lagged.saturating_add(n);
                        tracing::warn!(
                            skipped = n,
                            total_lagged,
                            "Redis pub/sub bridge lagged — broadcast buffer overflowed; dropped messages but bridge is healthy"
                        );
                        // Continue: receiver auto-recovers, no reconnect needed.
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break true;
                    }
                }
            };

            if bridge_closed {
                tracing::error!(
                    backoff_secs,
                    "Redis pub/sub bridge subscriber closed — reconnecting"
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    });
}

pub async fn start_node_heartbeat(state: AppState) {
    tokio::spawn(async move {
        let key = format!("ops:nodes:{}", state.node_id);
        loop {
            let payload = json!({
                "nodeId": state.node_id,
                "dropletId": state.node.droplet_id.as_deref(),
                "name": state.node.name.as_deref(),
                "publicIp": state.node.public_ip.as_deref(),
                "region": state.node.region.as_deref(),
                "connections": state.ws.connection_count(),
                "draining": state.draining.load(Ordering::Relaxed),
                "updatedAtMs": chrono::Utc::now().timestamp_millis(),
            })
            .to_string();

            if let Err(e) = state
                .redis
                .set::<(), _, _>(&key, payload, Some(Expiration::EX(45)), None, false)
                .await
            {
                tracing::warn!(error = %e, "Failed to refresh app node heartbeat");
            }

            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    });
}

/// Subscribe the Redis subscriber client to a topic (if not already).
pub async fn redis_subscribe(state: &AppState, topic: &str) {
    let sub = &state.redis_sub;
    tracing::debug!(topic, "Redis subscribe");
    let _: Result<(), _> = sub.subscribe(topic).await;
}

/// Unsubscribe the Redis subscriber client from a topic.
pub async fn redis_unsubscribe(state: &AppState, topic: &str) {
    tracing::debug!(topic, "Redis unsubscribe");
    let _: Result<(), _> = state.redis_sub.unsubscribe(topic).await;
}

/// Clean up a topic entirely (local unsubscribe all + Redis unsubscribe).
pub async fn cleanup_topic(state: &AppState, topic: &str) {
    state.ws.cleanup_topic(topic);
    redis_unsubscribe(state, topic).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_reason_is_restricted_to_plain_ascii() {
        assert_eq!(
            sanitize_drain_reason(Some("zdt<script>alert(1)</script>")),
            "zdtscriptalert1script"
        );
        assert_eq!(sanitize_drain_reason(Some("")), "zdt");
    }

    #[test]
    fn draining_event_uses_expected_wire_shape() {
        let value: serde_json::Value =
            serde_json::from_str(&server_draining_json("zdt", 0, 750)).unwrap();
        assert_eq!(value["op"], "SERVER_DRAINING");
        assert_eq!(value["d"]["reason"], "zdt");
        assert_eq!(value["d"]["closeAfterMs"], 750);
    }

    #[test]
    fn focused_channel_topics_are_distinct_from_legacy_channel_topic() {
        assert_eq!(channel_topic(42), "channel:42");
        assert_eq!(channel_live_topic(42), "channel_live:42");
        assert_eq!(channel_notify_topic(42), "channel_notify:42");
        assert_eq!(voice_topic(42), "voice:42");
        assert_eq!(
            focused_channel_topics(42),
            [
                "channel_live:42".to_string(),
                "channel_notify:42".to_string()
            ]
        );
        assert_eq!(
            all_channel_topics(42),
            vec![
                "channel:42".to_string(),
                "channel_live:42".to_string(),
                "channel_notify:42".to_string(),
                "voice:42".to_string(),
            ]
        );
    }

    #[test]
    fn drain_command_must_target_this_node() {
        let node = NodeRuntimeInfo {
            droplet_id: Some("123".to_string()),
            name: Some("verdant-app-nyc1-primary-1".to_string()),
            public_ip: Some("198.51.100.10".to_string()),
            region: Some("nyc1".to_string()),
        };
        let targeted = DrainCommand {
            target_node_id: None,
            target_droplet_id: Some("123".to_string()),
            target_public_ip: None,
            target_name: None,
            reason: None,
            reconnect_after_ms: None,
            close_after_ms: None,
        };
        assert!(drain_targets_node("node-a", &node, &targeted));

        let other_node = DrainCommand {
            target_node_id: None,
            target_droplet_id: Some("456".to_string()),
            target_public_ip: None,
            target_name: None,
            reason: None,
            reconnect_after_ms: None,
            close_after_ms: None,
        };
        assert!(!drain_targets_node("node-a", &node, &other_node));

        let untargeted = DrainCommand {
            target_node_id: None,
            target_droplet_id: None,
            target_public_ip: None,
            target_name: None,
            reason: None,
            reconnect_after_ms: None,
            close_after_ms: None,
        };
        assert!(!drain_targets_node("node-a", &node, &untargeted));
    }
}

/// Subscribe a connection to a set of topics (local + Redis).
pub async fn subscribe_connection(state: &AppState, conn_id: u64, topics: &[String]) {
    tracing::debug!(
        conn_id,
        count = topics.len(),
        "Subscribing connection to topics"
    );
    let realtime_topics = topics
        .iter()
        .map(String::as_str)
        .filter(|topic| is_realtime_scope_topic(topic))
        .collect::<Vec<_>>();
    if !realtime_topics.is_empty() {
        crate::realtime_trace!(
            conn_id,
            count = realtime_topics.len(),
            topics = ?realtime_topics,
            "realtime_scope: subscribing connection to realtime topics"
        );
    }
    for topic in topics {
        state.ws.subscribe(conn_id, topic);
        redis_subscribe(state, topic).await;
    }
}

/// Unsubscribe a connection from a set of topics (local + Redis if topic becomes empty).
pub async fn unsubscribe_connection(state: &AppState, conn_id: u64, topics: &[String]) {
    tracing::debug!(
        conn_id,
        count = topics.len(),
        "Unsubscribing connection from topics"
    );
    let realtime_topics = topics
        .iter()
        .map(String::as_str)
        .filter(|topic| is_realtime_scope_topic(topic))
        .collect::<Vec<_>>();
    if !realtime_topics.is_empty() {
        crate::realtime_trace!(
            conn_id,
            count = realtime_topics.len(),
            topics = ?realtime_topics,
            "realtime_scope: unsubscribing connection from realtime topics"
        );
    }
    for topic in topics {
        state.ws.unsubscribe(conn_id, topic);
        let empty = state
            .ws
            .topic_subscribers
            .get(topic)
            .map(|s| s.is_empty())
            .unwrap_or(true);
        if empty {
            redis_unsubscribe(state, topic).await;
        }
    }
}

async fn redis_unsubscribe_if_empty(state: &AppState, topic: &str) {
    let empty = state
        .ws
        .topic_subscribers
        .get(topic)
        .map(|s| s.is_empty())
        .unwrap_or(true);
    if empty {
        redis_unsubscribe(state, topic).await;
    }
}

/// Subscribe all of a user's active WS connections to topics.
pub async fn subscribe_user(state: &AppState, user_id: i64, topics: &[String]) {
    let conn_ids = state.ws.get_user_conn_ids(user_id);
    for conn_id in &conn_ids {
        subscribe_connection(state, *conn_id, topics).await;
    }
}

/// Unsubscribe all of a user's active WS connections from server-related topics.
pub async fn unsubscribe_user_from_server(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    channel_ids: &[i64],
) {
    let conn_ids = state.ws.get_user_conn_ids(user_id);
    let presence = presence_topic(server_id);
    let channel_topics: Vec<String> = channel_ids
        .iter()
        .flat_map(|id| all_channel_topics(*id))
        .collect();

    for conn_id in &conn_ids {
        state.ws.unsubscribe(*conn_id, &presence);
        for topic in &channel_topics {
            state.ws.unsubscribe(*conn_id, topic);
        }
    }
    redis_unsubscribe_if_empty(state, &presence).await;
    for topic in &channel_topics {
        redis_unsubscribe_if_empty(state, topic).await;
    }
    tracing::info!(
        user_id,
        server_id,
        channels = channel_ids.len(),
        "Unsubscribed user from server topics"
    );
}

/// Unsubscribe all of a user's active WS connections from a single channel topic.
pub async fn unsubscribe_user_from_channel(state: &AppState, user_id: i64, channel_id: i64) {
    let conn_ids = state.ws.get_user_conn_ids(user_id);
    let topics = all_channel_topics(channel_id);
    for conn_id in &conn_ids {
        for topic in &topics {
            state.ws.unsubscribe(*conn_id, topic);
        }
    }
    for topic in &topics {
        redis_unsubscribe_if_empty(state, topic).await;
    }
    tracing::info!(
        user_id,
        channel_id,
        "Unsubscribed user from channel topics (override change)"
    );
}
