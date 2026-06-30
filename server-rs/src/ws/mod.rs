pub mod bot_gateway;
pub mod connection;
#[allow(dead_code)]
pub mod events;
pub mod handlers;
pub mod topics;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::handlers::extract_client_ip;
use crate::state::AppState;
use connection::{Encoding, OutboundMsg, run_connection};

/// Global connection manager — tracks all WebSocket connections.
///
/// # Architecture (April 2026)
///
/// Each WS connection has:
/// - A unique `conn_id` (monotonic counter)
/// - A `user_id` (set after IDENTIFY)
/// - An `encoding` (JSON or Protobuf, determined by first frame)
/// - An unbounded mpsc channel for outbound messages
/// - A set of subscribed topic names
///
/// Messages are delivered via pub/sub topics:
/// - `channel_live:{id}` — full live events for focused/voice channels
/// - `channel_notify:{id}` — metadata-only unread signals for channels the connection has viewed
/// - `presence:{server_id}` — online/offline status for a server
/// - `user:{id}` — DMs, relationships, direct notifications
/// - `broadcast:system` — force-update, feature flags
///
/// # Scaling
///
/// Redis pub/sub bridges messages across instances; each instance fans out
/// only to its local websocket connections.
pub struct ConnectionManager {
    /// userId → set of connection IDs for that user (max 5 per user)
    connections: DashMap<i64, HashSet<u64>>,
    /// connId → (sender, encoding), combined to reduce fanout lookups.
    /// Bounded channels cap memory for slow clients.
    pub(crate) conn_info: DashMap<u64, (mpsc::Sender<OutboundMsg>, Encoding)>,
    /// connId → set of topic names this connection is subscribed to
    pub(crate) subscriptions: DashMap<u64, HashSet<String>>,
    /// topic → set of connection IDs subscribed to that topic (used by publish_local)
    pub(crate) topic_subscribers: DashMap<String, HashSet<u64>>,
    /// connId → userId reverse lookup (for disconnect cleanup)
    pub(crate) conn_user: DashMap<u64, i64>,
    /// connId → focused channel id. Mirrored from per-connection state so
    /// HTTP voice leave can avoid removing a live topic that is still focused.
    pub(crate) conn_focus_channel: DashMap<u64, i64>,
    /// connId → joined voice channel id. HTTP voice endpoints update this for
    /// all active connections belonging to the user.
    pub(crate) conn_voice_channel: DashMap<u64, i64>,
    /// Connections that can decode coalesced `WsMessage::Batch` frames.
    pub(crate) batch_conns: DashMap<u64, ()>,
    /// Monotonic counter for generating unique connection IDs
    next_conn_id: AtomicU64,
}

#[allow(dead_code)]
impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            conn_info: DashMap::new(),
            subscriptions: DashMap::new(),
            topic_subscribers: DashMap::new(),
            conn_user: DashMap::new(),
            conn_focus_channel: DashMap::new(),
            conn_voice_channel: DashMap::new(),
            batch_conns: DashMap::new(),
            next_conn_id: AtomicU64::new(1),
        }
    }

    /// Mark a connection as capable of decoding `WsMessage::Batch`
    /// frames. Called during IDENTIFY if the client advertised
    /// `?batch=1` on the upgrade URL.
    pub fn mark_batch_capable(&self, conn_id: u64) {
        self.batch_conns.insert(conn_id, ());
    }

    /// Check if a connection opted into Batch frames. Used by the
    /// broadcast coalescer when it has to decide whether to pack a
    /// burst into a single frame or send individual frames.
    pub fn is_batch_capable(&self, conn_id: u64) -> bool {
        self.batch_conns.contains_key(&conn_id)
    }

    /// Return all active connection IDs. Used during graceful shutdown
    /// to broadcast close frames to every connected client.
    pub fn all_conn_ids(&self) -> Vec<u64> {
        self.conn_info.iter().map(|entry| *entry.key()).collect()
    }

    pub fn connection_count(&self) -> usize {
        self.conn_info.len()
    }

    /// Generate a unique connection ID.
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a connection for a user after IDENTIFY.
    pub fn add_connection(&self, user_id: i64, conn_id: u64, tx: mpsc::Sender<OutboundMsg>) {
        self.connections.entry(user_id).or_default().insert(conn_id);
        self.conn_info.insert(conn_id, (tx, Encoding::Unknown));
        self.conn_user.insert(conn_id, user_id);
        self.subscriptions.entry(conn_id).or_default();
    }

    /// Set the encoding for a connection (called when first frame is received).
    pub fn set_encoding(&self, conn_id: u64, encoding: Encoding) {
        if let Some(mut entry) = self.conn_info.get_mut(&conn_id) {
            entry.1 = encoding;
        }
    }

    /// Get the encoding for a connection.
    pub fn get_encoding(&self, conn_id: u64) -> Encoding {
        self.conn_info
            .get(&conn_id)
            .map(|e| e.1)
            .unwrap_or(Encoding::Json)
    }

    /// Remove a connection on disconnect. Returns topics that now have zero subscribers.
    pub fn remove_connection(&self, conn_id: u64) -> Vec<String> {
        let mut emptied_topics = Vec::new();

        // Remove from user -> connections map
        if let Some((_, user_id)) = self.conn_user.remove(&conn_id) {
            if let Some(mut conns) = self.connections.get_mut(&user_id) {
                conns.remove(&conn_id);
                if conns.is_empty() {
                    drop(conns);
                    self.connections.remove(&user_id);
                }
            }
        }

        // Unsubscribe from all topics
        if let Some((_, topics)) = self.subscriptions.remove(&conn_id) {
            for topic in topics {
                if let Some(mut subs) = self.topic_subscribers.get_mut(&topic) {
                    subs.remove(&conn_id);
                    if subs.is_empty() {
                        drop(subs);
                        self.topic_subscribers.remove(&topic);
                        emptied_topics.push(topic);
                    }
                }
            }
        }

        // Remove sender + encoding (combined in conn_info)
        self.conn_info.remove(&conn_id);
        self.conn_focus_channel.remove(&conn_id);
        self.conn_voice_channel.remove(&conn_id);

        // Clear batch-capable flag (no-op for legacy conns).
        self.batch_conns.remove(&conn_id);

        emptied_topics
    }

    /// Subscribe a connection to a topic (local routing).
    pub fn subscribe(&self, conn_id: u64, topic: &str) {
        if let Some(mut subs) = self.subscriptions.get_mut(&conn_id) {
            subs.insert(topic.to_string());
        }
        self.topic_subscribers
            .entry(topic.to_string())
            .or_default()
            .insert(conn_id);
    }

    /// Unsubscribe a connection from a topic.
    pub fn unsubscribe(&self, conn_id: u64, topic: &str) {
        if let Some(mut subs) = self.subscriptions.get_mut(&conn_id) {
            subs.remove(topic);
        }
        if let Some(mut set) = self.topic_subscribers.get_mut(topic) {
            set.remove(&conn_id);
            if set.is_empty() {
                drop(set);
                self.topic_subscribers.remove(topic);
            }
        }
    }

    /// Send a message to a specific connection.
    pub fn send_to(&self, conn_id: u64, msg: OutboundMsg) {
        if let Some(info) = self.conn_info.get(&conn_id) {
            let _ = info.0.try_send(msg);
        }
    }

    /// Send a message to all connections of a user.
    pub fn send_to_user(&self, user_id: i64, msg: OutboundMsg) {
        if let Some(conns) = self.connections.get(&user_id) {
            for &conn_id in conns.iter() {
                if let Some(info) = self.conn_info.get(&conn_id) {
                    let _ = info.0.try_send(msg.clone());
                }
            }
        }
    }

    /// Publish a message to all connections subscribed to a topic (local routing).
    /// JSON-first variant — used by events that only have JSON (e.g., TYPING_START).
    /// For events with proto, use `publish_local_proto_first()` instead.
    pub fn publish_local(
        &self,
        topic: &str,
        json_msg: &OutboundMsg,
        proto_bytes: Option<&[u8]>,
    ) -> usize {
        let mut count = 0;
        if let Some(conns) = self.topic_subscribers.get(topic) {
            let proto_arc: Option<Arc<[u8]>> = proto_bytes.map(Arc::from);
            for &conn_id in conns.iter() {
                // Single DashMap lookup gets both sender + encoding
                if let Some(info) = self.conn_info.get(&conn_id) {
                    let msg = if info.1 == Encoding::Protobuf {
                        if let Some(ref bytes) = proto_arc {
                            OutboundMsg::Binary(bytes.clone())
                        } else {
                            json_msg.clone()
                        }
                    } else {
                        json_msg.clone()
                    };
                    let _ = info.0.try_send(msg);
                    count += 1;
                }
            }
        }
        count
    }

    /// Proto-first publish — the primary publish path for all events with proto definitions.
    ///
    /// Builds proto once and allocates JSON only when a subscriber needs it.
    pub fn publish_local_proto_first(
        &self,
        topic: &str,
        proto_bytes: &[u8],
        json_text: &str,
    ) -> usize {
        let mut count = 0;
        if let Some(conns) = self.topic_subscribers.get(topic) {
            let proto_arc: Arc<[u8]> = Arc::from(proto_bytes);
            let mut json_arc: Option<Arc<str>> = None;

            for &conn_id in conns.iter() {
                // Single DashMap lookup: sender + encoding in one entry
                if let Some(info) = self.conn_info.get(&conn_id) {
                    let msg = if info.1 == Encoding::Protobuf {
                        OutboundMsg::Binary(proto_arc.clone())
                    } else {
                        let json = json_arc.get_or_insert_with(|| Arc::from(json_text));
                        OutboundMsg::Text(json.clone())
                    };
                    let _ = info.0.try_send(msg);
                    count += 1;
                }
            }
        }
        count
    }

    /// Publish to all local subscribers except one connection (e.g., exclude the sender).
    /// Uses proto-first with JSON fallback, same as `publish_local_proto_first`.
    pub fn publish_local_except(
        &self,
        topic: &str,
        json_msg: &OutboundMsg,
        proto_bytes: Option<&[u8]>,
        exclude_conn: u64,
    ) -> usize {
        let mut count = 0;
        if let Some(conns) = self.topic_subscribers.get(topic) {
            let proto_arc: Option<Arc<[u8]>> = proto_bytes.map(Arc::from);
            for &conn_id in conns.iter() {
                if conn_id == exclude_conn {
                    continue;
                }
                if let Some(info) = self.conn_info.get(&conn_id) {
                    let msg = if info.1 == Encoding::Protobuf {
                        if let Some(ref bytes) = proto_arc {
                            OutboundMsg::Binary(bytes.clone())
                        } else {
                            json_msg.clone()
                        }
                    } else {
                        json_msg.clone()
                    };
                    let _ = info.0.try_send(msg);
                    count += 1;
                }
            }
        }
        count
    }

    /// Check if a user has any active connections.
    pub fn is_online(&self, user_id: i64) -> bool {
        self.connections
            .get(&user_id)
            .map(|c| !c.is_empty())
            .unwrap_or(false)
    }

    /// List every user id that has at least one active WS connection.
    pub fn connected_user_ids(&self) -> Vec<i64> {
        self.connections
            .iter()
            .filter(|entry| !entry.value().is_empty())
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get all connection IDs for a user.
    pub fn get_user_conn_ids(&self, user_id: i64) -> Vec<u64> {
        self.connections
            .get(&user_id)
            .map(|c| c.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn set_focused_channel(&self, conn_id: u64, channel_id: Option<i64>) {
        if let Some(channel_id) = channel_id {
            self.conn_focus_channel.insert(conn_id, channel_id);
        } else {
            self.conn_focus_channel.remove(&conn_id);
        }
    }

    pub fn set_voice_channel_for_user(&self, user_id: i64, channel_id: i64) {
        for conn_id in self.get_user_conn_ids(user_id) {
            self.conn_voice_channel.insert(conn_id, channel_id);
        }
    }

    pub fn get_voice_channel(&self, conn_id: u64) -> Option<i64> {
        self.conn_voice_channel.get(&conn_id).map(|v| *v)
    }

    pub fn clear_voice_channel_for_user(
        &self,
        user_id: i64,
        channel_id: i64,
    ) -> Vec<(u64, Option<i64>)> {
        let mut conns = Vec::new();
        for conn_id in self.get_user_conn_ids(user_id) {
            if self
                .conn_voice_channel
                .get(&conn_id)
                .map(|v| *v == channel_id)
                .unwrap_or(false)
            {
                self.conn_voice_channel.remove(&conn_id);
            }
            conns.push((conn_id, self.conn_focus_channel.get(&conn_id).map(|v| *v)));
        }
        conns
    }

    /// Get all unique user IDs that have connections subscribed to a topic.
    pub fn get_topic_user_ids(&self, topic: &str) -> Vec<i64> {
        let mut user_ids = HashSet::new();
        if let Some(conns) = self.topic_subscribers.get(topic) {
            for &conn_id in conns.iter() {
                if let Some(uid) = self.conn_user.get(&conn_id) {
                    user_ids.insert(*uid);
                }
            }
        }
        user_ids.into_iter().collect()
    }

    /// Remove a topic entirely — unsubscribe all connections from it.
    /// Used when a channel or server is deleted to prevent orphaned topic entries.
    pub fn cleanup_topic(&self, topic: &str) {
        if let Some((_, conn_ids)) = self.topic_subscribers.remove(topic) {
            for conn_id in conn_ids {
                if let Some(mut subs) = self.subscriptions.get_mut(&conn_id) {
                    subs.remove(topic);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_channel_clear_reports_each_connection_focus() {
        let manager = ConnectionManager::new();
        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        manager.add_connection(7, 1, tx1);
        manager.add_connection(7, 2, tx2);
        manager.set_focused_channel(1, Some(10));
        manager.set_focused_channel(2, Some(20));
        manager.set_voice_channel_for_user(7, 10);

        assert_eq!(manager.get_voice_channel(1), Some(10));
        assert_eq!(manager.get_voice_channel(2), Some(10));

        let mut cleared = manager.clear_voice_channel_for_user(7, 10);
        cleared.sort_by_key(|(conn_id, _)| *conn_id);

        assert_eq!(cleared, vec![(1, Some(10)), (2, Some(20))]);
        assert!(manager.conn_voice_channel.get(&1).is_none());
        assert!(manager.conn_voice_channel.get(&2).is_none());
        assert_eq!(manager.conn_focus_channel.get(&1).map(|v| *v), Some(10));
    }

    #[test]
    fn removing_one_of_multiple_user_connections_keeps_user_online_until_last_connection() {
        let manager = ConnectionManager::new();
        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        manager.add_connection(7, 1, tx1);
        manager.add_connection(7, 2, tx2);

        assert!(manager.is_online(7));

        manager.remove_connection(1);
        assert!(
            manager.is_online(7),
            "disconnect cleanup must not mark a backend-local user offline while another socket remains"
        );

        manager.remove_connection(2);
        assert!(
            !manager.is_online(7),
            "offline cleanup should run only after the last backend-local socket is gone"
        );
    }
}

/// Rate limit config for WS upgrades: 10 per 60 seconds per IP.
/// Previously 5/60s which was too aggressive — dev hard-refreshes and
/// client reconnects after update would quickly exhaust the limit.
const WS_UPGRADE_LIMIT: crate::middleware::rate_limit::RateLimitConfig =
    crate::middleware::rate_limit::RateLimitConfig {
        window_secs: 60,
        max: 10,
        prefix: "rl:ws",
    };

/// Axum handler for WebSocket upgrade at `/ws`.
pub async fn upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));

    // Loadtest bypass via X-Loadtest-Secret header — lets the loadtest
    // driver burst N WS upgrades from one IP without tripping the
    // per-IP upgrade rate limiter.
    let loadtest_bypass = crate::middleware::rate_limit::is_loadtest_bypass(&state, &headers);

    if !loadtest_bypass {
        // Rate limit WS connection attempts per IP (stress test header
        // bypass is checked inside enforce_opt_bypass).
        if let Err(_) = crate::middleware::rate_limit::enforce_opt_bypass(
            &state,
            &WS_UPGRADE_LIMIT,
            &ip,
            Some(&headers),
        )
        .await
        {
            tracing::warn!(%ip, "WebSocket upgrade rate limited");
            return (axum::http::StatusCode::TOO_MANY_REQUESTS, "Rate limited").into_response();
        }
    }

    if let Err(e) = crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await {
        return e.into_response();
    }

    if state.draining.load(Ordering::Relaxed) {
        tracing::info!(%ip, "WebSocket upgrade rejected: node draining");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Server draining",
        )
            .into_response();
    }

    let conn_id = state.ws.next_conn_id();

    // Opt-in Batch frame support via `?batch=1` query param. Detected
    // here so the flag is known before IDENTIFY. Legacy clients (no
    // param) still receive one frame per event.
    let supports_batch = matches!(query.get("batch").map(String::as_str), Some("1"));

    if loadtest_bypass {
        tracing::info!(conn_id, %ip, supports_batch, "WebSocket upgrade (loadtest bypass)");
    } else {
        tracing::info!(conn_id, %ip, supports_batch, "WebSocket upgrade");
    }

    ws.max_frame_size(16 * 1024)
        .max_message_size(16 * 1024)
        .on_upgrade(move |socket| async move {
            run_connection(socket, state, conn_id, addr, supports_batch).await;
        })
}
