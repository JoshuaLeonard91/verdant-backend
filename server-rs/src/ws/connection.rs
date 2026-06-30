use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{CloseFrame, Message as WsMsg, WebSocket};
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::middleware::rate_limit;
use crate::proto::{Identify, Pong, WsMessage, ws_message};
use crate::state::AppState;

use super::handlers;

// ─── Rate limiting constants ─────────────────────────────────────────
const RATE_WINDOW_SECS: u64 = 10;
const RATE_MAX: u32 = 50;
const RATE_HARD_MAX: u32 = 100; // Force disconnect

// ─── Auth timeout ────────────────────────────────────────────────────
const AUTH_TIMEOUT_SECS: u64 = 15;

/// Encoding mode for a connection — determined by the first frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Not yet determined — waiting for first frame.
    Unknown,
    Json,
    Protobuf,
}

/// Outbound message to send to a connection.
/// Uses Arc for Text/Binary variants so broadcast to N connections shares one allocation.
#[derive(Debug, Clone)]
pub enum OutboundMsg {
    Text(Arc<str>),
    Binary(Arc<[u8]>),
    Close(u16, String),
}

/// Per-connection mutable state.
pub struct ConnectionState {
    pub conn_id: u64,
    pub user_id: Option<i64>,
    pub authenticated: bool,
    pub session_id: Option<String>,
    pub client_version: Option<String>,
    pub encoding: Encoding,
    /// The server the client is currently viewing — only this server's presence topic is subscribed.
    pub focused_server_id: Option<i64>,
    /// The channel receiving full live events for this connection.
    pub focused_channel_id: Option<i64>,
    /// Voice channel that should remain live even while the user reads a text channel.
    pub joined_voice_channel_id: Option<i64>,
    /// Visible member-list ranges per server.
    pub member_ranges: HashMap<i64, Vec<(i64, i64)>>,
    /// Server IDs this connection may access when authenticated with a
    /// federated client capability. `None` means a normal local session.
    pub federated_allowed_server_ids: Option<HashSet<i64>>,
    /// Timestamp of when the last READY (full or delta) was sent on this connection.
    /// Used by delta READY to know the cutoff time for incremental queries.
    pub last_ready_at: Option<chrono::DateTime<chrono::Utc>>,
    // Rate limiting
    pub msg_count: u32,
    pub window_start: Instant,
    /// Set during IDENTIFY when the authenticated user is a
    /// synthetic loadtest account (username prefix
    /// `loadtest_user_`). Causes `check_rate_limit` and the per-op
    /// dispatcher rate limit to short-circuit to Ok.
    pub bypass_rate_limits: bool,
    /// Set if the client advertised `?batch=1` on the WS upgrade URL.
    /// When true, the broadcast coalescer packs coalesced bursts into
    /// a `WsMessage::Batch` frame instead of sending individual frames.
    /// Commit C (2026-04-11).
    pub supports_batch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResumeFields {
    session_id: Option<String>,
    last_ready_at: Option<String>,
}

fn resume_fields_from_json_identify(d: Option<&Value>) -> ResumeFields {
    ResumeFields {
        session_id: d
            .and_then(|d| d.get("resumeSessionId"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        last_ready_at: d
            .and_then(|d| d.get("lastReadyAt"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    }
}

fn resume_fields_from_proto_identify(identify: &Identify) -> ResumeFields {
    ResumeFields {
        session_id: identify.resume_session_id.clone(),
        last_ready_at: identify.last_ready_at.clone(),
    }
}

fn heartbeat_pong_message() -> WsMessage {
    WsMessage {
        payload: Some(ws_message::Payload::Pong(Pong {})),
    }
}

impl ConnectionState {
    pub fn new(conn_id: u64, supports_batch: bool) -> Self {
        Self {
            conn_id,
            user_id: None,
            authenticated: false,
            session_id: None,
            client_version: None,
            encoding: Encoding::Unknown,
            focused_server_id: None,
            focused_channel_id: None,
            joined_voice_channel_id: None,
            member_ranges: HashMap::new(),
            federated_allowed_server_ids: None,
            last_ready_at: None,
            msg_count: 0,
            window_start: Instant::now(),
            bypass_rate_limits: false,
            supports_batch,
        }
    }

    /// Check rate limit. Returns true if within limit.
    pub fn check_rate_limit(&mut self) -> RateResult {
        if self.bypass_rate_limits {
            return RateResult::Ok;
        }
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= RATE_WINDOW_SECS {
            self.msg_count = 0;
            self.window_start = now;
        }
        self.msg_count += 1;

        if self.msg_count > RATE_HARD_MAX {
            RateResult::Disconnect
        } else if self.msg_count > RATE_MAX {
            RateResult::Limited
        } else {
            RateResult::Ok
        }
    }
}

pub enum RateResult {
    Ok,
    Limited,
    Disconnect,
}

/// Run a single WebSocket connection's lifecycle.
pub async fn run_connection(
    socket: WebSocket,
    state: AppState,
    conn_id: u64,
    _addr: SocketAddr,
    supports_batch: bool,
) {
    let (mut ws_sink, mut ws_stream) = socket.split();
    // Bounded channel: prevents a slow client from accumulating unbounded
    // memory. Capacity 2048 gives headroom above the 1024 high-water mark
    // in the write loop — when the write loop detects >1024 queued, it
    // disconnects the client. The bounded capacity ensures memory never
    // exceeds ~2MB per connection (2048 × ~1KB per message).
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundMsg>(2048);
    let mut conn_state = ConnectionState::new(conn_id, supports_batch);

    // Write loop: drain outbound_rx → send to WS.
    //
    // OPTIMIZATION: batch N messages into ONE TCP write via
    // `feed()` + single `flush()`. The prior version called
    // `ws_sink.send(frame).await` per message, which internally
    // calls `feed` then `flush` → one TLS-encoded TCP write per
    // frame. For high-fanout channels this caps throughput at
    // ~500 msg/s per connection regardless of message size.
    //
    // With feed+flush we queue N frames without flushing, then
    // do one TCP write at the end. Measured 3–5× cut in
    // per-message CPU time on saturated connections.
    //
    // The task wake-up coalescing (try_recv drain inside the
    // outer recv().await) is preserved from the prior version.
    //
    // High-water mark: if >1024 messages are queued, the client
    // is too slow to keep up — disconnect to prevent memory
    // growth.
    const OUTBOUND_HIGH_WATER: usize = 1024;
    let mut write_handle = tokio::spawn(async move {
        // Convert an OutboundMsg into the matching tungstenite frame.
        // Returns None for Close (which breaks the loop).
        fn to_ws_msg(msg: OutboundMsg) -> Result<WsMsg, Option<(u16, String)>> {
            match msg {
                OutboundMsg::Text(text) => Ok(WsMsg::Text(text.as_ref().into())),
                OutboundMsg::Binary(data) => Ok(WsMsg::Binary(Vec::from(data.as_ref()).into())),
                OutboundMsg::Close(code, reason) => Err(Some((code, reason))),
            }
        }

        'outer: while let Some(first) = outbound_rx.recv().await {
            // Handle the first message — if it's a Close, send it
            // and exit immediately (no batching makes sense post-Close).
            let first_frame = match to_ws_msg(first) {
                Ok(f) => f,
                Err(Some((code, reason))) => {
                    let _ = ws_sink
                        .send(WsMsg::Close(Some(CloseFrame {
                            code,
                            reason: reason.into(),
                        })))
                        .await;
                    break;
                }
                Err(None) => break,
            };
            // feed() queues the frame in the sink buffer WITHOUT
            // flushing to the TCP socket.
            if ws_sink.feed(first_frame).await.is_err() {
                break;
            }

            // Drain any additional queued messages with try_recv
            // and feed them too. No awaits on each feed — they
            // just append to the buffer.
            let mut drained = 0u32;
            let mut close_pending: Option<(u16, String)> = None;
            while let Ok(msg) = outbound_rx.try_recv() {
                match to_ws_msg(msg) {
                    Ok(frame) => {
                        if ws_sink.feed(frame).await.is_err() {
                            break 'outer;
                        }
                        drained += 1;
                    }
                    Err(Some(close)) => {
                        close_pending = Some(close);
                        break;
                    }
                    Err(None) => break 'outer,
                }
                // Safety valve: cap batch size to avoid holding a
                // huge buffer in memory while still getting the win
                // for typical bursts.
                if drained >= 256 {
                    break;
                }
            }

            // Flush the batched frames: one TCP write for all
            // queued frames. This is where the syscall savings
            // show up.
            if ws_sink.flush().await.is_err() {
                break;
            }

            // If a Close arrived mid-drain, send it after flushing
            // everything else so no messages are lost before close.
            if let Some((code, reason)) = close_pending {
                let _ = ws_sink
                    .send(WsMsg::Close(Some(CloseFrame {
                        code,
                        reason: reason.into(),
                    })))
                    .await;
                break;
            }

            // Check for slow client
            if outbound_rx.len() > OUTBOUND_HIGH_WATER {
                tracing::warn!(
                    conn_id,
                    queue_len = outbound_rx.len(),
                    "Slow client, disconnecting"
                );
                let _ = ws_sink
                    .send(WsMsg::Close(Some(CloseFrame {
                        code: 4008,
                        reason: "Slow client".into(),
                    })))
                    .await;
                break;
            }
        }
    });

    tracing::info!(conn_id, "WebSocket connected");

    // Auth timeout: if not authenticated within 15s, close
    let auth_tx = outbound_tx.clone();
    let mut auth_timeout = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS)).await;
        auth_tx
    });

    // Read loop
    loop {
        tokio::select! {
            // Check auth timeout
            auth_tx_res = &mut auth_timeout, if !conn_state.authenticated => {
                tracing::warn!(conn_id, "Auth timeout, closing connection");
                if let Ok(tx) = auth_tx_res {
                    let _ = tx.try_send(OutboundMsg::Close(
                        4001,
                        "Authentication timeout".to_string(),
                    ));
                }
                break;
            }
            // Read from WS
            frame = ws_stream.next() => {
                let Some(frame_result) = frame else {
                    // Connection closed
                    break;
                };

                let msg = match frame_result {
                    Ok(msg) => msg,
                    Err(e) => {
                        tracing::debug!(conn_id, "WS read error: {e}");
                        break;
                    }
                };

                match msg {
                    WsMsg::Close(frame) => {
                        tracing::info!(
                            conn_id,
                            user_id = ?conn_state.user_id,
                            code = frame.as_ref().map(|f| f.code),
                            reason = ?frame.as_ref().map(|f| f.reason.to_string()),
                            "WS close frame received"
                        );
                        break;
                    }
                    WsMsg::Ping(_) => {}
                    WsMsg::Pong(_) => {}
                    WsMsg::Text(text) => {
                        // First frame determines encoding
                        if conn_state.encoding == Encoding::Unknown {
                            conn_state.encoding = Encoding::Json;
                            state.ws.set_encoding(conn_state.conn_id, Encoding::Json);
                            tracing::debug!(conn_id, "Encoding set to JSON");
                        }

                        // Rate limit
                        match conn_state.check_rate_limit() {
                            RateResult::Ok => {}
                            RateResult::Limited => {
                                tracing::warn!(conn_id, user_id = ?conn_state.user_id, count = conn_state.msg_count, "Rate limited");
                                let err = super::events::ws_error_json("RATE_LIMITED", "Rate limited", "RATE_LIMITED");
                                let _ = outbound_tx.try_send(OutboundMsg::Text(err.into()));
                                continue;
                            }
                            RateResult::Disconnect => {
                                tracing::warn!(conn_id, user_id = ?conn_state.user_id, count = conn_state.msg_count, "Rate limit hard max, disconnecting");
                                let _ = outbound_tx.try_send(OutboundMsg::Close(
                                    4008,
                                    "Rate limit exceeded".to_string(),
                                ));
                                break;
                            }
                        }

                        handle_text_frame(
                            &text,
                            &state,
                            &mut conn_state,
                            &outbound_tx,
                        )
                        .await;
                    }
                    WsMsg::Binary(data) => {
                        if conn_state.encoding == Encoding::Unknown {
                            conn_state.encoding = Encoding::Protobuf;
                            state.ws.set_encoding(conn_state.conn_id, Encoding::Protobuf);
                            tracing::debug!(conn_id, "Encoding set to Protobuf");
                        }

                        // Rate limit
                        match conn_state.check_rate_limit() {
                            RateResult::Ok => {}
                            RateResult::Limited => {
                                tracing::warn!(conn_id, user_id = ?conn_state.user_id, count = conn_state.msg_count, "Rate limited (proto)");
                                let err_msg = super::events::ws_error_proto("RATE_LIMITED", "Rate limited", "RATE_LIMITED");
                                if let Some(bytes) = encode_proto(&err_msg) {
                                    let _ = outbound_tx.try_send(OutboundMsg::Binary(bytes.into()));
                                }
                                continue;
                            }
                            RateResult::Disconnect => {
                                tracing::warn!(conn_id, user_id = ?conn_state.user_id, count = conn_state.msg_count, "Rate limit hard max, disconnecting (proto)");
                                let _ = outbound_tx.try_send(OutboundMsg::Close(
                                    4008,
                                    "Rate limit exceeded".to_string(),
                                ));
                                break;
                            }
                        }

                        // Enforce max payload size (8KB)
                        if data.len() > 8192 {
                            tracing::warn!(conn_id, user_id = ?conn_state.user_id, size = data.len(), "Payload too large, disconnecting");
                            let _ = outbound_tx.try_send(OutboundMsg::Close(
                                4009,
                                "Payload too large".to_string(),
                            ));
                            break;
                        }

                        handle_binary_frame(
                            &data,
                            &state,
                            &mut conn_state,
                            &outbound_tx,
                        )
                        .await;
                    }
                }
            }
        }
    }

    // Cleanup — abort auth timeout task if still pending (prevents
    // a leaked 15s tokio::sleep task on early disconnect before IDENTIFY)
    auth_timeout.abort();

    tracing::info!(conn_id, user_id = ?conn_state.user_id, "WebSocket disconnected");

    // If authenticated, handle disconnect (set offline if no other connections)
    if let Some(user_id) = conn_state.user_id {
        let emptied = state.ws.remove_connection(conn_id);
        if !emptied.is_empty() {
            let state_unsub = state.clone();
            tokio::spawn(async move {
                for topic in &emptied {
                    super::topics::redis_unsubscribe(&state_unsub, topic).await;
                }
            });
        }

        if !state.ws.is_online(user_id) {
            // Schedule permission cache cleanup (grace period)
            state.permissions.schedule_cleanup(user_id);

            // Fire-and-forget: update status to offline + broadcast
            let state_clone = state.clone();
            let federated_allowed_server_ids = conn_state.federated_allowed_server_ids.clone();
            tokio::spawn(async move {
                handlers::handle_disconnect(user_id, &state_clone, federated_allowed_server_ids)
                    .await;
            });
        }
    } else {
        let emptied = state.ws.remove_connection(conn_id);
        if !emptied.is_empty() {
            let state_unsub = state.clone();
            tokio::spawn(async move {
                for topic in &emptied {
                    super::topics::redis_unsubscribe(&state_unsub, topic).await;
                }
            });
        }
    }

    // Give the write loop up to 2s to drain pending messages
    // (including the close frame we just queued). If it does not
    // finish, abort it explicitly; dropping a JoinHandle detaches it.
    match tokio::time::timeout(std::time::Duration::from_secs(2), &mut write_handle).await {
        Ok(_) => {} // drained cleanly
        Err(_) => write_handle.abort(),
    }
}

/// Check per-operation rate limit for an authenticated WS user.
/// Returns true if the request should proceed, false if rate-limited.
async fn check_ws_op_rate_limit(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    config: &rate_limit::RateLimitConfig,
    op: &str,
) -> bool {
    let Some(user_id) = conn.user_id else {
        return true;
    };
    // Bypass for synthetic loadtest users. Flag is set during
    // IDENTIFY after the user profile is fetched; we fall back to
    // the DashMap check as a belt-and-suspenders guard.
    if conn.bypass_rate_limits || state.user_profiles.is_loadtest_user(user_id) {
        return true;
    }
    match rate_limit::enforce(state, config, &user_id.to_string()).await {
        Ok(_) => true,
        Err(_) => {
            match conn.encoding {
                Encoding::Json | Encoding::Unknown => {
                    let err = super::events::ws_error_json(op, "Rate limited", "RATE_LIMITED");
                    let _ = tx.try_send(OutboundMsg::Text(err.into()));
                }
                Encoding::Protobuf => {
                    let err = super::events::ws_error_proto(op, "Rate limited", "RATE_LIMITED");
                    if let Some(bytes) = encode_proto(&err) {
                        let _ = tx.try_send(OutboundMsg::Binary(bytes.into()));
                    }
                }
            }
            false
        }
    }
}

/// Parse and dispatch a JSON text frame.
async fn handle_text_frame(
    text: &str,
    state: &AppState,
    conn: &mut ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
) {
    // Enforce max payload size (8KB)
    if text.len() > 8192 {
        tracing::warn!(conn_id = conn.conn_id, user_id = ?conn.user_id, size = text.len(), "Text payload too large, closing");
        let _ = tx.try_send(OutboundMsg::Close(4009, "Payload too large".to_string()));
        return;
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        let err = super::events::ws_error_json("PARSE_ERROR", "Invalid JSON", "PARSE_ERROR");
        let _ = tx.try_send(OutboundMsg::Text(err.into()));
        return;
    };

    // Extract the op field to determine message type
    let op = value.get("op").and_then(|v| v.as_str()).unwrap_or("");
    tracing::debug!(conn_id = conn.conn_id, op, "Frame received (JSON)");

    // Security gate: only IDENTIFY may run unauthenticated. Every other op
    // reaches handlers only after `conn.user_id` has been established.
    match op {
        "IDENTIFY" => {
            let d = value.get("d");
            let token = d
                .and_then(|d| d.get("token"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let client_version = d
                .and_then(|d| d.get("clientVersion"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let resume = resume_fields_from_json_identify(d);
            let initial_status = d
                .and_then(|d| d.get("initialStatus"))
                .and_then(|v| v.as_str())
                .map(|s| match s {
                    "online" => 1,
                    "idle" => 2,
                    "dnd" => 3,
                    "offline" => 4,
                    _ => 0,
                })
                .unwrap_or(0);
            let afk = d
                .and_then(|d| d.get("afk"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            handlers::handle_identify(
                state,
                conn,
                tx,
                token,
                client_version,
                resume.session_id,
                resume.last_ready_at,
                initial_status,
                afk,
            )
            .await;
        }
        _ if !conn.authenticated => {
            let err = super::events::ws_error_json(op, "Not authenticated", "NOT_AUTHENTICATED");
            let _ = tx.try_send(OutboundMsg::Text(err.into()));
            return;
        }
        "TYPING_START" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::TYPING_LIMIT, "TYPING_START")
                .await
            {
                return;
            }
            let channel_id = value
                .get("d")
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            handlers::handle_typing(state, conn, tx, channel_id).await;
        }
        "MESSAGE_SEND" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::MESSAGE_LIMIT, "MESSAGE_SEND")
                .await
            {
                return;
            }
            let d = value.get("d");
            let channel_id = d
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = d
                .and_then(|d| d.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let nonce = d
                .and_then(|d| d.get("nonce"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reply_to_id = d.and_then(|d| d.get("replyToId")).and_then(|v| v.as_str());
            handlers::handle_message_send(state, conn, tx, channel_id, content, nonce, reply_to_id)
                .await;
        }
        "MESSAGE_EDIT" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::MESSAGE_LIMIT, "MESSAGE_EDIT")
                .await
            {
                return;
            }
            let d = value.get("d");
            let channel_id = d
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let message_id = d
                .and_then(|d| d.get("messageId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = d
                .and_then(|d| d.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            handlers::handle_message_edit(state, conn, tx, channel_id, message_id, content).await;
        }
        "MESSAGE_DELETE" => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::MESSAGE_LIMIT,
                "MESSAGE_DELETE",
            )
            .await
            {
                return;
            }
            let d = value.get("d");
            let channel_id = d
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let message_id = d
                .and_then(|d| d.get("messageId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            handlers::handle_message_delete(state, conn, tx, channel_id, message_id).await;
        }
        "REACTION_ADD" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::REACTION_LIMIT, "REACTION_ADD")
                .await
            {
                return;
            }
            let d = value.get("d");
            let channel_id = d
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let message_id = d
                .and_then(|d| d.get("messageId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let emoji = d
                .and_then(|d| d.get("emoji"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let emoji_id = d
                .and_then(|d| d.get("emojiId"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            handlers::handle_reaction_add(
                state,
                conn,
                tx,
                channel_id,
                message_id,
                emoji,
                emoji_id.as_deref(),
            )
            .await;
        }
        "REACTION_REMOVE" => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::REACTION_LIMIT,
                "REACTION_REMOVE",
            )
            .await
            {
                return;
            }
            let d = value.get("d");
            let channel_id = d
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let message_id = d
                .and_then(|d| d.get("messageId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let emoji = d
                .and_then(|d| d.get("emoji"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            handlers::handle_reaction_remove(state, conn, tx, channel_id, message_id, emoji).await;
        }
        "CHANNEL_ACK" => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::READ_STATE_LIMIT,
                "CHANNEL_ACK",
            )
            .await
            {
                return;
            }
            let d = value.get("d");
            let channel_id = d
                .and_then(|d| d.get("channelId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let message_id = d
                .and_then(|d| d.get("messageId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            handlers::handle_channel_ack(state, conn, channel_id, message_id).await;
        }
        "PRESENCE_UPDATE" => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::PRESENCE_LIMIT,
                "PRESENCE_UPDATE",
            )
            .await
            {
                return;
            }
            let d = value.get("d");
            let status_val = d.and_then(|d| d.get("status"));
            // Accept both string ("online") and integer (1) status values
            let status = match status_val {
                Some(v) if v.is_i64() => v.as_i64().unwrap_or(0) as i32,
                Some(v) if v.is_string() => match v.as_str().unwrap_or("") {
                    "online" => 1,
                    "idle" => 2,
                    "dnd" => 3,
                    "offline" => 4,
                    _ => 0,
                },
                _ => 0,
            };
            // afk = true means auto-idle (client-detected inactivity).
            // Legacy compat: "auto" field is the same as "afk".
            let afk = d
                .and_then(|d| d.get("afk"))
                .and_then(|v| v.as_bool())
                .unwrap_or_else(|| {
                    d.and_then(|d| d.get("auto"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                });
            handlers::handle_presence_update(state, conn, status, afk).await;
        }
        "PING" => {
            let pong = heartbeat_pong_message();
            if let Some(bytes) = encode_proto(&pong) {
                let _ = tx.try_send(OutboundMsg::Binary(bytes.into()));
            }
            // Refresh Redis presence TTL on heartbeat.
            if let Some(uid) = conn.user_id {
                crate::services::presence::refresh(&state.redis, uid).await;
            }
        }
        "FOCUS_SERVER" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::WS_NAV_LIMIT, "FOCUS_SERVER")
                .await
            {
                return;
            }
            let d = value.get("d");
            let server_id = d
                .and_then(|d| d.get("serverId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            handlers::handle_focus_server(state, conn, tx, server_id).await;
        }
        "FOCUS_CHANNEL" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::WS_NAV_LIMIT, "FOCUS_CHANNEL")
                .await
            {
                return;
            }
            let channel_id = value
                .get("d")
                .and_then(|d| d.get("channelId"))
                .and_then(|v| if v.is_null() { None } else { v.as_str() });
            handlers::handle_focus_channel(state, conn, tx, channel_id).await;
        }
        "REQUEST_MEMBERS" => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::WS_NAV_LIMIT,
                "REQUEST_MEMBERS",
            )
            .await
            {
                return;
            }
            let d = value.get("d");
            let server_id = d
                .and_then(|d| d.get("serverId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let query = d
                .and_then(|d| d.get("query"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let limit = d
                .and_then(|d| d.get("limit"))
                .and_then(|v| v.as_i64())
                .unwrap_or(100);
            let after = d.and_then(|d| d.get("after")).and_then(|v| v.as_str());
            handlers::handle_request_members(state, conn, tx, server_id, query, limit, after).await;
        }
        "SUBSCRIBE_MEMBER_RANGES" => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::WS_NAV_LIMIT,
                "SUBSCRIBE_MEMBER_RANGES",
            )
            .await
            {
                return;
            }
            let d = value.get("d");
            let server_id = d
                .and_then(|d| d.get("serverId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ranges: Vec<(i64, i64)> = d
                .and_then(|d| d.get("ranges"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| {
                            let a = r.as_array()?;
                            Some((a.get(0)?.as_i64()?, a.get(1)?.as_i64()?))
                        })
                        .collect()
                })
                .unwrap_or_default();
            handlers::handle_subscribe_member_ranges(state, conn, tx, server_id, &ranges).await;
        }
        "VOICE_LEAVE" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::VOICE_LIMIT, "VOICE_LEAVE")
                .await
            {
                return;
            }
            handlers::handle_voice_leave(state, conn, tx).await;
        }
        "VOICE_STATE" => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::VOICE_LIMIT, "VOICE_STATE")
                .await
            {
                return;
            }
            let d = value.get("d");
            let self_mute = d.and_then(|d| d.get("selfMute")).and_then(|v| v.as_bool());
            let self_deaf = d.and_then(|d| d.get("selfDeaf")).and_then(|v| v.as_bool());
            handlers::handle_voice_state_update(state, conn, tx, self_mute, self_deaf).await;
        }
        other => {
            let err = super::events::ws_error_json(other, "Unknown op", "UNKNOWN_OP");
            let _ = tx.try_send(OutboundMsg::Text(err.into()));
        }
    }
}

/// Parse and dispatch a protobuf binary frame.
async fn handle_binary_frame(
    data: &[u8],
    state: &AppState,
    conn: &mut ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
) {
    let Ok(ws_msg) = WsMessage::decode(data) else {
        let err = super::events::ws_error_proto("PARSE_ERROR", "Invalid protobuf", "PARSE_ERROR");
        if let Some(bytes) = encode_proto(&err) {
            let _ = tx.try_send(OutboundMsg::Binary(bytes.into()));
        }
        return;
    };

    let Some(payload) = ws_msg.payload else {
        return;
    };

    tracing::debug!(conn_id = conn.conn_id, "Frame received (proto)");

    // Same authentication gate as JSON frames; protobuf changes encoding only,
    // not the trust model.
    match payload {
        ws_message::Payload::Identify(identify) => {
            let resume = resume_fields_from_proto_identify(&identify);
            handlers::handle_identify(
                state,
                conn,
                tx,
                &identify.token,
                identify.client_version,
                resume.session_id,
                resume.last_ready_at,
                identify.initial_status,
                identify.afk,
            )
            .await;
        }
        _ if !conn.authenticated => {
            let err =
                super::events::ws_error_proto("UNKNOWN", "Not authenticated", "NOT_AUTHENTICATED");
            if let Some(bytes) = encode_proto(&err) {
                let _ = tx.try_send(OutboundMsg::Binary(bytes.into()));
            }
            return;
        }
        ws_message::Payload::ClientTypingStart(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::TYPING_LIMIT, "TYPING_START")
                .await
            {
                return;
            }
            handlers::handle_typing(state, conn, tx, &ev.channel_id).await;
        }
        ws_message::Payload::ClientMessageSend(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::MESSAGE_LIMIT, "MESSAGE_SEND")
                .await
            {
                return;
            }
            handlers::handle_message_send(
                state,
                conn,
                tx,
                &ev.channel_id,
                &ev.content,
                &ev.nonce,
                ev.reply_to_id.as_deref(),
            )
            .await;
        }
        ws_message::Payload::ClientMessageEdit(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::MESSAGE_LIMIT, "MESSAGE_EDIT")
                .await
            {
                return;
            }
            handlers::handle_message_edit(
                state,
                conn,
                tx,
                &ev.channel_id,
                &ev.message_id,
                &ev.content,
            )
            .await;
        }
        ws_message::Payload::ClientMessageDelete(ev) => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::MESSAGE_LIMIT,
                "MESSAGE_DELETE",
            )
            .await
            {
                return;
            }
            handlers::handle_message_delete(state, conn, tx, &ev.channel_id, &ev.message_id).await;
        }
        ws_message::Payload::ClientReactionAdd(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::REACTION_LIMIT, "REACTION_ADD")
                .await
            {
                return;
            }
            handlers::handle_reaction_add(
                state,
                conn,
                tx,
                &ev.channel_id,
                &ev.message_id,
                &ev.emoji,
                ev.emoji_id.as_deref(),
            )
            .await;
        }
        ws_message::Payload::ClientReactionRemove(ev) => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::REACTION_LIMIT,
                "REACTION_REMOVE",
            )
            .await
            {
                return;
            }
            handlers::handle_reaction_remove(
                state,
                conn,
                tx,
                &ev.channel_id,
                &ev.message_id,
                &ev.emoji,
            )
            .await;
        }
        ws_message::Payload::ClientChannelAck(ev) => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::READ_STATE_LIMIT,
                "CHANNEL_ACK",
            )
            .await
            {
                return;
            }
            handlers::handle_channel_ack(state, conn, &ev.channel_id, &ev.message_id).await;
        }
        ws_message::Payload::ClientPresenceUpdate(ev) => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::PRESENCE_LIMIT,
                "PRESENCE_UPDATE",
            )
            .await
            {
                return;
            }
            handlers::handle_presence_update(state, conn, ev.status, ev.afk).await;
        }
        ws_message::Payload::Ping(_) => {
            let pong = heartbeat_pong_message();
            if let Some(bytes) = encode_proto(&pong) {
                let _ = tx.try_send(OutboundMsg::Binary(bytes.into()));
            }
            // Refresh Redis presence TTL on heartbeat.
            if let Some(uid) = conn.user_id {
                crate::services::presence::refresh(&state.redis, uid).await;
            }
        }
        ws_message::Payload::Pong(_) => {
            // Client pong — no action needed
        }
        ws_message::Payload::ClientVoiceLeave(_) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::VOICE_LIMIT, "VOICE_LEAVE")
                .await
            {
                return;
            }
            handlers::handle_voice_leave(state, conn, tx).await;
        }
        ws_message::Payload::ClientVoiceState(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::VOICE_LIMIT, "VOICE_STATE")
                .await
            {
                return;
            }
            handlers::handle_voice_state_update(state, conn, tx, ev.self_mute, ev.self_deaf).await;
        }
        ws_message::Payload::ClientFocusServer(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::WS_NAV_LIMIT, "FOCUS_SERVER")
                .await
            {
                return;
            }
            handlers::handle_focus_server(state, conn, tx, &ev.server_id).await;
        }
        ws_message::Payload::ClientFocusChannel(ev) => {
            if !check_ws_op_rate_limit(state, conn, tx, &rate_limit::WS_NAV_LIMIT, "FOCUS_CHANNEL")
                .await
            {
                return;
            }
            handlers::handle_focus_channel(state, conn, tx, ev.channel_id.as_deref()).await;
        }
        ws_message::Payload::ClientRequestMembers(ev) => {
            if !check_ws_op_rate_limit(
                state,
                conn,
                tx,
                &rate_limit::WS_NAV_LIMIT,
                "REQUEST_MEMBERS",
            )
            .await
            {
                return;
            }
            handlers::handle_request_members(
                state,
                conn,
                tx,
                &ev.server_id,
                ev.query.as_deref().unwrap_or(""),
                ev.limit as i64,
                None,
            )
            .await;
        }
        // Server→client payloads received from client — ignore
        _ => {}
    }
}

/// Encode a proto WsMessage to bytes.
pub fn encode_proto(msg: &WsMessage) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Ping, UserStatus};
    use prost::Message as ProstMessage;
    use serde_json::json;

    #[test]
    fn heartbeat_pong_message_encodes_protobuf_pong() {
        let bytes = encode_proto(&heartbeat_pong_message()).expect("PONG should encode");
        let decoded = WsMessage::decode(bytes.as_slice()).expect("PONG should decode");

        assert!(matches!(
            decoded.payload,
            Some(ws_message::Payload::Pong(Pong {}))
        ));
    }

    #[test]
    fn protobuf_ping_and_pong_payloads_keep_stable_tags() {
        let ping = WsMessage {
            payload: Some(ws_message::Payload::Ping(Ping {})),
        };
        let ping_bytes = encode_proto(&ping).expect("PING should encode");
        let decoded_ping = WsMessage::decode(ping_bytes.as_slice()).expect("PING should decode");

        assert!(matches!(
            decoded_ping.payload,
            Some(ws_message::Payload::Ping(Ping {}))
        ));

        let pong_bytes = encode_proto(&heartbeat_pong_message()).expect("PONG should encode");
        let decoded_pong = WsMessage::decode(pong_bytes.as_slice()).expect("PONG should decode");

        assert!(matches!(
            decoded_pong.payload,
            Some(ws_message::Payload::Pong(Pong {}))
        ));
    }

    #[test]
    fn json_identify_resume_fields_match_tauri_and_flutter_names() {
        let identify = json!({
            "token": "redacted",
            "resumeSessionId": "session-123",
            "lastReadyAt": "2026-06-04T19:21:00Z"
        });

        let resume = resume_fields_from_json_identify(Some(&identify));

        assert_eq!(
            resume,
            ResumeFields {
                session_id: Some("session-123".to_string()),
                last_ready_at: Some("2026-06-04T19:21:00Z".to_string()),
            }
        );
    }

    #[test]
    fn proto_identify_resume_fields_are_preserved_for_ready_delta() {
        let identify = Identify {
            token: "redacted".to_string(),
            client_version: Some("flutter-test".to_string()),
            resume_session_id: Some("session-123".to_string()),
            last_ready_at: Some("2026-06-04T19:21:00Z".to_string()),
            initial_status: UserStatus::Online as i32,
            afk: false,
        };

        let resume = resume_fields_from_proto_identify(&identify);

        assert_eq!(
            resume,
            ResumeFields {
                session_id: Some("session-123".to_string()),
                last_ready_at: Some("2026-06-04T19:21:00Z".to_string()),
            }
        );
    }
}
