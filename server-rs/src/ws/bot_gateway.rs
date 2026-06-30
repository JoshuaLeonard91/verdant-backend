use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message as WsMsg, WebSocket};
use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};

use crate::handlers::extract_client_ip;
use crate::middleware::auth::{BotIdentity, authenticate_bot_token};
use crate::middleware::rate_limit;
use crate::services::pg::bot_outbox::BotOutboxRow;
use crate::services::pg::bots::{
    SCOPE_AUDIT_READ, SCOPE_FEEDS_READ, SCOPE_MEMBERS_READ, SCOPE_MESSAGE_CONTENT_READ,
    SCOPE_MESSAGES_READ, has_scope,
};
use crate::state::AppState;

const BOT_EVENT_BATCH_LIMIT: i64 = 100;
const BOT_POLL_INTERVAL_MS: u64 = 1000;
const BOT_FRAME_LIMIT: u32 = 60;

const BOT_WS_UPGRADE_LIMIT: rate_limit::RateLimitConfig = rate_limit::RateLimitConfig {
    window_secs: 60,
    max: 20,
    prefix: "rl:bot-ws",
};

#[derive(Debug)]
struct BotConnectionState {
    conn_id: u64,
    authenticated: bool,
    bot: Option<BotIdentity>,
    intents: HashSet<String>,
    last_event_id: i64,
    frame_count: u32,
    frame_window_start: Instant,
}

impl BotConnectionState {
    fn new(conn_id: u64) -> Self {
        Self {
            conn_id,
            authenticated: false,
            bot: None,
            intents: HashSet::new(),
            last_event_id: 0,
            frame_count: 0,
            frame_window_start: Instant::now(),
        }
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.frame_window_start).as_secs() >= 10 {
            self.frame_count = 0;
            self.frame_window_start = now;
        }
        self.frame_count += 1;
        self.frame_count <= BOT_FRAME_LIMIT
    }
}

fn json_event(op: &str, data: Value) -> WsMsg {
    WsMsg::Text(json!({ "op": op, "d": data }).to_string().into())
}

fn json_error(code: &str, message: &str) -> WsMsg {
    json_event("ERROR", json!({ "code": code, "message": message }))
}

fn parse_id_string(value: Option<&Value>) -> Option<i64> {
    value
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| value.and_then(|v| v.as_i64()))
}

fn parse_intents(value: Option<&Value>) -> Result<HashSet<String>, &'static str> {
    let Some(value) = value else {
        return Ok(HashSet::from(["FEEDS".to_string()]));
    };
    let Some(arr) = value.as_array() else {
        return Err("invalid_intents");
    };

    let mut intents = HashSet::new();
    for item in arr {
        let Some(raw) = item.as_str() else {
            return Err("invalid_intents");
        };
        let intent = raw.trim().to_ascii_uppercase();
        if !matches!(
            intent.as_str(),
            "FEEDS" | "MESSAGES" | "MEMBERS" | "AUDIT_LOG"
        ) {
            return Err("invalid_intents");
        }
        intents.insert(intent);
    }
    Ok(intents)
}

fn allowed_server_ids(bot: &BotIdentity, value: Option<&Value>) -> HashSet<i64> {
    let Some(value) = value else {
        return HashSet::from([bot.server_id]);
    };
    let Some(arr) = value.as_array() else {
        return HashSet::new();
    };
    if arr.is_empty() {
        return HashSet::from([bot.server_id]);
    }

    let mut requested = HashSet::new();
    for item in arr {
        let Some(id) = parse_id_string(Some(item)) else {
            return HashSet::new();
        };
        requested.insert(id);
    }
    if requested.is_empty() || requested.contains(&bot.server_id) {
        HashSet::from([bot.server_id])
    } else {
        HashSet::new()
    }
}

async fn feed_allowed(state: &AppState, bot: &BotIdentity, row: &BotOutboxRow) -> bool {
    let Some(feed_id) = row.feed_id else {
        return false;
    };
    if !bot.allowed_feed_ids.contains(&feed_id) {
        return false;
    }

    let feed = match crate::services::pg::feeds::by_id(&state.pg, feed_id).await {
        Ok(Some(feed)) => feed,
        Ok(None) => return false,
        Err(e) => {
            tracing::warn!(bot_id = bot.bot_id, feed_id, error = %e, "bot gateway feed permission read failed");
            return false;
        }
    };

    match crate::services::bot_permissions::can_view_feed(state, bot, &feed).await {
        Ok(allowed) => allowed,
        Err(e) => {
            tracing::warn!(bot_id = bot.bot_id, feed_id, error = %e, "bot gateway feed permission check failed");
            false
        }
    }
}

async fn channel_allowed(state: &AppState, bot: &BotIdentity, row: &BotOutboxRow) -> bool {
    let Some(channel_id) = row.channel_id else {
        return false;
    };
    if !bot.allowed_channel_ids.contains(&channel_id) {
        return false;
    }

    match crate::services::bot_permissions::has_channel_permission(
        state,
        bot,
        channel_id,
        crate::services::permissions::bits::VIEW_CHANNEL,
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(e) => {
            tracing::warn!(bot_id = bot.bot_id, channel_id, error = %e, "bot gateway channel permission check failed");
            false
        }
    }
}

async fn audit_allowed(state: &AppState, bot: &BotIdentity) -> bool {
    match crate::services::bot_permissions::has_server_permission(
        state,
        bot,
        crate::services::permissions::bits::MANAGE_SERVER,
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(e) => {
            tracing::warn!(bot_id = bot.bot_id, server_id = bot.server_id, error = %e, "bot gateway audit permission check failed");
            false
        }
    }
}

fn strip_message_content(mut payload: Value) -> Value {
    if let Some(message) = payload.get_mut("message").and_then(|v| v.as_object_mut()) {
        message.insert("content".to_string(), Value::String(String::new()));
        message.insert("contentRedacted".to_string(), Value::Bool(true));
    }
    payload
}

async fn dispatch_payload(
    state: &AppState,
    bot: &BotIdentity,
    intents: &HashSet<String>,
    row: &BotOutboxRow,
) -> Option<Value> {
    match row.event_type.as_str() {
        crate::services::bot_events::EVENT_FEED_ANNOUNCEMENT_CREATE
        | crate::services::bot_events::EVENT_FEED_ANNOUNCEMENT_UPDATE
        | crate::services::bot_events::EVENT_FEED_ANNOUNCEMENT_DELETE => {
            if intents.contains("FEEDS")
                && has_scope(&bot.scopes, SCOPE_FEEDS_READ)
                && feed_allowed(state, bot, row).await
            {
                Some(row.payload.clone())
            } else {
                None
            }
        }
        crate::services::bot_events::EVENT_MESSAGE_CREATE
        | crate::services::bot_events::EVENT_MESSAGE_UPDATE
        | crate::services::bot_events::EVENT_MESSAGE_DELETE => {
            if !(intents.contains("MESSAGES")
                && has_scope(&bot.scopes, SCOPE_MESSAGES_READ)
                && channel_allowed(state, bot, row).await)
            {
                return None;
            }
            if row.event_type == crate::services::bot_events::EVENT_MESSAGE_DELETE
                || has_scope(&bot.scopes, SCOPE_MESSAGE_CONTENT_READ)
            {
                Some(row.payload.clone())
            } else {
                Some(strip_message_content(row.payload.clone()))
            }
        }
        crate::services::bot_events::EVENT_MEMBER_JOIN
        | crate::services::bot_events::EVENT_MEMBER_LEAVE => {
            if intents.contains("MEMBERS") && has_scope(&bot.scopes, SCOPE_MEMBERS_READ) {
                Some(row.payload.clone())
            } else {
                None
            }
        }
        crate::services::bot_events::EVENT_AUDIT_LOG_CREATE => {
            if intents.contains("AUDIT_LOG")
                && has_scope(&bot.scopes, SCOPE_AUDIT_READ)
                && audit_allowed(state, bot).await
            {
                Some(row.payload.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

async fn send_outbox_events(
    socket: &mut futures_util::stream::SplitSink<WebSocket, WsMsg>,
    state: &AppState,
    conn: &mut BotConnectionState,
) -> bool {
    let Some(bot) = conn.bot.as_ref() else {
        return true;
    };

    match crate::services::pg::bots::token_by_id(&state.pg, bot.token_id).await {
        Ok(Some(token)) if token.revoked_at_ms.is_none() => {}
        Ok(_) => {
            tracing::warn!(
                bot_id = bot.bot_id,
                token_id = bot.token_id,
                "bot gateway token revoked or deleted; closing session"
            );
            return false;
        }
        Err(e) => {
            tracing::warn!(
                bot_id = bot.bot_id,
                token_id = bot.token_id,
                error = %e,
                "bot gateway token revalidation failed; closing session"
            );
            return false;
        }
    }

    let rows = match crate::services::pg::bot_outbox::list_after(
        &state.pg,
        bot.server_id,
        conn.last_event_id,
        BOT_EVENT_BATCH_LIMIT,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(bot_id = bot.bot_id, error = %e, "bot gateway outbox poll failed");
            return true;
        }
    };

    for row in rows {
        conn.last_event_id = row.id;
        if row.server_id != Some(bot.server_id) {
            continue;
        }
        let Some(payload) = dispatch_payload(state, bot, &conn.intents, &row).await else {
            continue;
        };
        let event = json!({
            "op": "DISPATCH",
            "t": row.event_type,
            "s": row.id.to_string(),
            "d": payload,
        });
        if socket
            .send(WsMsg::Text(event.to_string().into()))
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

async fn handle_identify(
    state: &AppState,
    conn: &mut BotConnectionState,
    data: Option<&Value>,
) -> Result<Value, &'static str> {
    if conn.authenticated {
        return Err("already_authenticated");
    }

    let token = data
        .and_then(|d| d.get("token"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            data.and_then(|d| d.get("authorization"))
                .and_then(|v| v.as_str())
        })
        .and_then(|s| s.strip_prefix("Bot ").or(Some(s)))
        .ok_or("missing_token")?;

    let bot = authenticate_bot_token(state, token)
        .await
        .map_err(|_| "invalid_token")?;

    let server_ids = allowed_server_ids(&bot, data.and_then(|d| d.get("serverIds")));
    if !server_ids.contains(&bot.server_id) {
        return Err("server_not_allowed");
    }

    let intents = parse_intents(data.and_then(|d| d.get("intents")))?;
    // Do not trust client-provided cursors on a fresh identify. The outbox
    // retains events for durability, but an arbitrary low cursor would let a
    // newly minted token or newly permissioned bot replay historical events it
    // could not observe in real time. Until resume cursors are server-issued,
    // new sessions start at the current tail.
    let last_event_id = crate::services::pg::bot_outbox::latest_id(&state.pg, bot.server_id)
        .await
        .unwrap_or(0);

    conn.authenticated = true;
    conn.last_event_id = last_event_id;
    conn.intents = intents.clone();
    state
        .bot_gateway
        .add_session(conn.conn_id, bot.bot_id, bot.server_id);
    conn.bot = Some(bot.clone());

    let presence = state
        .bot_gateway
        .presence_payload(bot.bot_id, bot.server_id, "online");
    crate::ws::topics::publish_json(
        state,
        &crate::ws::topics::presence_topic(bot.server_id),
        &json!({ "op": "BOT_PRESENCE_UPDATE", "d": presence }).to_string(),
    )
    .await;

    Ok(json!({
        "sessionId": uuid::Uuid::new_v4().to_string(),
        "bot": {
            "id": bot.bot_id.to_string(),
            "serverId": bot.server_id.to_string(),
            "name": bot.name,
        },
        "serverIds": [bot.server_id.to_string()],
        "intents": intents.into_iter().collect::<Vec<_>>(),
        "lastEventId": last_event_id.to_string(),
    }))
}

async fn run_bot_connection(socket: WebSocket, state: AppState, conn_id: u64) {
    let (mut sink, mut stream) = socket.split();
    let mut conn = BotConnectionState::new(conn_id);
    let mut poll = tokio::time::interval(Duration::from_millis(BOT_POLL_INTERVAL_MS));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(conn_id, "Bot gateway connected");

    loop {
        tokio::select! {
            _ = poll.tick(), if conn.authenticated => {
                if !send_outbox_events(&mut sink, &state, &mut conn).await {
                    break;
                }
            }
            frame = stream.next() => {
                let Some(frame) = frame else { break };
                let Ok(frame) = frame else { break };
                match frame {
                    WsMsg::Close(_) => break,
                    WsMsg::Ping(data) => {
                        if sink.send(WsMsg::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    WsMsg::Pong(_) => {}
                    WsMsg::Binary(_) => {
                        let _ = sink.send(json_error("UNSUPPORTED_FRAME", "Bot gateway accepts JSON text frames")).await;
                    }
                    WsMsg::Text(text) => {
                        if !conn.check_rate_limit() {
                            let _ = sink.send(WsMsg::Close(Some(CloseFrame {
                                code: 4029,
                                reason: "Rate limited".into(),
                            }))).await;
                            break;
                        }
                        let Ok(value) = serde_json::from_str::<Value>(&text) else {
                            let _ = sink.send(json_error("PARSE_ERROR", "Invalid JSON")).await;
                            continue;
                        };
                        let op = value.get("op").and_then(|v| v.as_str()).unwrap_or("");
                        match op {
                            "IDENTIFY" => {
                                match handle_identify(&state, &mut conn, value.get("d")).await {
                                    Ok(data) => {
                                        if sink.send(json_event("READY", data)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(code) => {
                                        let _ = sink.send(json_error(code, "Bot identify failed")).await;
                                        let _ = sink.send(WsMsg::Close(Some(CloseFrame {
                                            code: 4001,
                                            reason: "Authentication failed".into(),
                                        }))).await;
                                        break;
                                    }
                                }
                            }
                            "RESUME" => {
                                if !conn.authenticated {
                                    let _ = sink.send(json_error("NOT_AUTHENTICATED", "Identify first")).await;
                                    continue;
                                }
                                if let Some(id) = value.get("d").and_then(|d| d.get("lastEventId")).and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| v.as_i64())) {
                                    conn.last_event_id = conn.last_event_id.max(id.max(0));
                                }
                                let _ = sink.send(json_event("RESUMED", json!({ "lastEventId": conn.last_event_id.to_string() }))).await;
                            }
                            "PING" => {
                                let _ = sink.send(json_event("PONG", json!({}))).await;
                            }
                            _ => {
                                let _ = sink.send(json_error("UNKNOWN_OP", "Unknown bot gateway op")).await;
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(session) = state.bot_gateway.remove_session(conn_id) {
        let still_online = state.bot_gateway.is_bot_online(session.bot_id);
        if !still_online {
            let presence =
                state
                    .bot_gateway
                    .presence_payload(session.bot_id, session.server_id, "offline");
            crate::ws::topics::publish_json(
                &state,
                &crate::ws::topics::presence_topic(session.server_id),
                &json!({ "op": "BOT_PRESENCE_UPDATE", "d": presence }).to_string(),
            )
            .await;
        }
    }

    tracing::info!(conn_id, "Bot gateway disconnected");
}

pub async fn upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));

    if let Err(_) = rate_limit::enforce(&state, &BOT_WS_UPGRADE_LIMIT, &ip).await {
        tracing::warn!(%ip, "Bot gateway upgrade rate limited");
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, "Rate limited").into_response();
    }

    let conn_id = state.ws.next_conn_id();
    ws.max_frame_size(16 * 1024)
        .max_message_size(16 * 1024)
        .on_upgrade(move |socket| async move {
            run_bot_connection(socket, state, conn_id).await;
        })
}
