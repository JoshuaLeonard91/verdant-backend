use std::collections::{HashMap, HashSet};

use chrono::Utc;
use prost::Message as ProstMessage;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::error::AppError;
use crate::proto::{self, WsMessage};
use crate::repo::{categories, channels, servers};
use crate::services::banner_crop;
use crate::services::cdn;
use crate::services::channel_access::verify_channel_access;
use crate::services::crypto::{self, VerifiedTokenKind};
use crate::services::message_media_policy::check_media_urls;
use crate::services::permissions::{IdentifyCacheData, IdentifyServer, bits};
use crate::services::sanitize::sanitize_message_content;
use crate::state::AppState;

use super::connection::{ConnectionState, Encoding, OutboundMsg};
use super::events;
use super::topics;

const MAX_MESSAGE_LENGTH: usize = 4000;
const MAX_UNIQUE_REACTIONS_PER_MESSAGE: i64 = 20;
const CHANNEL_TYPE_SERVER_VOICE: i32 = 3;

fn parse_id(s: &str) -> Option<i64> {
    s.parse::<i64>().ok()
}

fn visible_voice_channel_ids(visible_channels: &[&channels::ChannelRow]) -> Vec<i64> {
    visible_channels
        .iter()
        .filter(|c| c.r#type == CHANNEL_TYPE_SERVER_VOICE)
        .map(|c| c.id)
        .collect()
}

fn federated_connection_allows_server(conn: &ConnectionState, server_id: Option<i64>) -> bool {
    match (&conn.federated_allowed_server_ids, server_id) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(allowed), Some(server_id)) => allowed.contains(&server_id),
    }
}

fn ready_allows_dm_relationship_state(conn: &ConnectionState) -> bool {
    conn.federated_allowed_server_ids.is_none()
}

fn ready_order_from_preferences(
    order: &Value,
    allowed_server_ids: Option<&HashSet<i64>>,
) -> Vec<String> {
    order
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|value| {
                    let raw = value
                        .as_str()
                        .map(String::from)
                        .or_else(|| value.as_i64().map(|n| n.to_string()))?;
                    if let Some(allowed) = allowed_server_ids {
                        let server_id = raw.parse::<i64>().ok()?;
                        allowed.contains(&server_id).then_some(raw)
                    } else {
                        Some(raw)
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn ready_preferences_for_scope(preferences: &Value, include_private_user_state: bool) -> Value {
    if include_private_user_state {
        preferences.clone()
    } else {
        Value::Null
    }
}

fn scoped_member_roles_for_ready(
    roles: Vec<(i64, i64)>,
    ready_server_ids: &HashSet<i64>,
) -> Vec<(i64, i64)> {
    roles
        .into_iter()
        .filter(|(server_id, _)| ready_server_ids.contains(server_id))
        .collect()
}

fn scoped_read_states_for_ready(
    read_states: Vec<(i64, i64)>,
    visible_channel_ids: &HashSet<i64>,
    server_scoped_federated_ready: bool,
) -> Vec<(i64, i64)> {
    if !server_scoped_federated_ready {
        return read_states;
    }
    read_states
        .into_iter()
        .filter(|(channel_id, _)| visible_channel_ids.contains(channel_id))
        .collect()
}

fn scoped_presence_server_ids(
    mut server_ids: Vec<i64>,
    federated_allowed_server_ids: Option<&HashSet<i64>>,
) -> Vec<i64> {
    if let Some(allowed_server_ids) = federated_allowed_server_ids {
        server_ids.retain(|server_id| allowed_server_ids.contains(server_id));
    }
    server_ids
}

/// Send an outbound message respecting the connection's encoding.
#[allow(dead_code)]
fn send(tx: &mpsc::Sender<OutboundMsg>, conn: &ConnectionState, json: &str, proto: &WsMessage) {
    match conn.encoding {
        Encoding::Protobuf => {
            let mut buf = Vec::with_capacity(proto.encoded_len());
            if proto.encode(&mut buf).is_ok() {
                let _ = tx.try_send(OutboundMsg::Binary(buf.into()));
            }
        }
        _ => {
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
        }
    }
}

#[allow(dead_code)]
fn send_json(tx: &mpsc::Sender<OutboundMsg>, text: String) {
    let _ = tx.try_send(OutboundMsg::Text(text.into()));
}

fn send_error(
    tx: &mpsc::Sender<OutboundMsg>,
    conn: &ConnectionState,
    origin_op: &str,
    error: &str,
    code: &str,
) {
    match conn.encoding {
        Encoding::Protobuf => {
            let msg = events::ws_error_proto(origin_op, error, code);
            let mut buf = Vec::with_capacity(msg.encoded_len());
            if msg.encode(&mut buf).is_ok() {
                let _ = tx.try_send(OutboundMsg::Binary(buf.into()));
            }
        }
        _ => {
            let _ = tx.try_send(OutboundMsg::Text(
                events::ws_error_json(origin_op, error, code).into(),
            ));
        }
    }
}

async fn record_channel_activity(state: &AppState, channel_id: i64, user_id: i64, ts_ms: i64) {
    use fred::interfaces::{HashesInterface, KeysInterface};
    let key = format!("channel:{channel_id}:activity");
    if let Err(e) = state
        .redis
        .hset::<(), _, _>(&key, (user_id.to_string(), ts_ms.to_string()))
        .await
    {
        tracing::warn!(channel_id, user_id, error = %e, "Failed to record channel activity");
        return;
    }
    let _: Result<bool, _> = state.redis.expire(&key, 86400, None).await;
}

async fn enqueue_federation_channel_event(
    state: &AppState,
    channel_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    now_ms: i64,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Channel { channel_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        now_ms,
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            channel_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "Federation WS channel event producer completed"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            channel_id,
            error = %error,
            "Federation WS channel event producer failed"
        ),
    }
}

async fn enqueue_federation_server_event(
    state: &AppState,
    server_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    now_ms: i64,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        now_ms,
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            server_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "Federation WS server event producer completed"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            server_id,
            error = %error,
            "Federation WS server event producer failed"
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_message_create_scoped(
    state: &AppState,
    channel_id: i64,
    channel_id_str: &str,
    server_id: Option<i64>,
    message_id: &str,
    author_id: &str,
    created_at: &str,
    author_username: Option<&str>,
    author_display_name: Option<&str>,
    author_avatar_url: Option<&str>,
    message_json: &str,
    message_proto: &WsMessage,
    mention_source: &str,
) {
    let live_topic = topics::channel_live_topic(channel_id);
    let notify_topic = topics::channel_notify_topic(channel_id);
    let live_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&live_topic)
        .map(|set| set.len())
        .unwrap_or(0);
    let notify_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&notify_topic)
        .map(|set| set.len())
        .unwrap_or(0);
    crate::realtime_trace!(
        channel_id,
        server_id = ?server_id,
        message_id,
        author_id,
        live_topic = %live_topic,
        notify_topic = %notify_topic,
        live_local_subscribers,
        notify_local_subscribers,
        "realtime_scope: publishing MESSAGE_CREATE live, CHANNEL_UNREAD_SIGNAL notify, and CHANNEL_ACTIVITY_UPDATE live"
    );
    topics::publish(state, &live_topic, message_json, message_proto).await;

    let server_id_str = server_id.map(|sid| sid.to_string());
    let unread_json = events::channel_unread_signal_json(
        channel_id_str,
        server_id_str.as_deref(),
        message_id,
        author_id,
        created_at,
        false,
        server_id.is_none(),
    );
    let unread_proto = events::channel_unread_signal_proto(
        channel_id_str.to_string(),
        server_id_str,
        message_id.to_string(),
        author_id.to_string(),
        created_at.to_string(),
        false,
        server_id.is_none(),
    );
    topics::publish(state, &notify_topic, &unread_json, &unread_proto).await;

    if let Ok(author_id_i64) = author_id.parse::<i64>() {
        match crate::services::message_notifications::publish_targeted_unread_signals(
            state,
            channel_id,
            channel_id_str,
            server_id,
            message_id,
            author_id_i64,
            created_at,
            mention_source,
        )
        .await
        {
            Ok(stats) => crate::realtime_trace!(
                channel_id,
                server_id = ?server_id,
                message_id,
                targeted = stats.target_count,
                mentions = stats.mention_count,
                channel_prefs = stats.channel_pref_count,
                skipped_permissions = stats.skipped_permission_count,
                "realtime_scope: targeted unread fanout complete"
            ),
            Err(err) => tracing::warn!(
                channel_id,
                server_id = ?server_id,
                message_id,
                error = %err,
                "targeted unread fanout failed"
            ),
        }
    } else {
        crate::realtime_trace!(
            channel_id,
            server_id = ?server_id,
            message_id,
            author_id,
            "realtime_scope: skipped targeted unread fanout because author id was not numeric"
        );
    }

    let activity_json = events::channel_activity_update_json(
        channel_id_str,
        author_id,
        created_at,
        author_username,
        author_display_name,
        author_avatar_url,
    );
    let activity_proto = events::channel_activity_update_proto(
        channel_id_str.to_string(),
        author_id.to_string(),
        created_at.to_string(),
        author_username.map(str::to_string),
        author_display_name.map(str::to_string),
        author_avatar_url.map(str::to_string),
    );
    topics::publish(state, &live_topic, &activity_json, &activity_proto).await;
}

// ─── IDENTIFY ────────────────────────────────────────────────────────

pub async fn handle_identify(
    state: &AppState,
    conn: &mut ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    token: &str,
    client_version: Option<String>,
    resume_session_id: Option<String>,
    last_ready_at: Option<String>,
    initial_status: i32,
    afk: bool,
) {
    tracing::info!(conn_id = conn.conn_id, "IDENTIFY received");

    if conn.authenticated {
        tracing::warn!(
            conn_id = conn.conn_id,
            "IDENTIFY rejected: already authenticated"
        );
        send_error(
            tx,
            conn,
            "IDENTIFY",
            "Already authenticated",
            "WS_ALREADY_AUTHENTICATED",
        );
        return;
    }

    if state.draining.load(std::sync::atomic::Ordering::Relaxed) {
        let json = topics::server_draining_json("zdt", 0, 500);
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        let _ = tx.try_send(OutboundMsg::Close(1001, "Server draining".to_string()));
        return;
    }

    if token.is_empty() {
        tracing::warn!(conn_id = conn.conn_id, "IDENTIFY rejected: empty token");
        let _ = tx.try_send(OutboundMsg::Close(
            4001,
            "Authentication required".to_string(),
        ));
        return;
    }

    // Store client version
    let cv = client_version.unwrap_or_else(|| "0.0.0".to_string());
    conn.client_version = Some(cv.clone());

    // Check if client is outdated
    if let (Ok(client_v), Ok(min_v)) = (
        semver::Version::parse(&cv),
        semver::Version::parse(&state.config.min_client_version),
    ) {
        if client_v < min_v {
            let json = events::force_update_json(
                &state.config.min_client_version,
                "https://github.com/JoshuaLeonard91/verdant/releases/latest",
            );
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
            let _ = tx.try_send(OutboundMsg::Close(4010, "Client outdated".to_string()));
            return;
        }
    }

    // Verify JWT access token
    let verified = match crypto::verify_access_token_for_instance(
        token,
        &state.config.jwt_secret,
        &state.redis,
        Some(&state.config.instance_id),
    )
    .await
    {
        Ok(v) => {
            tracing::info!(user_id = v.user_id, "IDENTIFY: token verified successfully");
            v
        }
        Err(e) => {
            tracing::warn!(error = %e, token_len = token.len(), "IDENTIFY: token verification FAILED");
            let _ = tx.try_send(OutboundMsg::Close(4004, "Invalid token".to_string()));
            return;
        }
    };
    let federated_client_identity =
        match crate::middleware::auth::federated_client_identity_for_token(state, &verified).await {
            Ok(identity) => identity,
            Err(e) => {
                tracing::warn!(error = %e, "IDENTIFY: federated client token rejected");
                let _ = tx.try_send(OutboundMsg::Close(4004, "Invalid token".to_string()));
                return;
            }
        };

    let user_id = verified.user_id;

    if let Err(e) = crate::services::app_bans::ensure_user_not_banned(state, user_id).await {
        tracing::warn!(user_id, error = %e, "IDENTIFY rejected: account banned");
        let _ = tx.try_send(OutboundMsg::Close(4003, "Account banned".to_string()));
        return;
    }

    // Per-user IDENTIFY rate limit. Gate AFTER token verification
    // (so an unauthenticated burst can't cause us to even talk to
    // Redis) but BEFORE the expensive READY composer fan-out. The
    // composer is the most expensive op in the engine — capping
    // identify-per-user-per-minute prevents reconnect-storm DoS
    // and abusive clients hammering the composer.
    //
    if let Err(e) = crate::middleware::rate_limit::enforce(
        state,
        &crate::middleware::rate_limit::IDENTIFY_LIMIT,
        &user_id.to_string(),
    )
    .await
    {
        tracing::warn!(user_id, error = %e, "IDENTIFY rate-limited");
        let _ = tx.try_send(OutboundMsg::Close(
            4029,
            "Too many IDENTIFY requests".to_string(),
        ));
        return;
    }

    if matches!(verified.kind, VerifiedTokenKind::UserSession)
        && state.config.email_verification_required()
    {
        let email_verified = match crate::services::pg::users::email_verified_by_id(
            &state.pg, user_id,
        )
        .await
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                tracing::warn!(
                    user_id,
                    "IDENTIFY rejected: user not found for email verification check"
                );
                let _ = tx.try_send(OutboundMsg::Close(4004, "User not found".to_string()));
                return;
            }
            Err(e) => {
                tracing::error!(user_id, error = %e, "IDENTIFY rejected: email verification check failed");
                let _ = tx.try_send(OutboundMsg::Close(4500, "Database unavailable".to_string()));
                return;
            }
        };

        if !email_verified {
            tracing::warn!(user_id, "IDENTIFY rejected: email verification required");
            send_error(
                tx,
                conn,
                "IDENTIFY",
                "Please verify your email address to continue.",
                "EMAIL_VERIFICATION_REQUIRED",
            );
            let _ = tx.try_send(OutboundMsg::Close(
                4003,
                "Email verification required".to_string(),
            ));
            return;
        }
    }

    // Security invariant: attach identity only after token, ban, email, and
    // IDENTIFY rate-limit checks pass; dispatch gates all other ops on this.
    conn.user_id = Some(user_id);
    conn.authenticated = true;
    conn.session_id = Some(uuid::Uuid::new_v4().to_string());
    conn.federated_allowed_server_ids = federated_client_identity.as_ref().map(|identity| {
        identity
            .server_ids
            .iter()
            .copied()
            .collect::<HashSet<i64>>()
    });

    // Per-user connection cap: evict oldest if at limit
    const MAX_CONNECTIONS_PER_USER: usize = 5;
    let existing = state.ws.get_user_conn_ids(user_id);
    if existing.len() >= MAX_CONNECTIONS_PER_USER {
        if let Some(&oldest) = existing.iter().min() {
            state.ws.send_to(
                oldest,
                OutboundMsg::Close(4008, "Too many connections".to_string()),
            );
            state.ws.remove_connection(oldest);
        }
    }

    // Register connection
    state.ws.add_connection(user_id, conn.conn_id, tx.clone());

    // Replay encoding into conn_info AFTER add_connection. The read
    // loop calls `set_encoding()` on the first binary/text frame, but
    // that happens BEFORE `add_connection` has inserted the conn_info
    // row — so the set_encoding call silently no-ops and conn_info
    // stays at `Encoding::Unknown` forever. Broadcast fan-out reads
    // encoding from conn_info so fanout can choose protobuf or JSON per connection.
    state.ws.set_encoding(conn.conn_id, conn.encoding);

    // If the WS upgrade advertised `?batch=1`, mark this conn as
    // batch-capable so the broadcast coalescer can pack merged bursts
    // into a single Batch frame instead of sending individual frames.
    if conn.supports_batch {
        state.ws.mark_batch_capable(conn.conn_id);
    }

    // ─── Delta READY: attempt incremental reconnect ─────────────────────
    // If the client sent resume_session_id + last_ready_at AND the user's
    // permission cache is still warm (another connection was recent), we can
    // skip the full READY fetch and send only what changed since last_ready_at.
    // This saves ~10 DB queries on reconnect for users who briefly lost connection.
    //
    // Max delta window: 5 minutes. Beyond that, too much may have changed.
    const MAX_DELTA_WINDOW_SECS: i64 = 300;

    if let (Some(_resume_sid), Some(last_ready_str)) = (&resume_session_id, &last_ready_at) {
        if let Ok(since) = chrono::DateTime::parse_from_rfc3339(last_ready_str) {
            let since_utc = since.with_timezone(&chrono::Utc);
            let age = Utc::now().signed_duration_since(since_utc);

            // Only attempt delta if: within time window AND permission cache is warm
            if age.num_seconds() <= MAX_DELTA_WINDOW_SECS
                && age.num_seconds() >= 0
                && state.permissions.get_user_server_ids(user_id).is_some()
            {
                tracing::info!(
                    user_id,
                    conn_id = conn.conn_id,
                    age_secs = age.num_seconds(),
                    "Attempting delta READY"
                );

                match handle_delta_ready(state, conn, tx, user_id, since_utc).await {
                    Ok(()) => {
                        // Delta READY succeeded — we're done
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(
                            user_id,
                            conn_id = conn.conn_id,
                            error = %e,
                            "Delta READY failed, falling back to full READY"
                        );
                        // Fall through to full READY
                    }
                }
            } else {
                tracing::debug!(
                    user_id,
                    conn_id = conn.conn_id,
                    age_secs = age.num_seconds(),
                    "Delta READY skipped: outside time window or cold cache"
                );
            }
        }
    }

    // ─── READY data fan-out ───────────────────────────────────────
    //
    // Dependency order: user record, server ids, then per-server data.
    let user_id_big = user_id;

    let user_row = match crate::services::pg::users::by_id(&state.pg, user_id_big).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(
                user_id = user_id_big,
                "IDENTIFY aborted: user not found in PG"
            );
            let _ = tx.try_send(OutboundMsg::Close(4004, "User not found".to_string()));
            return;
        }
        Err(e) => {
            tracing::error!(user_id = user_id_big, error = %e, "IDENTIFY aborted: PG user read failed");
            let _ = tx.try_send(OutboundMsg::Close(4500, "Database unavailable".to_string()));
            return;
        }
    };

    // Warm the user_profiles cache so downstream sync checks
    // (loadtest prefix bypass, author lookups) hit without a
    // round-trip. The cache shares its backing call with this
    // IDENTIFY's user fetch — DashMap dedup so this is a noop here.
    let _ = state
        .user_profiles
        .get_or_fetch(&state.pg, user_id_big)
        .await;

    if state.user_profiles.is_loadtest_user(user_id_big) {
        conn.bypass_rate_limits = true;
        tracing::info!(
            user_id = user_id_big,
            "IDENTIFY: loadtest user, rate limits bypassed"
        );
    }

    let mut server_ids_for_user =
        crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id_big)
            .await
            .unwrap_or_default();
    if let Some(allowed_server_ids) = &conn.federated_allowed_server_ids {
        server_ids_for_user.retain(|server_id| allowed_server_ids.contains(server_id));
        if server_ids_for_user.is_empty() {
            tracing::warn!(
                user_id = user_id_big,
                allowed_server_count = allowed_server_ids.len(),
                "IDENTIFY rejected: federated client token has no active allowed memberships"
            );
            let _ = tx.try_send(OutboundMsg::Close(4004, "Membership pending".to_string()));
            return;
        }
    }

    // Parallel fan-out: per-server lists run in parallel via
    // `futures::join_all`; per-user reads run alongside via
    // `tokio::join!`. Per-server fan-out scales linearly with server
    // count; for solo prod (≤50 servers/user) this is a few-ms wall
    // time on a warm pool.
    let pg = state.pg.clone();
    let server_ids_arr = server_ids_for_user.clone();
    let ready_server_id_set: HashSet<i64> = server_ids_arr.iter().copied().collect();
    let ready_allows_dm_relationship_state = ready_allows_dm_relationship_state(conn);

    let channels_per_server = futures_util::future::join_all(server_ids_arr.iter().map(|sid| {
        let pg = pg.clone();
        let sid = *sid;
        async move { crate::services::pg::channels::list_for_server(&pg, sid).await }
    }));
    let categories_per_server = futures_util::future::join_all(server_ids_arr.iter().map(|sid| {
        let pg = pg.clone();
        let sid = *sid;
        async move { crate::services::pg::categories::list_for_server(&pg, sid).await }
    }));
    let roles_per_server = futures_util::future::join_all(server_ids_arr.iter().map(|sid| {
        let pg = pg.clone();
        let sid = *sid;
        async move { crate::services::pg::roles::list_for_server(&pg, sid).await }
    }));
    let emojis_per_server = futures_util::future::join_all(server_ids_arr.iter().map(|sid| {
        let pg = pg.clone();
        let sid = *sid;
        async move { crate::services::pg::emojis::list_for_server(&pg, sid).await }
    }));
    let feeds_per_server = futures_util::future::join_all(server_ids_arr.iter().map(|sid| {
        let pg = pg.clone();
        let sid = *sid;
        async move { crate::services::pg::feeds::list_for_server(&pg, sid).await }
    }));
    let relationships_for_ready = {
        let pg = pg.clone();
        async move {
            if ready_allows_dm_relationship_state {
                crate::services::pg::relationships::list_for_user(&pg, user_id_big).await
            } else {
                Ok(Vec::new())
            }
        }
    };
    let dm_channel_ids_for_ready = {
        let pg = pg.clone();
        async move {
            if ready_allows_dm_relationship_state {
                crate::services::pg::dms::list_channel_ids_for_user(&pg, user_id_big).await
            } else {
                Ok(Vec::new())
            }
        }
    };

    let (
        server_rows_pg,
        chans_per_srv,
        cats_per_srv,
        roles_per_srv,
        emojis_per_srv,
        feeds_per_srv,
        my_member_roles_pg,
        read_states_pg,
        relationships_pg,
        dm_channel_ids_pg,
    ) = tokio::join!(
        crate::services::pg::servers::by_ids(&pg, &server_ids_arr),
        channels_per_server,
        categories_per_server,
        roles_per_server,
        emojis_per_server,
        feeds_per_server,
        crate::services::pg::roles::list_for_user(&pg, user_id_big),
        crate::services::pg::read_states::list_for_user(&pg, user_id_big),
        relationships_for_ready,
        dm_channel_ids_for_ready,
    );

    let server_rows: Vec<servers::ServerRow> = server_rows_pg.unwrap_or_default();
    let all_channels: Vec<channels::ChannelRow> = chans_per_srv
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect();
    let all_categories: Vec<categories::CategoryRow> = cats_per_srv
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect();
    let all_roles_raw: Vec<crate::services::pg::roles::RoleRow> = roles_per_srv
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect();
    let all_emojis_raw: Vec<crate::services::pg::emojis::EmojiRow> = emojis_per_srv
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect();
    let all_feeds_raw: Vec<crate::services::pg::feeds::FeedRow> = feeds_per_srv
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect();
    let my_member_roles: Vec<(i64, i64)> = my_member_roles_pg
        .unwrap_or_default()
        .into_iter()
        .map(|m| (m.server_id, m.role_id))
        .collect();
    let my_member_roles = scoped_member_roles_for_ready(my_member_roles, &ready_server_id_set);
    let read_states: Vec<(i64, i64)> = read_states_pg
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.channel_id, r.last_read_message_id))
        .collect();
    let relationships_raw: Vec<crate::services::pg::relationships::RelationshipRow> =
        relationships_pg.unwrap_or_default();
    let dm_channel_ids: Vec<i64> = dm_channel_ids_pg.unwrap_or_default();

    // Convert to the local row types the rest of the handler consumes.
    let all_roles: Vec<RoleRow> = all_roles_raw
        .iter()
        .map(|r| RoleRow {
            id: r.id,
            server_id: r.server_id,
            name: r.name.clone(),
            color: if r.color == 0 { None } else { Some(r.color) },
            permissions: r.permissions,
            position: r.position,
            color_only: r.color_only,
            show_as_section: r.show_as_section,
            color_priority: r.color_priority,
            created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.created_at_ms)
                .unwrap_or_else(chrono::Utc::now),
        })
        .collect();
    let all_emojis: Vec<EmojiRow> = all_emojis_raw
        .iter()
        .map(|e| EmojiRow {
            id: e.id,
            server_id: e.server_id,
            name: e.name.clone(),
            url: e.url.clone(),
            created_by: e.created_by,
            created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(e.created_at_ms)
                .unwrap_or_else(chrono::Utc::now),
        })
        .collect();

    // Resolve relationship target user info via one batch read.
    let rel_target_ids: Vec<i64> = relationships_raw.iter().map(|r| r.target_id).collect();
    let rel_target_users = crate::services::pg::users::by_ids(&state.pg, &rel_target_ids)
        .await
        .unwrap_or_default();
    let rel_target_lookup: HashMap<i64, &crate::repo::users::UserRow> =
        rel_target_users.iter().map(|u| (u.id, u)).collect();
    let rel_status_map: HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &rel_target_ids)
            .await
            .into_iter()
            .collect();

    let relationship_rows: Vec<RelationshipRow> = relationships_raw
        .iter()
        .map(|r| {
            let target = rel_target_lookup.get(&r.target_id);
            RelationshipRow {
                target_id: r.target_id,
                rel_type: r.rel_type as i32,
                created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.created_at_ms)
                    .unwrap_or_else(chrono::Utc::now),
                target_username: target.map(|u| u.username.clone()).unwrap_or_default(),
                target_avatar_url: target.and_then(|u| u.avatar_url.clone()),
                target_display_name: target.and_then(|u| u.display_name.clone()),
                target_status_type: rel_status_map
                    .get(&r.target_id)
                    .cloned()
                    .unwrap_or_else(|| "offline".to_string()),
                notes: r.notes.clone().unwrap_or_default(),
                nickname_color: r.nickname_color.clone().filter(|s| !s.is_empty()),
            }
        })
        .collect();

    let server_ids: Vec<i64> = server_rows.iter().map(|s| s.id).collect();

    tracing::info!(
        user_id = user_id_big,
        servers = server_rows.len(),
        channels = all_channels.len(),
        "IDENTIFY: served READY data"
    );

    // ─── Populate permission cache (lightweight — server data is lazy-loaded) ───
    {
        let cache_data = IdentifyCacheData {
            server_ids: server_ids.clone(),
            servers: server_rows
                .iter()
                .map(|s| IdentifyServer {
                    id: s.id,
                    owner_id: s.owner_id,
                })
                .collect(),
            member_roles: my_member_roles.clone(),
            dm_channel_ids: dm_channel_ids.clone(),
            // Build lightweight channel_index: (channel_id, server_id) for all server channels
            channel_index_entries: all_channels
                .iter()
                .filter_map(|c| c.server_id.map(|sid| (c.id, sid)))
                .collect(),
        };
        state
            .permissions
            .populate_from_identify(user_id, cache_data);
    }

    // ─── Member counts for large-server detection ───
    // Parallel fan-out over the per-server `member_count` query.
    let count_futs = futures_util::future::join_all(server_ids.iter().map(|sid| {
        let pg = state.pg.clone();
        let sid = *sid;
        async move {
            (
                sid,
                crate::services::pg::servers::member_count(&pg, sid)
                    .await
                    .unwrap_or(0),
            )
        }
    }))
    .await;
    let server_member_counts: HashMap<i64, i64> = count_futs.into_iter().collect();

    // Load channel overrides before any VIEW_CHANNEL filtering. IDENTIFY
    // populated only the lightweight channel index; treating an unloaded
    // server as visible leaks private channels on cold caches.
    let loaded_server_results = futures_util::future::join_all(
        server_ids
            .iter()
            .map(|sid| state.permissions.lazy_load_server(*sid)),
    )
    .await;
    let mut permission_ready_servers: std::collections::HashSet<i64> =
        std::collections::HashSet::with_capacity(server_ids.len());
    for (sid, result) in server_ids.iter().copied().zip(loaded_server_results) {
        match result {
            Ok(_) => {
                permission_ready_servers.insert(sid);
            }
            Err(e) => {
                tracing::error!(
                    user_id,
                    server_id = sid,
                    error = %e,
                    "IDENTIFY: permission cache load failed; hiding server channels from READY"
                );
            }
        }
    }

    // ─── Build topic subscriptions ───
    let mut topic_list: Vec<String> = Vec::new();

    // Subscribe only to the focused server's presence topic.
    let focused_server_id: Option<i64> = user_row
        .preferences
        .get("activeServerId")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|sid| server_ids.contains(sid)); // must be a server the user is in

    conn.focused_server_id = focused_server_id;

    if let Some(focused_sid) = focused_server_id {
        topic_list.push(topics::presence_topic(focused_sid));
    }

    // Channel visibility is authorization, not subscription. Do not subscribe
    // all visible server channels here; FOCUS_CHANNEL adds live + notify topics
    // only after this connection actually views a channel.
    let mut visible_channels = Vec::with_capacity(all_channels.len());
    for ch in &all_channels {
        if let Some(sid) = ch.server_id {
            if !permission_ready_servers.contains(&sid) {
                continue;
            }
            let can_view = state
                .permissions
                .has_channel_permission(user_id, ch.id, bits::VIEW_CHANNEL)
                .unwrap_or(false);
            if can_view {
                visible_channels.push(ch);
            }
        } else {
            // Non-server channels (shouldn't happen here, but include for safety)
            visible_channels.push(ch);
        }
    }

    let voice_channel_ids = visible_voice_channel_ids(&visible_channels);
    for &voice_channel_id in &voice_channel_ids {
        topic_list.push(topics::voice_topic(voice_channel_id));
    }
    let visible_voice_channel_id_set: HashSet<i64> = voice_channel_ids.iter().copied().collect();
    let visible_channel_id_set: HashSet<i64> = visible_channels.iter().map(|ch| ch.id).collect();
    let read_states = scoped_read_states_for_ready(
        read_states,
        &visible_channel_id_set,
        conn.federated_allowed_server_ids.is_some(),
    );
    let restored_voice_state = state.voice.get_user_state(&state.redis, user_id).await;
    if let Some(vs) = restored_voice_state.as_ref() {
        if visible_voice_channel_id_set.contains(&vs.channel_id) {
            conn.joined_voice_channel_id = Some(vs.channel_id);
            state.ws.set_voice_channel_for_user(user_id, vs.channel_id);
        } else {
            tracing::warn!(
                user_id,
                channel_id = vs.channel_id,
                "IDENTIFY: ignoring stale voice state for channel without VIEW_CHANNEL"
            );
        }
    }

    // DM notify topics are private user graph state and are not part of a
    // server-scoped federated READY capability.
    if ready_allows_dm_relationship_state {
        for &dm_id in &dm_channel_ids {
            topic_list.push(topics::channel_notify_topic(dm_id));
        }
    }

    // Private user graph fanout is not part of a server-scoped federated
    // READY capability; server/channel topics carry the authorized runtime
    // surface for that scoped connection.
    if ready_allows_dm_relationship_state {
        topic_list.push(topics::user_topic(user_id));
    }

    // System broadcast
    topic_list.push(topics::system_topic());

    crate::realtime_trace!(
        user_id,
        conn_id = conn.conn_id,
        focused_server_id = ?focused_server_id,
        visible_channel_count = visible_channels.len(),
        dm_notify_count = dm_channel_ids.len(),
        restored_voice_channel_id = ?conn.joined_voice_channel_id,
        visible_voice_channel_count = voice_channel_ids.len(),
        topic_count = topic_list.len(),
        "realtime_scope: IDENTIFY subscribed visible voice topics, presence for focused server, private user topics when allowed, system topic; no broad server text channel subscriptions"
    );
    topics::subscribe_connection(state, conn.conn_id, &topic_list).await;

    // ─── Build member_role_ids map (server_id -> [role_ids]) ───
    let mut member_role_map: HashMap<String, Vec<String>> = HashMap::new();
    for (server_id, role_id) in &my_member_roles {
        member_role_map
            .entry(server_id.to_string())
            .or_default()
            .push(role_id.to_string());
    }

    // ─── Fetch DM channels with participants ───
    let dm_channels = build_dm_channels_from_pg(state, &dm_channel_ids).await;

    // ─── Filter announcement feeds by viewer role ───
    // Already fetched into `all_feeds_raw` above; just apply the
    // visibility filter. Role-scoped: empty visible_role_ids = open
    // to everyone; ADMINISTRATOR bypasses.
    let my_roles_by_server: HashMap<i64, std::collections::HashSet<i64>> = {
        let mut m: HashMap<i64, std::collections::HashSet<i64>> = HashMap::new();
        for (sid, rid) in &my_member_roles {
            m.entry(*sid).or_default().insert(*rid);
        }
        m
    };
    let mut feeds_raw: Vec<crate::services::pg::feeds::FeedRow> =
        Vec::with_capacity(all_feeds_raw.len());
    for f in all_feeds_raw {
        let sid = f.server_id;
        let is_admin = state
            .permissions
            .check_server_permission(user_id, sid, bits::ADMINISTRATOR)
            .await
            .is_ok();
        let user_roles = my_roles_by_server.get(&sid);
        let visible = is_admin
            || f.visible_role_ids.is_empty()
            || user_roles.map_or(false, |rs| {
                f.visible_role_ids.iter().any(|r| rs.contains(r))
            });
        if visible {
            feeds_raw.push(f);
        }
    }
    let feeds_json: Vec<Value> = feeds_raw.iter().map(|f| {
        let description = f.description.clone().filter(|s| !s.is_empty());
        let icon = f.icon.clone().filter(|s| !s.is_empty());
        json!({
            "id": f.id.to_string(),
            "serverId": f.server_id.to_string(),
            "name": f.name,
            "description": description,
            "icon": icon,
            "position": f.position,
            "publishRoleIds": if f.publish_role_ids.is_empty() {
                Value::Null
            } else {
                Value::Array(f.publish_role_ids.iter().map(|id| Value::String(id.to_string())).collect())
            },
            "visibleRoleIds": if f.visible_role_ids.is_empty() {
                Value::Null
            } else {
                Value::Array(f.visible_role_ids.iter().map(|id| Value::String(id.to_string())).collect())
            },
            "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(f.created_at_ms)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        })
    }).collect();

    // ─── Build READY payload ───
    let session_id = conn.session_id.clone().unwrap_or_default();
    let server_version = env!("CARGO_PKG_VERSION").to_string();

    // Ordering preferences
    let active_ready_server_ids: HashSet<i64> = server_ids.iter().copied().collect();
    let server_order = ready_order_from_preferences(
        &user_row.server_order,
        conn.federated_allowed_server_ids
            .is_some()
            .then_some(&active_ready_server_ids),
    );
    let favorite_order = ready_order_from_preferences(
        &user_row.favorite_order,
        conn.federated_allowed_server_ids
            .is_some()
            .then_some(&active_ready_server_ids),
    );
    let ready_preferences =
        ready_preferences_for_scope(&user_row.preferences, ready_allows_dm_relationship_state);

    // Build JSON READY
    let servers_json: Vec<Value> = server_rows
        .iter()
        .map(|s| {
            let mc = server_member_counts.get(&s.id).copied().unwrap_or(0);
            json!({
                "id": s.id.to_string(),
                "name": s.name,
                "ownerId": s.owner_id.to_string(),
                "iconUrl": cdn::resolve(s.icon_url.as_deref()),
                "description": null,
                "voiceBitrate": s.voice_bitrate,
                "welcomeChannelId": s.welcome_channel_id.map(|id| id.to_string()),
                "announceChannelId": s.announce_channel_id.map(|id| id.to_string()),
                "welcomeMessage": s.welcome_message,
                "bannerUrl": cdn::resolve(s.banner_url.as_deref()),
                "bannerCrop": banner_crop::to_json(s.banner_crop),
                "accentColor": s.accent_color,
                "bannerOffsetY": s.banner_offset_y,
                "emojiVersion": s.emoji_version,
                "large": mc > LARGE_SERVER_THRESHOLD,
                "memberCount": mc,
                "createdAt": s.created_at.to_rfc3339(),
                "updatedAt": s.created_at.to_rfc3339(),
            })
        })
        .collect();

    // Use visible_channels (VIEW_CHANNEL filtered) instead of all_channels
    let channels_json: Vec<Value> = visible_channels
        .iter()
        .map(|c| {
            json!({
                "id": c.id.to_string(),
                "type": c.r#type,
                "serverId": c.server_id.map(|id| id.to_string()),
                "name": c.name,
                "topic": c.topic,
                "position": c.position,
                "categoryId": c.category_id.map(|id| id.to_string()),
                "readOnly": c.read_only,
                "slowmodeSeconds": c.slowmode_seconds,
                "createdAt": c.created_at.to_rfc3339(),
            })
        })
        .collect();

    let categories_json: Vec<Value> = all_categories
        .iter()
        .map(|c| {
            json!({
                "id": c.id.to_string(),
                "serverId": c.server_id.to_string(),
                "name": c.name,
                "position": c.position,
                "emoji": c.emoji,
                "createdAt": c.created_at.to_rfc3339(),
            })
        })
        .collect();

    let roles_json: Vec<Value> = all_roles
        .iter()
        .map(|r| {
            let color = match r.color {
                Some(c) if c != 0 => json!(format!("#{:06x}", c)),
                _ => json!(null),
            };
            json!({
                "id": r.id.to_string(),
                "serverId": r.server_id.to_string(),
                "name": r.name,
                "color": color,
                "permissions": r.permissions.to_string(),
                "position": r.position,
                "colorOnly": r.color_only,
                "showAsSection": r.show_as_section,
                "colorPriority": r.color_priority,
                "createdAt": r.created_at.to_rfc3339(),
                "updatedAt": r.created_at.to_rfc3339(),
            })
        })
        .collect();

    // When lazy_emoji_loading is ON, omit emojis from READY — clients use IndexedDB cache
    let lazy_emojis = state.feature_flags.resolve("lazy_emoji_loading", user_id);
    let emojis_json: Vec<Value> = if lazy_emojis {
        vec![]
    } else {
        all_emojis
            .iter()
            .map(|e| {
                json!({
                    "id": e.id.to_string(),
                    "serverId": e.server_id.to_string(),
                    "name": e.name,
                    "url": cdn::resolve(Some(&e.url)),
                    "createdBy": e.created_by.to_string(),
                    "createdAt": e.created_at.to_rfc3339(),
                })
            })
            .collect()
    };

    let relationships_json: Vec<Value> = relationship_rows
        .iter()
        .map(|r| {
            json!({
                "userId": r.target_id.to_string(),
                "type": r.rel_type,
                "user": {
                    "id": r.target_id.to_string(),
                    "username": r.target_username,
                    "displayName": r.target_display_name,
                    "avatarUrl": cdn::resolve(r.target_avatar_url.as_deref()),
                    "status": r.target_status_type,
                },
                "createdAt": r.created_at.to_rfc3339(),
                "notes": r.notes,
                "nicknameColor": r.nickname_color,
            })
        })
        .collect();

    let dm_channels_json: Vec<Value> = dm_channels.iter().map(|d| d.json.clone()).collect();

    let read_states_json: Vec<Value> = read_states
        .iter()
        .map(|(channel_id, msg_id)| {
            json!({
                "channelId": channel_id.to_string(),
                "lastReadMessageId": msg_id.to_string(),
            })
        })
        .collect();

    let member_role_ids_json: Value = member_role_map
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect::<serde_json::Map<String, Value>>()
        .into();

    // Feature flags from in-memory service
    let feature_flags = state.feature_flags.get_all();

    // Presence decision.
    //
    // afk=true  → client is auto-idled (hook fired on inactivity). The client's
    //             initial_status is the current display (usually "idle"); trust it.
    // afk=false → use stored preferred_status because initial_status is
    //             client memory, not a fresh manual choice.
    let client_status = |s: i32| match s {
        1 => Some("online"),
        2 => Some("idle"),
        3 => Some("dnd"),
        4 => Some("offline"),
        _ => None,
    };
    let effective_status = if afk {
        client_status(initial_status).unwrap_or_else(|| {
            if user_row.preferred_status.is_empty() {
                "online"
            } else {
                user_row.preferred_status.as_str()
            }
        })
    } else if user_row.preferred_status.is_empty() {
        "online"
    } else {
        user_row.preferred_status.as_str()
    };
    tracing::info!(
        user_id,
        initial_status,
        afk,
        effective_status,
        preferred_status = user_row.preferred_status.as_str(),
        "IDENTIFY: presence (Redis-backed)"
    );

    // Write presence to Redis (ephemeral, with TTL).
    crate::services::presence::set(&state.redis, user_id, effective_status).await;

    // IDENTIFY must not persist preferred_status; reconnect state can be stale.

    // Migration: backfill empty preferred_status for legacy users.
    if user_row.preferred_status.is_empty() {
        let _ = sqlx::query(
            "UPDATE users SET preferred_status = 'online', updated_at_ms = $2 WHERE id = $1",
        )
        .bind(user_id)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(&state.pg)
        .await;
    }

    // Include focused-server presences only below the large-server threshold.
    const LARGE_SERVER_THRESHOLD: i64 = 250;

    let mut presences_json: Vec<Value> = if let Some(focused_sid) = focused_server_id {
        let member_count = server_member_counts.get(&focused_sid).copied().unwrap_or(0);
        if member_count <= LARGE_SERVER_THRESHOLD {
            fetch_server_presences(state, focused_sid, user_id).await
        } else {
            vec![] // Large server: client must REQUEST_MEMBERS
        }
    } else {
        vec![]
    };
    // Always include the requesting user's own presence so the client
    // can render their status indicator immediately. fetch_server_presences
    // excludes the requesting user to avoid double-counting from other
    // users' perspective, but the client needs its own entry for the
    // member list sidebar.
    presences_json.push(json!({
        "userId": user_id.to_string(),
        "status": effective_status,
    }));

    // Collect voice states for all voice channels the user has access to.
    // Voice channels have type=3. Query Redis for active participants in parallel.
    // Keep the raw VoiceState vec around so the proto path can consume it directly.
    let voice_states_raw: Vec<crate::services::voice::VoiceState> = {
        let voice_futures: Vec<_> = voice_channel_ids
            .iter()
            .map(|&ch_id| state.voice.get_participants(&state.redis, ch_id))
            .collect();
        let voice_results = futures_util::future::join_all(voice_futures).await;

        let mut states = Vec::new();
        for participants in voice_results {
            for vs in participants {
                states.push(vs);
            }
        }
        states
    };
    let voice_states_json: Vec<Value> = voice_states_raw.iter().map(|vs| vs.to_json()).collect();

    // Fetch subscription info for READY
    let subscription_info =
        crate::services::subscription::get_subscription_info(&state.pg, user_id).await;
    let entitlements =
        crate::services::entitlements::Entitlements::for_config(&state.config, &subscription_info);
    let instance_info = crate::services::instance::current_user_info(&state.config, false);

    // Pre-compute user ID string once — reused in READY payload and presence broadcast
    let uid_str = user_id.to_string();

    let ready_data = json!({
        "sessionId": session_id,
        "userId": &uid_str,
        "username": user_row.username,
        "usernameSet": user_row.username_set,
        "displayName": user_row.display_name,
        "avatarUrl": cdn::resolve(user_row.avatar_url.as_deref()),
        "bannerUrl": cdn::resolve(user_row.banner_url.as_deref()),
        "bannerBaseColor": user_row.banner_base_color.as_deref().filter(|s| !s.trim().is_empty()),
        "bannerCrop": banner_crop::to_json(user_row.banner_crop),
        "memberListBannerUrl": if entitlements.member_list_banner { cdn::resolve(user_row.member_list_banner_url.as_deref()) } else { None },
        "memberListBannerCrop": if entitlements.member_list_banner { banner_crop::to_json(user_row.member_list_banner_crop) } else { serde_json::Value::Null },
        "bio": user_row.bio.as_deref().filter(|s| !s.trim().is_empty()),
        "customStatusText": user_row.custom_status_text.as_deref().filter(|s| !s.trim().is_empty()),
        "customStatusEmoji": user_row.custom_status_emoji.as_deref().filter(|s| !s.trim().is_empty()),
        "userStatus": effective_status,
        "servers": servers_json,
        "serverOrder": server_order,
        "favoriteOrder": favorite_order,
        "categories": categories_json,
        "channels": channels_json,
        "emojis": emojis_json,
        "dmChannelIds": dm_channel_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "relationships": relationships_json,
        "dmChannels": dm_channels_json,
        "voiceStates": voice_states_json,
        "presences": presences_json,
        "readStates": read_states_json,
        "roles": roles_json,
        "feeds": feeds_json,
        "memberRoleIds": member_role_ids_json,
        "serverVersion": server_version,
        "minClientVersion": state.config.min_client_version,
        "featureFlags": feature_flags,
        "preferences": ready_preferences,
        "subscription": subscription_info,
        "instance": instance_info,
        "entitlements": entitlements,
    });

    // Dual-path READY send: proto binary for Protobuf conns, JSON text
    // for JSON/Unknown conns. Proto is ~40% smaller on the wire and
    // avoids a serde_json::to_string on every IDENTIFY. READY is a
    // once-per-connect event so the extra build cost is amortized.
    //
    if conn.encoding == Encoding::Protobuf {
        // Build proto DM channels by extracting from the dm_channels JSON
        // we already built. Avoids a second PG round trip — the JSON
        // builder did the work, we just transcribe the participant list.
        let dm_channels_proto: Vec<proto::DmChannel> = dm_channels
            .iter()
            .filter_map(|d| {
                let v = &d.json;
                let id = v.get("id")?.as_str()?.to_string();
                let r#type = v.get("type")?.as_i64()? as i32;
                let name = v.get("name").and_then(|n| n.as_str()).map(String::from);
                let created_at = v
                    .get("createdAt")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                let participants: Vec<proto::DmParticipant> = v
                    .get("participants")
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| {
                                Some(proto::DmParticipant {
                                    id: p.get("id")?.as_str()?.to_string(),
                                    username: p.get("username")?.as_str().unwrap_or("").to_string(),
                                    avatar_url: p
                                        .get("avatarUrl")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    status: p
                                        .get("status")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("offline")
                                        .to_string(),
                                    display_name: p
                                        .get("displayName")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                    name_color: p
                                        .get("nameColor")
                                        .and_then(|v| v.as_str())
                                        .map(String::from),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(proto::DmChannel {
                    id,
                    r#type,
                    name,
                    participants,
                    last_message_id: v
                        .get("lastMessageId")
                        .and_then(|m| m.as_str())
                        .map(String::from),
                    last_message_at: v
                        .get("lastMessageAt")
                        .and_then(|m| m.as_str())
                        .map(String::from),
                    created_at,
                })
            })
            .collect();

        // Build presences from presences_json (Vec<Value> with userId + status keys)
        let presences_proto: Vec<proto::PresenceEntry> = presences_json
            .iter()
            .filter_map(|v| {
                Some(proto::PresenceEntry {
                    user_id: v.get("userId")?.as_str()?.to_string(),
                    status: v.get("status")?.as_str()?.to_string(),
                })
            })
            .collect();

        // Build proto feeds from PG FeedRow data.
        let feeds_proto: Vec<proto::Feed> = feeds_raw
            .iter()
            .map(|f| proto::Feed {
                id: f.id.to_string(),
                server_id: f.server_id.to_string(),
                name: f.name.clone(),
                description: f.description.clone().filter(|s| !s.is_empty()),
                icon: f.icon.clone().filter(|s| !s.is_empty()),
                position: f.position,
                publish_role_ids: f.publish_role_ids.iter().map(|id| id.to_string()).collect(),
                view_role_ids: f.visible_role_ids.iter().map(|id| id.to_string()).collect(),
                created_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(f.created_at_ms)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            })
            .collect();

        // Build member_role_ids map from my_member_roles Vec<(server_id, role_id)>
        let member_role_ids_proto: HashMap<String, proto::MemberRoleIds> = {
            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            for (server_id, role_id) in &my_member_roles {
                map.entry(server_id.to_string())
                    .or_default()
                    .push(role_id.to_string());
            }
            map.into_iter()
                .map(|(k, v)| (k, proto::MemberRoleIds { role_ids: v }))
                .collect()
        };

        let proto_ready = proto::Ready {
            session_id: session_id.clone(),
            user_id: uid_str.clone(),
            username: user_row.username.clone(),
            username_set: Some(user_row.username_set),
            display_name: user_row.display_name.clone(),
            avatar_url: cdn::resolve(user_row.avatar_url.as_deref()),
            banner_url: cdn::resolve(user_row.banner_url.as_deref()),
            banner_base_color: user_row
                .banner_base_color
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string),
            user_status: effective_status.to_string(),
            servers: server_rows
                .iter()
                .map(|s| {
                    let mc = server_member_counts.get(&s.id).copied().unwrap_or(0);
                    proto::Server {
                        id: s.id.to_string(),
                        name: s.name.clone(),
                        owner_id: s.owner_id.to_string(),
                        icon_url: cdn::resolve(s.icon_url.as_deref()),
                        description: None,
                        voice_bitrate: s.voice_bitrate,
                        created_at: s.created_at.to_rfc3339(),
                        updated_at: s.created_at.to_rfc3339(),
                        welcome_channel_id: s.welcome_channel_id.map(|id| id.to_string()),
                        announce_channel_id: s.announce_channel_id.map(|id| id.to_string()),
                        welcome_message: s.welcome_message.clone(),
                        emoji_version: s.emoji_version,
                        large: mc > LARGE_SERVER_THRESHOLD,
                        member_count: mc as i64,
                        banner_url: cdn::resolve(s.banner_url.as_deref()),
                        accent_color: s.accent_color.clone(),
                        banner_offset_y: s.banner_offset_y,
                    }
                })
                .collect(),
            server_order: server_order.clone(),
            favorite_order: favorite_order.clone(),
            categories: all_categories
                .iter()
                .map(|c| proto::Category {
                    id: c.id.to_string(),
                    server_id: c.server_id.to_string(),
                    name: c.name.clone(),
                    position: c.position,
                    created_at: c.created_at.to_rfc3339(),
                    emoji: c.emoji.clone(),
                })
                .collect(),
            channels: visible_channels
                .iter()
                .map(|c| proto::Channel {
                    id: c.id.to_string(),
                    r#type: c.r#type,
                    server_id: c.server_id.map(|id| id.to_string()),
                    name: c.name.clone(),
                    topic: c.topic.clone(),
                    position: c.position,
                    category_id: c.category_id.map(|id| id.to_string()),
                    created_at: c.created_at.to_rfc3339(),
                    read_only: c.read_only,
                    slowmode_seconds: c.slowmode_seconds,
                })
                .collect(),
            emojis: if lazy_emojis {
                vec![]
            } else {
                all_emojis
                    .iter()
                    .map(|e| proto::Emoji {
                        id: e.id.to_string(),
                        server_id: e.server_id.to_string(),
                        name: e.name.clone(),
                        url: cdn::resolve(Some(&e.url)).unwrap_or_default(),
                        created_by: e.created_by.to_string(),
                        created_at: e.created_at.to_rfc3339(),
                    })
                    .collect()
            },
            dm_channel_ids: dm_channel_ids.iter().map(|id| id.to_string()).collect(),
            relationships: relationship_rows
                .iter()
                .map(|r| proto::Relationship {
                    user_id: r.target_id.to_string(),
                    r#type: r.rel_type,
                    user: Some(proto::RelationshipUser {
                        id: r.target_id.to_string(),
                        username: r.target_username.clone(),
                        avatar_url: cdn::resolve(r.target_avatar_url.as_deref()),
                        status: r.target_status_type.clone(),
                    }),
                    created_at: r.created_at.to_rfc3339(),
                    notes: if r.notes.is_empty() {
                        None
                    } else {
                        Some(r.notes.clone())
                    },
                    nickname_color: r.nickname_color.clone(),
                })
                .collect(),
            dm_channels: dm_channels_proto,
            voice_states: voice_states_raw
                .iter()
                .map(|v| proto::VoiceState {
                    user_id: v.user_id.to_string(),
                    channel_id: Some(v.channel_id.to_string()),
                    server_id: v.server_id.to_string(),
                    self_mute: v.self_mute,
                    self_deaf: v.self_deaf,
                    server_mute: v.server_mute,
                    server_deaf: v.server_deaf,
                })
                .collect(),
            read_states: read_states
                .iter()
                .map(|(channel_id, msg_id)| proto::ChannelReadState {
                    channel_id: channel_id.to_string(),
                    last_read_message_id: msg_id.to_string(),
                })
                .collect(),
            roles: all_roles
                .iter()
                .map(|r| {
                    let color = match r.color {
                        Some(c) if c != 0 => Some(format!("#{:06x}", c)),
                        _ => None,
                    };
                    proto::Role {
                        id: r.id.to_string(),
                        server_id: r.server_id.to_string(),
                        name: r.name.clone(),
                        color,
                        permissions: r.permissions.to_string(),
                        position: r.position,
                        color_only: r.color_only,
                        show_as_section: r.show_as_section,
                        color_priority: r.color_priority,
                        created_at: r.created_at.to_rfc3339(),
                        updated_at: r.created_at.to_rfc3339(),
                    }
                })
                .collect(),
            member_role_ids: member_role_ids_proto,
            server_version: server_version.clone(),
            min_client_version: state.config.min_client_version.clone(),
            feature_flags: feature_flags.clone(),
            preferences_json: {
                let v = &ready_preferences;
                if v.is_null() {
                    None
                } else {
                    serde_json::to_string(v).ok()
                }
            },
            subscription_json: serde_json::to_string(&subscription_info).ok(),
            entitlements_json: serde_json::to_string(&entitlements).ok(),
            instance_json: serde_json::to_string(&instance_info).ok(),
            presences: presences_proto,
            feeds: feeds_proto,
        };
        let ws_msg = events::ready_proto(proto_ready);
        if let Some(bytes) = super::connection::encode_proto(&ws_msg) {
            // READY is the most critical WS message — use blocking send
            // to guarantee delivery. try_send can drop it if the bounded
            // channel is full during the IDENTIFY burst.
            if tx.send(OutboundMsg::Binary(bytes.into())).await.is_err() {
                tracing::error!(user_id, "READY proto send failed — channel closed");
                return;
            }
        } else {
            // Encode failed (shouldn't happen) — fall back to JSON
            let json_text = events::ready_json(ready_data);
            if tx.send(OutboundMsg::Text(json_text.into())).await.is_err() {
                tracing::error!(user_id, "READY JSON send failed — channel closed");
                return;
            }
        }
    } else {
        let json_text = events::ready_json(ready_data);
        if tx.send(OutboundMsg::Text(json_text.into())).await.is_err() {
            tracing::error!(user_id, "READY JSON send failed — channel closed");
            return;
        }
    }

    // Record the timestamp for potential delta READY on reconnect
    conn.last_ready_at = Some(Utc::now());

    tracing::info!(
        user_id,
        conn_id = conn.conn_id,
        servers = server_ids.len(),
        channels = all_channels.len(),
        dm_channels = dm_channel_ids.len(),
        topics = topic_list.len(),
        "IDENTIFY complete, READY sent"
    );

    // Broadcast presence to all servers + friends
    let proto_status = match effective_status {
        "online" => proto::UserStatus::Online as i32,
        "idle" => proto::UserStatus::Idle as i32,
        "dnd" => proto::UserStatus::Dnd as i32,
        "offline" => proto::UserStatus::Offline as i32,
        _ => proto::UserStatus::Online as i32,
    };
    let json = events::presence_update_json(&uid_str, proto_status);
    let proto_msg = events::presence_update_proto(uid_str, proto_status);
    broadcast_presence(
        state,
        &server_ids,
        user_id,
        &json,
        &proto_msg,
        conn.federated_allowed_server_ids.is_none(),
    )
    .await;
}

// ─── DELTA READY ────────────────────────────────────────────────────
//
// Sends an incremental READY payload containing only changes since
// the client's last READY timestamp. This saves ~10 DB queries on
// reconnect for users who briefly lost their connection.
//
// The approach:
// 1. Get server_ids from the warm permission cache
// 2. Query only channels/roles modified since `since`
// 3. Query current read states (cheap single-table scan)
// 4. Fetch presences for the focused server
// 5. Re-subscribe to all existing topics
// 6. Send READY_DELTA instead of full READY
//
// If anything fails, returns Err so the caller can fall back to full READY.

async fn handle_delta_ready(
    _state: &AppState,
    _conn: &mut ConnectionState,
    _tx: &mpsc::Sender<OutboundMsg>,
    _user_id: i64,
    _since: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    // Delta READY is disabled; fall back to full READY.
    Err("delta READY disabled".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("handlers.rs");

    fn channel(id: i64, channel_type: i32) -> channels::ChannelRow {
        channels::ChannelRow {
            id,
            r#type: channel_type,
            server_id: Some(1),
            name: Some(format!("channel-{id}")),
            topic: None,
            position: 0,
            category_id: None,
            read_only: false,
            slowmode_seconds: 0,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn visible_voice_channel_ids_use_server_voice_type() {
        let text = channel(10, 0);
        let dm = channel(20, 1);
        let voice = channel(30, CHANNEL_TYPE_SERVER_VOICE);

        assert_eq!(visible_voice_channel_ids(&[&text, &dm, &voice]), vec![30]);
    }

    #[test]
    fn federated_connection_scope_allows_only_claimed_server_ids() {
        let mut conn = ConnectionState::new(1, false);
        assert!(federated_connection_allows_server(&conn, Some(42)));
        assert!(federated_connection_allows_server(&conn, None));
        assert!(ready_allows_dm_relationship_state(&conn));

        conn.federated_allowed_server_ids = Some([42_i64].into_iter().collect());

        assert!(federated_connection_allows_server(&conn, Some(42)));
        assert!(!federated_connection_allows_server(&conn, Some(43)));
        assert!(!federated_connection_allows_server(&conn, None));
        assert!(!ready_allows_dm_relationship_state(&conn));
    }

    #[test]
    fn scoped_presence_server_ids_filters_federated_tokens() {
        let allowed = [42_i64, 44].into_iter().collect();

        assert_eq!(
            scoped_presence_server_ids(vec![40, 42, 43, 44], Some(&allowed)),
            vec![42, 44]
        );
        assert_eq!(scoped_presence_server_ids(vec![40, 42], None), vec![40, 42]);
    }

    #[test]
    fn federated_ready_private_dm_and_relationship_state_is_gated() {
        let ready_fanout = SOURCE
            .split("READY data fan-out")
            .nth(1)
            .expect("READY fan-out source should exist")
            .split("Populate permission cache")
            .next()
            .expect("permission cache follows READY fan-out");
        let private_gate = ready_fanout
            .find("ready_allows_dm_relationship_state")
            .expect("READY must explicitly gate DM and relationship state");
        let relationships_read = ready_fanout
            .find("relationships::list_for_user")
            .expect("relationship hydration read should exist");
        let dm_read = ready_fanout
            .find("dms::list_channel_ids_for_user")
            .expect("DM channel hydration read should exist");

        assert!(
            private_gate < relationships_read && private_gate < dm_read,
            "server-scoped federated READY must gate private user state before PG hydration"
        );

        let dm_notify_source = SOURCE
            .split("DM notify topics")
            .nth(1)
            .expect("DM notify topic block should exist")
            .split("Private user graph fanout")
            .next()
            .expect("user topic follows DM notify topics");
        assert!(
            dm_notify_source.contains("ready_allows_dm_relationship_state"),
            "server-scoped federated READY must not subscribe to DM notify topics"
        );

        let private_topic_source = SOURCE
            .split("Private user graph fanout")
            .nth(1)
            .expect("private user topic block should exist")
            .split("System broadcast")
            .next()
            .expect("system topic follows private user topic");
        assert!(
            private_topic_source.contains("ready_allows_dm_relationship_state")
                && private_topic_source.contains("topics::user_topic(user_id)"),
            "server-scoped federated READY must not subscribe to private user fanout"
        );
    }

    #[test]
    fn federated_ready_scopes_order_preferences_member_roles_and_read_states() {
        let allowed = [42_i64, 44].into_iter().collect::<HashSet<_>>();
        let order = json!(["42", "43", 44, "not-a-server"]);

        assert_eq!(
            ready_order_from_preferences(&order, Some(&allowed)),
            vec!["42".to_string(), "44".to_string()]
        );
        assert_eq!(
            ready_order_from_preferences(&order, None),
            vec![
                "42".to_string(),
                "43".to_string(),
                "44".to_string(),
                "not-a-server".to_string()
            ]
        );

        assert_eq!(
            ready_preferences_for_scope(&json!({"hiddenDmIds":["7"]}), false),
            Value::Null
        );
        assert_eq!(
            ready_preferences_for_scope(&json!({"theme":"dark"}), true),
            json!({"theme":"dark"})
        );

        assert_eq!(
            scoped_member_roles_for_ready(vec![(42, 1), (43, 2), (44, 3)], &allowed),
            vec![(42, 1), (44, 3)]
        );

        let visible_channels = [100_i64, 102].into_iter().collect::<HashSet<_>>();
        assert_eq!(
            scoped_read_states_for_ready(
                vec![(100, 900), (101, 901), (102, 902)],
                &visible_channels,
                true
            ),
            vec![(100, 900), (102, 902)]
        );
        assert_eq!(
            scoped_read_states_for_ready(vec![(101, 901)], &visible_channels, false),
            vec![(101, 901)]
        );
    }
}

/// Broadcast presence update to all of a user's servers and friends.
async fn broadcast_presence(
    state: &AppState,
    server_ids: &[i64],
    user_id: i64,
    json: &str,
    proto_msg: &WsMessage,
    include_friend_topics: bool,
) {
    let server_topics: Vec<String> = server_ids
        .iter()
        .map(|sid| topics::presence_topic(*sid))
        .collect();
    topics::publish_to_topics(state, &server_topics, json, proto_msg).await;

    if !include_friend_topics {
        return;
    }

    // Fan out to friends via the PG relationships table. rel_type == 1 is
    // a confirmed friendship. Fail open — presence is best-effort.
    let friends: Vec<i64> = crate::services::pg::relationships::list_for_user(&state.pg, user_id)
        .await
        .map(|rows| {
            rows.into_iter()
                .filter(|r| r.rel_type == crate::services::pg::relationships::REL_FRIEND)
                .map(|r| r.target_id)
                .collect()
        })
        .unwrap_or_default();
    if !friends.is_empty() {
        let friend_topics: Vec<String> =
            friends.iter().map(|fid| topics::user_topic(*fid)).collect();
        topics::publish_to_topics(state, &friend_topics, json, proto_msg).await;
    }
}

// ─── TYPING_START ────────────────────────────────────────────────────

pub async fn handle_typing(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: &str,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    let Some(channel_id) = parse_id(channel_id_str) else {
        send_error(tx, conn, "TYPING_START", "Invalid channelId", "INVALID_ID");
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => return, // Silently ignore if no access
    };
    if !federated_connection_allows_server(conn, server_id) {
        return;
    }

    // A member denied VIEW_CHANNEL via a channel override must not
    // broadcast typing into a channel they can't see.
    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            return;
        }
    }

    let now = Utc::now().to_rfc3339();
    let uid_str = user_id.to_string();

    let json = events::typing_start_json(channel_id_str, &uid_str, &now);
    let proto_msg = events::typing_start_proto(channel_id_str.to_string(), uid_str, now);

    tracing::debug!(user_id, channel_id, "TYPING_START");
    topics::publish_except(
        state,
        &topics::channel_live_topic(channel_id),
        &json,
        &proto_msg,
        conn.conn_id,
    )
    .await;
    enqueue_federation_channel_event(
        state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::TypingStart {
            channel_id,
            user_id,
        },
        Utc::now().timestamp_millis(),
    )
    .await;
}

// ─── MESSAGE_SEND ────────────────────────────────────────────────────

pub async fn handle_message_send(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: &str,
    content: &str,
    nonce: &str,
    reply_to_id_str: Option<&str>,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };
    let handler_start = std::time::Instant::now();

    if crate::services::app_bans::ensure_user_not_banned(state, user_id)
        .await
        .is_err()
    {
        let json = events::message_send_error_json(nonce, "Account banned", "ACCOUNT_BANNED");
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        let _ = tx.try_send(OutboundMsg::Close(4003, "Account banned".to_string()));
        return;
    }

    // Validate nonce length (prevent bandwidth amplification)
    if nonce.len() > 64 {
        let json = events::message_send_error_json(nonce, "Nonce too long", "VALIDATION_FAILED");
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        return;
    }

    // Rate limit message sending — use in-memory limiter (zero-await, O(1)).
    // WS connections are per-instance, so cross-instance Redis is unnecessary here.
    // This eliminates a Redis round-trip from every message send.
    //
    // Bypass for synthetic loadtest users (username prefix `loadtest_user_`)
    // so the admin-created accounts can fire sustained traffic without
    // tripping the limiter. The prefix is reserved — the register handler
    // rejects it for real signups.
    if !state.user_profiles.is_loadtest_user(user_id) {
        use crate::middleware::rate_limit::MESSAGE_LIMIT;
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window = now_secs / MESSAGE_LIMIT.window_secs;
        let key = format!("{}:{}:{}", MESSAGE_LIMIT.prefix, user_id, window);
        let count = state
            .local_rate_limiter
            .check_public(&key, window, MESSAGE_LIMIT.window_secs);
        if count
            > MESSAGE_LIMIT.max
                * if state.config.stress_test_key.is_some() {
                    100
                } else {
                    1
                }
        {
            let json = events::message_send_error_json(nonce, "Too many messages", "RATE_LIMITED");
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
            return;
        }
    }

    let Some(channel_id) = parse_id(channel_id_str) else {
        send_error(tx, conn, "MESSAGE_SEND", "Invalid channelId", "INVALID_ID");
        return;
    };

    // Verify channel access via permission cache (zero-await).
    // The cache was populated during IDENTIFY. If the user is subscribed to
    // this channel's topic, they already passed the access check.
    // Falls back to full DB check only on cache miss.
    let server_id_opt = match state.permissions.verify_access(user_id, channel_id) {
        crate::services::permissions::CacheResult::Hit(0) => None, // DM channel
        crate::services::permissions::CacheResult::Hit(sid) => Some(sid), // Server channel
        crate::services::permissions::CacheResult::Denied(_) => {
            let json =
                events::message_send_error_json(nonce, "Access denied", "CHANNEL_ACCESS_DENIED");
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
            return;
        }
        crate::services::permissions::CacheResult::Miss => {
            // Cache miss — fall back to full check (async, hits DB)
            match verify_channel_access(state, user_id, channel_id).await {
                Ok(sid) => sid,
                Err(_) => {
                    let json = events::message_send_error_json(
                        nonce,
                        "Access denied",
                        "CHANNEL_ACCESS_DENIED",
                    );
                    let _ = tx.try_send(OutboundMsg::Text(json.into()));
                    return;
                }
            }
        }
    };
    if !federated_connection_allows_server(conn, server_id_opt) {
        let json = events::message_send_error_json(nonce, "Access denied", "CHANNEL_ACCESS_DENIED");
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        return;
    }

    // Check VIEW_CHANNEL + SEND_MESSAGES permission for server channels.
    // Use the channel-aware path so channel overrides cannot be bypassed
    // when the cache is cold or incomplete.
    if let Some(server_id) = server_id_opt {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, server_id, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            let json =
                events::message_send_error_json(nonce, "Access denied", "CHANNEL_ACCESS_DENIED");
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
            return;
        }
        // Audit note: channel access proves membership or DM participation;
        // server channels then require explicit send permission.
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, server_id, bits::SEND_MESSAGES)
            .await
            .is_err()
        {
            let json = events::message_send_error_json(
                nonce,
                "Missing permission: SEND_MESSAGES",
                "PERMISSION_SEND_MESSAGES",
            );
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
            return;
        }
    } else if let Err(e) =
        crate::services::channel_access::ensure_dm_channel_send_allowed(state, user_id, channel_id)
            .await
    {
        let code = match e {
            AppError::NotFound(_) => "CHANNEL_ACCESS_DENIED",
            AppError::WithCode { code, .. } => code,
            _ => "DM_NOT_ALLOWED",
        };
        let json = events::message_send_error_json(nonce, "Unable to message this user", code);
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        return;
    }

    // Read-only + slowmode enforcement (must match HTTP handler in messages.rs)
    // Only query DB if permission cache indicates the channel might have restrictions.
    // Most channels are not read-only and have no slowmode — skip the DB round-trip.
    if let Some(server_id) = server_id_opt {
        // Check permission cache first — if user has MANAGE_MESSAGES, skip all restrictions
        let has_manage = state
            .permissions
            .has_channel_permission(user_id, channel_id, bits::MANAGE_MESSAGES)
            .unwrap_or(false);

        if !has_manage {
            // Only fetch channel from PG if user doesn't have MANAGE_MESSAGES
            // (need to check read_only and slowmode_seconds).
            let _ = server_id;
            if let Ok(Some(channel)) =
                crate::services::pg::channels::by_id(&state.pg, channel_id).await
            {
                if channel.read_only {
                    let json = events::message_send_error_json(
                        nonce,
                        "This channel is read-only",
                        "CHANNEL_READ_ONLY",
                    );
                    let _ = tx.try_send(OutboundMsg::Text(json.into()));
                    return;
                }

                if channel.slowmode_seconds > 0 {
                    let key = format!("slowmode:{}:{}", channel_id, user_id);
                    let set_result: bool = fred::interfaces::KeysInterface::set(
                        &state.redis,
                        &key,
                        "1",
                        Some(fred::types::Expiration::EX(channel.slowmode_seconds as i64)),
                        Some(fred::types::SetOptions::NX),
                        false,
                    )
                    .await
                    .unwrap_or(false);
                    if !set_result {
                        let ttl: i64 = fred::interfaces::KeysInterface::ttl(&state.redis, &key)
                            .await
                            .unwrap_or(0);
                        let msg = format!("Slowmode active, retry in {} seconds", ttl.max(1));
                        let json = events::message_send_error_json(nonce, &msg, "SLOWMODE_ACTIVE");
                        let _ = tx.try_send(OutboundMsg::Text(json.into()));
                        return;
                    }
                }
            }
        }
    }

    // Sanitize and validate content
    let content = sanitize_message_content(content);
    if content.is_empty() {
        let json = events::message_send_error_json(
            nonce,
            "Message content must not be empty",
            "VALIDATION_FAILED",
        );
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        return;
    }
    if content.len() > MAX_MESSAGE_LENGTH {
        let json = events::message_send_error_json(nonce, "Message too long", "VALIDATION_FAILED");
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        return;
    }

    // Validate custom emojis only when the message contains shortcode candidates.
    let content =
        if crate::services::subscription::contains_custom_emoji_shortcode_candidate(&content) {
            let entitlements =
                crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id)
                    .await;
            crate::services::subscription::validate_message_emojis_with_entitlement(
                &state.pg,
                user_id,
                server_id_opt,
                &content,
                entitlements.cross_server_emoji,
            )
            .await
        } else {
            content
        };
    let content = content.as_str();

    // Block media URLs from non-whitelisted hosts
    if let Some(host) = check_media_urls(content) {
        tracing::warn!(user_id, %host, "Blocked media URL from untrusted host");
        let json = events::message_send_error_json(
            nonce,
            "Media URLs are only allowed from trusted sources",
            "BLOCKED_MEDIA_URL",
        );
        let _ = tx.try_send(OutboundMsg::Text(json.into()));
        return;
    }

    // ─── Reply validation ──────────────────────────────────────────
    // Parse reply_to_id and verify the referenced message is in the same channel.
    let reply_to_id: Option<i64> = match reply_to_id_str {
        Some(s) if !s.is_empty() => {
            let Some(rid) = parse_id(s) else {
                let json =
                    events::message_send_error_json(nonce, "Invalid replyToId", "INVALID_ID");
                let _ = tx.try_send(OutboundMsg::Text(json.into()));
                return;
            };
            Some(rid)
        }
        _ => None,
    };

    // Reply validation — PG lookup. by_id_unhinted scans all partitions;
    // we then verify the message belongs to this channel and isn't tombstoned.
    let reply_snapshot: Option<(i64, String, i64, String, Option<String>, Option<String>)> =
        if let Some(rid) = reply_to_id {
            match crate::services::pg::messages::by_id_unhinted(&state.pg, rid).await {
                Ok(Some(msg))
                    if !crate::services::pg::messages::is_deleted(&msg)
                        && msg.channel_id == channel_id =>
                {
                    let (ruser, ravatar, rdisplay) = state
                        .user_profiles
                        .get_or_fetch_vdb(&state, msg.author_id)
                        .await;
                    Some((
                        msg.id,
                        msg.content.clone(),
                        msg.author_id,
                        ruser,
                        ravatar,
                        rdisplay,
                    ))
                }
                Ok(_) => {
                    let json = events::message_send_error_json(
                        nonce,
                        "Reply target not found in this channel",
                        "REPLY_TARGET_NOT_FOUND",
                    );
                    let _ = tx.try_send(OutboundMsg::Text(json.into()));
                    return;
                }
                Err(e) => {
                    tracing::error!(user_id, channel_id, reply_to = rid, error = %e, "Failed to fetch reply target");
                    let json = events::message_send_error_json(
                        nonce,
                        "Failed to validate reply",
                        "DB_ERROR",
                    );
                    let _ = tx.try_send(OutboundMsg::Text(json.into()));
                    return;
                }
            }
        } else {
            None
        };

    // Fetch author info (cache-first, avoids DB hit on every message)
    let (author_username, author_avatar, author_display_name) =
        state.user_profiles.get_or_fetch_vdb(&state, user_id).await;

    let id = state.snowflake.next_id();
    let now = Utc::now();
    let uid_str = user_id.to_string();
    let id_str = id.to_string();

    // ─── PRIMARY WRITE: Postgres ─────────────────────────────
    //
    // Single-row insert into the partitioned `messages` table.
    let row = crate::services::pg::messages::MessageRow {
        id,
        channel_id,
        author_id: user_id,
        r#type: 0,
        flags: 0,
        content: content.to_string(),
        reply_to: reply_to_id,
        edited_at_ms: None,
        created_at_ms: now.timestamp_millis(),
    };
    if let Err(e) = crate::services::pg::messages::insert(&state.pg, &row).await {
        tracing::error!(
            channel_id, user_id, message_id = id, error = %e,
            "PG primary message insert failed"
        );
        if let Ok(json) = serde_json::to_string(&serde_json::json!({
            "type": "MESSAGE_SEND_FAILED",
            "error": "PG write failed",
            "nonce": nonce,
        })) {
            let _ = tx.try_send(OutboundMsg::Text(json.into()));
        }
        return;
    }

    // Build proto reply snapshot (cheap — just struct field assignment)
    let reply_to_proto =
        reply_snapshot
            .as_ref()
            .map(
                |(rid, rcontent, raid, ruser, ravatar, rdisplay)| proto::ReplySnapshot {
                    id: rid.to_string(),
                    content: rcontent.clone(),
                    author: Some(proto::MessageAuthor {
                        id: raid.to_string(),
                        username: ruser.clone(),
                        avatar_url: ravatar.clone(),
                        display_name: rdisplay.clone(),
                    }),
                },
            );

    let now_rfc = now.to_rfc3339();

    // Build proto message (primary format — all Tauri clients use proto)
    let proto_msg_event = events::message_create_proto(proto::Message {
        id: id_str.clone(),
        channel_id: channel_id_str.to_string(),
        author_id: uid_str.clone(),
        author: Some(proto::MessageAuthor {
            id: uid_str.clone(),
            username: author_username.clone(),
            avatar_url: author_avatar.clone(),
            display_name: author_display_name.clone(),
        }),
        content: content.to_string(),
        r#type: 0,
        attachments: vec![],
        reactions: vec![],
        edited: false,
        created_at: now_rfc.clone(),
        updated_at: now_rfc.clone(),
        nonce: Some(nonce.to_string()),
        reply_to: reply_to_proto.clone(),
        edited_at: None,
    });

    // Build JSON lazily — only needed for JSON clients (rare) and Redis cross-instance relay.
    // This avoids serde_json::to_string() on every message when all connections are proto.
    let reply_to_json =
        reply_snapshot
            .as_ref()
            .map(|(rid, rcontent, raid, ruser, ravatar, rdisplay)| {
                json!({
                    "id": rid.to_string(),
                    "content": rcontent,
                    "author": {
                        "id": raid.to_string(),
                        "username": ruser,
                        "displayName": rdisplay,
                        "avatarUrl": ravatar,
                    }
                })
            });
    let msg_json = json!({
        "id": id_str,
        "channelId": channel_id_str,
        "authorId": uid_str,
        "author": {
            "id": uid_str,
            "username": author_username,
            "displayName": author_display_name,
            "avatarUrl": author_avatar,
        },
        "content": content,
        "edited": false,
        "createdAt": now_rfc,
        "updatedAt": now_rfc,
        "reactions": [],
        "attachments": [],
        "nonce": nonce,
        "replyTo": reply_to_json,
    });
    if let Some(server_id) = server_id_opt {
        crate::services::bot_events::enqueue(
            state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MESSAGE_CREATE,
                server_id: Some(server_id),
                channel_id: Some(channel_id),
                feed_id: None,
                actor_user_id: Some(user_id),
                actor_bot_id: None,
                payload: json!({
                    "serverId": server_id.to_string(),
                    "channelId": channel_id_str,
                    "message": msg_json.clone(),
                }),
            },
        );
    }
    let event_json = events::message_create_json(&msg_json);

    let handler_elapsed_us = handler_start.elapsed().as_micros();
    tracing::info!(
        user_id, channel_id, msg_id = %id_str,
        handler_us = handler_elapsed_us,
        "MESSAGE_SEND broadcast"
    );
    let ts_ms = now.timestamp_millis();
    record_channel_activity(state, channel_id, user_id, ts_ms).await;
    publish_message_create_scoped(
        state,
        channel_id,
        channel_id_str,
        server_id_opt,
        &id_str,
        &uid_str,
        &now_rfc,
        Some(&author_username),
        author_display_name.as_deref(),
        author_avatar.as_deref(),
        &event_json,
        &proto_msg_event,
        content,
    )
    .await;
    enqueue_federation_channel_event(
        state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessageCreate {
            channel_id,
            server_id: server_id_opt,
            message_id: id,
            author_user_id: user_id,
            content: content.to_string(),
            nonce: Some(nonce.to_string()),
            reply_to_message_id: reply_to_id,
        },
        ts_ms,
    )
    .await;

    // Fire-and-forget cache write
    let cached_msg = crate::services::message_cache::build_cached_message_new(
        id_str,
        channel_id_str.to_string(),
        uid_str,
        author_username,
        author_avatar,
        author_display_name,
        content.to_string(),
        0,
        now.to_rfc3339(),
        reply_to_proto,
        vec![],
    );
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.cache_message(channel_id, id, &cached_msg).await });
}

// ─── MESSAGE_EDIT ────────────────────────────────────────────────────

pub async fn handle_message_edit(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: &str,
    message_id_str: &str,
    content: &str,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    let Some(channel_id) = parse_id(channel_id_str) else {
        send_error(tx, conn, "MESSAGE_EDIT", "Invalid channelId", "INVALID_ID");
        return;
    };
    let Some(message_id) = parse_id(message_id_str) else {
        send_error(tx, conn, "MESSAGE_EDIT", "Invalid messageId", "INVALID_ID");
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => {
            send_error(
                tx,
                conn,
                "MESSAGE_EDIT",
                "Access denied",
                "CHANNEL_ACCESS_DENIED",
            );
            return;
        }
    };
    if !federated_connection_allows_server(conn, server_id) {
        send_error(
            tx,
            conn,
            "MESSAGE_EDIT",
            "Access denied",
            "CHANNEL_ACCESS_DENIED",
        );
        return;
    }

    // A member denied VIEW_CHANNEL via a channel override must not be
    // able to edit messages (their own included) in that channel —
    // treat the channel as nonexistent for them.
    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            send_error(
                tx,
                conn,
                "MESSAGE_EDIT",
                "Access denied",
                "CHANNEL_ACCESS_DENIED",
            );
            return;
        }
    }

    let content = sanitize_message_content(content);
    if content.is_empty() || content.len() > MAX_MESSAGE_LENGTH {
        send_error(
            tx,
            conn,
            "MESSAGE_EDIT",
            "Invalid content length",
            "VALIDATION_FAILED",
        );
        return;
    }
    let content = content.as_str();

    // Block media URLs from non-whitelisted hosts (same check as MESSAGE_SEND)
    if let Some(host) = check_media_urls(content) {
        tracing::warn!(user_id, %host, "Blocked media URL from untrusted host in MESSAGE_EDIT");
        send_error(
            tx,
            conn,
            "MESSAGE_EDIT",
            "Media URLs are only allowed from trusted sources",
            "BLOCKED_MEDIA_URL",
        );
        return;
    }

    // PG message lookup — confirms existence + author + tombstone status.
    let existing = match crate::services::pg::messages::by_id_unhinted(&state.pg, message_id).await
    {
        Ok(Some(m))
            if !crate::services::pg::messages::is_deleted(&m) && m.channel_id == channel_id =>
        {
            m
        }
        Ok(_) => {
            send_error(tx, conn, "MESSAGE_EDIT", "Message not found", "NOT_FOUND");
            return;
        }
        Err(e) => {
            tracing::error!(user_id, message_id, channel_id, error = %e, "handle_message_edit: PG read failed");
            send_error(
                tx,
                conn,
                "MESSAGE_EDIT",
                "Failed to edit message",
                "DB_ERROR",
            );
            return;
        }
    };

    if existing.author_id != user_id {
        send_error(
            tx,
            conn,
            "MESSAGE_EDIT",
            "Not the author",
            "MESSAGE_NOT_AUTHOR",
        );
        return;
    }

    let content =
        if crate::services::subscription::contains_custom_emoji_shortcode_candidate(content) {
            let entitlements =
                crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id)
                    .await;
            crate::services::subscription::validate_message_emojis_with_entitlement(
                &state.pg,
                user_id,
                server_id,
                content,
                entitlements.cross_server_emoji,
            )
            .await
        } else {
            content.to_string()
        };
    let content = content.as_str();

    let now = Utc::now();
    let uid_str = user_id.to_string();
    let now_ms = now.timestamp_millis();

    if let Err(e) = crate::services::pg::messages::edit(
        &state.pg,
        message_id,
        existing.created_at_ms,
        content,
        now_ms,
    )
    .await
    {
        tracing::error!(user_id, message_id, channel_id, error = %e, "handle_message_edit: PG update failed");
        send_error(
            tx,
            conn,
            "MESSAGE_EDIT",
            "Failed to edit message",
            "DB_ERROR",
        );
        return;
    }

    // Resolve the author profile for the broadcast JSON. The
    // existing VdbMessageRecord carries author_id only, so we
    // hit user_profiles for the display fields.
    let (author_username, author_avatar_url, author_display_name) =
        state.user_profiles.get_or_fetch_vdb(state, user_id).await;
    let created_at_millis = (message_id >> 22) + 1_735_689_600_000;
    let created_at = chrono::DateTime::<Utc>::from_timestamp_millis(created_at_millis)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    let reaction_map = crate::services::reactions::list_reactions_batch_with_fallback(
        &state.redis,
        None,
        &[message_id],
    )
    .await;
    let msg_reactions: Vec<Value> = reaction_map
        .get(&message_id)
        .map(|mr| {
            mr.by_emoji
                .iter()
                .map(|(emoji, user_ids)| {
                    json!({
                        "emoji": emoji,
                        "emojiId": Value::Null,
                        "count": user_ids.len(),
                        "me": user_ids.iter().any(|u| *u == user_id),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let proto_reactions: Vec<proto::Reaction> = reaction_map
        .get(&message_id)
        .map(|mr| {
            mr.by_emoji
                .iter()
                .map(|(emoji, user_ids)| proto::Reaction {
                    emoji: emoji.clone(),
                    emoji_id: None,
                    count: user_ids.len() as i32,
                    me: user_ids.iter().any(|u| *u == user_id),
                })
                .collect()
        })
        .unwrap_or_default();
    let attachment_rows = crate::services::pg::attachments::for_messages(&state.pg, &[message_id])
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                user_id,
                message_id,
                channel_id,
                error = %e,
                "handle_message_edit: attachment lookup failed"
            );
            Vec::new()
        });
    let msg_attachments: Vec<Value> = attachment_rows
        .iter()
        .map(|a| {
            json!({
                "id": a.id.to_string(),
                "messageId": a.message_id.map(|id| id.to_string()).unwrap_or_default(),
                "filename": a.filename.clone(),
                "url": crate::handlers::uploads::attachment_media_url(&state.config.instance_api_url, a.id),
                "contentType": a.content_type.clone(),
                "size": a.size_bytes,
            })
        })
        .collect();
    let cached_attachments: Vec<proto::Attachment> = attachment_rows
        .iter()
        .map(|a| proto::Attachment {
            id: a.id.to_string(),
            message_id: a.message_id.map(|id| id.to_string()).unwrap_or_default(),
            filename: a.filename.clone(),
            url: crate::handlers::uploads::attachment_media_url(
                &state.config.instance_api_url,
                a.id,
            ),
            content_type: a.content_type.clone(),
            size: a.size_bytes.min(i32::MAX as i64).max(0) as i32,
        })
        .collect();

    let updated_json = json!({
        "id": message_id.to_string(),
        "channelId": channel_id.to_string(),
        "authorId": uid_str,
        "author": {
            "id": uid_str,
            "username": author_username,
            "displayName": author_display_name,
            "avatarUrl": cdn::resolve(author_avatar_url.as_deref()),
        },
        "content": content,
        "edited": true,
        "createdAt": created_at,
        "updatedAt": now.to_rfc3339(),
        "reactions": msg_reactions,
        "attachments": msg_attachments,
    });
    if let Some(server_id) = server_id {
        crate::services::bot_events::enqueue(
            state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MESSAGE_UPDATE,
                server_id: Some(server_id),
                channel_id: Some(channel_id),
                feed_id: None,
                actor_user_id: Some(user_id),
                actor_bot_id: None,
                payload: json!({
                    "serverId": server_id.to_string(),
                    "channelId": channel_id.to_string(),
                    "message": updated_json.clone(),
                }),
            },
        );
    }

    let event_json = events::message_update_json(&updated_json);
    let proto_msg = events::message_update_proto(proto::Message {
        id: message_id.to_string(),
        channel_id: channel_id.to_string(),
        author_id: uid_str.clone(),
        author: Some(proto::MessageAuthor {
            id: uid_str,
            username: author_username.clone(),
            avatar_url: author_avatar_url.clone(),
            display_name: author_display_name.clone(),
        }),
        content: content.to_string(),
        r#type: 0,
        attachments: cached_attachments,
        reactions: proto_reactions,
        edited: true,
        created_at,
        updated_at: now.to_rfc3339(),
        nonce: None,
        reply_to: None,
        edited_at: Some(now.to_rfc3339()),
    });

    tracing::info!(user_id, message_id, channel_id, "MESSAGE_EDIT");
    topics::publish(
        state,
        &topics::channel_live_topic(channel_id),
        &event_json,
        &proto_msg,
    )
    .await;
    enqueue_federation_channel_event(
        state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessageUpdate {
            channel_id,
            message_id,
            author_user_id: user_id,
            content: content.to_string(),
        },
        now_ms,
    )
    .await;

    // Invalidate entire channel cache; the next read backfills fresh data.
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.invalidate_channel(channel_id).await });
}

// ─── MESSAGE_DELETE ──────────────────────────────────────────────────

pub async fn handle_message_delete(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: &str,
    message_id_str: &str,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    let Some(channel_id) = parse_id(channel_id_str) else {
        send_error(
            tx,
            conn,
            "MESSAGE_DELETE",
            "Invalid channelId",
            "INVALID_ID",
        );
        return;
    };
    let Some(message_id) = parse_id(message_id_str) else {
        send_error(
            tx,
            conn,
            "MESSAGE_DELETE",
            "Invalid messageId",
            "INVALID_ID",
        );
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => {
            send_error(
                tx,
                conn,
                "MESSAGE_DELETE",
                "Access denied",
                "CHANNEL_ACCESS_DENIED",
            );
            return;
        }
    };
    if !federated_connection_allows_server(conn, server_id) {
        send_error(
            tx,
            conn,
            "MESSAGE_DELETE",
            "Access denied",
            "CHANNEL_ACCESS_DENIED",
        );
        return;
    }

    // A member denied VIEW_CHANNEL via a channel override must not be
    // able to delete messages (their own included) in that channel —
    // treat the channel as nonexistent for them.
    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            send_error(
                tx,
                conn,
                "MESSAGE_DELETE",
                "Access denied",
                "CHANNEL_ACCESS_DENIED",
            );
            return;
        }
    }

    // PG message lookup.
    let existing = match crate::services::pg::messages::by_id_unhinted(&state.pg, message_id).await
    {
        Ok(Some(m))
            if !crate::services::pg::messages::is_deleted(&m) && m.channel_id == channel_id =>
        {
            m
        }
        Ok(_) => {
            send_error(tx, conn, "MESSAGE_DELETE", "Message not found", "NOT_FOUND");
            return;
        }
        Err(e) => {
            tracing::error!(user_id, message_id, channel_id, error = %e, "handle_message_delete: PG read failed");
            send_error(
                tx,
                conn,
                "MESSAGE_DELETE",
                "Failed to delete message",
                "DB_ERROR",
            );
            return;
        }
    };

    let is_author = existing.author_id == user_id;
    if !is_author {
        if let Some(sid) = server_id {
            // Check MANAGE_MESSAGES permission
            let has_manage = state.permissions.has_channel_permission(
                user_id,
                channel_id,
                bits::MANAGE_MESSAGES,
            );
            match has_manage {
                Some(true) => {} // Permitted
                Some(false) => {
                    send_error(
                        tx,
                        conn,
                        "MESSAGE_DELETE",
                        "Missing permission",
                        "PERMISSION_MISSING",
                    );
                    return;
                }
                None => {
                    // Cache miss; run the full permission check.
                    if let Err(_) = state
                        .permissions
                        .check_channel_permission(user_id, channel_id, sid, bits::MANAGE_MESSAGES)
                        .await
                    {
                        send_error(
                            tx,
                            conn,
                            "MESSAGE_DELETE",
                            "Missing permission",
                            "PERMISSION_MISSING",
                        );
                        return;
                    }
                }
            }
        } else {
            send_error(
                tx,
                conn,
                "MESSAGE_DELETE",
                "Not the author",
                "MESSAGE_NOT_AUTHOR",
            );
            return;
        }
    }

    if let Err(e) =
        crate::services::pg::messages::tombstone(&state.pg, message_id, existing.created_at_ms)
            .await
    {
        tracing::error!(user_id, message_id, channel_id, error = %e, "handle_message_delete: PG tombstone failed");
        send_error(
            tx,
            conn,
            "MESSAGE_DELETE",
            "Failed to delete message",
            "DB_ERROR",
        );
        return;
    }

    let id_str = message_id.to_string();
    let ch_str = channel_id.to_string();

    let event_json = events::message_delete_json(&id_str, &ch_str);
    let proto_msg = events::message_delete_proto(id_str, ch_str);
    if let Some(server_id) = server_id {
        crate::services::bot_events::enqueue(
            state,
            crate::services::bot_events::BotEvent {
                event_type: crate::services::bot_events::EVENT_MESSAGE_DELETE,
                server_id: Some(server_id),
                channel_id: Some(channel_id),
                feed_id: None,
                actor_user_id: Some(user_id),
                actor_bot_id: None,
                payload: json!({
                    "serverId": server_id.to_string(),
                    "channelId": channel_id.to_string(),
                    "messageId": message_id.to_string(),
                }),
            },
        );
    }

    let live_topic = topics::channel_live_topic(channel_id);
    let live_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&live_topic)
        .map(|set| set.len())
        .unwrap_or(0);
    crate::realtime_trace!(
        user_id,
        message_id,
        channel_id,
        is_author,
        live_topic = %live_topic,
        live_local_subscribers,
        "realtime_scope: publishing MESSAGE_DELETE to focused live subscribers"
    );
    topics::publish(state, &live_topic, &event_json, &proto_msg).await;
    enqueue_federation_channel_event(
        state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::MessageDelete {
            channel_id,
            message_id,
            author_user_id: existing.author_id,
        },
        Utc::now().timestamp_millis(),
    )
    .await;

    // Surgically remove from cache (keeps warm marker intact)
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.remove_single_message(channel_id, message_id).await });
}

// ─── REACTION_ADD ────────────────────────────────────────────────────

pub async fn handle_reaction_add(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: &str,
    message_id_str: &str,
    emoji: &str,
    emoji_id: Option<&str>,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    // Validate emoji length (Unicode emoji are typically 1-11 bytes, custom emoji IDs are snowflakes)
    if emoji.is_empty() || emoji.len() > 32 {
        send_error(
            tx,
            conn,
            "REACTION_ADD",
            "Invalid emoji",
            "VALIDATION_FAILED",
        );
        return;
    }

    let Some(channel_id) = parse_id(channel_id_str) else {
        return;
    };
    let Some(message_id) = parse_id(message_id_str) else {
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => return,
    };
    if !federated_connection_allows_server(conn, server_id) {
        return;
    }

    // VIEW_CHANNEL gate — overrides must hide the channel completely.
    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            return;
        }
    }

    let _ = emoji_id; // not persisted in the Redis reactions store yet
    let _ = MAX_UNIQUE_REACTIONS_PER_MESSAGE; // cap now lives in services::reactions

    // Confirm the message exists (and isn't tombstoned) via PG.
    match crate::services::pg::messages::by_id_unhinted(&state.pg, message_id).await {
        Ok(Some(m))
            if !crate::services::pg::messages::is_deleted(&m) && m.channel_id == channel_id => {}
        Ok(_) => {
            send_error(tx, conn, "REACTION_ADD", "Message not found", "NOT_FOUND");
            return;
        }
        Err(e) => {
            tracing::error!(user_id, message_id, channel_id, error = %e, "handle_reaction_add: PG read failed");
            return;
        }
    }

    if crate::services::subscription::is_custom_emoji_reaction_shortcode_candidate(emoji) {
        let entitlements =
            crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id)
                .await;
        if !crate::services::subscription::validate_reaction_emoji_with_entitlement(
            &state.pg,
            user_id,
            server_id,
            emoji,
            entitlements.cross_server_emoji,
        )
        .await
        {
            send_error(
                tx,
                conn,
                "REACTION_ADD",
                "Emoji is not available",
                "EMOJI_NOT_ALLOWED",
            );
            return;
        }
    }

    // Atomic Redis Lua script — adds the user to the per-emoji
    // set and enforces the unique-emoji cap in one round trip.
    match crate::services::reactions::add_reaction(&state.redis, message_id, emoji, user_id).await {
        Ok(crate::services::reactions::AddReactionResult::Added) => {}
        Ok(crate::services::reactions::AddReactionResult::AlreadyPresent) => return,
        Ok(crate::services::reactions::AddReactionResult::LimitReached) => return,
        Err(e) => {
            tracing::error!(error = %e, "handle_reaction_add: redis eval failed");
            return;
        }
    }

    tracing::info!(user_id, message_id, channel_id, emoji, "REACTION_ADD");
    let uid_str = user_id.to_string();
    let json = events::reaction_add_json(message_id_str, channel_id_str, &uid_str, emoji, emoji_id);
    let proto_msg = events::reaction_add_proto(
        message_id_str.to_string(),
        channel_id_str.to_string(),
        uid_str,
        emoji.to_string(),
        emoji_id.map(|s| s.to_string()),
    );

    topics::publish(
        state,
        &topics::channel_live_topic(channel_id),
        &json,
        &proto_msg,
    )
    .await;
    enqueue_federation_channel_event(
        state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::ReactionAdd {
            channel_id,
            message_id,
            user_id,
            emoji: emoji.to_string(),
            emoji_id: emoji_id.and_then(parse_id),
        },
        Utc::now().timestamp_millis(),
    )
    .await;

    // Invalidate channel cache (reaction snapshot in CachedMessage is stale).
    // Redis is the authoritative reaction store post-migration; no
    // secondary write needed.
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.invalidate_channel(channel_id).await });
}

// ─── REACTION_REMOVE ─────────────────────────────────────────────────

pub async fn handle_reaction_remove(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: &str,
    message_id_str: &str,
    emoji: &str,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    let Some(channel_id) = parse_id(channel_id_str) else {
        return;
    };
    let Some(message_id) = parse_id(message_id_str) else {
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => return,
    };
    if !federated_connection_allows_server(conn, server_id) {
        return;
    }

    // VIEW_CHANNEL gate — overrides must hide the channel completely.
    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            return;
        }
    }

    // Confirm the target message belongs to this channel before mutating
    // the Redis reaction set. Without this, a crafted frame could provide
    // an accessible channel ID while targeting a message from another channel.
    match crate::services::pg::messages::by_id_unhinted(&state.pg, message_id).await {
        Ok(Some(m))
            if !crate::services::pg::messages::is_deleted(&m) && m.channel_id == channel_id => {}
        Ok(_) => {
            send_error(
                tx,
                conn,
                "REACTION_REMOVE",
                "Message not found",
                "NOT_FOUND",
            );
            return;
        }
        Err(e) => {
            tracing::error!(user_id, message_id, channel_id, error = %e, "handle_reaction_remove: PG read failed");
            return;
        }
    }

    let removed =
        crate::services::reactions::remove_reaction(&state.redis, message_id, emoji, user_id)
            .await
            .unwrap_or(false);
    if !removed {
        return; // Nothing to remove
    }

    tracing::info!(user_id, message_id, channel_id, emoji, "REACTION_REMOVE");
    let uid_str = user_id.to_string();
    let json = events::reaction_remove_json(message_id_str, channel_id_str, &uid_str, emoji);
    let proto_msg = events::reaction_remove_proto(
        message_id_str.to_string(),
        channel_id_str.to_string(),
        uid_str,
        emoji.to_string(),
    );

    topics::publish(
        state,
        &topics::channel_live_topic(channel_id),
        &json,
        &proto_msg,
    )
    .await;
    enqueue_federation_channel_event(
        state,
        channel_id,
        crate::federation::producer::FederationLocalEvent::ReactionRemove {
            channel_id,
            message_id,
            user_id,
            emoji: emoji.to_string(),
            emoji_id: None,
        },
        Utc::now().timestamp_millis(),
    )
    .await;

    // Invalidate channel cache (reaction snapshot in CachedMessage is stale).
    // Redis is the authoritative reaction store post-migration; no
    // secondary write needed.
    let cache = state.message_cache.clone();
    tokio::spawn(async move { cache.invalidate_channel(channel_id).await });
}

// ─── CHANNEL_ACK ─────────────────────────────────────────────────────

pub async fn handle_channel_ack(
    state: &AppState,
    conn: &ConnectionState,
    channel_id_str: &str,
    message_id_str: &str,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    let Some(channel_id) = parse_id(channel_id_str) else {
        return;
    };
    let Some(message_id) = parse_id(message_id_str) else {
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => return,
    };
    if !federated_connection_allows_server(conn, server_id) {
        return;
    }

    // A member denied VIEW_CHANNEL via an override must not be able
    // to persist read state on a hidden channel (would re-surface
    // as cursor state on clients).
    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            return;
        }
    }

    tracing::debug!(user_id, channel_id, message_id, "CHANNEL_ACK");

    // PG is the read-state store. The upsert uses GREATEST() semantics
    // so out-of-order ACKs from multiple devices never regress.
    let pg = state.pg.clone();
    let now_ms = chrono::Utc::now().timestamp_millis();
    tokio::spawn(async move {
        if let Err(e) =
            crate::services::pg::read_states::update(&pg, user_id, channel_id, message_id, now_ms)
                .await
        {
            tracing::warn!(user_id, channel_id, message_id, error = %e, "PG read_state update failed (WS)");
        }
    });
}

// ─── PRESENCE_UPDATE ─────────────────────────────────────────────────

pub async fn handle_presence_update(
    state: &AppState,
    conn: &ConnectionState,
    status: i32,
    afk: bool,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    // Validate status enum (1-4: online, idle, dnd, offline)
    if !(1..=4).contains(&status) {
        return;
    }

    let status_str = match status {
        1 => "online",
        2 => "idle",
        3 => "dnd",
        4 => "offline",
        _ => return,
    };

    tracing::info!(user_id, status = status_str, afk, "PRESENCE_UPDATE");

    // Write to Redis (ephemeral presence).
    crate::services::presence::set(&state.redis, user_id, status_str).await;

    // Only persist preferred_status to PG when this is a manual choice (!afk).
    // Auto-idle/resume is ephemeral and should never touch the durable store.
    if !afk {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Err(e) =
            sqlx::query("UPDATE users SET preferred_status = $2, updated_at_ms = $3 WHERE id = $1")
                .bind(user_id)
                .bind(status_str)
                .bind(now_ms)
                .execute(&state.pg)
                .await
        {
            tracing::warn!(user_id, error = %e, "PRESENCE_UPDATE: PG preferred_status write failed");
        }
    }

    // Broadcast to all servers + friends.
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id)
        .await
        .unwrap_or_default();
    let server_ids =
        scoped_presence_server_ids(server_ids, conn.federated_allowed_server_ids.as_ref());

    let uid_str = user_id.to_string();
    let json = events::presence_update_json(&uid_str, status);
    let proto_msg = events::presence_update_proto(uid_str, status);
    broadcast_presence(
        state,
        &server_ids,
        user_id,
        &json,
        &proto_msg,
        conn.federated_allowed_server_ids.is_none(),
    )
    .await;
    let now_ms = Utc::now().timestamp_millis();
    for server_id in server_ids {
        enqueue_federation_server_event(
            state,
            server_id,
            crate::federation::producer::FederationLocalEvent::PresenceUpdate {
                user_id,
                status: status_str.to_string(),
            },
            now_ms,
        )
        .await;
    }
}

// ─── VOICE_LEAVE ─────────────────────────────────────────────────────

pub async fn handle_voice_leave(
    state: &AppState,
    conn: &mut ConnectionState,
    _tx: &mpsc::Sender<OutboundMsg>,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    tracing::info!(user_id, "VOICE_LEAVE");

    // Remove from voice service
    match state.voice.leave_all(&state.redis, user_id).await {
        Ok(Some(old_state)) => {
            tracing::info!(
                user_id,
                channel_id = old_state.channel_id,
                server_id = old_state.server_id,
                "User left voice channel"
            );

            // Broadcast VOICE_STATE_UPDATE with channelId = null (left)
            let json = events::voice_state_update_json(&json!({
                "userId": user_id.to_string(),
                "channelId": Value::Null,
                "serverId": old_state.server_id.to_string(),
                "selfMute": false,
                "selfDeaf": false,
                "serverMute": false,
                "serverDeaf": false,
            }));
            let proto_msg = events::voice_state_update_proto(proto::VoiceState {
                user_id: user_id.to_string(),
                channel_id: None,
                server_id: old_state.server_id.to_string(),
                self_mute: false,
                self_deaf: false,
                server_mute: false,
                server_deaf: false,
            });

            // Broadcast to clients that can view this voice channel. Voice
            // occupancy is scoped separately from focused text-channel live
            // traffic so observers can see joins/leaves without subscribing
            // to every text channel.
            topics::publish(
                state,
                &topics::voice_topic(old_state.channel_id),
                &json,
                &proto_msg,
            )
            .await;
            conn.joined_voice_channel_id = None;
            state
                .ws
                .clear_voice_channel_for_user(user_id, old_state.channel_id);
        }
        Ok(None) => {
            tracing::debug!(user_id, "VOICE_LEAVE but user was not in a channel");
        }
        Err(e) => {
            tracing::error!(user_id, error = %e, "Failed to leave voice channel");
        }
    }
}

// ─── VOICE_STATE (mute/deaf update) ─────────────────────────────────

pub async fn handle_voice_state_update(
    state: &AppState,
    conn: &ConnectionState,
    _tx: &mpsc::Sender<OutboundMsg>,
    self_mute: Option<bool>,
    self_deaf: Option<bool>,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    tracing::info!(user_id, ?self_mute, ?self_deaf, "VOICE_STATE update");

    match state
        .voice
        .update_state(&state.redis, user_id, self_mute, self_deaf)
        .await
    {
        Ok(Some(updated)) => {
            let json = events::voice_state_update_json(&updated.to_json());
            let proto_msg = events::voice_state_update_proto(proto::VoiceState {
                user_id: user_id.to_string(),
                channel_id: Some(updated.channel_id.to_string()),
                server_id: updated.server_id.to_string(),
                self_mute: updated.self_mute,
                self_deaf: updated.self_deaf,
                server_mute: updated.server_mute,
                server_deaf: updated.server_deaf,
            });

            topics::publish(
                state,
                &topics::voice_topic(updated.channel_id),
                &json,
                &proto_msg,
            )
            .await;
        }
        Ok(None) => {
            tracing::debug!(user_id, "VOICE_STATE update but user not in a channel");
        }
        Err(e) => {
            tracing::error!(user_id, error = %e, "Failed to update voice state");
        }
    }
}

// ─── DISCONNECT ──────────────────────────────────────────────────────

pub async fn handle_disconnect(
    user_id: i64,
    state: &AppState,
    federated_allowed_server_ids: Option<HashSet<i64>>,
) {
    // Graceful shutdown already handles offline presence without broadcast.
    if state
        .shutting_down
        .load(std::sync::atomic::Ordering::Relaxed)
        || state.draining.load(std::sync::atomic::Ordering::Relaxed)
    {
        tracing::debug!(user_id, "DISCONNECT skipped (planned drain in progress)");
        return;
    }
    tracing::info!(user_id, "DISCONNECT, setting offline");

    // Remove from voice channels on disconnect
    match state.voice.leave_all(&state.redis, user_id).await {
        Ok(Some(old_state)) => {
            tracing::info!(
                user_id,
                channel_id = old_state.channel_id,
                "Cleaned up voice on disconnect"
            );
            let json = events::voice_state_update_json(&json!({
                "userId": user_id.to_string(),
                "channelId": Value::Null,
                "serverId": old_state.server_id.to_string(),
                "selfMute": false,
                "selfDeaf": false,
                "serverMute": false,
                "serverDeaf": false,
            }));
            let proto_msg = events::voice_state_update_proto(proto::VoiceState {
                user_id: user_id.to_string(),
                channel_id: None,
                server_id: old_state.server_id.to_string(),
                self_mute: false,
                self_deaf: false,
                server_mute: false,
                server_deaf: false,
            });
            topics::publish(
                state,
                &topics::voice_topic(old_state.channel_id),
                &json,
                &proto_msg,
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => tracing::error!(user_id, error = %e, "Failed to clean up voice on disconnect"),
    }

    // Remove presence from Redis (clean disconnect = immediately offline).
    crate::services::presence::remove(&state.redis, user_id).await;

    // Broadcast presence offline to all servers + friends. Every server
    // the user belongs to receives the presence broadcast so members
    // who share a server see them go offline.
    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id)
        .await
        .unwrap_or_default();
    let server_ids = scoped_presence_server_ids(server_ids, federated_allowed_server_ids.as_ref());

    let uid_str = user_id.to_string();
    let json = events::presence_update_json(&uid_str, proto::UserStatus::Offline as i32);
    let proto_msg = events::presence_update_proto(uid_str, proto::UserStatus::Offline as i32);
    broadcast_presence(
        state,
        &server_ids,
        user_id,
        &json,
        &proto_msg,
        federated_allowed_server_ids.is_none(),
    )
    .await;
    let now_ms = Utc::now().timestamp_millis();
    for server_id in server_ids {
        enqueue_federation_server_event(
            state,
            server_id,
            crate::federation::producer::FederationLocalEvent::PresenceUpdate {
                user_id,
                status: "offline".to_string(),
            },
            now_ms,
        )
        .await;
    }
}

// ─── FOCUS_SERVER ────────────────────────────────────────────────────

pub async fn handle_focus_server(
    state: &AppState,
    conn: &mut ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    server_id_str: &str,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };
    let Some(server_id) = parse_id(server_id_str) else {
        return;
    };
    if !federated_connection_allows_server(conn, Some(server_id)) {
        return;
    }

    // Verify membership
    if state.require_membership(user_id, server_id).await.is_err() {
        return;
    }

    // Unsubscribe from old presence topic
    if let Some(old_sid) = conn.focused_server_id {
        if old_sid != server_id {
            let old_topic = topics::presence_topic(old_sid);
            topics::unsubscribe_connection(state, conn.conn_id, &[old_topic]).await;
        }
    }

    // Subscribe to new presence topic
    let new_topic = topics::presence_topic(server_id);
    topics::subscribe_connection(state, conn.conn_id, &[new_topic]).await;
    conn.focused_server_id = Some(server_id);

    // Send initial presences for this server (include self)
    let mut presences = fetch_server_presences(state, server_id, user_id).await;
    // Include the requesting user's own presence from Redis
    {
        let self_status = crate::services::presence::effective_status(&state.redis, user_id).await;
        presences.push(json!({ "userId": user_id.to_string(), "status": self_status }));
    }
    let json = serde_json::to_string(&json!({
        "op": "PRESENCE_BATCH",
        "d": { "serverId": server_id_str, "presences": presences }
    }))
    .unwrap();
    let _ = tx.try_send(OutboundMsg::Text(json.into()));
}

// ─── FOCUS_CHANNEL ───────────────────────────────────────────────────

pub async fn handle_focus_channel(
    state: &AppState,
    conn: &mut ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    channel_id_str: Option<&str>,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };

    let previous = conn.focused_channel_id;
    let joined_voice_channel_id = conn
        .joined_voice_channel_id
        .or_else(|| state.ws.get_voice_channel(conn.conn_id));
    crate::realtime_trace!(
        user_id,
        conn_id = conn.conn_id,
        previous_channel_id = ?previous,
        requested_channel_id = ?channel_id_str,
        joined_voice_channel_id = ?joined_voice_channel_id,
        "realtime_scope: FOCUS_CHANNEL received"
    );
    let Some(channel_id_raw) = channel_id_str.filter(|s| !s.trim().is_empty()) else {
        if let Some(old_channel_id) = previous {
            conn.focused_channel_id = None;
            state.ws.set_focused_channel(conn.conn_id, None);
            if joined_voice_channel_id != Some(old_channel_id) {
                crate::realtime_trace!(
                    user_id,
                    conn_id = conn.conn_id,
                    old_channel_id,
                    "realtime_scope: FOCUS_CHANNEL cleared focus and unsubscribed old live topic"
                );
                topics::unsubscribe_connection(
                    state,
                    conn.conn_id,
                    &[topics::channel_live_topic(old_channel_id)],
                )
                .await;
            } else {
                crate::realtime_trace!(
                    user_id,
                    conn_id = conn.conn_id,
                    old_channel_id,
                    "realtime_scope: FOCUS_CHANNEL cleared focus but kept old live topic for joined voice"
                );
            }
        } else {
            crate::realtime_trace!(
                user_id,
                conn_id = conn.conn_id,
                "realtime_scope: FOCUS_CHANNEL cleared focus with no previous live channel"
            );
        }
        return;
    };

    let Some(channel_id) = parse_id(channel_id_raw) else {
        crate::realtime_trace!(
            user_id,
            conn_id = conn.conn_id,
            requested_channel_id = channel_id_raw,
            "realtime_scope: FOCUS_CHANNEL rejected invalid channel id"
        );
        send_error(tx, conn, "FOCUS_CHANNEL", "Invalid channelId", "INVALID_ID");
        return;
    };

    let server_id = match verify_channel_access(state, user_id, channel_id).await {
        Ok(sid) => sid,
        Err(_) => {
            crate::realtime_trace!(
                user_id,
                conn_id = conn.conn_id,
                channel_id,
                "realtime_scope: FOCUS_CHANNEL rejected because channel access check failed"
            );
            send_error(
                tx,
                conn,
                "FOCUS_CHANNEL",
                "Channel not found",
                "CHANNEL_ACCESS_DENIED",
            );
            return;
        }
    };
    if !federated_connection_allows_server(conn, server_id) {
        send_error(
            tx,
            conn,
            "FOCUS_CHANNEL",
            "Channel not found",
            "CHANNEL_ACCESS_DENIED",
        );
        return;
    }

    if let Some(sid) = server_id {
        if state
            .permissions
            .check_channel_permission(user_id, channel_id, sid, bits::VIEW_CHANNEL)
            .await
            .is_err()
        {
            crate::realtime_trace!(
                user_id,
                conn_id = conn.conn_id,
                channel_id,
                server_id = sid,
                "realtime_scope: FOCUS_CHANNEL rejected because VIEW_CHANNEL is denied"
            );
            send_error(
                tx,
                conn,
                "FOCUS_CHANNEL",
                "Channel not found",
                "CHANNEL_ACCESS_DENIED",
            );
            return;
        }
    }

    if let Some(old_channel_id) = previous {
        if old_channel_id != channel_id && joined_voice_channel_id != Some(old_channel_id) {
            crate::realtime_trace!(
                user_id,
                conn_id = conn.conn_id,
                old_channel_id,
                new_channel_id = channel_id,
                "realtime_scope: FOCUS_CHANNEL unsubscribing previous live topic"
            );
            topics::unsubscribe_connection(
                state,
                conn.conn_id,
                &[topics::channel_live_topic(old_channel_id)],
            )
            .await;
        } else if old_channel_id != channel_id {
            crate::realtime_trace!(
                user_id,
                conn_id = conn.conn_id,
                old_channel_id,
                new_channel_id = channel_id,
                "realtime_scope: FOCUS_CHANNEL keeping previous live topic because it is joined voice"
            );
        }
    }

    let focused_topics = topics::focused_channel_topics(channel_id);
    crate::realtime_trace!(
        user_id,
        conn_id = conn.conn_id,
        channel_id,
        server_id = ?server_id,
        live_topic = %focused_topics[0],
        notify_topic = %focused_topics[1],
        "realtime_scope: FOCUS_CHANNEL subscribing live plus notify for viewed channel"
    );
    topics::subscribe_connection(state, conn.conn_id, &focused_topics).await;
    conn.focused_channel_id = Some(channel_id);
    state
        .ws
        .set_focused_channel(conn.conn_id, conn.focused_channel_id);
}

// ─── REQUEST_MEMBERS ─────────────────────────────────────────────────

pub async fn handle_request_members(
    state: &AppState,
    conn: &ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    server_id_str: &str,
    query: &str,
    limit: i64,
    _after: Option<&str>,
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };
    let Some(server_id) = parse_id(server_id_str) else {
        return;
    };
    if !federated_connection_allows_server(conn, Some(server_id)) {
        return;
    }

    if state.require_membership(user_id, server_id).await.is_err() {
        return;
    }

    let limit = limit.clamp(1, 100) as usize;

    // Member search currently returns online users known to the permission cache.
    let online_uids = state.ws.connected_user_ids();
    let query_lc = query.to_lowercase();

    // Filter to server members first, then batch-fetch user records.
    let mut candidate_ids: Vec<i64> = Vec::new();
    for uid in online_uids {
        if candidate_ids.len() >= limit {
            break;
        }
        let is_member = match state.permissions.is_member_cached(uid, server_id) {
            Some(v) => v,
            None => state
                .permissions
                .check_membership(uid, server_id)
                .await
                .is_ok(),
        };
        if is_member {
            candidate_ids.push(uid);
        }
    }
    let users = crate::services::pg::users::by_ids(&state.pg, &candidate_ids)
        .await
        .unwrap_or_default();
    let mut members: Vec<(i64, String, Option<String>, Option<String>, String)> = users
        .into_iter()
        .filter(|u| query.is_empty() || u.username.to_lowercase().contains(&query_lc))
        .map(|u| {
            (
                u.id,
                u.username,
                u.display_name,
                u.avatar_url,
                u.status_type,
            )
        })
        .collect();
    members.sort_by(|a, b| a.1.cmp(&b.1));

    // Batch-fetch presence from Redis for all members
    let member_ids: Vec<i64> = members.iter().map(|(id, ..)| *id).collect();
    let presences = crate::services::presence::batch_get(&state.redis, &member_ids).await;
    let presence_map: std::collections::HashMap<i64, String> = presences.into_iter().collect();
    let federation_identities =
        match crate::federation::storage::remote_principals_for_local_user_ids(
            &state.pg,
            &member_ids,
        )
        .await
        {
            Ok(identities) => identities,
            Err(error) => {
                tracing::error!(
                    server_id,
                    error = %error,
                    "REQUEST_MEMBERS: federation remote principal lookup failed"
                );
                std::collections::HashMap::new()
            }
        };

    let chunk: Vec<Value> = members
        .iter()
        .map(|(id, username, display_name, avatar_url, _status)| {
            let effective = presence_map
                .get(id)
                .map(|s| s.as_str())
                .unwrap_or("offline");
            let federation = federation_identities.get(id).map(|identity| {
                json!({
                    "homePeerId": identity.home_peer_id,
                    "remoteUserId": identity.remote_user_id,
                    "remoteUsername": identity.remote_username,
                })
            });
            json!({
                "userId": id.to_string(),
                "username": username,
                "displayName": display_name,
                "avatarUrl": cdn::resolve(avatar_url.as_deref()),
                "status": effective,
                "federation": federation,
            })
        })
        .collect();

    let json_out = serde_json::to_string(&json!({
        "op": "MEMBERS_CHUNK",
        "d": {
            "serverId": server_id_str,
            "members": chunk,
            "chunkIndex": 0,
            "chunkCount": 1,
        }
    }))
    .unwrap();
    let _ = tx.try_send(OutboundMsg::Text(json_out.into()));
}

// ─── SUBSCRIBE_MEMBER_RANGES ─────────────────────────────────────────

/// Range-based member list subscription.  The client tells us which slices of
/// the sorted member list it currently has visible in the sidebar (e.g. rows
/// 0-99, 200-249).  We return only those slices, with total/online counts so
/// the client can render a scroll-bar.  The server stores the subscribed ranges
/// on the connection so future PRESENCE_UPDATE events can include the member's
/// list index for client-side range filtering.
///
/// Maximum 3 ranges per request, each capped at 200 entries.
pub async fn handle_subscribe_member_ranges(
    state: &AppState,
    conn: &mut ConnectionState,
    tx: &mpsc::Sender<OutboundMsg>,
    server_id_str: &str,
    ranges: &[(i64, i64)],
) {
    let user_id = match conn.user_id {
        Some(id) => id,
        None => return,
    };
    let Some(server_id) = parse_id(server_id_str) else {
        return;
    };
    if !federated_connection_allows_server(conn, Some(server_id)) {
        return;
    }

    if state.require_membership(user_id, server_id).await.is_err() {
        return;
    }

    // ── Input validation ────────────────────────────────────────────
    const MAX_RANGES: usize = 3;
    const MAX_RANGE_SIZE: i64 = 200;

    let mut validated_ranges: Vec<(i64, i64)> = Vec::with_capacity(MAX_RANGES);
    for &(start, end) in ranges.iter().take(MAX_RANGES) {
        if start < 0 || end < 0 || start >= end {
            continue; // skip invalid
        }
        let clamped_end = end.min(start + MAX_RANGE_SIZE);
        validated_ranges.push((start, clamped_end));
    }

    if validated_ranges.is_empty() {
        // Clear subscription — the client scrolled away or sent empty ranges
        conn.member_ranges.remove(&server_id);
        return;
    }

    // Store the subscribed ranges on the connection
    conn.member_ranges
        .insert(server_id, validated_ranges.clone());

    // ── Fetch online members via the WS connection registry ─────────
    // Post-PG-rip we don't have a persistent per-server member
    // iterator. Online-only membership is good enough for the
    // sidebar member list on solo prod; the offline members
    // surface via PRESENCE_UPDATE broadcasts as they come online.
    let mut online_member_ids: Vec<i64> = Vec::new();
    for uid in state.ws.connected_user_ids() {
        let is_member = match state.permissions.is_member_cached(uid, server_id) {
            Some(v) => v,
            None => state
                .permissions
                .check_membership(uid, server_id)
                .await
                .is_ok(),
        };
        if is_member {
            online_member_ids.push(uid);
        }
    }
    let users = crate::services::pg::users::by_ids(&state.pg, &online_member_ids)
        .await
        .unwrap_or_default();
    let all_members: Vec<(i64, String, Option<String>, Option<String>, String)> = users
        .into_iter()
        .map(|u| {
            (
                u.id,
                u.username,
                u.display_name,
                u.avatar_url,
                u.status_type,
            )
        })
        .collect();

    // Batch-fetch presence from Redis for all members
    let member_ids: Vec<i64> = all_members.iter().map(|(id, ..)| *id).collect();
    let presences = crate::services::presence::batch_get(&state.redis, &member_ids).await;
    let presence_map: std::collections::HashMap<i64, String> = presences.into_iter().collect();

    // ── Sort: online members first, then alphabetical ───────────────
    let mut sorted: Vec<(i64, String, Option<String>, Option<String>, String, bool)> = all_members
        .into_iter()
        .map(|(id, username, display_name, avatar_url, _status)| {
            let effective_status = presence_map
                .get(&id)
                .cloned()
                .unwrap_or_else(|| "offline".to_string());
            let is_online = effective_status != "offline";
            (
                id,
                username,
                display_name,
                avatar_url,
                effective_status,
                is_online,
            )
        })
        .collect();
    sorted.sort_by(|a, b| b.5.cmp(&a.5).then_with(|| a.1.cmp(&b.1)));

    let total_count = sorted.len();
    let online_count = sorted.iter().filter(|m| m.5).count();

    // ── Extract and send each requested range ───────────────────────
    for (start, end) in &validated_ranges {
        let start = *start as usize;
        let end = (*end as usize).min(total_count);
        if start >= total_count {
            continue;
        }

        let chunk: Vec<Value> = sorted[start..end]
            .iter()
            .map(|(id, username, display_name, avatar_url, status, _)| {
                json!({
                    "userId": id.to_string(),
                    "username": username,
                    "displayName": display_name,
                    "avatarUrl": cdn::resolve(avatar_url.as_deref()),
                    "status": status,
                })
            })
            .collect();

        let json_out = serde_json::to_string(&json!({
            "op": "MEMBER_LIST_UPDATE",
            "d": {
                "serverId": server_id_str,
                "range": [start, end],
                "members": chunk,
                "totalCount": total_count,
                "onlineCount": online_count,
            }
        }))
        .unwrap();
        let _ = tx.try_send(OutboundMsg::Text(json_out.into()));
    }
}

// ─── Presence fetch helper (shared by IDENTIFY + FOCUS_SERVER) ──────

/// Fetch online presences for a single server. Returns userId+status pairs
/// for members who are online (have active WS connections) and not invisible.
///
/// Post-PG-rip we iterate the WS connection registry and
/// filter by the permission cache's per-user membership data —
/// offline users aren't in either, so they correctly drop out.
async fn fetch_server_presences(
    state: &AppState,
    server_id: i64,
    exclude_user_id: i64,
) -> Vec<Value> {
    let mut out = Vec::new();
    for uid in state.ws.connected_user_ids() {
        if uid == exclude_user_id {
            continue;
        }
        // Cache-first membership check with durable fallback while cache warms.
        let is_member = match state.permissions.is_member_cached(uid, server_id) {
            Some(true) => true,
            Some(false) => false,
            None => {
                // Cache miss; check membership directly.
                state
                    .permissions
                    .check_membership(uid, server_id)
                    .await
                    .is_ok()
            }
        };
        if !is_member {
            continue;
        }
        // Read presence from Redis (ephemeral). Missing key = offline.
        if let Some(status) = crate::services::presence::get(&state.redis, uid).await {
            out.push(json!({
                "userId": uid.to_string(),
                "status": status,
            }));
        }
    }
    out
}

// ─── Row structs (pure in-memory shapes) ─────────────────────────────
// Plain structs holding deserialized IDENTIFY shard data.

#[derive(Debug)]
struct RelationshipRow {
    target_id: i64,
    rel_type: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    target_username: String,
    target_avatar_url: Option<String>,
    target_display_name: Option<String>,
    target_status_type: String,
    notes: String,
    nickname_color: Option<String>,
}

#[derive(Debug)]
struct RoleRow {
    id: i64,
    server_id: i64,
    name: String,
    color: Option<i32>,
    permissions: i64,
    position: i32,
    color_only: bool,
    show_as_section: bool,
    color_priority: i32,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
struct EmojiRow {
    id: i64,
    server_id: i64,
    name: String,
    url: String,
    created_by: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

// ─── PG-side builder for the dm_channels JSON array ──────────
//
// Fetches each DM channel + its members from PG, then batches the
// participant user lookup, presence read, and latest message metadata.
async fn build_dm_channels_from_pg(state: &AppState, dm_channel_ids: &[i64]) -> Vec<DmChannelInfo> {
    if dm_channel_ids.is_empty() {
        return vec![];
    }

    let channels = crate::services::pg::dms::channels_by_ids(&state.pg, dm_channel_ids)
        .await
        .unwrap_or_default();

    // Pull members per channel in parallel.
    let members_by_channel = futures_util::future::join_all(channels.iter().map(|c| {
        let pg = state.pg.clone();
        let cid = c.id;
        async move {
            (
                cid,
                crate::services::pg::dms::list_members(&pg, cid)
                    .await
                    .unwrap_or_default(),
            )
        }
    }))
    .await;

    // Collect distinct participant ids for one batched user + presence read.
    let mut all_uids: Vec<i64> = members_by_channel
        .iter()
        .flat_map(|(_, ms)| ms.iter().map(|m| m.user_id))
        .collect();
    all_uids.sort();
    all_uids.dedup();

    let users = crate::services::pg::users::by_ids(&state.pg, &all_uids)
        .await
        .unwrap_or_default();
    let user_lookup: HashMap<i64, &crate::repo::users::UserRow> =
        users.iter().map(|u| (u.id, u)).collect();
    let presence_map: HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &all_uids)
            .await
            .into_iter()
            .collect();
    let last_messages =
        crate::services::pg::messages::latest_by_channel_ids(&state.pg, dm_channel_ids)
            .await
            .unwrap_or_default();

    // Index members by channel for O(1) lookup.
    let members_idx: HashMap<i64, Vec<crate::services::pg::dms::DmMemberRow>> =
        members_by_channel.into_iter().collect();

    channels
        .iter()
        .filter_map(|ch| {
            let members = members_idx.get(&ch.id).cloned().unwrap_or_default();
            let participants_json: Vec<Value> = members
                .iter()
                .map(|m| {
                    let user = user_lookup.get(&m.user_id).copied();
                    let username = user.map(|u| u.username.as_str()).unwrap_or("");
                    let display_name = user.and_then(|u| u.display_name.as_deref());
                    let avatar_url = user.and_then(|u| u.avatar_url.as_deref());
                    let effective_status = presence_map
                        .get(&m.user_id)
                        .map(|s| s.as_str())
                        .unwrap_or("offline");
                    let name_color = m.name_color.clone().filter(|s| !s.is_empty());
                    json!({
                        "id": m.user_id.to_string(),
                        "username": username,
                        "displayName": display_name,
                        "avatarUrl": cdn::resolve(avatar_url),
                        "status": effective_status,
                        "nameColor": name_color,
                    })
                })
                .collect();

            let created_at =
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ch.created_at_ms)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default();
            let last_message = last_messages.get(&ch.id);
            let last_message_at = last_message
                .and_then(|m| {
                    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(m.created_at_ms)
                })
                .map(|t| t.to_rfc3339());

            Some(DmChannelInfo {
                json: json!({
                    "id": ch.id.to_string(),
                    "type": ch.r#type as i32,
                    "name": ch.name.clone().filter(|n| !n.is_empty()),
                    "participants": participants_json,
                    "lastMessageId": last_message.map(|m| m.id.to_string()),
                    "lastMessageAt": last_message_at,
                    "createdAt": created_at,
                }),
            })
        })
        .collect()
}

struct DmChannelInfo {
    json: Value,
}
