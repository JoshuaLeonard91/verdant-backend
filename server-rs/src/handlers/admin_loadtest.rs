//! Admin routes for loadtest scaffolding.
//!
//! These routes let an operator stamp out N synthetic users + a
//! dedicated server + channel + @everyone role directly in PG,
//! skipping registration, email verification, and registration-key
//! consumption. They return a ready-to-use list of `{user_id, token}`
//! pairs so an external load-test client can open N
//! WebSockets and fire sustained traffic.
//!
//! Protected by `X-Loadtest-Secret: <LOADTEST_SECRET>` (min 16
//! chars, set in the server config). When unset, both routes
//! return 503. Routes should only be exposed on internal/admin
//! infrastructure — the users they create have no email and no
//! password, so access to the secret = access to anonymous
//! authenticated sessions.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use chrono::Duration as ChronoDuration;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::services::crypto::generate_access_token_with_ttl;
use crate::services::permissions::bits;
use crate::state::AppState;

const MAX_LOADTEST_USERS_PER_CALL: i64 = 1000;
const MAX_LIVE_LOADTEST_USERS: usize = 5000;
const LOADTEST_DEFAULT_PERMISSIONS: i64 = bits::VIEW_CHANNEL
    | bits::SEND_MESSAGES
    | bits::ATTACH_FILES
    | bits::USE_CUSTOM_EMOJIS
    | bits::CONNECT
    | bits::SPEAK;

const REDIS_KEY_LOADTEST_SERVERS: &str = "loadtest:servers";
const REDIS_KEY_LOADTEST_USERS: &str = "loadtest:users";

#[derive(Deserialize)]
pub struct SetupQuery {
    #[serde(default)]
    pub count: Option<i64>,
    #[serde(default)]
    pub channels: Option<i64>,
    #[serde(default)]
    pub servers: Option<i64>,
}

fn verify_secret(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let expected = match state.config.loadtest_secret.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Err(AppError::WithCode {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "LOADTEST_DISABLED",
                message: "LOADTEST_SECRET not configured".into(),
            });
        }
    };
    let provided = headers
        .get("x-loadtest-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() {
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "LOADTEST_UNAUTHORIZED",
            message: "Invalid loadtest secret".into(),
        });
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    if diff != 0 {
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "LOADTEST_UNAUTHORIZED",
            message: "Invalid loadtest secret".into(),
        });
    }
    Ok(())
}

// ─── POST /api/admin/loadtest/setup?count=N ─────────────────────────

pub async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SetupQuery>,
) -> AppResult<Json<Value>> {
    verify_secret(&state, &headers)?;

    let count = q.count.unwrap_or(100);
    if count < 1 || count > MAX_LOADTEST_USERS_PER_CALL {
        return Err(AppError::Validation(format!(
            "count must be between 1 and {MAX_LOADTEST_USERS_PER_CALL}"
        )));
    }
    let count = count as usize;
    let num_servers = q.servers.unwrap_or(1).max(1).min(500) as usize;
    let num_channels_per_server = q.channels.unwrap_or(1).max(1).min(500) as usize;

    tracing::info!(
        "POST /api/admin/loadtest/setup count={} servers={} channels_per_server={}",
        count,
        num_servers,
        num_channels_per_server
    );

    let jwt_secret = state.config.jwt_secret.clone();

    use fred::interfaces::SetsInterface;
    let existing: i64 = state
        .redis
        .scard(REDIS_KEY_LOADTEST_USERS)
        .await
        .unwrap_or(0);
    if existing as usize + count > MAX_LIVE_LOADTEST_USERS {
        return Err(AppError::Validation(format!(
            "loadtest cap reached: {existing} existing + {count} new > {MAX_LIVE_LOADTEST_USERS}"
        )));
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let password_hash =
        crate::services::crypto::hash_password("loadtest").map_err(|_| AppError::Internal)?;

    // (id, username, token)
    let mut users: Vec<(i64, String, String)> = Vec::with_capacity(count);

    for i in 0..count {
        let user_id = state.snowflake.next_id();
        let username = format!("loadtest_user_{user_id}");
        let email = format!("{user_id}@loadtest.invalid");
        let display_name = format!("Loadtest {i}");

        crate::services::pg::users::insert(
            &state.pg,
            crate::services::pg::users::InsertUser {
                id: user_id,
                email: &email,
                password_hash: &password_hash,
                username: &username,
                display_name: Some(&display_name),
                username_set: true,
                email_verified: true,
                now_ms,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(user_id, error = %e, "loadtest setup: PG user write failed");
            AppError::Internal
        })?;

        let token =
            generate_access_token_with_ttl(user_id, &jwt_secret, None, ChronoDuration::hours(24))
                .map_err(|_| AppError::Internal)?;

        users.push((user_id, username, token));
    }

    let mut server_user_indices: Vec<Vec<usize>> = vec![Vec::new(); num_servers];
    for (i, _) in users.iter().enumerate() {
        server_user_indices[i % num_servers].push(i);
    }

    struct ServerInfo {
        server_id: i64,
        channel_ids: Vec<i64>,
    }
    let mut server_infos: Vec<ServerInfo> = Vec::with_capacity(num_servers);
    let mut user_assignment: Vec<(i64, i64)> = vec![(0, 0); count];

    for (srv_idx, member_indices) in server_user_indices.iter().enumerate() {
        if member_indices.is_empty() {
            continue;
        }

        let owner_user_idx = member_indices[0];
        let owner_id = users[owner_user_idx].0;

        let server_id = state.snowflake.next_id();
        let server_name = if num_servers == 1 {
            format!("__loadtest_{server_id}")
        } else {
            format!("__loadtest_{server_id}_s{srv_idx}")
        };

        crate::services::pg::servers::insert(&state.pg, server_id, &server_name, owner_id, now_ms)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "loadtest setup: PG server insert failed");
                AppError::Internal
            })?;

        // Auto-join the owner.
        crate::services::pg::servers::add_member(&state.pg, server_id, owner_id, now_ms)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "loadtest setup: PG owner add_member failed");
                AppError::Internal
            })?;

        // @everyone role for this server.
        let everyone_role_id = state.snowflake.next_id();
        crate::services::pg::roles::insert(
            &state.pg,
            everyone_role_id,
            server_id,
            "@everyone",
            0,
            LOADTEST_DEFAULT_PERMISSIONS,
            0,
            false,
            false,
            0,
            now_ms,
        )
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "loadtest setup: PG role insert failed");
            AppError::Internal
        })?;

        let mut channel_ids: Vec<i64> = Vec::with_capacity(num_channels_per_server);
        for ch_idx in 0..num_channels_per_server {
            let channel_id = state.snowflake.next_id();
            let ch_name = if num_channels_per_server == 1 {
                "general".to_string()
            } else {
                format!("channel-{ch_idx}")
            };
            crate::services::pg::channels::insert(
                &state.pg,
                channel_id,
                server_id,
                0i16,
                Some(&ch_name),
                Some("loadtest fire zone"),
                ch_idx as i32,
                None,
                false,
                0,
                now_ms,
            )
            .await
            .map_err(|e| {
                tracing::error!(channel_id, error = %e, "loadtest setup: PG channel insert failed");
                AppError::Internal
            })?;
            channel_ids.push(channel_id);
        }

        for &user_idx in member_indices.iter().skip(1) {
            let uid = users[user_idx].0;
            if let Err(e) =
                crate::services::pg::servers::add_member(&state.pg, server_id, uid, now_ms).await
            {
                tracing::error!(user_id = uid, server_id, error = %e, "loadtest setup: add_member failed");
            }
        }

        for (local_idx, &user_idx) in member_indices.iter().enumerate() {
            let assigned_channel = channel_ids[local_idx % num_channels_per_server];
            user_assignment[user_idx] = (server_id, assigned_channel);
        }

        let _: Result<(), _> = state
            .redis
            .sadd::<(), _, _>(REDIS_KEY_LOADTEST_SERVERS, server_id.to_string())
            .await;

        server_infos.push(ServerInfo {
            server_id,
            channel_ids,
        });
    }

    let user_id_strs: Vec<String> = users.iter().map(|(id, _, _)| id.to_string()).collect();
    if !user_id_strs.is_empty() {
        let _: Result<(), _> = state
            .redis
            .sadd::<(), _, _>(REDIS_KEY_LOADTEST_USERS, user_id_strs.clone())
            .await;
    }

    tracing::info!(
        count = users.len(),
        num_servers = server_infos.len(),
        num_channels_per_server,
        "loadtest setup complete"
    );

    let users_json: Vec<Value> = users
        .iter()
        .enumerate()
        .map(|(i, (id, username, token))| {
            let (srv_id, ch_id) = user_assignment[i];
            json!({
                "id": id.to_string(),
                "username": username,
                "token": token,
                "channelId": ch_id.to_string(),
                "serverId": srv_id.to_string(),
            })
        })
        .collect();

    let servers_json: Vec<Value> = server_infos
        .iter()
        .map(|si| {
            json!({
                "serverId": si.server_id.to_string(),
                "channelIds": si.channel_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let first_server_id = server_infos[0].server_id;
    let first_channel_id = server_infos[0].channel_ids[0];
    let all_channel_ids: Vec<String> = server_infos
        .iter()
        .flat_map(|si| si.channel_ids.iter().map(|id| id.to_string()))
        .collect();

    Ok(Json(json!({
        "serverId": first_server_id.to_string(),
        "channelId": first_channel_id.to_string(),
        "channelIds": all_channel_ids,
        "servers": servers_json,
        "users": users_json,
    })))
}

// ─── GET /api/admin/broadcast-stats ─────────────────────────────────

pub async fn broadcast_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    verify_secret(&state, &headers)?;
    Ok(Json(state.broadcast.stats.snapshot()))
}

// ─── POST /api/admin/loadtest/teardown ──────────────────────────────

pub async fn teardown(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    verify_secret(&state, &headers)?;
    tracing::info!("POST /api/admin/loadtest/teardown");

    use fred::interfaces::SetsInterface;
    let now_ms = chrono::Utc::now().timestamp_millis();

    let server_ids: Vec<String> = state
        .redis
        .smembers::<Vec<String>, _>(REDIS_KEY_LOADTEST_SERVERS)
        .await
        .unwrap_or_default();
    let mut servers_soft_deleted: u64 = 0;
    for sid_str in &server_ids {
        let Ok(sid) = sid_str.parse::<i64>() else {
            continue;
        };
        match crate::services::pg::servers::soft_delete(&state.pg, sid, now_ms).await {
            Ok(_) => servers_soft_deleted += 1,
            Err(e) => {
                tracing::warn!(server_id = sid, error = %e, "teardown: soft-delete server failed")
            }
        }
    }

    let user_ids: Vec<String> = state
        .redis
        .smembers::<Vec<String>, _>(REDIS_KEY_LOADTEST_USERS)
        .await
        .unwrap_or_default();
    let mut users_soft_deleted: u64 = 0;
    for uid_str in &user_ids {
        let Ok(uid) = uid_str.parse::<i64>() else {
            continue;
        };
        match crate::services::pg::users::soft_delete(&state.pg, uid).await {
            Ok(_) => {
                users_soft_deleted += 1;
                state.user_profiles.invalidate(uid);
            }
            Err(e) => {
                tracing::warn!(user_id = uid, error = %e, "teardown: soft-delete user failed")
            }
        }
    }

    use fred::interfaces::KeysInterface;
    let _: Result<(), _> =
        KeysInterface::del::<(), _>(&state.redis, REDIS_KEY_LOADTEST_SERVERS).await;
    let _: Result<(), _> =
        KeysInterface::del::<(), _>(&state.redis, REDIS_KEY_LOADTEST_USERS).await;

    tracing::info!(
        servers_soft_deleted,
        users_soft_deleted,
        "loadtest teardown complete"
    );

    Ok(Json(json!({
        "serversSoftDeleted": servers_soft_deleted,
        "usersSoftDeleted": users_soft_deleted,
    })))
}
