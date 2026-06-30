use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::repo::channels;
use crate::services::permissions::bits;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const CHANNEL_TYPE_SERVER_VOICE: i32 = 3;

fn voice_state_to_proto(vs: &crate::services::voice::VoiceState) -> crate::proto::VoiceState {
    crate::proto::VoiceState {
        user_id: vs.user_id.to_string(),
        channel_id: Some(vs.channel_id.to_string()),
        server_id: vs.server_id.to_string(),
        self_mute: vs.self_mute,
        self_deaf: vs.self_deaf,
        server_mute: vs.server_mute,
        server_deaf: vs.server_deaf,
    }
}

fn voice_not_enabled() -> AppError {
    AppError::WithCode {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "VOICE_NOT_AVAILABLE",
        message: "Voice chat is not yet available on this server".into(),
    }
}

fn require_voice(state: &AppState) -> AppResult<()> {
    if !state.config.livekit_enabled() {
        return Err(voice_not_enabled());
    }
    Ok(())
}

async fn require_voice_entitlement(state: &AppState, user_id: i64) -> AppResult<()> {
    let entitlements =
        crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id).await;
    if !entitlements.voice_chat {
        return Err(voice_not_enabled());
    }
    Ok(())
}

fn hide_voice_channel_access_error(err: AppError) -> AppError {
    match err {
        AppError::Forbidden | AppError::MissingPermission | AppError::NotMember => {
            AppError::NotFound("channel")
        }
        err => err,
    }
}

async fn require_server_voice_channel(
    state: &AppState,
    channel_id: i64,
    context: &'static str,
) -> AppResult<(channels::ChannelRow, i64)> {
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, context, error = %e, "voice: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    let server_id = channel.server_id.ok_or(AppError::NotFound("channel"))?;

    if channel.r#type != CHANNEL_TYPE_SERVER_VOICE {
        tracing::warn!(
            channel_id,
            server_id,
            channel_type = channel.r#type,
            context,
            "Rejected voice operation on non-voice channel"
        );
        return Err(AppError::NotFound("channel"));
    }

    Ok((channel, server_id))
}

async fn require_voice_channel_access(
    state: &AppState,
    user_id: i64,
    channel_id: i64,
    server_id: i64,
    permission: Option<i64>,
) -> AppResult<()> {
    state
        .require_membership(user_id, server_id)
        .await
        .map_err(|_| AppError::NotFound("channel"))?;
    state
        .permissions
        .check_channel_permission(user_id, channel_id, server_id, bits::VIEW_CHANNEL)
        .await
        .map_err(hide_voice_channel_access_error)?;

    if let Some(permission) = permission {
        state
            .permissions
            .check_channel_permission(user_id, channel_id, server_id, permission)
            .await?;
    }

    Ok(())
}

async fn broadcast_voice_state(
    state: &AppState,
    channel_id: i64,
    vs: &crate::services::voice::VoiceState,
) {
    let topic = topics::voice_topic(channel_id);
    let json_text = events::voice_state_update_json(&vs.to_json());
    let proto_msg = events::voice_state_update_proto(voice_state_to_proto(vs));
    topics::publish(state, &topic, &json_text, &proto_msg).await;
}

async fn broadcast_voice_leave(state: &AppState, channel_id: i64, server_id: i64, user_id: i64) {
    let topic = topics::voice_topic(channel_id);
    let leave_data = json!({
        "userId": user_id.to_string(),
        "channelId": serde_json::Value::Null,
        "serverId": server_id.to_string(),
    });
    let json_text = events::voice_state_update_json(&leave_data);
    let proto_msg = events::voice_state_update_proto(crate::proto::VoiceState {
        user_id: user_id.to_string(),
        channel_id: None,
        server_id: server_id.to_string(),
        self_mute: false,
        self_deaf: false,
        server_mute: false,
        server_deaf: false,
    });
    topics::publish(state, &topic, &json_text, &proto_msg).await;
}

// ─── POST /api/channels/:channelId/voice/join ───────────────────────

pub async fn voice_join(
    State(state): State<AppState>,
    user_id: UserId,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/channels/{}/voice/join user_id={}",
        channel_id_str,
        user_id.0
    );
    require_voice(&state)?;
    require_voice_entitlement(&state, user_id.0).await?;
    let channel_id = parse_id(&channel_id_str)?;
    rate_limit::enforce(&state, &rate_limit::VOICE_LIMIT, &user_id.0.to_string()).await?;

    let (_channel, server_id) =
        require_server_voice_channel(&state, channel_id, "voice_join").await?;
    require_voice_channel_access(
        &state,
        user_id.0,
        channel_id,
        server_id,
        Some(bits::CONNECT),
    )
    .await?;

    // Generate LiveKit token
    let lk_api_key = state.config.livekit_api_key.as_deref().unwrap();
    let lk_api_secret = state.config.livekit_api_secret.as_deref().unwrap();
    let room_name = crate::services::voice::livekit_room_name(server_id, channel_id);

    // Create the LiveKit room through the selected cluster endpoint
    // (idempotent — ignores "already exists"). The returned URL is the
    // signaling endpoint this client should connect to.
    let livekit_node = crate::services::voice::create_livekit_room_on_cluster(
        &state.redis,
        &state.config.livekit_nodes,
        lk_api_key,
        lk_api_secret,
        &room_name,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create LiveKit room: {e}");
        AppError::Internal
    })?;

    let token = crate::services::voice::generate_livekit_token(
        lk_api_key,
        lk_api_secret,
        &room_name,
        &user_id.0.to_string(),
    )
    .map_err(|e| {
        tracing::error!("Failed to generate LiveKit token: {e}");
        AppError::Internal
    })?;

    let join_result = state
        .voice
        .join_capped(
            &state.redis,
            user_id.0,
            channel_id,
            server_id,
            crate::services::voice::LIVEKIT_ROOM_MAX_PARTICIPANTS,
        )
        .await
        .map_err(|e| match e {
            crate::services::voice::VoiceJoinError::ChannelFull => AppError::WithCode {
                status: StatusCode::CONFLICT,
                code: "VOICE_CHANNEL_FULL",
                message: "This voice channel is full".into(),
            },
            _ => AppError::Internal,
        })?;
    let voice_state = join_result.state;

    if let Some(previous) = join_result.previous {
        broadcast_voice_leave(&state, previous.channel_id, previous.server_id, user_id.0).await;
        state
            .ws
            .clear_voice_channel_for_user(user_id.0, previous.channel_id);
    }

    // Broadcast VOICE_STATE_UPDATE to everyone who can view this voice channel.
    state.ws.set_voice_channel_for_user(user_id.0, channel_id);
    topics::subscribe_user(&state, user_id.0, &[topics::voice_topic(channel_id)]).await;
    broadcast_voice_state(&state, channel_id, &voice_state).await;
    let participant_count = state
        .voice
        .get_participants(&state.redis, channel_id)
        .await
        .len();

    tracing::info!("Voice joined channel={} user_id={}", channel_id, user_id.0);
    Ok(Json(json!({
        "token": token,
        "url": livekit_node.url,
        "voiceState": voice_state.to_json(),
        "participantCount": participant_count,
        "participantLimit": crate::services::voice::LIVEKIT_ROOM_MAX_PARTICIPANTS,
    })))
}

// ─── DELETE /api/channels/:channelId/voice/leave ────────────────────

pub async fn voice_leave(
    State(state): State<AppState>,
    user_id: UserId,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/channels/{}/voice/leave user_id={}",
        channel_id_str,
        user_id.0
    );
    require_voice(&state)?;
    let channel_id = parse_id(&channel_id_str)?;

    let removed = state
        .voice
        .leave(&state.redis, user_id.0, channel_id)
        .await
        .map_err(|_| AppError::Internal)?;

    if let Some(vs) = &removed {
        // Broadcast leave to everyone who can view this voice channel.
        broadcast_voice_leave(&state, channel_id, vs.server_id, user_id.0).await;
        state.ws.clear_voice_channel_for_user(user_id.0, channel_id);
    }

    tracing::info!("Voice left channel={} user_id={}", channel_id, user_id.0);
    Ok(Json(json!({ "success": true })))
}

// ─── PATCH /api/voice/state ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceStateUpdate {
    pub self_mute: Option<bool>,
    pub self_deaf: Option<bool>,
}

pub async fn voice_state(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<VoiceStateUpdate>,
) -> AppResult<Json<Value>> {
    tracing::info!("PATCH /api/voice/state user_id={}", user_id.0);
    require_voice(&state)?;
    rate_limit::enforce(&state, &rate_limit::VOICE_LIMIT, &user_id.0.to_string()).await?;

    let updated = state
        .voice
        .update_state(&state.redis, user_id.0, body.self_mute, body.self_deaf)
        .await
        .map_err(|_| AppError::Internal)?;

    match updated {
        Some(vs) => {
            broadcast_voice_state(&state, vs.channel_id, &vs).await;

            Ok(Json(vs.to_json()))
        }
        None => Err(AppError::Validation(
            "You are not in a voice channel".into(),
        )),
    }
}

// ─── POST /api/channels/:channelId/voice/mute/:targetUserId ────────

pub async fn voice_mute(
    State(state): State<AppState>,
    user_id: UserId,
    Path((channel_id_str, target_user_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/channels/{}/voice/mute/{} user_id={}",
        channel_id_str,
        target_user_id_str,
        user_id.0
    );
    require_voice(&state)?;
    let channel_id = parse_id(&channel_id_str)?;
    let target_user_id = parse_id(&target_user_id_str)?;
    rate_limit::enforce(&state, &rate_limit::VOICE_LIMIT, &user_id.0.to_string()).await?;

    let (_channel, server_id) =
        require_server_voice_channel(&state, channel_id, "voice_mute").await?;
    require_voice_channel_access(
        &state,
        user_id.0,
        channel_id,
        server_id,
        Some(bits::MUTE_MEMBERS),
    )
    .await?;

    // Cannot server-mute yourself
    if target_user_id == user_id.0 {
        return Err(AppError::Validation("Cannot server-mute yourself".into()));
    }

    // Role hierarchy check — actor must outrank target
    state
        .permissions
        .check_hierarchy(user_id.0, target_user_id, server_id)
        .await?;

    let updated = state
        .voice
        .set_server_state(&state.redis, target_user_id, channel_id, Some(true), None)
        .await
        .map_err(|_| AppError::Internal)?;

    if let Some(vs) = &updated {
        broadcast_voice_state(&state, channel_id, vs).await;
    }

    tracing::info!(
        "Voice server-muted target={} channel={} by={}",
        target_user_id,
        channel_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/channels/:channelId/voice/deafen/:targetUserId ──────

pub async fn voice_deafen(
    State(state): State<AppState>,
    user_id: UserId,
    Path((channel_id_str, target_user_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/channels/{}/voice/deafen/{} user_id={}",
        channel_id_str,
        target_user_id_str,
        user_id.0
    );
    require_voice(&state)?;
    let channel_id = parse_id(&channel_id_str)?;
    let target_user_id = parse_id(&target_user_id_str)?;
    rate_limit::enforce(&state, &rate_limit::VOICE_LIMIT, &user_id.0.to_string()).await?;

    let (_channel, server_id) =
        require_server_voice_channel(&state, channel_id, "voice_deafen").await?;
    require_voice_channel_access(
        &state,
        user_id.0,
        channel_id,
        server_id,
        Some(bits::DEAFEN_MEMBERS),
    )
    .await?;

    // Cannot server-deafen yourself
    if target_user_id == user_id.0 {
        return Err(AppError::Validation("Cannot server-deafen yourself".into()));
    }

    // Role hierarchy check — actor must outrank target
    state
        .permissions
        .check_hierarchy(user_id.0, target_user_id, server_id)
        .await?;

    let updated = state
        .voice
        .set_server_state(&state.redis, target_user_id, channel_id, None, Some(true))
        .await
        .map_err(|_| AppError::Internal)?;

    if let Some(vs) = &updated {
        broadcast_voice_state(&state, channel_id, vs).await;
    }

    tracing::info!(
        "Voice server-deafened target={} channel={} by={}",
        target_user_id,
        channel_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── GET /api/channels/:channelId/voice/participants ────────────────

pub async fn voice_participants(
    State(state): State<AppState>,
    user_id: UserId,
    Path(channel_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/channels/{}/voice/participants user_id={}",
        channel_id_str,
        user_id.0
    );
    require_voice(&state)?;
    let channel_id = parse_id(&channel_id_str)?;

    let (_channel, server_id) =
        require_server_voice_channel(&state, channel_id, "voice_participants").await?;
    require_voice_channel_access(&state, user_id.0, channel_id, server_id, None).await?;

    let participants = state.voice.get_participants(&state.redis, channel_id).await;
    let result: Vec<Value> = participants.iter().map(|p| p.to_json()).collect();

    Ok(Json(json!(result)))
}

// ─── POST /api/voice/webhook ────────────────────────────────────────
// LiveKit webhook — NO auth middleware (HMAC verified by WebhookReceiver)

pub async fn voice_webhook(State(_state): State<AppState>) -> AppResult<Json<Value>> {
    // Voice webhook disabled until LiveKit HMAC verification is implemented.
    // Returning 501 prevents unauthenticated abuse of this endpoint.
    Err(AppError::WithCode {
        status: StatusCode::NOT_IMPLEMENTED,
        code: "NOT_IMPLEMENTED",
        message: "Voice webhooks are not yet implemented".into(),
    })
}
