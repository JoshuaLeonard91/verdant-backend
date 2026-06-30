use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::middleware::{
    auth::{BotIdentity, OptionalBot, UserId},
    rate_limit,
};
use crate::services::audit::{self, AuditAction, AuditEntry};
use crate::services::banner_crop::{self, BannerCrop};
use crate::services::crypto::generate_bot_token;
use crate::services::permissions::bits;
use crate::services::pg::bots::{
    ALL_SCOPES, BotRow, SCOPE_ANNOUNCEMENTS_WRITE, SCOPE_AUDIT_READ, SCOPE_FEEDS_READ,
    SCOPE_MEMBERS_READ, SCOPE_MESSAGE_CONTENT_READ, SCOPE_MESSAGES_READ, SCOPE_MESSAGES_WRITE,
    SCOPE_UPLOADS_WRITE, has_scope,
};
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;

use super::parse_id;

const MAX_BOTS_PER_SERVER: usize = 25;
const MAX_TOKENS_PER_BOT: usize = 10;
const DEFAULT_BOT_AVATAR_PRESET: &str = "verdant";
const DEFAULT_BOT_BANNER_PRESET: &str = "aurora";
const BOT_AVATAR_PRESETS: &[&str] = &["verdant", "signal", "release", "shield", "spark", "orbit"];
const BOT_BANNER_PRESETS: &[&str] = &["aurora", "terminal", "signal", "night", "sunrise", "violet"];

#[derive(Deserialize)]
pub struct CreateBotRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "avatarPreset")]
    pub avatar_preset: Option<String>,
    #[serde(rename = "bannerPreset")]
    pub banner_preset: Option<String>,
}

#[derive(Default, Deserialize)]
pub struct UpdateBotRequest {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    #[serde(rename = "avatarPreset")]
    pub avatar_preset: Option<String>,
    #[serde(rename = "bannerPreset")]
    pub banner_preset: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BannerCropPatchRequest {
    pub banner_crop: Option<BannerCrop>,
}

#[derive(Default, Deserialize)]
pub struct GenerateTokenRequest {
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "allowedFeedIds")]
    pub allowed_feed_ids: Option<Vec<String>>,
    #[serde(rename = "allowedChannelIds")]
    pub allowed_channel_ids: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
pub struct ListBotsQueryParams {
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

pub(crate) fn serialize_bot(state: &AppState, r: &BotRow, role_ids: &[i64]) -> Value {
    json!({
        "id": r.id.to_string(),
        "serverId": r.server_id.to_string(),
        "name": r.name,
        "description": r.description.clone().filter(|s| !s.is_empty()),
        "avatarUrl": crate::services::cdn::resolve(r.avatar_url.as_deref()),
        "bannerUrl": crate::services::cdn::resolve(r.banner_url.as_deref()),
        "bannerCrop": banner_crop::to_json(r.banner_crop()),
        "avatarPreset": r.avatar_preset.as_deref().unwrap_or(DEFAULT_BOT_AVATAR_PRESET),
        "bannerPreset": r.banner_preset.as_deref().unwrap_or(DEFAULT_BOT_BANNER_PRESET),
        "roleIds": role_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "bot": true,
        "status": if state.bot_gateway.is_bot_online(r.id) { "online" } else { "offline" },
        "createdAt": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.created_at_ms)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    })
}

fn bot_identity_for_permission(bot: &BotRow, role_ids: &[i64]) -> BotIdentity {
    BotIdentity {
        bot_id: bot.id,
        token_id: 0,
        server_id: bot.server_id,
        name: bot.name.clone(),
        description: bot.description.clone(),
        avatar_url: bot.avatar_url.clone(),
        banner_url: bot.banner_url.clone(),
        banner_crop: bot.banner_crop(),
        avatar_preset: bot.avatar_preset.clone(),
        banner_preset: bot.banner_preset.clone(),
        role_ids: role_ids.to_vec(),
        scopes: Vec::new(),
        allowed_feed_ids: Vec::new(),
        allowed_channel_ids: Vec::new(),
    }
}

fn validate_requested_scopes(scopes: Option<&[String]>) -> AppResult<()> {
    let Some(scopes) = scopes else {
        return Ok(());
    };
    for scope in scopes {
        let trimmed = scope.trim();
        if trimmed.is_empty() || !ALL_SCOPES.contains(&trimmed) {
            return Err(AppError::Validation("Unknown bot token scope".into()));
        }
    }
    Ok(())
}

async fn validate_bot_list_channel(
    state: &AppState,
    requester_id: i64,
    server_id: i64,
    channel_id: i64,
) -> AppResult<()> {
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "list_bots: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    if channel.server_id != Some(server_id) {
        return Err(AppError::NotFound("channel"));
    }
    match state
        .permissions
        .check_channel_permission(requester_id, channel_id, server_id, bits::VIEW_CHANNEL)
        .await
    {
        Ok(()) => Ok(()),
        Err(AppError::Internal) => Err(AppError::Internal),
        Err(_) => Err(AppError::NotFound("channel")),
    }
}

fn sanitize_bot_description(value: Option<String>) -> AppResult<Option<String>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let description = sanitize_text(&raw);
    if description.len() > 500 {
        return Err(AppError::Validation(
            "Bot description must be at most 500 characters".into(),
        ));
    }
    Ok(if description.is_empty() {
        None
    } else {
        Some(description)
    })
}

async fn bot_role_ids(state: &AppState, bot_id: i64, server_id: i64) -> Vec<i64> {
    match crate::services::pg::bots::list_role_ids(&state.pg, bot_id, server_id).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!(bot_id, server_id, error = %e, "bot_role_ids: PG read failed");
            Vec::new()
        }
    }
}

async fn actor_highest_position(state: &AppState, user_id: i64, server_id: i64) -> i32 {
    if let Some(pos) = state
        .permissions
        .get_highest_role_position(user_id, server_id)
    {
        return pos;
    }
    let role_ids = crate::services::pg::roles::list_role_ids(&state.pg, user_id, server_id)
        .await
        .unwrap_or_default();
    let mut max_pos: i32 = 0;
    for rid in role_ids {
        if let Ok(Some(role)) = crate::services::pg::roles::by_id(&state.pg, rid).await {
            if !role.color_only && role.position > max_pos {
                max_pos = role.position;
            }
        }
    }
    max_pos
}

async fn server_owner_id(state: &AppState, server_id: i64) -> Option<i64> {
    crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .ok()
        .flatten()
        .map(|s| s.owner_id)
}

fn role_hierarchy_error(message: &'static str) -> AppError {
    AppError::WithCode {
        status: StatusCode::FORBIDDEN,
        code: "ROLE_HIERARCHY",
        message: message.into(),
    }
}

fn is_everyone_role(role: &crate::services::pg::roles::RoleRow) -> bool {
    role.position == 0 && role.name == "@everyone" && !role.color_only
}

fn serialize_scopes(scopes: &[String]) -> Value {
    json!(scopes)
}

fn normalize_visual_preset(
    value: Option<String>,
    allowed: &[&str],
    default_value: &str,
    field: &str,
) -> AppResult<String> {
    let preset = value
        .map(|v| sanitize_text(&v).to_ascii_lowercase())
        .unwrap_or_else(|| default_value.to_string());
    if allowed.contains(&preset.as_str()) {
        Ok(preset)
    } else {
        Err(AppError::Validation(format!("Invalid {field} preset")))
    }
}

fn validate_visual_preset(
    value: Option<String>,
    allowed: &[&str],
    field: &str,
) -> AppResult<Option<String>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let preset = sanitize_text(&raw).to_ascii_lowercase();
    if allowed.contains(&preset.as_str()) {
        Ok(Some(preset))
    } else {
        Err(AppError::Validation(format!("Invalid {field} preset")))
    }
}

fn parse_id_list(ids: Option<Vec<String>>, field: &str) -> AppResult<Vec<i64>> {
    let mut parsed = Vec::new();
    for id in ids.unwrap_or_default() {
        let value =
            parse_id(&id).map_err(|_| AppError::Validation(format!("Invalid {field} id")))?;
        if !parsed.contains(&value) {
            parsed.push(value);
        }
        if parsed.len() > 100 {
            return Err(AppError::Validation(format!(
                "{field} allowlist cannot exceed 100 entries"
            )));
        }
    }
    Ok(parsed)
}

async fn can_user_view_feed(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    feed: &crate::services::pg::feeds::FeedRow,
) -> AppResult<bool> {
    if feed.visible_role_ids.is_empty() {
        return Ok(true);
    }
    if state
        .permissions
        .check_server_permission(user_id, server_id, bits::ADMINISTRATOR)
        .await
        .is_ok()
    {
        return Ok(true);
    }

    let role_ids = crate::services::pg::roles::list_role_ids(&state.pg, user_id, server_id)
        .await
        .map_err(|e| {
            tracing::error!(user_id, server_id, error = %e, "generate_token: PG role list failed");
            AppError::Internal
        })?;
    let user_roles: std::collections::HashSet<i64> = role_ids.into_iter().collect();
    Ok(feed
        .visible_role_ids
        .iter()
        .any(|id| user_roles.contains(id)))
}

// ─── POST /api/servers/:serverId/bots ───────────────────────────────

pub async fn create_bot(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<CreateBotRequest>,
) -> AppResult<Response> {
    tracing::info!(
        "POST /api/servers/{}/bots user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let name = sanitize_text(&body.name);
    if name.is_empty() || name.len() > 32 {
        return Err(AppError::Validation(
            "Bot name must be 1-32 characters".into(),
        ));
    }
    let description = sanitize_bot_description(body.description)?;
    let avatar_preset = normalize_visual_preset(
        body.avatar_preset,
        BOT_AVATAR_PRESETS,
        DEFAULT_BOT_AVATAR_PRESET,
        "avatar",
    )?;
    let banner_preset = normalize_visual_preset(
        body.banner_preset,
        BOT_BANNER_PRESETS,
        DEFAULT_BOT_BANNER_PRESET,
        "banner",
    )?;

    let existing = crate::services::pg::bots::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_bot: PG list failed");
            AppError::Internal
        })?;
    if existing.len() >= MAX_BOTS_PER_SERVER {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "BOT_LIMIT_REACHED",
            message: format!("Server has reached the maximum of {MAX_BOTS_PER_SERVER} bots"),
        });
    }

    let id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::bots::insert(
        &state.pg,
        id,
        server_id,
        &name,
        description.as_deref(),
        Some(&avatar_preset),
        Some(&banner_preset),
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(id, error = %e, "create_bot: PG write failed");
        AppError::Internal
    })?;

    let row = BotRow {
        id,
        server_id,
        name,
        description,
        avatar_url: None,
        banner_url: None,
        banner_crop_x: None,
        banner_crop_y: None,
        banner_crop_width: None,
        banner_crop_height: None,
        avatar_preset: Some(avatar_preset),
        banner_preset: Some(banner_preset),
        created_at_ms: now_ms,
    };
    let bot_json = serialize_bot(&state, &row, &[]);
    tracing::info!(
        "Bot created id={} server={} by={}",
        id,
        server_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(bot_json)).into_response())
}

// ─── GET /api/servers/:serverId/bots ────────────────────────────────

pub async fn list_bots(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Query(params): Query<ListBotsQueryParams>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/bots user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let result = list_bots_json(&state, user_id.0, server_id, params).await?;

    Ok(Json(json!(result)))
}

pub(crate) async fn list_bots_json(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    params: ListBotsQueryParams,
) -> AppResult<Vec<Value>> {
    state.require_membership(user_id, server_id).await?;

    let bots = crate::services::pg::bots::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_bots: PG read failed");
            AppError::Internal
        })?;

    let bot_roles = crate::services::pg::bots::list_roles_for_server(&state.pg, server_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(server_id, error = %e, "list_bots: PG bot role read failed");
            Vec::new()
        });
    let mut roles_by_bot: std::collections::HashMap<i64, Vec<i64>> =
        std::collections::HashMap::new();
    for row in bot_roles {
        roles_by_bot
            .entry(row.bot_id)
            .or_default()
            .push(row.role_id);
    }

    let channel_id = params.channel_id.as_deref().map(parse_id).transpose()?;
    if let Some(channel_id) = channel_id {
        validate_bot_list_channel(state, user_id, server_id, channel_id).await?;
    }

    let mut result = Vec::with_capacity(bots.len());
    for bot in &bots {
        let role_ids = roles_by_bot.get(&bot.id).map(Vec::as_slice).unwrap_or(&[]);
        if let Some(channel_id) = channel_id {
            let identity = bot_identity_for_permission(bot, role_ids);
            if !crate::services::bot_permissions::has_channel_permission(
                &state,
                &identity,
                channel_id,
                bits::VIEW_CHANNEL,
            )
            .await?
            {
                continue;
            }
        }
        result.push(serialize_bot(state, bot, role_ids));
    }
    Ok(result)
}

// ─── GET /api/bot/me ─────────────────────────────────────────────────

pub async fn update_bot(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
    Json(body): Json<UpdateBotRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/servers/{}/bots/{} user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "update_bot: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    let name = body.name.map(|n| sanitize_text(&n));
    if let Some(ref name) = name {
        if name.is_empty() || name.len() > 32 {
            return Err(AppError::Validation(
                "Bot name must be 1-32 characters".into(),
            ));
        }
    }
    let description = match body.description {
        Some(value) => Some(sanitize_bot_description(value)?.unwrap_or_default()),
        None => None,
    };
    let avatar_preset = validate_visual_preset(body.avatar_preset, BOT_AVATAR_PRESETS, "avatar")?;
    let banner_preset = validate_visual_preset(body.banner_preset, BOT_BANNER_PRESETS, "banner")?;

    crate::services::pg::bots::update(
        &state.pg,
        bot_id,
        name.as_deref(),
        description.as_deref(),
        None,
        None,
        avatar_preset.as_deref(),
        banner_preset.as_deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!(bot_id, error = %e, "update_bot: PG write failed");
        AppError::Internal
    })?;

    let updated = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "update_bot: PG reload failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;

    let role_ids = bot_role_ids(&state, bot_id, server_id).await;
    Ok(Json(serialize_bot(&state, &updated, &role_ids)))
}

pub async fn update_bot_banner_crop(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
    Json(body): Json<BannerCropPatchRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/servers/{}/bots/{}/banner/crop user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "update_bot_banner_crop: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    let crop = body.banner_crop.map(|crop| crop.validate()).transpose()?;
    crate::services::pg::bots::update_banner_crop(&state.pg, bot_id, crop)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "update_bot_banner_crop: PG write failed");
            AppError::Internal
        })?;

    let updated = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "update_bot_banner_crop: PG reload failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;

    let role_ids = bot_role_ids(&state, bot_id, server_id).await;
    Ok(Json(serialize_bot(&state, &updated, &role_ids)))
}

pub async fn bot_me(
    State(state): State<AppState>,
    optional_bot: OptionalBot,
) -> AppResult<Json<Value>> {
    let OptionalBot(Some(bot)) = optional_bot else {
        return Err(AppError::Forbidden);
    };
    rate_limit::enforce(
        &state,
        &rate_limit::API_LIMIT,
        &format!("bot:{}", bot.bot_id),
    )
    .await?;
    Ok(Json(json!({
        "id": bot.bot_id.to_string(),
        "serverId": bot.server_id.to_string(),
        "tokenId": bot.token_id.to_string(),
        "name": bot.name,
        "description": bot.description.clone().filter(|s| !s.is_empty()),
        "avatarUrl": crate::services::cdn::resolve(bot.avatar_url.as_deref()),
        "bannerUrl": crate::services::cdn::resolve(bot.banner_url.as_deref()),
        "bannerCrop": banner_crop::to_json(bot.banner_crop),
        "avatarPreset": bot.avatar_preset.as_deref().unwrap_or(DEFAULT_BOT_AVATAR_PRESET),
        "bannerPreset": bot.banner_preset.as_deref().unwrap_or(DEFAULT_BOT_BANNER_PRESET),
        "scopes": serialize_scopes(&bot.scopes),
        "allowedFeedIds": bot.allowed_feed_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "allowedChannelIds": bot.allowed_channel_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "gatewayUrl": "/bot-gateway",
    })))
}

// ─── DELETE /api/servers/:serverId/bots/:botId ──────────────────────

pub async fn delete_bot(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/bots/{} user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "delete_bot: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    // Cascade — bot_tokens has ON DELETE CASCADE on bot_id, so a single
    // DELETE on bots is enough to clear tokens. Verify the schema does
    // this; otherwise we'd need a manual delete here.
    crate::services::pg::bots::delete(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "delete_bot: PG delete failed");
            AppError::Internal
        })?;

    tracing::info!(
        "Bot deleted id={} server={} by={}",
        bot_id,
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/servers/:serverId/bots/:botId/tokens ─────────────────

pub async fn generate_token(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str)): Path<(String, String)>,
    body: Option<Json<GenerateTokenRequest>>,
) -> AppResult<Response> {
    let body = body.map(|Json(body)| body).unwrap_or_default();
    tracing::info!(
        "POST /api/servers/{}/bots/{}/tokens user_id={}",
        server_id_str,
        bot_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "generate_token: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    // Per-bot live-token cap. list_tokens returns all rows incl. revoked;
    // we filter to live (revoked_at_ms IS NULL) in-memory. Token counts
    // are bounded so the extra rows are negligible.
    let tokens = crate::services::pg::bots::list_tokens(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "generate_token: PG token list failed");
            AppError::Internal
        })?;
    let live_count = tokens.iter().filter(|t| t.revoked_at_ms.is_none()).count();
    if live_count >= MAX_TOKENS_PER_BOT {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "BOT_LIMIT_REACHED",
            message: "Maximum active tokens reached for this bot".into(),
        });
    }

    let token_name = body
        .name
        .map(|n| sanitize_text(&n))
        .unwrap_or_else(|| "default".to_string());
    if token_name.is_empty() || token_name.len() > 64 {
        return Err(AppError::Validation(
            "Token name must be 1-64 characters".into(),
        ));
    }

    validate_requested_scopes(body.scopes.as_deref())?;
    let scopes = crate::services::pg::bots::normalize_scopes(body.scopes.as_deref());
    let allowed_feed_ids = parse_id_list(body.allowed_feed_ids, "feed")?;
    let allowed_channel_ids = parse_id_list(body.allowed_channel_ids, "channel")?;

    if !allowed_feed_ids.is_empty() {
        let feeds = crate::services::pg::feeds::list_for_server(&state.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "generate_token: PG feed list failed");
                AppError::Internal
            })?;
        let feeds_by_id: std::collections::HashMap<i64, _> =
            feeds.iter().map(|feed| (feed.id, feed)).collect();
        if allowed_feed_ids
            .iter()
            .any(|id| !feeds_by_id.contains_key(id))
        {
            return Err(AppError::Validation(
                "Allowed feed ids must belong to this server".into(),
            ));
        }
        if has_scope(&scopes, SCOPE_FEEDS_READ) || has_scope(&scopes, SCOPE_ANNOUNCEMENTS_WRITE) {
            for feed_id in &allowed_feed_ids {
                let Some(feed) = feeds_by_id.get(feed_id) else {
                    continue;
                };
                if !can_user_view_feed(&state, user_id.0, server_id, feed).await? {
                    return Err(AppError::WithCode {
                        status: StatusCode::FORBIDDEN,
                        code: "BOT_FEED_NOT_ALLOWED",
                        message: "Allowed feed ids must be visible to you".into(),
                    });
                }
            }
        }
    }

    if !allowed_channel_ids.is_empty() {
        let channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "generate_token: PG channel list failed");
                AppError::Internal
            })?;
        let channel_ids: std::collections::HashSet<i64> =
            channels.into_iter().map(|c| c.id).collect();
        if allowed_channel_ids
            .iter()
            .any(|id| !channel_ids.contains(id))
        {
            return Err(AppError::Validation(
                "Allowed channel ids must belong to this server".into(),
            ));
        }
        if has_scope(&scopes, SCOPE_MESSAGES_READ)
            || has_scope(&scopes, SCOPE_MESSAGES_WRITE)
            || has_scope(&scopes, SCOPE_MESSAGE_CONTENT_READ)
        {
            for channel_id in &allowed_channel_ids {
                match state
                    .permissions
                    .check_channel_permission(user_id.0, *channel_id, server_id, bits::VIEW_CHANNEL)
                    .await
                {
                    Ok(()) => {}
                    Err(AppError::Internal) => return Err(AppError::Internal),
                    Err(_) => {
                        return Err(AppError::WithCode {
                            status: StatusCode::FORBIDDEN,
                            code: "BOT_CHANNEL_NOT_ALLOWED",
                            message: "Allowed channel ids must be visible to you".into(),
                        });
                    }
                }
            }
        }
    }

    let (plaintext_token, token_hash) = generate_bot_token();
    let token_id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();

    crate::services::pg::bots::token_insert(
        &state.pg,
        token_id,
        bot_id,
        &token_hash,
        &token_name,
        &scopes,
        &allowed_feed_ids,
        &allowed_channel_ids,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(token_id, bot_id, error = %e, "generate_token: PG write failed");
        AppError::Internal
    })?;

    tracing::info!(
        "Bot token created token_id={} bot={} server={} by={}",
        token_id,
        bot_id,
        server_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(json!({
        "tokenId": token_id.to_string(),
        "token": plaintext_token,
        "name": token_name,
        "scopes": scopes,
        "allowedFeedIds": allowed_feed_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "allowedChannelIds": allowed_channel_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        "availableScopes": [
            SCOPE_ANNOUNCEMENTS_WRITE,
            SCOPE_FEEDS_READ,
            SCOPE_MESSAGES_WRITE,
            SCOPE_MESSAGES_READ,
            SCOPE_MESSAGE_CONTENT_READ,
            SCOPE_MEMBERS_READ,
            SCOPE_AUDIT_READ,
            SCOPE_UPLOADS_WRITE
        ],
    }))).into_response())
}

// ─── DELETE /api/servers/:serverId/bots/:botId/tokens/:tokenId ──────

pub async fn revoke_token(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str, token_id_str)): Path<(String, String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/bots/{}/tokens/{} user_id={}",
        server_id_str,
        bot_id_str,
        token_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;
    let token_id = parse_id(&token_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "revoke_token: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    let token = crate::services::pg::bots::token_by_id(&state.pg, token_id)
        .await
        .map_err(|e| {
            tracing::error!(token_id, error = %e, "revoke_token: PG token read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("token"))?;
    if token.bot_id != bot_id || token.revoked_at_ms.is_some() {
        return Err(AppError::NotFound("token"));
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::bots::token_revoke(&state.pg, token_id, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(token_id, error = %e, "revoke_token: PG write failed");
            AppError::Internal
        })?;

    tracing::info!(
        "Bot token revoked token_id={} bot={} server={} by={}",
        token_id,
        bot_id,
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── PUT/DELETE /api/servers/:serverId/bots/:botId/roles/:roleId ───────────

pub async fn assign_bot_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str, role_id_str)): Path<(String, String, String)>,
) -> AppResult<Response> {
    tracing::info!(
        "PUT /api/servers/{}/bots/{}/roles/{} user_id={}",
        server_id_str,
        bot_id_str,
        role_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;
    let role_id = parse_id(&role_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "assign_bot_role: PG bot read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    let target_role = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "assign_bot_role: PG role read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if target_role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }
    if is_everyone_role(&target_role) {
        return Err(AppError::Validation(
            "The @everyone role is assigned automatically".into(),
        ));
    }

    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    if !is_owner && !target_role.color_only && target_role.position >= actor_pos {
        return Err(role_hierarchy_error(
            "You cannot assign a role with equal or higher position than your own",
        ));
    }

    crate::services::pg::bots::assign_role(
        &state.pg,
        bot_id,
        server_id,
        role_id,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(|e| {
        tracing::error!(bot_id, server_id, role_id, error = %e, "assign_bot_role: PG assign failed");
        AppError::Internal
    })?;

    let role_ids = bot_role_ids(&state, bot_id, server_id)
        .await
        .into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>();

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::AssignRole,
            target_type: "bot",
            target_id: bot_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "roleId": role_id_str })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({ "success": true, "roleIds": role_ids })),
    )
        .into_response())
}

pub async fn remove_bot_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, bot_id_str, role_id_str)): Path<(String, String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/bots/{}/roles/{} user_id={}",
        server_id_str,
        bot_id_str,
        role_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let bot_id = parse_id(&bot_id_str)?;
    let role_id = parse_id(&role_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let bot = crate::services::pg::bots::by_id(&state.pg, bot_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, error = %e, "remove_bot_role: PG bot read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("bot"))?;
    if bot.server_id != server_id {
        return Err(AppError::NotFound("bot"));
    }

    let target_role = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "remove_bot_role: PG role read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if target_role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }
    if is_everyone_role(&target_role) {
        return Err(AppError::Validation(
            "The @everyone role cannot be removed".into(),
        ));
    }

    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    if !is_owner && !target_role.color_only && target_role.position >= actor_pos {
        return Err(role_hierarchy_error(
            "You cannot remove a role with equal or higher position than your own",
        ));
    }

    crate::services::pg::bots::unassign_role(&state.pg, bot_id, server_id, role_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id, server_id, role_id, error = %e, "remove_bot_role: PG unassign failed");
            AppError::Internal
        })?;

    let role_ids = bot_role_ids(&state, bot_id, server_id)
        .await
        .into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>();

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::RemoveRole,
            target_type: "bot",
            target_id: bot_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "roleId": role_id_str })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok(Json(json!({ "success": true, "roleIds": role_ids })))
}
