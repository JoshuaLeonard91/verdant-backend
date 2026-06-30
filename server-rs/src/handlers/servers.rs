use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::{
    auth::{
        FederatedClientIdentity, OptionalFederatedClient, UserId,
        federated_client_allows_server_id, require_federated_client_server_scope,
    },
    rate_limit,
};
use crate::repo::servers::ServerRow;
use crate::services::audit::{self, AuditAction, AuditEntry};
use crate::services::banner_crop::{self, BannerCrop};
use crate::services::cdn;
use crate::services::permissions::bits;
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

/// Default permissions for @everyone role (matches TS DEFAULT_PERMISSIONS).
const DEFAULT_PERMISSIONS: i64 = (1 << 0) | (1 << 1) | (1 << 8) | (1 << 9) | (1 << 12) | (1 << 13);
const CHANNEL_TYPE_SERVER_TEXT: i32 = 0;
const LARGE_SERVER_THRESHOLD: i64 = 250;
const MIN_VOICE_BITRATE: i32 = 64_000;

fn filter_federated_server_ids(
    server_ids: Vec<i64>,
    identity: Option<&FederatedClientIdentity>,
) -> Vec<i64> {
    match identity {
        Some(identity) => server_ids
            .into_iter()
            .filter(|server_id| federated_client_allows_server_id(Some(identity), *server_id))
            .collect(),
        None => server_ids,
    }
}

fn filter_federated_order(order: &Value, identity: Option<&FederatedClientIdentity>) -> Value {
    let Some(identity) = identity else {
        return order.clone();
    };
    let Some(items) = order.as_array() else {
        return json!([]);
    };
    Value::Array(
        items
            .iter()
            .filter(|item| {
                let server_id = item
                    .as_str()
                    .and_then(|value| value.parse::<i64>().ok())
                    .or_else(|| item.as_i64());
                server_id
                    .map(|id| federated_client_allows_server_id(Some(identity), id))
                    .unwrap_or(false)
            })
            .cloned()
            .collect(),
    )
}

#[cfg(test)]
mod federated_scope_tests {
    use super::{filter_federated_order, filter_federated_server_ids};
    use crate::middleware::auth::FederatedClientIdentity;
    use serde_json::json;

    fn identity(server_ids: Vec<i64>) -> FederatedClientIdentity {
        FederatedClientIdentity {
            home_peer_id: "host:home.example.com".to_string(),
            remote_user_id: "remote-user-1".to_string(),
            server_ids,
        }
    }

    #[test]
    fn filters_server_list_and_order_for_federated_client_scope() {
        let scope = identity(vec![20, 40]);

        assert_eq!(
            filter_federated_server_ids(vec![10, 20, 30, 40], Some(&scope)),
            vec![20, 40]
        );
        assert_eq!(
            filter_federated_server_ids(vec![10, 20], None),
            vec![10, 20]
        );
        assert_eq!(
            filter_federated_order(&json!(["10", "20", 40, "oops"]), Some(&scope)),
            json!(["20", 40])
        );
        assert_eq!(
            filter_federated_order(&json!(["10", "20"]), None),
            json!(["10", "20"])
        );
    }
}

fn deserialize_nullable_patch_field<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

fn validate_voice_bitrate(bitrate: i32, max_voice_bitrate: u32) -> AppResult<()> {
    let upper = i32::try_from(max_voice_bitrate).unwrap_or(i32::MAX);
    if upper < MIN_VOICE_BITRATE {
        return Err(AppError::Validation(
            "Voice bitrate changes are not enabled for this account or instance".into(),
        ));
    }
    if !(MIN_VOICE_BITRATE..=upper).contains(&bitrate) {
        return Err(AppError::Validation(format!(
            "Voice bitrate must be {MIN_VOICE_BITRATE}-{upper}"
        )));
    }
    Ok(())
}

async fn validate_configured_text_channel(
    state: &AppState,
    server_id: i64,
    channel_id: i64,
    field: &'static str,
) -> AppResult<i64> {
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, channel_id, field, error = %e, "update_server: PG channel read failed");
            AppError::Internal
        })?
        .ok_or_else(|| {
            AppError::Validation(format!("{field} must reference a text channel in this server"))
        })?;

    if channel.server_id != Some(server_id) || channel.r#type != CHANNEL_TYPE_SERVER_TEXT {
        tracing::warn!(
            server_id,
            channel_id,
            field,
            channel_server_id = ?channel.server_id,
            channel_type = channel.r#type,
            "Rejected configured server channel outside this server or non-text channel"
        );
        return Err(AppError::Validation(format!(
            "{field} must reference a text channel in this server"
        )));
    }

    Ok(channel_id)
}

async fn parse_configured_text_channel_update(
    state: &AppState,
    server_id: i64,
    input: &Option<String>,
    field: &'static str,
) -> AppResult<i64> {
    let Some(raw) = input.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(0);
    };
    let channel_id = parse_id(raw)?;
    validate_configured_text_channel(state, server_id, channel_id, field).await
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateServerRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub icon_url: Option<String>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateServerRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub icon_url: Option<Option<String>>,
    pub voice_bitrate: Option<i32>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub welcome_channel_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub announce_channel_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub welcome_message: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub welcome_screen_description: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub welcome_screen_channels: Option<Option<serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_nullable_patch_field")]
    pub accent_color: Option<Option<String>>,
    pub banner_offset_y: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BannerCropPatchRequest {
    pub banner_crop: Option<BannerCrop>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct DeleteServerRequest {
    #[validate(length(min = 1, max = 100))]
    pub server_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn update_server_request_distinguishes_missing_null_and_value_fields() {
        let missing: UpdateServerRequest = serde_json::from_value(json!({})).unwrap();
        assert!(missing.welcome_channel_id.is_none());
        assert!(missing.icon_url.is_none());

        let cleared: UpdateServerRequest = serde_json::from_value(json!({
            "welcomeChannelId": null,
            "iconUrl": null
        }))
        .unwrap();
        assert!(matches!(cleared.welcome_channel_id, Some(None)));
        assert!(matches!(cleared.icon_url, Some(None)));

        let updated: UpdateServerRequest = serde_json::from_value(json!({
            "welcomeChannelId": "123",
            "iconUrl": "https://cdn.example/icon.png"
        }))
        .unwrap();
        assert_eq!(
            updated
                .welcome_channel_id
                .as_ref()
                .and_then(|v| v.as_deref()),
            Some("123")
        );
        assert_eq!(
            updated.icon_url.as_ref().and_then(|v| v.as_deref()),
            Some("https://cdn.example/icon.png")
        );
    }

    #[test]
    fn voice_bitrate_validation_uses_entitlement_maximum() {
        assert!(super::validate_voice_bitrate(64_000, 96_000).is_ok());
        assert!(super::validate_voice_bitrate(96_000, 96_000).is_ok());
        assert!(super::validate_voice_bitrate(96_001, 96_000).is_err());
        assert!(super::validate_voice_bitrate(63_999, 96_000).is_err());
    }
}

// ─── POST /api/servers ──────────────────────────────────────────────

pub async fn create_server(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Json(body): Json<CreateServerRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!("POST /api/servers user_id={}", user_id.0);
    if let Some(identity) = federated_client {
        tracing::warn!(
            user_id = user_id.0,
            home_peer_id = %identity.home_peer_id,
            remote_user_id = %identity.remote_user_id,
            "Federated client token rejected for server creation"
        );
        return Err(AppError::Forbidden);
    }
    rate_limit::enforce(&state, &rate_limit::SERVER_LIMIT, &user_id.0.to_string()).await?;

    let body = CreateServerRequest {
        name: sanitize_text(&body.name),
        ..body
    };
    if body.name.is_empty() || body.name.len() > 100 {
        return Err(AppError::Validation(
            "Server name must be 1-100 characters".into(),
        ));
    }

    let server_id = state.snowflake.next_id();
    let general_text_channel_id = state.snowflake.next_id();
    let general_voice_channel_id = state.snowflake.next_id();
    let role_id = state.snowflake.next_id();
    let text_cat_id = state.snowflake.next_id();
    let voice_cat_id = state.snowflake.next_id();
    let uid = user_id.0;
    let now_ms = chrono::Utc::now().timestamp_millis();

    crate::services::pg::servers::insert(&state.pg, server_id, &body.name, uid, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_server: PG server write failed");
            AppError::Internal
        })?;

    // Set icon_url via update. New servers no longer create legacy
    // welcome/announcement text channels by default.
    let icon_url = body.icon_url.clone().filter(|s| !s.is_empty());
    crate::services::pg::servers::update(
        &state.pg,
        server_id,
        crate::services::pg::servers::UpdateServer {
            icon_url: icon_url.as_deref(),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "create_server: PG server icon/welcome update failed");
        AppError::Internal
    })?;

    crate::services::pg::servers::add_member(&state.pg, server_id, uid, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_server: PG owner add_member failed");
            AppError::Internal
        })?;

    crate::services::pg::categories::insert(
        &state.pg,
        text_cat_id,
        server_id,
        "Text Channels",
        0,
        None,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "create_server: text category write failed");
        AppError::Internal
    })?;
    crate::services::pg::categories::insert(
        &state.pg,
        voice_cat_id,
        server_id,
        "Voice Channels",
        1,
        None,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "create_server: voice category write failed");
        AppError::Internal
    })?;

    crate::services::pg::channels::insert(
        &state.pg,
        general_text_channel_id,
        server_id,
        0i16,
        Some("general"),
        None,
        0,
        Some(text_cat_id),
        false,
        0,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "create_server: general text channel write failed");
        AppError::Internal
    })?;
    crate::services::pg::channels::insert(
        &state.pg,
        general_voice_channel_id,
        server_id,
        3i16,
        Some("general"),
        None,
        0,
        Some(voice_cat_id),
        false,
        0,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "create_server: general voice channel write failed");
        AppError::Internal
    })?;

    crate::services::pg::roles::insert(
        &state.pg,
        role_id,
        server_id,
        "@everyone",
        0,
        DEFAULT_PERMISSIONS,
        0,
        false,
        false,
        0,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, role_id, error = %e, "create_server: @everyone role write failed");
        AppError::Internal
    })?;

    state.permissions.add_user_server(uid, server_id);
    state
        .permissions
        .add_channel_meta(general_text_channel_id, server_id, 0);
    state
        .permissions
        .add_channel_meta(general_voice_channel_id, server_id, 3);

    tracing::info!(
        "Server created id={} name={} owner={}",
        server_id,
        body.name,
        uid
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": server_id.to_string(),
            "name": body.name,
            "iconUrl": body.icon_url,
            "ownerId": uid.to_string(),
            "defaultChannelId": general_text_channel_id.to_string(),
            "welcomeChannelId": Value::Null,
            "announceChannelId": Value::Null,
            "everyoneRoleId": role_id.to_string(),
            "memberCount": 1,
        })),
    )
        .into_response())
}

// ─── GET /api/servers ───────────────────────────────────────────────

pub(crate) fn server_row_to_json(rec: &ServerRow, member_count: i64) -> Value {
    json!({
        "id": rec.id.to_string(),
        "name": rec.name,
        "iconUrl": cdn::resolve(rec.icon_url.as_deref()),
        "ownerId": rec.owner_id.to_string(),
        "description": Value::Null,
        "voiceBitrate": rec.voice_bitrate,
        "welcomeChannelId": rec.welcome_channel_id.map(|id| id.to_string()),
        "announceChannelId": rec.announce_channel_id.map(|id| id.to_string()),
        "bannerUrl": cdn::resolve(rec.banner_url.as_deref()),
        "bannerCrop": banner_crop::to_json(rec.banner_crop),
        "accentColor": rec.accent_color.clone(),
        "bannerOffsetY": rec.banner_offset_y,
        "memberCount": member_count,
        "large": member_count > LARGE_SERVER_THRESHOLD,
        "createdAt": rec.created_at.to_rfc3339(),
        "updatedAt": rec.created_at.to_rfc3339(),
    })
}

pub async fn list_servers(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/servers user_id={}", user_id.0);

    let server_ids = crate::services::pg::servers::list_server_ids_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "list_servers: PG list_ids failed");
            AppError::Internal
        })?;
    let server_ids = filter_federated_server_ids(server_ids, federated_client.as_ref());
    let rows = crate::services::pg::servers::by_ids(&state.pg, &server_ids)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "list_servers: PG by_ids failed");
            AppError::Internal
        })?;

    let user_record = crate::services::pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "list_servers: PG user read failed");
            AppError::Internal
        })?;

    let count_futs = futures_util::future::join_all(rows.iter().map(|row| {
        let pg = state.pg.clone();
        let server_id = row.id;
        async move {
            (
                server_id,
                crate::services::pg::servers::member_count(&pg, server_id)
                    .await
                    .unwrap_or(0),
            )
        }
    }))
    .await;
    let member_counts: std::collections::HashMap<i64, i64> = count_futs.into_iter().collect();
    let server_list: Vec<Value> = rows
        .iter()
        .map(|row| server_row_to_json(row, member_counts.get(&row.id).copied().unwrap_or(0)))
        .collect();
    let media = crate::handlers::media_diagnostics::summarize_servers_media(&server_list);

    let (server_order, favorite_order) = match user_record {
        Some(u) => {
            // server_order/favorite_order land as JSON arrays of stringified IDs
            (
                filter_federated_order(&u.server_order, federated_client.as_ref()),
                filter_federated_order(&u.favorite_order, federated_client.as_ref()),
            )
        }
        None => (json!([]), json!([])),
    };

    tracing::info!(
        media = ?media,
        "Listed {} servers for user_id={}",
        server_list.len(),
        user_id.0
    );
    Ok(Json(json!({
        "servers": server_list,
        "serverOrder": server_order,
        "favoriteOrder": favorite_order,
    })))
}

// ─── GET /api/servers/:serverId ─────────────────────────────────────

pub async fn get_server(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!("GET /api/servers/{} user_id={}", server_id_str, user_id.0);
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    state
        .require_membership(user_id.0, server_id)
        .await
        .map_err(|_| AppError::NotFound("server"))?;

    let rec = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "get_server: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .unwrap_or(0);
    let response = server_row_to_json(&rec, member_count);
    let media = crate::handlers::media_diagnostics::summarize_server_media(&response);
    tracing::info!(
        server_id,
        user_id = user_id.0,
        media = ?media,
        "servers.get_server emitted media fields"
    );
    Ok(Json(response))
}

// ─── PATCH /api/servers/:serverId/banner/crop ───────────────────────

pub async fn update_server_banner_crop(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
    Json(body): Json<BannerCropPatchRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/servers/{}/banner/crop user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::SERVER_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let crop = body.banner_crop.map(|crop| crop.validate()).transpose()?;
    crate::services::pg::servers::update_banner_crop(&state.pg, server_id, crop)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "update_server_banner_crop: PG write failed");
            AppError::Internal
        })?;

    let record = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "update_server_banner_crop: PG re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .unwrap_or(0);
    let response_json = server_row_to_json(&record, member_count);
    let topic = topics::presence_topic(server_id);
    let json_text = events::server_update_json(&response_json);
    topics::publish_json(&state, &topic, &json_text).await;

    Ok(Json(response_json))
}

// ─── PATCH /api/servers/:serverId ───────────────────────────────────

pub async fn update_server(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
    Json(body): Json<UpdateServerRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!("PATCH /api/servers/{} user_id={}", server_id_str, user_id.0);
    rate_limit::enforce(&state, &rate_limit::SERVER_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_SERVER)
        .await?;

    let body = UpdateServerRequest {
        name: body.name.map(|s| sanitize_text(&s)),
        welcome_message: body
            .welcome_message
            .map(|opt| opt.map(|s| sanitize_text(&s))),
        welcome_screen_description: body
            .welcome_screen_description
            .map(|opt| opt.map(|s| sanitize_text(&s))),
        ..body
    };

    if let Some(ref name) = body.name {
        if name.is_empty() || name.len() > 100 {
            return Err(AppError::Validation(
                "Server name must be 1-100 characters".into(),
            ));
        }
    }
    if let Some(Some(ref url)) = body.icon_url {
        if !url.starts_with("https://") {
            return Err(AppError::Validation("Icon URL must use HTTPS".into()));
        }
    }
    if let Some(bitrate) = body.voice_bitrate {
        let entitlements =
            crate::services::entitlements::current_for_user(&state.pg, &state.config, user_id.0)
                .await;
        validate_voice_bitrate(bitrate, entitlements.max_voice_bitrate)?;
    }
    if let Some(Some(ref hex)) = body.accent_color {
        if hex.len() != 7
            || !hex.starts_with('#')
            || !hex[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(AppError::Validation(
                "Accent color must be #RRGGBB hex".into(),
            ));
        }
    }
    if let Some(offset) = body.banner_offset_y {
        if !(0..=100).contains(&offset) {
            return Err(AppError::Validation("Banner offset must be 0-100".into()));
        }
    }

    let has_changes = body.name.is_some()
        || body.icon_url.is_some()
        || body.voice_bitrate.is_some()
        || body.welcome_channel_id.is_some()
        || body.announce_channel_id.is_some()
        || body.welcome_message.is_some()
        || body.welcome_screen_description.is_some()
        || body.welcome_screen_channels.is_some()
        || body.accent_color.is_some()
        || body.banner_offset_y.is_some();
    if !has_changes {
        return Err(AppError::NoChanges);
    }

    // For nullable text columns we can't clear-to-NULL via COALESCE
    // — pass empty strings the read layer maps back to None.
    let icon_url_arg: Option<String> = body
        .icon_url
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());
    let welcome_msg_arg: Option<String> = body
        .welcome_message
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());
    let welcome_desc_arg: Option<String> = body
        .welcome_screen_description
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());
    let welcome_screen_channels_json: Option<serde_json::Value> = body
        .welcome_screen_channels
        .as_ref()
        .map(|opt| opt.clone().unwrap_or(serde_json::Value::Array(vec![])));
    let accent_arg: Option<String> = body
        .accent_color
        .as_ref()
        .map(|opt| opt.clone().unwrap_or_default());

    let welcome_ch: Option<i64> = match body.welcome_channel_id.as_ref() {
        Some(opt) => Some(
            parse_configured_text_channel_update(&state, server_id, opt, "welcomeChannelId")
                .await?,
        ),
        None => None,
    };
    let announce_ch: Option<i64> = match body.announce_channel_id.as_ref() {
        Some(opt) => Some(
            parse_configured_text_channel_update(&state, server_id, opt, "announceChannelId")
                .await?,
        ),
        None => None,
    };

    crate::services::pg::servers::update(
        &state.pg,
        server_id,
        crate::services::pg::servers::UpdateServer {
            name: body.name.as_deref(),
            icon_url: icon_url_arg.as_deref(),
            voice_bitrate: body.voice_bitrate,
            welcome_channel_id: welcome_ch,
            announce_channel_id: announce_ch,
            welcome_message: welcome_msg_arg.as_deref(),
            welcome_screen_description: welcome_desc_arg.as_deref(),
            welcome_screen_channels: welcome_screen_channels_json.as_ref(),
            accent_color: accent_arg.as_deref(),
            banner_offset_y: body.banner_offset_y,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, error = %e, "update_server: PG write failed");
        AppError::Internal
    })?;

    let record = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "update_server: PG re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .unwrap_or(0);
    let response_json = server_row_to_json(&record, member_count);
    let topic = topics::presence_topic(server_id);
    let json_text = events::server_update_json(&response_json);
    let proto_server = crate::proto::Server {
        id: record.id.to_string(),
        name: record.name.clone(),
        owner_id: record.owner_id.to_string(),
        icon_url: cdn::resolve(record.icon_url.as_deref()),
        description: None,
        voice_bitrate: record.voice_bitrate,
        created_at: record.created_at.to_rfc3339(),
        updated_at: record.created_at.to_rfc3339(),
        welcome_channel_id: record.welcome_channel_id.map(|id| id.to_string()),
        announce_channel_id: record.announce_channel_id.map(|id| id.to_string()),
        welcome_message: record.welcome_message.clone(),
        emoji_version: record.emoji_version,
        large: member_count > LARGE_SERVER_THRESHOLD,
        member_count,
        banner_url: cdn::resolve(record.banner_url.as_deref()),
        accent_color: record.accent_color.clone(),
        banner_offset_y: record.banner_offset_y,
    };
    let proto_msg = events::server_update_proto(proto_server);
    topics::publish(&state, &topic, &json_text, &proto_msg).await;

    tracing::info!("Server updated id={} user_id={}", server_id, user_id.0);
    Ok(Json(response_json))
}

// ─── DELETE /api/servers/:serverId ──────────────────────────────────

pub async fn delete_server(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
    Json(body): Json<DeleteServerRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "DELETE /api/servers/{} user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::SERVER_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    let record = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "delete_server: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    if record.owner_id != user_id.0 {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "SERVER_OWNER_ONLY",
            message: "Only the server owner can delete the server".into(),
        });
    }
    if body.server_name != record.name {
        return Err(AppError::Validation("Server name does not match".into()));
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::services::pg::servers::soft_delete(&state.pg, server_id, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "delete_server: PG soft delete failed");
            AppError::Internal
        })?;

    let topic = topics::presence_topic(server_id);
    let json_text = events::server_delete_json(&server_id_str);
    let proto_msg = events::server_delete_proto(server_id_str.clone());
    topics::publish(&state, &topic, &json_text, &proto_msg).await;

    let channel_ids: Vec<i64> =
        crate::services::pg::channels::list_for_server(&state.pg, server_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| c.id)
            .collect();
    topics::cleanup_topic(&state, &topic).await;
    for ch_id in channel_ids {
        for ch_topic in topics::all_channel_topics(ch_id) {
            topics::cleanup_topic(&state, &ch_topic).await;
        }
    }

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::DeleteServer,
            target_type: "server",
            target_id: server_id,
            server_id: Some(server_id),
            metadata: None,
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        "Server soft-deleted id={} by owner={}",
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── POST /api/servers/:serverId/restore ────────────────────────────

pub async fn restore_server(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "POST /api/servers/{}/restore user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::SERVER_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    let record = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "restore_server: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    if record.owner_id != user_id.0 {
        return Err(AppError::NotFound("server"));
    }
    if record.deleted_at.is_none() {
        return Ok(Json(json!({ "success": true })));
    }

    sqlx::query("UPDATE servers SET deleted_at_ms = NULL WHERE id = $1")
        .bind(server_id)
        .execute(&state.pg)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "restore_server: PG write failed");
            AppError::Internal
        })?;

    tracing::info!("Server restored id={} by owner={}", server_id, user_id.0);
    Ok(Json(json!({ "success": true })))
}

// ─── GET /api/servers/:serverId/members ─────────────────────────────

const MEMBER_FETCH_LIMIT: i64 = 1000;

#[derive(Deserialize)]
pub struct MemberQueryParams {
    pub limit: Option<i64>,
    pub after: Option<String>,
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

async fn filter_member_ids_for_channel(
    state: &AppState,
    requester_id: i64,
    server_id: i64,
    channel_id: i64,
    member_ids: Vec<i64>,
) -> AppResult<Vec<i64>> {
    let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(channel_id, error = %e, "list_members: PG channel read failed");
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
        Ok(()) => {}
        Err(AppError::Internal) => return Err(AppError::Internal),
        Err(_) => return Err(AppError::NotFound("channel")),
    }

    let mut visible = Vec::with_capacity(member_ids.len());
    for member_id in member_ids {
        match state
            .permissions
            .check_channel_permission(member_id, channel_id, server_id, bits::VIEW_CHANNEL)
            .await
        {
            Ok(()) => visible.push(member_id),
            Err(AppError::Internal) => return Err(AppError::Internal),
            Err(_) => {}
        }
    }
    Ok(visible)
}

fn federation_identity_json(
    identity: Option<&crate::federation::storage::RemotePrincipalIdentity>,
) -> Value {
    match identity {
        Some(identity) => json!({
            "homePeerId": identity.home_peer_id,
            "remoteUserId": identity.remote_user_id,
            "remoteUsername": identity.remote_username,
        }),
        None => Value::Null,
    }
}

pub async fn list_members(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
    Query(params): Query<MemberQueryParams>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/members user_id={}",
        server_id_str,
        user_id.0
    );
    crate::middleware::rate_limit::enforce(
        &state,
        &crate::middleware::rate_limit::API_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let server_id = parse_id(&server_id_str)?;
    let result = list_members_json(
        &state,
        user_id.0,
        federated_client.as_ref(),
        server_id,
        params,
    )
    .await?;

    tracing::info!(
        "Listed {} members for server_id={}",
        result.len(),
        server_id
    );
    Ok(Json(json!(result)))
}

pub(crate) async fn list_members_json(
    state: &AppState,
    requester_id: i64,
    federated_client: Option<&FederatedClientIdentity>,
    server_id: i64,
    params: MemberQueryParams,
) -> AppResult<Vec<Value>> {
    require_federated_client_server_scope(federated_client, server_id)?;

    state
        .require_membership(requester_id, server_id)
        .await
        .map_err(|_| AppError::NotFound("server"))?;

    let limit = params
        .limit
        .unwrap_or(MEMBER_FETCH_LIMIT)
        .min(MEMBER_FETCH_LIMIT)
        .max(1);
    let after = params.after.as_ref().map(|s| parse_id(s)).transpose()?;

    let mut all_ids =
        crate::services::pg::servers::list_member_ids_for_server(&state.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "list_members: PG index read failed");
                AppError::Internal
            })?;
    all_ids.sort_unstable();
    all_ids.dedup();

    if let Some(channel_id_str) = params.channel_id.as_deref() {
        let channel_id = parse_id(channel_id_str)?;
        all_ids =
            filter_member_ids_for_channel(state, requester_id, server_id, channel_id, all_ids)
                .await?;
    }

    let page: Vec<i64> = all_ids
        .into_iter()
        .filter(|id| after.map_or(true, |cursor| *id > cursor))
        .take(limit as usize)
        .collect();

    let users = crate::services::pg::users::by_ids(&state.pg, &page)
        .await
        .unwrap_or_default();
    let user_lookup: std::collections::HashMap<i64, _> =
        users.into_iter().map(|u| (u.id, u)).collect();
    let presence_map: std::collections::HashMap<i64, String> =
        crate::services::presence::batch_get(&state.redis, &page)
            .await
            .into_iter()
            .collect();
    let federation_identities =
        crate::federation::storage::remote_principals_for_local_user_ids(&state.pg, &page)
            .await
            .map_err(|e| {
                tracing::error!(
                    server_id,
                    error = %e,
                    "list_members: federation remote principal lookup failed"
                );
                AppError::Internal
            })?;

    let mut result: Vec<Value> = Vec::with_capacity(page.len());
    for uid in &page {
        let Some(user) = user_lookup.get(uid) else {
            continue;
        };
        if user.deleted_at.is_some() {
            continue;
        }
        let role_ids: Vec<String> =
            crate::services::pg::roles::list_role_ids(&state.pg, *uid, server_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.to_string())
                .collect();
        let official_subscription_active =
            crate::services::entitlements::official_subscription_active_from_db(
                user.subscribed,
                user.subscription_expires_at,
            );
        let member_list_banner_visible = crate::services::entitlements::member_list_banner_visible(
            &state.config,
            official_subscription_active,
        );
        result.push(json!({
            "userId": user.id.to_string(),
            "username": user.username,
            "displayName": user.display_name,
            "avatarUrl": cdn::resolve(user.avatar_url.as_deref()),
            "bannerUrl": cdn::resolve(user.banner_url.as_deref()),
            "bannerBaseColor": user.banner_base_color.as_deref().filter(|s| !s.trim().is_empty()),
            "bannerCrop": banner_crop::to_json(user.banner_crop),
            "memberListBannerUrl": if member_list_banner_visible { cdn::resolve(user.member_list_banner_url.as_deref()) } else { None },
            "memberListBannerCrop": if member_list_banner_visible { banner_crop::to_json(user.member_list_banner_crop) } else { serde_json::Value::Null },
            "bio": user.bio.as_deref().filter(|s| !s.trim().is_empty()),
            "customStatusText": user.custom_status_text.as_deref().filter(|s| !s.trim().is_empty()),
            "customStatusEmoji": user.custom_status_emoji.as_deref().filter(|s| !s.trim().is_empty()),
            "nickname": Value::Null,
            "status": presence_map.get(uid).map(|s| s.as_str()).unwrap_or("offline"),
            "joinedAt": user.created_at.to_rfc3339(),
            "roleIds": role_ids,
            "federation": federation_identity_json(federation_identities.get(uid)),
        }));
    }

    let media = crate::handlers::media_diagnostics::summarize_member_media(&result, "member");
    tracing::info!(
        server_id,
        requester_id,
        member_count = result.len(),
        channel_scoped = params.channel_id.is_some(),
        media = ?media,
        "servers.list_members emitted media fields"
    );

    Ok(result)
}

// ─── DELETE /api/servers/:serverId/leave ─────────────────────────────

pub async fn leave_server(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/leave user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::SERVER_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "leave_server: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("server"))?;

    if server.owner_id == user_id.0 {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "SERVER_OWNER_CANNOT_LEAVE",
            message: "The server owner cannot leave. Transfer ownership or delete the server."
                .into(),
        });
    }

    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, user_id.0)
        .await
        .unwrap_or(false);
    if !is_member {
        return Err(AppError::NotMember);
    }

    if let Err(e) =
        crate::services::pg::servers::remove_member(&state.pg, server_id, user_id.0).await
    {
        tracing::error!(user_id = user_id.0, server_id, error = %e, "leave_server: PG remove_member failed");
        return Err(AppError::Internal);
    }
    let _ = crate::services::pg::roles::replace_user_roles_in_server(
        &state.pg,
        user_id.0,
        server_id,
        &[],
    )
    .await;

    state.permissions.remove_user_server(user_id.0, server_id);

    let topic = topics::presence_topic(server_id);
    let uid_str = user_id.0.to_string();
    let json_text = events::member_remove_json(&server_id_str, &uid_str);
    let proto_msg = events::member_remove_proto(server_id_str.clone(), uid_str.clone());
    crate::services::bot_events::enqueue(
        &state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_LEAVE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(user_id.0),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str.clone(),
                "userId": uid_str.clone(),
                "reason": "leave",
            }),
        },
    );
    topics::publish(&state, &topic, &json_text, &proto_msg).await;

    tracing::info!(
        "User left server server_id={} user_id={}",
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

// ─── PATCH /api/servers/:serverId/members/@me/welcome ────────────────

pub async fn dismiss_welcome(
    State(state): State<AppState>,
    user_id: UserId,
    OptionalFederatedClient(federated_client): OptionalFederatedClient,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/servers/{}/members/@me/welcome user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;
    require_federated_client_server_scope(federated_client.as_ref(), server_id)?;

    state
        .require_membership(user_id.0, server_id)
        .await
        .map_err(|_| AppError::NotFound("server"))?;

    use fred::interfaces::KeysInterface;
    let key = format!("welcomed:{}:{}", user_id.0, server_id);
    let _: Result<(), _> = state
        .redis
        .set::<(), _, _>(&key, "1", None, None, false)
        .await;

    tracing::info!(
        "Welcome dismissed server_id={} user_id={}",
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}
