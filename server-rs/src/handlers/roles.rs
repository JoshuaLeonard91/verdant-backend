use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use validator::Validate;

use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::audit::{self, AuditAction, AuditEntry};
use crate::services::channel_visibility;
use crate::services::permissions::{CacheInvalidationEvent, bits};
use crate::services::pg::roles::RoleRow as PgRoleRow;
use crate::services::sanitize::sanitize_text;
use crate::state::AppState;
use crate::ws::{events, topics};

use super::parse_id;

const MAX_ROLES_PER_SERVER: i64 = 250;

/// Resolve the actor's highest role position on `server_id`.
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

fn create_role_position(
    existing: &[PgRoleRow],
    actor_highest_position: i32,
    is_owner: bool,
) -> AppResult<i32> {
    let next_position = existing
        .iter()
        .filter(|r| !r.color_only)
        .map(|r| r.position)
        .max()
        .map(|p| p + 1)
        .unwrap_or(0);
    if is_owner {
        return Ok(next_position);
    }

    if actor_highest_position <= 1 {
        return Err(role_hierarchy_error(
            "You cannot create a role at or above your own highest role",
        ));
    }

    Ok(next_position.min(actor_highest_position - 1))
}

fn next_color_priority(existing: &[PgRoleRow]) -> i32 {
    existing
        .iter()
        .map(|r| r.color_priority)
        .max()
        .map(|p| p + 1)
        .unwrap_or(1)
}

fn is_everyone_role(role: &PgRoleRow) -> bool {
    role.position == 0 && role.name == "@everyone" && !role.color_only
}

fn validate_name_color_role(role: &PgRoleRow, server_id: i64) -> AppResult<()> {
    if role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }
    if !role.color_only {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "NAME_COLOR_ROLE_REQUIRED",
            message: "Name color selection must use a Name Color role".into(),
        });
    }
    if role.color == 0 {
        return Err(AppError::Validation(
            "Name color selection requires a role color".into(),
        ));
    }
    Ok(())
}

fn validate_role_type_unchanged(
    role: &PgRoleRow,
    requested_color_only: Option<bool>,
) -> AppResult<()> {
    if requested_color_only.is_some_and(|requested| requested != role.color_only) {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "ROLE_TYPE_IMMUTABLE",
            message: "Create a new Access Role or Name Color instead of changing a role type"
                .into(),
        });
    }
    Ok(())
}

async fn user_role_ids_in_server(state: &AppState, user_id: i64, server_id: i64) -> Vec<String> {
    crate::services::pg::roles::list_role_ids(&state.pg, user_id, server_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|id| id.to_string())
        .collect()
}

async fn broadcast_role_event(
    state: &AppState,
    server_id: i64,
    server_id_str: &str,
    row: &PgRoleRow,
    create: bool,
) {
    let role_json = serialize_role(row);
    let proto_role = role_to_proto(row);
    let (json_text, proto_msg) = if create {
        (
            events::role_create_json(server_id_str, &role_json),
            events::role_create_proto(server_id_str.to_string(), proto_role),
        )
    } else {
        (
            events::role_update_json(server_id_str, &role_json),
            events::role_update_proto(server_id_str.to_string(), proto_role),
        )
    };
    topics::publish_to_presence(state, server_id, &json_text, &proto_msg).await;
}

async fn enqueue_federation_role_event(
    state: &AppState,
    server_id: i64,
    event: crate::federation::producer::FederationLocalEvent,
    log_label: &'static str,
) {
    match crate::federation::producer::enqueue_local_event_for_scope(
        state,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        &event,
        crate::federation::producer::FederationProducerSource::Local,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    {
        Ok(report) if report.selected_peers > 0 => tracing::info!(
            server_id,
            selected_peers = report.selected_peers,
            inserted = report.inserted,
            duplicates = report.duplicates,
            "{log_label}"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(server_id, error = %error, "{log_label} failed"),
    }
}

async fn snapshot_online_channel_visibility(
    state: &AppState,
    server_id: i64,
) -> AppResult<(
    Vec<crate::repo::channels::ChannelRow>,
    HashMap<i64, HashSet<i64>>,
)> {
    let channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "roles: PG channel visibility list failed");
            AppError::Internal
        })?;
    let online_members = state.permissions.collect_online_server_members(server_id);
    let visible_by_user = channel_visibility::snapshot_visible_channels_by_user(
        state,
        server_id,
        &online_members,
        &channels,
    )
    .await?;
    Ok((channels, visible_by_user))
}

async fn snapshot_user_channel_visibility(
    state: &AppState,
    server_id: i64,
    user_id: i64,
) -> AppResult<(Vec<crate::repo::channels::ChannelRow>, HashSet<i64>)> {
    let channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, user_id, error = %e, "roles: PG user channel visibility list failed");
            AppError::Internal
        })?;
    let visible =
        channel_visibility::visible_channel_ids_for_user(state, user_id, server_id, &channels)
            .await?;
    Ok((channels, visible))
}

fn parse_hex_color(s: &str) -> AppResult<i32> {
    let hex = s.trim_start_matches('#');
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "Color must be a valid 6-digit hex code (e.g. #ff00aa)".into(),
        ));
    }
    Ok(i32::from_str_radix(hex, 16).unwrap_or(0))
}

fn role_created_at(r: &PgRoleRow) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.created_at_ms)
        .unwrap_or_else(chrono::Utc::now)
}

pub(crate) fn serialize_role(r: &PgRoleRow) -> Value {
    let color = if r.color != 0 {
        json!(format!("#{:06x}", r.color))
    } else {
        json!(null)
    };
    let created_at = role_created_at(r).to_rfc3339();
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
        "createdAt": created_at,
        "updatedAt": created_at,
    })
}

fn role_to_proto(r: &PgRoleRow) -> crate::proto::Role {
    let color_str = if r.color != 0 {
        Some(format!("#{:06x}", r.color))
    } else {
        None
    };
    let created_at = role_created_at(r).to_rfc3339();
    crate::proto::Role {
        id: r.id.to_string(),
        server_id: r.server_id.to_string(),
        name: r.name.clone(),
        color: color_str,
        permissions: r.permissions.to_string(),
        position: r.position,
        color_only: r.color_only,
        show_as_section: r.show_as_section,
        color_priority: r.color_priority,
        created_at: created_at.clone(),
        updated_at: created_at,
    }
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoleRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub color: Option<String>,
    pub permissions: Option<String>,
    #[serde(default)]
    pub color_only: bool,
    #[serde(default)]
    pub show_as_section: bool,
    pub color_priority: Option<i32>,
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRoleRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    pub color: Option<Option<String>>,
    pub permissions: Option<String>,
    pub position: Option<i32>,
    pub color_only: Option<bool>,
    pub show_as_section: Option<bool>,
    pub color_priority: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleOrderItem {
    pub id: String,
    pub position: Option<i32>,
    pub color_priority: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReorderRolesRequest {
    pub items: Vec<RoleOrderItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetNameColorRequest {
    pub role_id: Option<String>,
}

// ─── POST /api/servers/:serverId/roles ──────────────────────────────

pub async fn create_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<CreateRoleRequest>,
) -> AppResult<Response> {
    body.validate()?;
    tracing::info!(
        "POST /api/servers/{}/roles user_id={} name={}",
        server_id_str,
        user_id.0,
        body.name
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let body = CreateRoleRequest {
        name: sanitize_text(&body.name),
        ..body
    };

    if body.name.is_empty() || body.name.len() > 100 {
        return Err(AppError::Validation(
            "Role name must be 1-100 characters".into(),
        ));
    }
    if let Some(priority) = body.color_priority {
        if !(0..=10_000).contains(&priority) {
            return Err(AppError::Validation(
                "Color priority must be between 0 and 10000".into(),
            ));
        }
    }

    let existing = crate::services::pg::roles::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "create_role: PG list roles failed");
            AppError::Internal
        })?;
    if existing.len() as i64 >= MAX_ROLES_PER_SERVER {
        return Err(AppError::WithCode {
            status: StatusCode::BAD_REQUEST,
            code: "ROLE_LIMIT_REACHED",
            message: format!("Server has reached the maximum of {MAX_ROLES_PER_SERVER} roles"),
        });
    }

    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    let actor_pos = if is_owner {
        i32::MAX
    } else {
        actor_highest_position(&state, user_id.0, server_id).await
    };
    let color_only = body.color_only;
    let position = if color_only {
        existing
            .iter()
            .map(|r| r.position)
            .max()
            .map(|p| p + 1)
            .unwrap_or(1)
    } else {
        create_role_position(&existing, actor_pos, is_owner)?
    };
    let color_int = match body.color.as_deref() {
        Some(c) => parse_hex_color(c)?,
        None => 0,
    };
    let mut perms: i64 = if color_only {
        0
    } else {
        body.permissions
            .as_deref()
            .map(|p| p.parse().unwrap_or(0))
            .unwrap_or(0)
    };
    if !color_only {
        let actor_perms = state
            .permissions
            .resolve_server_permissions(user_id.0, server_id)
            .await?;
        perms &= actor_perms;
    }
    let show_as_section = if color_only {
        false
    } else {
        body.show_as_section
    };
    let color_priority = body.color_priority.unwrap_or_else(|| {
        if color_int == 0 {
            0
        } else {
            next_color_priority(&existing)
        }
    });

    let id = state.snowflake.next_id();
    let now_ms = chrono::Utc::now().timestamp_millis();

    crate::services::pg::roles::insert(
        &state.pg,
        id,
        server_id,
        &body.name,
        color_int,
        perms,
        position,
        color_only,
        show_as_section,
        color_priority,
        now_ms,
    )
    .await
    .map_err(|e| {
        tracing::error!(role_id = id, error = %e, "create_role: PG insert failed");
        AppError::Internal
    })?;

    let row = PgRoleRow {
        id,
        server_id,
        name: body.name.clone(),
        color: color_int,
        permissions: perms,
        position,
        color_only,
        show_as_section,
        color_priority,
        created_at_ms: now_ms,
    };

    state.permissions.invalidate_server_roles(server_id).await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::ServerRolesChanged { server_id },
            &state.node_id,
        )
        .await;

    broadcast_role_event(&state, server_id, &server_id_str, &row, true).await;
    enqueue_federation_role_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::RoleCreate {
            server_id,
            actor_user_id: user_id.0,
            role_id: id,
            name: row.name.clone(),
            color: if row.color == 0 {
                None
            } else {
                Some(format!("#{:06x}", row.color))
            },
            permissions: Some(row.permissions),
            color_only: row.color_only,
            show_as_section: row.show_as_section,
            color_priority: Some(row.color_priority),
        },
        "Federation role create producer completed",
    )
    .await;

    let role_json = serialize_role(&row);
    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::CreateRole,
            target_type: "role",
            target_id: id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "name": &row.name })),
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        "Role created id={} server={} by={}",
        id,
        server_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(role_json)).into_response())
}

// ─── GET /api/servers/:serverId/roles ───────────────────────────────

pub async fn list_roles(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "GET /api/servers/{}/roles user_id={}",
        server_id_str,
        user_id.0
    );
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;

    let mut rows = crate::services::pg::roles::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "list_roles: PG read failed");
            AppError::Internal
        })?;
    rows.sort_by_key(|r| r.position);

    let result: Vec<Value> = rows.iter().map(serialize_role).collect();
    Ok(Json(json!(result)))
}

// ─── PATCH /api/servers/:serverId/roles/reorder ─────────────────────

pub async fn reorder_roles(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<ReorderRolesRequest>,
) -> AppResult<Json<Value>> {
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let roles = crate::services::pg::roles::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "reorder_roles: PG list roles failed");
            AppError::Internal
        })?;
    let roles_by_id: HashMap<i64, PgRoleRow> = roles.iter().map(|r| (r.id, r.clone())).collect();
    let mut seen = HashSet::new();
    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    let mut position_items: Vec<(i64, i32)> = Vec::new();
    let mut color_items: Vec<(i64, i32)> = Vec::new();
    let mut federation_items = Vec::new();

    for item in body.items {
        let role_id = parse_id(&item.id)?;
        if !seen.insert(role_id) {
            return Err(AppError::Validation(
                "Duplicate role in reorder payload".into(),
            ));
        }
        let role = roles_by_id
            .get(&role_id)
            .ok_or(AppError::NotFound("role"))?;

        if let Some(position) = item.position {
            if position < 0 {
                return Err(AppError::Validation(
                    "Role position must be non-negative".into(),
                ));
            }
            if is_everyone_role(role) {
                return Err(AppError::WithCode {
                    status: StatusCode::FORBIDDEN,
                    code: "ROLE_EVERYONE_PROTECTED",
                    message: "Cannot change the @everyone role's position".into(),
                });
            }
            if !is_owner && !role.color_only && position >= actor_pos {
                return Err(AppError::WithCode {
                    status: StatusCode::FORBIDDEN,
                    code: "ROLE_HIERARCHY",
                    message: "Cannot move a role equal to or above your own".into(),
                });
            }
            position_items.push((role_id, position));
        }

        if let Some(priority) = item.color_priority {
            if !(0..=10_000).contains(&priority) {
                return Err(AppError::Validation(
                    "Color priority must be between 0 and 10000".into(),
                ));
            }
            color_items.push((role_id, priority));
        }
        federation_items.push(crate::federation::producer::FederationRoleReorderItem {
            role_id,
            position: item.position,
            color_priority: item.color_priority,
        });
    }

    crate::services::pg::roles::reorder_display(&state.pg, &position_items, &color_items)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "reorder_roles: PG write failed");
            AppError::Internal
        })?;

    state.permissions.invalidate_server_roles(server_id).await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::ServerRolesChanged { server_id },
            &state.node_id,
        )
        .await;

    let updated_rows = crate::services::pg::roles::list_for_server(&state.pg, server_id)
        .await
        .map_err(|e| {
            tracing::error!(server_id, error = %e, "reorder_roles: PG re-read failed");
            AppError::Internal
        })?;
    for row in &updated_rows {
        broadcast_role_event(&state, server_id, &server_id_str, row, false).await;
    }
    enqueue_federation_role_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::RoleReorder {
            server_id,
            actor_user_id: user_id.0,
            items: federation_items,
        },
        "Federation role reorder producer completed",
    )
    .await;

    Ok(Json(json!(
        updated_rows.iter().map(serialize_role).collect::<Vec<_>>()
    )))
}

// ─── PATCH /api/servers/:serverId/roles/:roleId ─────────────────────

pub async fn update_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, role_id_str)): Path<(String, String)>,
    Json(body): Json<UpdateRoleRequest>,
) -> AppResult<Json<Value>> {
    body.validate()?;
    tracing::info!(
        "PATCH /api/servers/{}/roles/{} user_id={}",
        server_id_str,
        role_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let role_id = parse_id(&role_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let record = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "update_role: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if record.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }

    let body = UpdateRoleRequest {
        name: body.name.map(|s| sanitize_text(&s)),
        ..body
    };

    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    if !is_owner && !record.color_only && record.position >= actor_pos {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "ROLE_HIERARCHY",
            message: "You cannot edit a role with equal or higher position than your own".into(),
        });
    }

    if is_everyone_role(&record) {
        if let Some(ref name) = body.name {
            if name != "@everyone" {
                return Err(AppError::WithCode {
                    status: StatusCode::BAD_REQUEST,
                    code: "ROLE_EVERYONE_PROTECTED",
                    message: "Cannot rename the @everyone role".into(),
                });
            }
        }
        if body.position.is_some() {
            return Err(AppError::WithCode {
                status: StatusCode::FORBIDDEN,
                code: "ROLE_EVERYONE_PROTECTED",
                message: "Cannot change the @everyone role's position".into(),
            });
        }
    }
    validate_role_type_unchanged(&record, body.color_only)?;

    let has_changes = body.name.is_some()
        || body.color.is_some()
        || body.permissions.is_some()
        || body.position.is_some()
        || body.color_only.is_some()
        || body.show_as_section.is_some()
        || body.color_priority.is_some();
    if !has_changes {
        return Err(AppError::NoChanges);
    }
    if let Some(priority) = body.color_priority {
        if !(0..=10_000).contains(&priority) {
            return Err(AppError::Validation(
                "Color priority must be between 0 and 10000".into(),
            ));
        }
    }
    if let Some(position) = body.position {
        if position < 0 {
            return Err(AppError::Validation(
                "Role position must be non-negative".into(),
            ));
        }
    }

    let new_color: Option<i32> = match body.color.as_ref() {
        Some(opt) => Some(match opt.as_deref() {
            Some(c) => parse_hex_color(c)?,
            None => 0,
        }),
        None => None,
    };

    let final_color_only = body.color_only.unwrap_or(record.color_only);
    let new_permissions: Option<i64> = if final_color_only {
        Some(0)
    } else {
        match body.permissions.as_deref() {
            Some(p) => {
                let mut perms: i64 = p.parse().unwrap_or(0);
                let actor_perms = state
                    .permissions
                    .resolve_server_permissions(user_id.0, server_id)
                    .await?;
                perms &= actor_perms;
                Some(perms)
            }
            None => None,
        }
    };

    let existing_for_position = if record.color_only && !final_color_only && body.position.is_none()
    {
        Some(
            crate::services::pg::roles::list_for_server(&state.pg, server_id)
                .await
                .map_err(|e| {
                    tracing::error!(server_id, error = %e, "update_role: PG list roles failed");
                    AppError::Internal
                })?,
        )
    } else {
        None
    };

    let new_position = if let Some(pos) = body.position {
        if !is_owner && !final_color_only && pos >= actor_pos {
            return Err(AppError::WithCode {
                status: StatusCode::FORBIDDEN,
                code: "ROLE_HIERARCHY",
                message: "Cannot set role position equal to or above your own".into(),
            });
        }
        Some(pos)
    } else if record.color_only && !final_color_only {
        Some(create_role_position(
            existing_for_position.as_deref().unwrap_or(&[]),
            actor_pos,
            is_owner,
        )?)
    } else {
        None
    };

    let new_show_as_section = if final_color_only {
        Some(false)
    } else {
        body.show_as_section
    };

    let new_color_priority = body.color_priority;

    let visibility_snapshot = if body.permissions.is_some() || body.color_only.is_some() {
        Some(snapshot_online_channel_visibility(&state, server_id).await?)
    } else {
        None
    };

    crate::services::pg::roles::update(
        &state.pg,
        role_id,
        body.name.as_deref(),
        new_color,
        new_permissions,
        new_position,
        body.color_only,
        new_show_as_section,
        new_color_priority,
    )
    .await
    .map_err(|e| {
        tracing::error!(role_id, error = %e, "update_role: PG write failed");
        AppError::Internal
    })?;

    let updated = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "update_role: PG re-read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;

    state.permissions.invalidate_server_roles(server_id).await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::ServerRolesChanged { server_id },
            &state.node_id,
        )
        .await;

    broadcast_role_event(&state, server_id, &server_id_str, &updated, false).await;
    if let Some((channels, visible_by_user)) = visibility_snapshot {
        channel_visibility::reconcile_visible_channels_by_user(
            &state,
            server_id,
            &channels,
            &visible_by_user,
        )
        .await?;
    }
    enqueue_federation_role_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::RoleUpdate {
            server_id,
            actor_user_id: user_id.0,
            role_id,
            name: body.name.clone(),
            color: body.color.clone(),
            permissions: new_permissions,
            position: new_position,
            show_as_section: new_show_as_section,
            color_priority: new_color_priority,
        },
        "Federation role update producer completed",
    )
    .await;

    let role_json = serialize_role(&updated);
    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::UpdateRole,
            target_type: "role",
            target_id: role_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str })),
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        "Role updated id={} server={} by={}",
        role_id,
        server_id,
        user_id.0
    );
    Ok(Json(role_json))
}

// ─── DELETE /api/servers/:serverId/roles/:roleId ────────────────────

pub async fn delete_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, role_id_str)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/roles/{} user_id={}",
        server_id_str,
        role_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let role_id = parse_id(&role_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let role = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "delete_role: PG read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }
    if is_everyone_role(&role) {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "ROLE_EVERYONE_PROTECTED",
            message: "Cannot delete the @everyone role".into(),
        });
    }

    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    if !is_owner && !role.color_only && role.position >= actor_pos {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "ROLE_HIERARCHY",
            message: "You cannot delete a role with equal or higher position than your own".into(),
        });
    }

    let visibility_snapshot = snapshot_online_channel_visibility(&state, server_id).await?;

    // PG cascades member_roles via FK. Single delete clears the role
    // and every (user, server, role) assignment in one shot.
    crate::services::pg::roles::delete(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "delete_role: PG delete failed");
            AppError::Internal
        })?;

    state.permissions.invalidate_server_roles(server_id).await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::ServerRolesChanged { server_id },
            &state.node_id,
        )
        .await;

    let json_text = events::role_delete_json(&server_id_str, &role_id_str);
    let proto_msg = events::role_delete_proto(server_id_str.clone(), role_id_str.clone());
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;
    channel_visibility::reconcile_visible_channels_by_user(
        &state,
        server_id,
        &visibility_snapshot.0,
        &visibility_snapshot.1,
    )
    .await?;
    enqueue_federation_role_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::RoleDelete {
            server_id,
            actor_user_id: user_id.0,
            role_id,
        },
        "Federation role delete producer completed",
    )
    .await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::DeleteRole,
            target_type: "role",
            target_id: role_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "name": &role.name })),
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        "Role deleted id={} server={} by={}",
        role_id,
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("roles.rs");

    fn source_after_signature(signature_kind: &str, name: &str) -> &'static str {
        let signature = format!("{signature_kind} {name}");
        let after_signature = SOURCE
            .split(&signature)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} source section should exist"));
        after_signature
            .split("// ───")
            .next()
            .expect("source section should be present")
    }

    fn handler_source(name: &str) -> &'static str {
        source_after_signature("pub async fn", name)
    }

    fn private_async_source(name: &str) -> &'static str {
        source_after_signature("async fn", name)
    }

    fn role(position: i32) -> PgRoleRow {
        PgRoleRow {
            id: position as i64,
            server_id: 1,
            name: format!("role-{position}"),
            color: 0,
            permissions: 0,
            position,
            color_only: false,
            show_as_section: false,
            color_priority: position,
            created_at_ms: 0,
        }
    }

    fn color_role(position: i32) -> PgRoleRow {
        PgRoleRow {
            color_only: true,
            permissions: bits::ADMINISTRATOR,
            name: format!("color-{position}"),
            ..role(position)
        }
    }

    #[test]
    fn owner_role_creation_stays_above_existing_roles() {
        let roles = vec![role(0), role(3), role(7)];
        assert_eq!(create_role_position(&roles, i32::MAX, true).unwrap(), 8);
    }

    #[test]
    fn non_owner_role_creation_stays_below_actor_highest_role() {
        let roles = vec![role(0), role(4), role(9)];
        assert_eq!(create_role_position(&roles, 6, false).unwrap(), 5);
    }

    #[test]
    fn non_owner_role_creation_uses_next_position_when_already_safe() {
        let roles = vec![role(0), role(1), role(2)];
        assert_eq!(create_role_position(&roles, 6, false).unwrap(), 3);
    }

    #[test]
    fn non_owner_without_manageable_position_is_rejected() {
        let roles = vec![role(0)];
        assert!(matches!(
            create_role_position(&roles, 1, false),
            Err(AppError::WithCode {
                code: "ROLE_HIERARCHY",
                ..
            })
        ));
    }

    #[test]
    fn color_only_roles_do_not_affect_permission_role_positioning() {
        let roles = vec![role(0), role(3), color_role(99)];
        assert_eq!(create_role_position(&roles, i32::MAX, true).unwrap(), 4);
        assert_eq!(create_role_position(&roles, 6, false).unwrap(), 4);
    }

    #[test]
    fn name_color_selection_accepts_only_same_server_color_roles() {
        let selected = PgRoleRow {
            id: 10,
            server_id: 1,
            color: 0x22c55e,
            ..color_role(10)
        };
        assert!(validate_name_color_role(&selected, 1).is_ok());

        let permission_role = PgRoleRow {
            id: 11,
            server_id: 1,
            color: 0x22c55e,
            color_only: false,
            ..role(11)
        };
        assert!(matches!(
            validate_name_color_role(&permission_role, 1),
            Err(AppError::WithCode {
                code: "NAME_COLOR_ROLE_REQUIRED",
                ..
            })
        ));

        let color_without_value = PgRoleRow {
            id: 12,
            server_id: 1,
            color: 0,
            ..color_role(12)
        };
        assert!(matches!(
            validate_name_color_role(&color_without_value, 1),
            Err(AppError::Validation(_))
        ));

        let other_server_color = PgRoleRow {
            id: 13,
            server_id: 2,
            color: 0x22c55e,
            ..color_role(13)
        };
        assert!(matches!(
            validate_name_color_role(&other_server_color, 1),
            Err(AppError::NotFound("role"))
        ));
    }

    #[test]
    fn role_type_cannot_change_after_creation() {
        let access = PgRoleRow {
            id: 20,
            server_id: 1,
            color_only: false,
            ..role(20)
        };
        assert!(validate_role_type_unchanged(&access, None).is_ok());
        assert!(validate_role_type_unchanged(&access, Some(false)).is_ok());
        assert!(matches!(
            validate_role_type_unchanged(&access, Some(true)),
            Err(AppError::WithCode {
                code: "ROLE_TYPE_IMMUTABLE",
                ..
            })
        ));

        let name_color = PgRoleRow {
            id: 21,
            server_id: 1,
            color: 0x22c55e,
            ..color_role(21)
        };
        assert!(validate_role_type_unchanged(&name_color, None).is_ok());
        assert!(validate_role_type_unchanged(&name_color, Some(true)).is_ok());
        assert!(matches!(
            validate_role_type_unchanged(&name_color, Some(false)),
            Err(AppError::WithCode {
                code: "ROLE_TYPE_IMMUTABLE",
                ..
            })
        ));
    }

    #[test]
    fn role_federation_helper_uses_server_scope() {
        let helper = private_async_source("enqueue_federation_role_event");

        assert!(helper.contains("FederationRouteScope::Server"));
        assert!(helper.contains("enqueue_local_event_for_scope"));
    }

    #[test]
    fn create_role_enqueues_federation_role_create() {
        let handler = handler_source("create_role");

        assert!(handler.contains("FederationLocalEvent::RoleCreate"));
        assert!(handler.contains("enqueue_federation_role_event"));
    }

    #[test]
    fn reorder_roles_enqueues_federation_role_reorder() {
        let handler = handler_source("reorder_roles");

        assert!(handler.contains("FederationLocalEvent::RoleReorder"));
        assert!(handler.contains("FederationRoleReorderItem"));
        assert!(handler.contains("enqueue_federation_role_event"));
    }

    #[test]
    fn update_role_enqueues_federation_role_update() {
        let handler = handler_source("update_role");

        assert!(handler.contains("FederationLocalEvent::RoleUpdate"));
        assert!(handler.contains("enqueue_federation_role_event"));
    }

    #[test]
    fn delete_role_enqueues_federation_role_delete() {
        let handler = handler_source("delete_role");

        assert!(handler.contains("FederationLocalEvent::RoleDelete"));
        assert!(handler.contains("enqueue_federation_role_event"));
    }

    #[test]
    fn assign_role_enqueues_federation_member_role_assign() {
        let handler = handler_source("assign_role");

        assert!(handler.contains("FederationLocalEvent::MemberRoleAssign"));
        assert!(handler.contains("enqueue_federation_role_event"));
    }

    #[test]
    fn remove_role_enqueues_federation_member_role_remove() {
        let handler = handler_source("remove_role");

        assert!(handler.contains("FederationLocalEvent::MemberRoleRemove"));
        assert!(handler.contains("enqueue_federation_role_event"));
    }
}

// ─── PUT /api/servers/:serverId/members/:userId/roles/:roleId ───────

pub async fn set_own_name_color(
    State(state): State<AppState>,
    user_id: UserId,
    Path(server_id_str): Path<String>,
    Json(body): Json<SetNameColorRequest>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "PATCH /api/servers/{}/members/@me/name-color user_id={}",
        server_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;

    state.require_membership(user_id.0, server_id).await?;

    let selected_role_id = match body.role_id.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(parse_id(raw)?),
        Some(_) => {
            return Err(AppError::Validation(
                "Name color role id must not be empty".into(),
            ));
        }
        None => None,
    };

    if let Some(role_id) = selected_role_id {
        let role = crate::services::pg::roles::by_id(&state.pg, role_id)
            .await
            .map_err(|e| {
                tracing::error!(role_id, error = %e, "set_own_name_color: PG role read failed");
                AppError::Internal
            })?
            .ok_or(AppError::NotFound("role"))?;
        validate_name_color_role(&role, server_id)?;
    }

    crate::services::pg::roles::set_user_name_color(
        &state.pg,
        user_id.0,
        server_id,
        selected_role_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(server_id, user_id = user_id.0, error = %e, "set_own_name_color: PG write failed");
        AppError::Internal
    })?;

    state
        .permissions
        .invalidate_user_roles(user_id.0, server_id)
        .await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::UserRolesChanged {
                user_id: user_id.0,
                server_id,
            },
            &state.node_id,
        )
        .await;

    let role_ids = user_role_ids_in_server(&state, user_id.0, server_id).await;
    let user_id_str = user_id.0.to_string();
    let json_text = events::member_role_update_json(&server_id_str, &user_id_str, &role_ids);
    let proto_msg =
        events::member_role_update_proto(server_id_str.clone(), user_id_str, role_ids.clone());
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::SetNameColor,
            target_type: "user",
            target_id: user_id.0,
            server_id: Some(server_id),
            metadata: Some(json!({
                "serverId": server_id_str,
                "roleId": selected_role_id.map(|id| id.to_string()),
            })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok(Json(json!({ "success": true, "roleIds": role_ids })))
}

pub async fn assign_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, target_user_str, role_id_str)): Path<(String, String, String)>,
) -> AppResult<Response> {
    tracing::info!(
        "PUT /api/servers/{}/members/{}/roles/{} user_id={}",
        server_id_str,
        target_user_str,
        role_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let target_user_id = parse_id(&target_user_str)?;
    let role_id = parse_id(&role_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, target_user_id)
        .await
        .unwrap_or(false);
    if !is_member {
        return Err(AppError::NotFound("member"));
    }

    let target_role = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "assign_role: PG role read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if target_role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }

    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    if !is_owner && !target_role.color_only && target_role.position >= actor_pos {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "ROLE_HIERARCHY",
            message: "You cannot assign a role with equal or higher position than your own".into(),
        });
    }

    let visibility_snapshot = if target_role.color_only {
        None
    } else {
        Some(snapshot_user_channel_visibility(&state, server_id, target_user_id).await?)
    };

    if target_role.color_only {
        crate::services::pg::roles::set_user_name_color(
            &state.pg,
            target_user_id,
            server_id,
            Some(role_id),
        )
        .await
        .map_err(|e| {
            tracing::error!(target_user_id, server_id, role_id, error = %e, "assign_role: PG name color assign failed");
            AppError::Internal
        })?;
    } else {
        crate::services::pg::roles::assign(&state.pg, target_user_id, server_id, role_id)
            .await
            .map_err(|e| {
                tracing::error!(target_user_id, server_id, role_id, error = %e, "assign_role: PG assign failed");
                AppError::Internal
            })?;
    }

    state
        .permissions
        .invalidate_user_roles(target_user_id, server_id)
        .await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::UserRolesChanged {
                user_id: target_user_id,
                server_id,
            },
            &state.node_id,
        )
        .await;

    let role_ids = user_role_ids_in_server(&state, target_user_id, server_id).await;

    let json_text = events::member_role_update_json(&server_id_str, &target_user_str, &role_ids);
    let proto_msg = events::member_role_update_proto(
        server_id_str.clone(),
        target_user_str.clone(),
        role_ids.clone(),
    );
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;
    if let Some((channels, before_visible)) = visibility_snapshot {
        let mut before_by_user = HashMap::new();
        before_by_user.insert(target_user_id, before_visible);
        channel_visibility::reconcile_visible_channels_by_user(
            &state,
            server_id,
            &channels,
            &before_by_user,
        )
        .await?;
    }
    enqueue_federation_role_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::MemberRoleAssign {
            server_id,
            actor_user_id: user_id.0,
            target_user_id,
            role_id,
        },
        "Federation member role assign producer completed",
    )
    .await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: if target_role.color_only {
                AuditAction::SetNameColor
            } else {
                AuditAction::AssignRole
            },
            target_type: "user",
            target_id: target_user_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "roleId": role_id_str })),
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        "Role assigned role={} to user={} server={} by={}",
        role_id,
        target_user_id,
        server_id,
        user_id.0
    );
    Ok((StatusCode::CREATED, Json(json!({ "success": true }))).into_response())
}

// ─── DELETE /api/servers/:serverId/members/:userId/roles/:roleId ────

pub async fn remove_role(
    State(state): State<AppState>,
    user_id: UserId,
    Path((server_id_str, target_user_str, role_id_str)): Path<(String, String, String)>,
) -> AppResult<Json<Value>> {
    tracing::info!(
        "DELETE /api/servers/{}/members/{}/roles/{} user_id={}",
        server_id_str,
        target_user_str,
        role_id_str,
        user_id.0
    );
    rate_limit::enforce(&state, &rate_limit::ROLE_LIMIT, &user_id.0.to_string()).await?;
    let server_id = parse_id(&server_id_str)?;
    let target_user_id = parse_id(&target_user_str)?;
    let role_id = parse_id(&role_id_str)?;

    state
        .require_permission(user_id.0, server_id, bits::MANAGE_ROLES)
        .await?;

    let target_role = crate::services::pg::roles::by_id(&state.pg, role_id)
        .await
        .map_err(|e| {
            tracing::error!(role_id, error = %e, "remove_role: PG role read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("role"))?;
    if target_role.server_id != server_id {
        return Err(AppError::NotFound("role"));
    }

    let actor_pos = actor_highest_position(&state, user_id.0, server_id).await;
    let is_owner = server_owner_id(&state, server_id).await == Some(user_id.0);
    if !is_owner && !target_role.color_only && target_role.position >= actor_pos {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "ROLE_HIERARCHY",
            message: "You cannot remove a role with equal or higher position than your own".into(),
        });
    }

    let visibility_snapshot =
        snapshot_user_channel_visibility(&state, server_id, target_user_id).await?;

    crate::services::pg::roles::unassign(&state.pg, target_user_id, server_id, role_id)
        .await
        .map_err(|e| {
            tracing::error!(target_user_id, server_id, role_id, error = %e, "remove_role: PG unassign failed");
            AppError::Internal
        })?;

    state
        .permissions
        .invalidate_user_roles(target_user_id, server_id)
        .await;
    state
        .permissions
        .publish_invalidation(
            &state.redis,
            CacheInvalidationEvent::UserRolesChanged {
                user_id: target_user_id,
                server_id,
            },
            &state.node_id,
        )
        .await;

    let role_ids = user_role_ids_in_server(&state, target_user_id, server_id).await;

    let json_text = events::member_role_update_json(&server_id_str, &target_user_str, &role_ids);
    let proto_msg = events::member_role_update_proto(
        server_id_str.clone(),
        target_user_str.clone(),
        role_ids.clone(),
    );
    topics::publish_to_presence(&state, server_id, &json_text, &proto_msg).await;
    let (channels, before_visible) = visibility_snapshot;
    let mut before_by_user = HashMap::new();
    before_by_user.insert(target_user_id, before_visible);
    channel_visibility::reconcile_visible_channels_by_user(
        &state,
        server_id,
        &channels,
        &before_by_user,
    )
    .await?;
    enqueue_federation_role_event(
        &state,
        server_id,
        crate::federation::producer::FederationLocalEvent::MemberRoleRemove {
            server_id,
            actor_user_id: user_id.0,
            target_user_id,
            role_id,
        },
        "Federation member role remove producer completed",
    )
    .await;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::RemoveRole,
            target_type: "user",
            target_id: target_user_id,
            server_id: Some(server_id),
            metadata: Some(json!({ "serverId": server_id_str, "roleId": role_id_str })),
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        "Role removed role={} from user={} server={} by={}",
        role_id,
        target_user_id,
        server_id,
        user_id.0
    );
    Ok(Json(json!({ "success": true })))
}
