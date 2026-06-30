use std::collections::HashSet;

use crate::error::{AppError, AppResult};
use crate::middleware::auth::BotIdentity;
use crate::services::permissions::bits;
use crate::services::pg::{channels as pg_channels, feeds::FeedRow, roles as pg_roles};
use crate::state::AppState;

struct BotServerPerms {
    everyone_role_id: i64,
    role_ids: HashSet<i64>,
    permissions: i64,
}

async fn server_permissions(state: &AppState, bot: &BotIdentity) -> AppResult<BotServerPerms> {
    let roles = pg_roles::list_for_server(&state.pg, bot.server_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id = bot.bot_id, server_id = bot.server_id, error = %e, "bot_permissions: PG roles read failed");
            AppError::Internal
        })?;

    let assigned_role_ids = match crate::services::pg::bots::list_role_ids(
        &state.pg,
        bot.bot_id,
        bot.server_id,
    )
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!(bot_id = bot.bot_id, server_id = bot.server_id, error = %e, "bot_permissions: bot role read failed; using identity role snapshot");
            bot.role_ids.clone()
        }
    };

    let mut role_ids: HashSet<i64> = assigned_role_ids.into_iter().collect();
    let mut permissions = 0i64;
    let mut everyone_role_id = 0i64;

    for role in roles {
        if role.color_only {
            role_ids.remove(&role.id);
            continue;
        }
        if role.position == 0 {
            everyone_role_id = role.id;
            role_ids.insert(role.id);
            permissions |= role.permissions;
            continue;
        }
        if role_ids.contains(&role.id) {
            permissions |= role.permissions;
        }
    }

    Ok(BotServerPerms {
        everyone_role_id,
        role_ids,
        permissions,
    })
}

pub async fn has_server_permission(
    state: &AppState,
    bot: &BotIdentity,
    permission: i64,
) -> AppResult<bool> {
    let perms = server_permissions(state, bot).await?;
    Ok(bits::has(perms.permissions, permission))
}

pub async fn has_channel_permission(
    state: &AppState,
    bot: &BotIdentity,
    channel_id: i64,
    permission: i64,
) -> AppResult<bool> {
    let channel = pg_channels::by_id(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id = bot.bot_id, channel_id, error = %e, "bot_permissions: PG channel read failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("channel"))?;
    if channel.server_id != Some(bot.server_id) {
        return Ok(false);
    }

    let mut perms = server_permissions(state, bot).await?;
    if bits::has(perms.permissions, bits::ADMINISTRATOR) {
        return Ok(true);
    }

    let overrides = pg_channels::list_overrides(&state.pg, channel_id)
        .await
        .map_err(|e| {
            tracing::error!(bot_id = bot.bot_id, channel_id, error = %e, "bot_permissions: PG override read failed");
            AppError::Internal
        })?;

    for override_row in overrides
        .iter()
        .filter(|o| o.role_id == perms.everyone_role_id)
    {
        perms.permissions &= !override_row.deny_bits;
        perms.permissions |= override_row.allow_bits;
    }

    let mut role_allow = 0i64;
    let mut role_deny = 0i64;
    for override_row in overrides
        .iter()
        .filter(|o| perms.role_ids.contains(&o.role_id))
    {
        if override_row.role_id == perms.everyone_role_id {
            continue;
        }
        role_deny |= override_row.deny_bits;
        role_allow |= override_row.allow_bits;
    }
    perms.permissions &= !role_deny;
    perms.permissions |= role_allow;

    Ok(bits::has(perms.permissions, permission))
}

pub async fn can_publish_feed(
    state: &AppState,
    bot: &BotIdentity,
    feed: &FeedRow,
) -> AppResult<bool> {
    if feed.server_id != bot.server_id {
        return Ok(false);
    }
    if !can_view_feed(state, bot, feed).await? {
        return Ok(false);
    }
    if has_server_permission(state, bot, bits::MANAGE_SERVER).await? {
        return Ok(true);
    }
    if feed.publish_role_ids.is_empty() {
        return Ok(false);
    }
    let perms = server_permissions(state, bot).await?;
    Ok(feed
        .publish_role_ids
        .iter()
        .any(|role_id| perms.role_ids.contains(role_id)))
}

pub async fn can_view_feed(state: &AppState, bot: &BotIdentity, feed: &FeedRow) -> AppResult<bool> {
    if feed.server_id != bot.server_id {
        return Ok(false);
    }
    if has_server_permission(state, bot, bits::ADMINISTRATOR).await? {
        return Ok(true);
    }
    if feed.visible_role_ids.is_empty() {
        return Ok(true);
    }
    let perms = server_permissions(state, bot).await?;
    Ok(feed
        .visible_role_ids
        .iter()
        .any(|role_id| perms.role_ids.contains(role_id)))
}
