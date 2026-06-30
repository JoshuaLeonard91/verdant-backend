use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::state::AppState;

use super::ownership::runtime_propagation_allowed;
use super::protocol::{FederationEventKind, FederationProtocolError, ParsedFederationEnvelope};
use super::storage::{self, EventInsertResult, InsertOutboundFederationEvent};

#[derive(Debug, Clone, PartialEq)]
pub struct ProducedFederationEnvelope {
    pub event_id: String,
    pub kind: FederationEventKind,
    pub destination_peer_id: String,
    pub payload_hash: String,
    pub body_json: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FederationProducerEnqueueReport {
    pub selected_peers: usize,
    pub inserted: usize,
    pub duplicates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationProducerPeer {
    pub peer_id: String,
    pub routes: Vec<FederationPeerRoute>,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationPeerRoute {
    Server { server_id: i64 },
    Channel { channel_id: i64 },
    Dm { channel_id: i64 },
    Principal { user_id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationRouteScope {
    Server { server_id: i64 },
    Channel { channel_id: i64 },
    Dm { channel_id: i64 },
    Principal { user_id: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationProducerSource {
    Local,
    InboundFederation {
        source_peer_id: String,
        remote_event_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationUnsupportedSurface {
    AttachmentMedia,
    Voice,
    BotExecution,
    Billing,
    ServerAdministration,
    EmojiUpload,
    OfficialRelay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationRoleReorderItem {
    pub role_id: i64,
    pub position: Option<i32>,
    pub color_priority: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationLayoutItem {
    pub id: i64,
    pub item_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationCategoryLayout {
    pub category_id: i64,
    pub channel_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FederationLocalEvent {
    PrincipalUpsert {
        user_id: i64,
        username: Option<String>,
        display_name: Option<String>,
        avatar_url: Option<String>,
    },
    MembershipJoin {
        server_id: i64,
        user_id: i64,
        invite_code: Option<String>,
        invite_code_hash: Option<String>,
    },
    MembershipLeave {
        server_id: i64,
        user_id: i64,
        reason: Option<String>,
    },
    MembershipRemove {
        server_id: i64,
        moderator_user_id: i64,
        target_user_id: i64,
        reason: Option<String>,
    },
    MembershipBan {
        server_id: i64,
        moderator_user_id: i64,
        target_user_id: i64,
        reason: Option<String>,
    },
    MembershipUnban {
        server_id: i64,
        moderator_user_id: i64,
        target_user_id: i64,
    },
    RoleCreate {
        server_id: i64,
        actor_user_id: i64,
        role_id: i64,
        name: String,
        color: Option<String>,
        permissions: Option<i64>,
        color_only: bool,
        show_as_section: bool,
        color_priority: Option<i32>,
    },
    RoleUpdate {
        server_id: i64,
        actor_user_id: i64,
        role_id: i64,
        name: Option<String>,
        color: Option<Option<String>>,
        permissions: Option<i64>,
        position: Option<i32>,
        show_as_section: Option<bool>,
        color_priority: Option<i32>,
    },
    RoleDelete {
        server_id: i64,
        actor_user_id: i64,
        role_id: i64,
    },
    RoleReorder {
        server_id: i64,
        actor_user_id: i64,
        items: Vec<FederationRoleReorderItem>,
    },
    CategoryCreate {
        server_id: i64,
        actor_user_id: i64,
        category_id: i64,
        name: String,
        emoji: Option<String>,
    },
    CategoryUpdate {
        server_id: i64,
        actor_user_id: i64,
        category_id: i64,
        name: Option<String>,
        position: Option<i32>,
        emoji: Option<Option<String>>,
    },
    CategoryDelete {
        server_id: i64,
        actor_user_id: i64,
        category_id: i64,
    },
    ChannelCreate {
        server_id: i64,
        actor_user_id: i64,
        channel_id: i64,
        name: String,
        topic: Option<String>,
        category_id: Option<i64>,
        read_only: bool,
        slowmode_seconds: i32,
    },
    ChannelUpdate {
        server_id: i64,
        actor_user_id: i64,
        channel_id: i64,
        name: Option<String>,
        topic: Option<Option<String>>,
        position: Option<i32>,
        category_id: Option<Option<i64>>,
        read_only: Option<bool>,
        slowmode_seconds: Option<i32>,
    },
    ChannelDelete {
        server_id: i64,
        actor_user_id: i64,
        channel_id: i64,
    },
    ChannelReorder {
        server_id: i64,
        actor_user_id: i64,
        top_level: Vec<FederationLayoutItem>,
        categories: Vec<FederationCategoryLayout>,
    },
    ChannelOverrideSet {
        server_id: i64,
        actor_user_id: i64,
        channel_id: i64,
        role_id: i64,
        allow: Option<i64>,
        deny: Option<i64>,
    },
    ChannelOverrideDelete {
        server_id: i64,
        actor_user_id: i64,
        channel_id: i64,
        role_id: i64,
    },
    MemberRoleAssign {
        server_id: i64,
        actor_user_id: i64,
        target_user_id: i64,
        role_id: i64,
    },
    MemberRoleRemove {
        server_id: i64,
        actor_user_id: i64,
        target_user_id: i64,
        role_id: i64,
    },
    EmojiRename {
        server_id: i64,
        actor_user_id: i64,
        emoji_id: i64,
        name: String,
    },
    EmojiDelete {
        server_id: i64,
        actor_user_id: i64,
        emoji_id: i64,
    },
    MessageCreate {
        channel_id: i64,
        server_id: Option<i64>,
        message_id: i64,
        author_user_id: i64,
        content: String,
        nonce: Option<String>,
        reply_to_message_id: Option<i64>,
    },
    MessageUpdate {
        channel_id: i64,
        message_id: i64,
        author_user_id: i64,
        content: String,
    },
    MessageDelete {
        channel_id: i64,
        message_id: i64,
        author_user_id: i64,
    },
    MessagePin {
        channel_id: i64,
        message_id: i64,
        actor_user_id: i64,
    },
    MessageUnpin {
        channel_id: i64,
        message_id: i64,
        actor_user_id: i64,
    },
    ReactionAdd {
        channel_id: i64,
        message_id: i64,
        user_id: i64,
        emoji: String,
        emoji_id: Option<i64>,
    },
    ReactionRemove {
        channel_id: i64,
        message_id: i64,
        user_id: i64,
        emoji: String,
        emoji_id: Option<i64>,
    },
    RelationshipRequest {
        user_id: i64,
        local_user_id: i64,
    },
    RelationshipAccept {
        user_id: i64,
        local_user_id: i64,
    },
    RelationshipRemove {
        user_id: i64,
        local_user_id: i64,
    },
    RelationshipBlock {
        user_id: i64,
        local_user_id: i64,
    },
    PresenceUpdate {
        user_id: i64,
        status: String,
    },
    TypingStart {
        channel_id: i64,
        user_id: i64,
    },
    ReadStateUpdate {
        channel_id: i64,
        message_id: i64,
        user_id: i64,
    },
    DmCreate {
        dm_id: i64,
        actor_user_id: i64,
        local_user_id: i64,
    },
    DmGroupCreate {
        dm_id: i64,
        actor_user_id: i64,
        local_user_ids: Vec<i64>,
        name: Option<String>,
    },
    Unsupported {
        surface: FederationUnsupportedSurface,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FederationProducerError {
    #[error("federation producer refused to rebroadcast inbound event")]
    InboundRebroadcast,
    #[error("federation runtime propagation is disabled under the server-owned model")]
    RuntimePropagationDisabled,
    #[error("unsupported federation surface: {0:?}")]
    UnsupportedSurface(FederationUnsupportedSurface),
    #[error("invalid federation producer payload")]
    InvalidPayload,
    #[error("invalid federation producer envelope")]
    InvalidEnvelope,
    #[error("federation producer storage failure")]
    Storage,
}

pub fn select_outbound_peers(
    candidates: &[FederationProducerPeer],
    local_peer_id: &str,
    scope: FederationRouteScope,
    source: FederationProducerSource,
) -> Vec<String> {
    if matches!(source, FederationProducerSource::InboundFederation { .. }) {
        return Vec::new();
    }

    let mut selected = Vec::new();
    for peer in candidates {
        if !peer.active || peer.peer_id == local_peer_id {
            continue;
        }
        if peer
            .routes
            .iter()
            .any(|route| route_matches_scope(*route, scope))
        {
            selected.push(peer.peer_id.clone());
        }
    }
    selected.sort();
    selected.dedup();
    selected
}

pub fn build_outbound_envelope(
    source_peer_id: &str,
    destination_peer_id: &str,
    event: &FederationLocalEvent,
    source: FederationProducerSource,
    sent_at_ms: i64,
) -> Result<ProducedFederationEnvelope, FederationProducerError> {
    if matches!(source, FederationProducerSource::InboundFederation { .. }) {
        return Err(FederationProducerError::InboundRebroadcast);
    }

    let kind = event_kind(event)?;
    if !runtime_propagation_allowed(kind) {
        return Err(FederationProducerError::RuntimePropagationDisabled);
    }

    let (kind, payload, dedupe_key) = event_payload(event)?;
    let dedupe_key = if event_kind_is_ephemeral(kind) {
        format!("{dedupe_key}:{sent_at_ms}")
    } else {
        dedupe_key
    };
    let event_id = stable_event_id(source_peer_id, destination_peer_id, kind, &dedupe_key);
    let payload_hash = payload_hash(&payload)?;
    let body_json = json!({
        "protocolVersion": 1,
        "eventId": event_id,
        "kind": kind.as_str(),
        "sourcePeerId": source_peer_id,
        "destinationPeerId": destination_peer_id,
        "sentAtMs": sent_at_ms,
        "payload": payload
    });

    ParsedFederationEnvelope::from_json(body_json.to_string().as_bytes()).map_err(|err| {
        if matches!(err, FederationProtocolError::InvalidPayload) {
            FederationProducerError::InvalidPayload
        } else {
            FederationProducerError::InvalidEnvelope
        }
    })?;

    Ok(ProducedFederationEnvelope {
        event_id,
        kind,
        destination_peer_id: destination_peer_id.to_string(),
        payload_hash,
        body_json,
    })
}

pub async fn enqueue_local_event_for_scope(
    state: &AppState,
    scope: FederationRouteScope,
    event: &FederationLocalEvent,
    source: FederationProducerSource,
    now_ms: i64,
) -> Result<FederationProducerEnqueueReport, FederationProducerError> {
    let kind = event_kind(event)?;
    if !runtime_propagation_allowed(kind) {
        tracing::debug!(
            event_kind = %kind.as_str(),
            scope = ?scope,
            "Federation producer skipped disabled runtime event"
        );
        return Ok(FederationProducerEnqueueReport::default());
    }

    let candidates = storage::producer_peers_for_scope(&state.pg, scope)
        .await
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                scope = ?scope,
                "Federation producer peer-route lookup failed"
            );
            FederationProducerError::Storage
        })?;
    let selected_peer_ids = select_outbound_peers(
        &candidates,
        &state.config.instance_id,
        scope,
        source.clone(),
    );
    let mut report = FederationProducerEnqueueReport {
        selected_peers: selected_peer_ids.len(),
        ..FederationProducerEnqueueReport::default()
    };

    for destination_peer_id in selected_peer_ids {
        let produced = build_outbound_envelope(
            &state.config.instance_id,
            &destination_peer_id,
            event,
            source.clone(),
            now_ms,
        )?;
        let result = storage::insert_outbound_event(
            &state.pg,
            InsertOutboundFederationEvent {
                id: state.snowflake.next_id(),
                destination_peer_id: &produced.destination_peer_id,
                event_id: &produced.event_id,
                event_kind: produced.kind,
                payload_hash: &produced.payload_hash,
                event_body_json: &produced.body_json,
                now_ms,
            },
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                destination_peer_id = %produced.destination_peer_id,
                event_id = %produced.event_id,
                event_kind = %produced.kind.as_str(),
                "Federation producer outbox insert failed"
            );
            FederationProducerError::Storage
        })?;

        match result {
            EventInsertResult::Inserted => {
                report.inserted += 1;
                tracing::info!(
                    destination_peer_id = %produced.destination_peer_id,
                    event_id = %produced.event_id,
                    event_kind = %produced.kind.as_str(),
                    "Federation outbound event enqueued"
                );
            }
            EventInsertResult::Duplicate => {
                report.duplicates += 1;
                tracing::debug!(
                    destination_peer_id = %produced.destination_peer_id,
                    event_id = %produced.event_id,
                    event_kind = %produced.kind.as_str(),
                    "Federation outbound event already enqueued"
                );
            }
        }
    }

    Ok(report)
}

fn route_matches_scope(route: FederationPeerRoute, scope: FederationRouteScope) -> bool {
    matches!(
        (route, scope),
        (
            FederationPeerRoute::Server { server_id: route_id },
            FederationRouteScope::Server { server_id: scope_id }
        ) if route_id == scope_id
    ) || matches!(
        (route, scope),
        (
            FederationPeerRoute::Channel { channel_id: route_id },
            FederationRouteScope::Channel { channel_id: scope_id }
        ) if route_id == scope_id
    ) || matches!(
        (route, scope),
        (
            FederationPeerRoute::Dm { channel_id: route_id },
            FederationRouteScope::Dm { channel_id: scope_id }
        ) if route_id == scope_id
    ) || matches!(
        (route, scope),
        (
            FederationPeerRoute::Principal { user_id: route_id },
            FederationRouteScope::Principal { user_id: scope_id }
        ) if route_id == scope_id
    )
}

fn event_kind(
    event: &FederationLocalEvent,
) -> Result<FederationEventKind, FederationProducerError> {
    match event {
        FederationLocalEvent::Unsupported { surface } => {
            Err(FederationProducerError::UnsupportedSurface(*surface))
        }
        FederationLocalEvent::PrincipalUpsert { .. } => Ok(FederationEventKind::PrincipalUpsert),
        FederationLocalEvent::MembershipJoin { .. } => Ok(FederationEventKind::MembershipJoin),
        FederationLocalEvent::MembershipLeave { .. } => Ok(FederationEventKind::MembershipLeave),
        FederationLocalEvent::MembershipRemove { .. } => Ok(FederationEventKind::MembershipRemove),
        FederationLocalEvent::MembershipBan { .. } => Ok(FederationEventKind::MembershipBan),
        FederationLocalEvent::MembershipUnban { .. } => Ok(FederationEventKind::MembershipUnban),
        FederationLocalEvent::RoleCreate { .. } => Ok(FederationEventKind::RoleCreate),
        FederationLocalEvent::RoleUpdate { .. } => Ok(FederationEventKind::RoleUpdate),
        FederationLocalEvent::RoleDelete { .. } => Ok(FederationEventKind::RoleDelete),
        FederationLocalEvent::RoleReorder { .. } => Ok(FederationEventKind::RoleReorder),
        FederationLocalEvent::CategoryCreate { .. } => Ok(FederationEventKind::CategoryCreate),
        FederationLocalEvent::CategoryUpdate { .. } => Ok(FederationEventKind::CategoryUpdate),
        FederationLocalEvent::CategoryDelete { .. } => Ok(FederationEventKind::CategoryDelete),
        FederationLocalEvent::ChannelCreate { .. } => Ok(FederationEventKind::ChannelCreate),
        FederationLocalEvent::ChannelUpdate { .. } => Ok(FederationEventKind::ChannelUpdate),
        FederationLocalEvent::ChannelDelete { .. } => Ok(FederationEventKind::ChannelDelete),
        FederationLocalEvent::ChannelReorder { .. } => Ok(FederationEventKind::ChannelReorder),
        FederationLocalEvent::ChannelOverrideSet { .. } => {
            Ok(FederationEventKind::ChannelOverrideSet)
        }
        FederationLocalEvent::ChannelOverrideDelete { .. } => {
            Ok(FederationEventKind::ChannelOverrideDelete)
        }
        FederationLocalEvent::MemberRoleAssign { .. } => Ok(FederationEventKind::MemberRoleAssign),
        FederationLocalEvent::MemberRoleRemove { .. } => Ok(FederationEventKind::MemberRoleRemove),
        FederationLocalEvent::EmojiRename { .. } => Ok(FederationEventKind::EmojiRename),
        FederationLocalEvent::EmojiDelete { .. } => Ok(FederationEventKind::EmojiDelete),
        FederationLocalEvent::MessageCreate { .. } => Ok(FederationEventKind::MessageCreate),
        FederationLocalEvent::MessageUpdate { .. } => Ok(FederationEventKind::MessageUpdate),
        FederationLocalEvent::MessageDelete { .. } => Ok(FederationEventKind::MessageDelete),
        FederationLocalEvent::MessagePin { .. } => Ok(FederationEventKind::MessagePin),
        FederationLocalEvent::MessageUnpin { .. } => Ok(FederationEventKind::MessageUnpin),
        FederationLocalEvent::ReactionAdd { .. } => Ok(FederationEventKind::ReactionAdd),
        FederationLocalEvent::ReactionRemove { .. } => Ok(FederationEventKind::ReactionRemove),
        FederationLocalEvent::RelationshipRequest { .. } => {
            Ok(FederationEventKind::RelationshipRequest)
        }
        FederationLocalEvent::RelationshipAccept { .. } => {
            Ok(FederationEventKind::RelationshipAccept)
        }
        FederationLocalEvent::RelationshipRemove { .. } => {
            Ok(FederationEventKind::RelationshipRemove)
        }
        FederationLocalEvent::RelationshipBlock { .. } => {
            Ok(FederationEventKind::RelationshipBlock)
        }
        FederationLocalEvent::PresenceUpdate { .. } => Ok(FederationEventKind::PresenceUpdate),
        FederationLocalEvent::TypingStart { .. } => Ok(FederationEventKind::TypingStart),
        FederationLocalEvent::ReadStateUpdate { .. } => Ok(FederationEventKind::ReadStateUpdate),
        FederationLocalEvent::DmCreate { .. } => Ok(FederationEventKind::DmCreate),
        FederationLocalEvent::DmGroupCreate { .. } => Ok(FederationEventKind::DmGroupCreate),
    }
}

fn event_payload(
    event: &FederationLocalEvent,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    match event {
        FederationLocalEvent::Unsupported { surface } => {
            Err(FederationProducerError::UnsupportedSurface(*surface))
        }
        FederationLocalEvent::PrincipalUpsert {
            user_id,
            username,
            display_name,
            avatar_url,
        } => Ok((
            FederationEventKind::PrincipalUpsert,
            json!({
                "remoteUserId": user_id.to_string(),
                "username": username,
                "displayName": display_name,
                "avatarUrl": avatar_url
            }),
            format!("principal_upsert:{user_id}"),
        )),
        FederationLocalEvent::MembershipJoin {
            server_id,
            user_id,
            invite_code,
            invite_code_hash,
        } => {
            let invite_code_hash = invite_code_hash
                .clone()
                .or_else(|| {
                    invite_code
                        .as_deref()
                        .map(crate::services::pg::server_invites::code_hash)
                })
                .ok_or(FederationProducerError::InvalidPayload)?;
            Ok((
                FederationEventKind::MembershipJoin,
                json!({
                    "serverId": server_id.to_string(),
                    "remoteUserId": user_id.to_string(),
                    "inviteCodeHash": invite_code_hash
                }),
                format!("membership_join:{server_id}:{user_id}"),
            ))
        }
        FederationLocalEvent::MembershipLeave {
            server_id,
            user_id,
            reason,
        } => Ok((
            FederationEventKind::MembershipLeave,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": user_id.to_string(),
                "reason": reason
            }),
            format!("membership_leave:{server_id}:{user_id}"),
        )),
        FederationLocalEvent::MembershipRemove {
            server_id,
            moderator_user_id,
            target_user_id,
            reason,
        } => membership_moderation_payload(
            FederationEventKind::MembershipRemove,
            "membership_remove",
            *server_id,
            *moderator_user_id,
            *target_user_id,
            reason,
        ),
        FederationLocalEvent::MembershipBan {
            server_id,
            moderator_user_id,
            target_user_id,
            reason,
        } => membership_moderation_payload(
            FederationEventKind::MembershipBan,
            "membership_ban",
            *server_id,
            *moderator_user_id,
            *target_user_id,
            reason,
        ),
        FederationLocalEvent::MembershipUnban {
            server_id,
            moderator_user_id,
            target_user_id,
        } => Ok((
            FederationEventKind::MembershipUnban,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": moderator_user_id.to_string(),
                "targetUserId": target_user_id.to_string()
            }),
            format!("membership_unban:{server_id}:{moderator_user_id}:{target_user_id}"),
        )),
        FederationLocalEvent::RoleCreate {
            server_id,
            actor_user_id,
            role_id,
            name,
            color,
            permissions,
            color_only,
            show_as_section,
            color_priority,
        } => Ok((
            FederationEventKind::RoleCreate,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteRoleId": role_id.to_string(),
                "name": name,
                "color": color,
                "permissions": permissions.map(|value| value.to_string()),
                "colorOnly": color_only,
                "showAsSection": show_as_section,
                "colorPriority": color_priority
            }),
            format!("role_create:{server_id}:{role_id}"),
        )),
        FederationLocalEvent::RoleUpdate {
            server_id,
            actor_user_id,
            role_id,
            name,
            color,
            permissions,
            position,
            show_as_section,
            color_priority,
        } => {
            let mut payload = json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteRoleId": role_id.to_string(),
                "name": name,
                "permissions": permissions.map(|value| value.to_string()),
                "position": position,
                "showAsSection": show_as_section,
                "colorPriority": color_priority
            });
            if let Some(color) = color {
                payload["color"] = color.as_ref().map_or(Value::Null, |value| json!(value));
            }
            Ok((
                FederationEventKind::RoleUpdate,
                payload,
                format!("role_update:{server_id}:{role_id}"),
            ))
        }
        FederationLocalEvent::RoleDelete {
            server_id,
            actor_user_id,
            role_id,
        } => mapped_id_payload(
            FederationEventKind::RoleDelete,
            "role_delete",
            *server_id,
            *actor_user_id,
            "remoteRoleId",
            *role_id,
        ),
        FederationLocalEvent::RoleReorder {
            server_id,
            actor_user_id,
            items,
        } => Ok((
            FederationEventKind::RoleReorder,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "items": items.iter().map(|item| {
                    let mut item_json = serde_json::Map::new();
                    item_json.insert("remoteRoleId".to_string(), json!(item.role_id.to_string()));
                    if let Some(position) = item.position {
                        item_json.insert("position".to_string(), json!(position));
                    }
                    if let Some(color_priority) = item.color_priority {
                        item_json.insert("colorPriority".to_string(), json!(color_priority));
                    }
                    Value::Object(item_json)
                }).collect::<Vec<_>>()
            }),
            format!("role_reorder:{server_id}:{actor_user_id}"),
        )),
        FederationLocalEvent::CategoryCreate {
            server_id,
            actor_user_id,
            category_id,
            name,
            emoji,
        } => Ok((
            FederationEventKind::CategoryCreate,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteCategoryId": category_id.to_string(),
                "name": name,
                "emoji": emoji
            }),
            format!("category_create:{server_id}:{category_id}"),
        )),
        FederationLocalEvent::CategoryUpdate {
            server_id,
            actor_user_id,
            category_id,
            name,
            position,
            emoji,
        } => {
            let mut payload = json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteCategoryId": category_id.to_string(),
                "name": name,
                "position": position
            });
            if let Some(emoji) = emoji {
                payload["emoji"] = emoji.as_ref().map_or(Value::Null, |value| json!(value));
            }
            Ok((
                FederationEventKind::CategoryUpdate,
                payload,
                format!("category_update:{server_id}:{category_id}"),
            ))
        }
        FederationLocalEvent::CategoryDelete {
            server_id,
            actor_user_id,
            category_id,
        } => mapped_id_payload(
            FederationEventKind::CategoryDelete,
            "category_delete",
            *server_id,
            *actor_user_id,
            "remoteCategoryId",
            *category_id,
        ),
        FederationLocalEvent::ChannelCreate {
            server_id,
            actor_user_id,
            channel_id,
            name,
            topic,
            category_id,
            read_only,
            slowmode_seconds,
        } => Ok((
            FederationEventKind::ChannelCreate,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteChannelId": channel_id.to_string(),
                "name": name,
                "topic": topic,
                "type": "text",
                "remoteCategoryId": category_id.map(|value| value.to_string()),
                "readOnly": read_only,
                "slowmodeSeconds": slowmode_seconds
            }),
            format!("channel_create:{server_id}:{channel_id}"),
        )),
        FederationLocalEvent::ChannelUpdate {
            server_id,
            actor_user_id,
            channel_id,
            name,
            topic,
            position,
            category_id,
            read_only,
            slowmode_seconds,
        } => {
            let mut payload = json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteChannelId": channel_id.to_string(),
                "name": name,
                "position": position,
                "readOnly": read_only,
                "slowmodeSeconds": slowmode_seconds
            });
            if let Some(topic) = topic {
                payload["topic"] = topic.as_ref().map_or(Value::Null, |value| json!(value));
            }
            if let Some(category_id) = category_id {
                payload["remoteCategoryId"] = category_id
                    .map(|value| json!(value.to_string()))
                    .unwrap_or(Value::Null);
            }
            Ok((
                FederationEventKind::ChannelUpdate,
                payload,
                format!("channel_update:{server_id}:{channel_id}"),
            ))
        }
        FederationLocalEvent::ChannelDelete {
            server_id,
            actor_user_id,
            channel_id,
        } => mapped_id_payload(
            FederationEventKind::ChannelDelete,
            "channel_delete",
            *server_id,
            *actor_user_id,
            "remoteChannelId",
            *channel_id,
        ),
        FederationLocalEvent::ChannelReorder {
            server_id,
            actor_user_id,
            top_level,
            categories,
        } => Ok((
            FederationEventKind::ChannelReorder,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "topLevel": top_level.iter().map(|item| {
                    json!({
                        "remoteId": item.id.to_string(),
                        "type": item.item_type
                    })
                }).collect::<Vec<_>>(),
                "categories": categories.iter().map(|category| {
                    (
                        category.category_id.to_string(),
                        json!(category.channel_ids.iter().map(i64::to_string).collect::<Vec<_>>())
                    )
                }).collect::<serde_json::Map<String, Value>>()
            }),
            format!("channel_reorder:{server_id}:{actor_user_id}"),
        )),
        FederationLocalEvent::ChannelOverrideSet {
            server_id,
            actor_user_id,
            channel_id,
            role_id,
            allow,
            deny,
        } => Ok((
            FederationEventKind::ChannelOverrideSet,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteChannelId": channel_id.to_string(),
                "roleId": role_id.to_string(),
                "allow": allow.map(|value| value.to_string()),
                "deny": deny.map(|value| value.to_string())
            }),
            format!("channel_override_set:{server_id}:{channel_id}:{role_id}"),
        )),
        FederationLocalEvent::ChannelOverrideDelete {
            server_id,
            actor_user_id,
            channel_id,
            role_id,
        } => Ok((
            FederationEventKind::ChannelOverrideDelete,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "remoteChannelId": channel_id.to_string(),
                "roleId": role_id.to_string()
            }),
            format!("channel_override_delete:{server_id}:{channel_id}:{role_id}"),
        )),
        FederationLocalEvent::MemberRoleAssign {
            server_id,
            actor_user_id,
            target_user_id,
            role_id,
        } => member_role_payload(
            FederationEventKind::MemberRoleAssign,
            "member_role_assign",
            *server_id,
            *actor_user_id,
            *target_user_id,
            *role_id,
        ),
        FederationLocalEvent::MemberRoleRemove {
            server_id,
            actor_user_id,
            target_user_id,
            role_id,
        } => member_role_payload(
            FederationEventKind::MemberRoleRemove,
            "member_role_remove",
            *server_id,
            *actor_user_id,
            *target_user_id,
            *role_id,
        ),
        FederationLocalEvent::EmojiRename {
            server_id,
            actor_user_id,
            emoji_id,
            name,
        } => Ok((
            FederationEventKind::EmojiRename,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "emojiId": emoji_id.to_string(),
                "name": name
            }),
            format!("emoji_rename:{server_id}:{emoji_id}"),
        )),
        FederationLocalEvent::EmojiDelete {
            server_id,
            actor_user_id,
            emoji_id,
        } => Ok((
            FederationEventKind::EmojiDelete,
            json!({
                "serverId": server_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "emojiId": emoji_id.to_string()
            }),
            format!("emoji_delete:{server_id}:{emoji_id}"),
        )),
        FederationLocalEvent::MessageCreate {
            channel_id,
            server_id,
            message_id,
            author_user_id,
            content,
            nonce,
            reply_to_message_id,
        } => Ok((
            FederationEventKind::MessageCreate,
            json!({
                "serverId": server_id.map(|value| value.to_string()),
                "channelId": channel_id.to_string(),
                "remoteMessageId": message_id.to_string(),
                "remoteUserId": author_user_id.to_string(),
                "content": content,
                "nonce": nonce,
                "replyToRemoteMessageId": reply_to_message_id.map(|value| value.to_string())
            }),
            format!("message_create:{channel_id}:{message_id}"),
        )),
        FederationLocalEvent::MessageUpdate {
            channel_id,
            message_id,
            author_user_id,
            content,
        } => message_payload(
            FederationEventKind::MessageUpdate,
            "message_update",
            *channel_id,
            *message_id,
            *author_user_id,
            Some(content),
        ),
        FederationLocalEvent::MessageDelete {
            channel_id,
            message_id,
            author_user_id,
        } => message_payload(
            FederationEventKind::MessageDelete,
            "message_delete",
            *channel_id,
            *message_id,
            *author_user_id,
            None,
        ),
        FederationLocalEvent::MessagePin {
            channel_id,
            message_id,
            actor_user_id,
        } => message_payload(
            FederationEventKind::MessagePin,
            "message_pin",
            *channel_id,
            *message_id,
            *actor_user_id,
            None,
        ),
        FederationLocalEvent::MessageUnpin {
            channel_id,
            message_id,
            actor_user_id,
        } => message_payload(
            FederationEventKind::MessageUnpin,
            "message_unpin",
            *channel_id,
            *message_id,
            *actor_user_id,
            None,
        ),
        FederationLocalEvent::ReactionAdd {
            channel_id,
            message_id,
            user_id,
            emoji,
            emoji_id,
        } => reaction_payload(
            FederationEventKind::ReactionAdd,
            "reaction_add",
            *channel_id,
            *message_id,
            *user_id,
            emoji,
            *emoji_id,
        ),
        FederationLocalEvent::ReactionRemove {
            channel_id,
            message_id,
            user_id,
            emoji,
            emoji_id,
        } => reaction_payload(
            FederationEventKind::ReactionRemove,
            "reaction_remove",
            *channel_id,
            *message_id,
            *user_id,
            emoji,
            *emoji_id,
        ),
        FederationLocalEvent::RelationshipRequest {
            user_id,
            local_user_id,
        } => relationship_payload(
            FederationEventKind::RelationshipRequest,
            "relationship_request",
            *user_id,
            *local_user_id,
        ),
        FederationLocalEvent::RelationshipAccept {
            user_id,
            local_user_id,
        } => relationship_payload(
            FederationEventKind::RelationshipAccept,
            "relationship_accept",
            *user_id,
            *local_user_id,
        ),
        FederationLocalEvent::RelationshipRemove {
            user_id,
            local_user_id,
        } => relationship_payload(
            FederationEventKind::RelationshipRemove,
            "relationship_remove",
            *user_id,
            *local_user_id,
        ),
        FederationLocalEvent::RelationshipBlock {
            user_id,
            local_user_id,
        } => relationship_payload(
            FederationEventKind::RelationshipBlock,
            "relationship_block",
            *user_id,
            *local_user_id,
        ),
        FederationLocalEvent::PresenceUpdate { user_id, status } => Ok((
            FederationEventKind::PresenceUpdate,
            json!({
                "remoteUserId": user_id.to_string(),
                "status": status
            }),
            format!("presence_update:{user_id}:{status}"),
        )),
        FederationLocalEvent::TypingStart {
            channel_id,
            user_id,
        } => Ok((
            FederationEventKind::TypingStart,
            json!({
                "channelId": channel_id.to_string(),
                "remoteUserId": user_id.to_string()
            }),
            format!("typing_start:{channel_id}:{user_id}"),
        )),
        FederationLocalEvent::ReadStateUpdate {
            channel_id,
            message_id,
            user_id,
        } => Ok((
            FederationEventKind::ReadStateUpdate,
            json!({
                "channelId": channel_id.to_string(),
                "remoteMessageId": message_id.to_string(),
                "remoteUserId": user_id.to_string()
            }),
            format!("read_state_update:{channel_id}:{message_id}:{user_id}"),
        )),
        FederationLocalEvent::DmCreate {
            dm_id,
            actor_user_id,
            local_user_id,
        } => Ok((
            FederationEventKind::DmCreate,
            json!({
                "dmId": dm_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "localUserId": local_user_id.to_string()
            }),
            format!("dm_create:{dm_id}:{actor_user_id}:{local_user_id}"),
        )),
        FederationLocalEvent::DmGroupCreate {
            dm_id,
            actor_user_id,
            local_user_ids,
            name,
        } => Ok((
            FederationEventKind::DmGroupCreate,
            json!({
                "dmId": dm_id.to_string(),
                "remoteUserId": actor_user_id.to_string(),
                "localUserIds": local_user_ids.iter().map(i64::to_string).collect::<Vec<_>>(),
                "name": name
            }),
            format!("dm_group_create:{dm_id}:{actor_user_id}"),
        )),
    }
}

fn membership_moderation_payload(
    kind: FederationEventKind,
    dedupe_prefix: &str,
    server_id: i64,
    moderator_user_id: i64,
    target_user_id: i64,
    reason: &Option<String>,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    Ok((
        kind,
        json!({
            "serverId": server_id.to_string(),
            "remoteUserId": moderator_user_id.to_string(),
            "targetUserId": target_user_id.to_string(),
            "reason": reason
        }),
        format!("{dedupe_prefix}:{server_id}:{moderator_user_id}:{target_user_id}"),
    ))
}

fn mapped_id_payload(
    kind: FederationEventKind,
    dedupe_prefix: &str,
    server_id: i64,
    actor_user_id: i64,
    id_key: &str,
    id_value: i64,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    Ok((
        kind,
        json!({
            "serverId": server_id.to_string(),
            "remoteUserId": actor_user_id.to_string(),
            id_key: id_value.to_string()
        }),
        format!("{dedupe_prefix}:{server_id}:{id_value}"),
    ))
}

fn member_role_payload(
    kind: FederationEventKind,
    dedupe_prefix: &str,
    server_id: i64,
    actor_user_id: i64,
    target_user_id: i64,
    role_id: i64,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    Ok((
        kind,
        json!({
            "serverId": server_id.to_string(),
            "remoteUserId": actor_user_id.to_string(),
            "targetUserId": target_user_id.to_string(),
            "roleId": role_id.to_string()
        }),
        format!("{dedupe_prefix}:{server_id}:{target_user_id}:{role_id}"),
    ))
}

fn message_payload(
    kind: FederationEventKind,
    dedupe_prefix: &str,
    channel_id: i64,
    message_id: i64,
    user_id: i64,
    content: Option<&str>,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    let mut payload = json!({
        "channelId": channel_id.to_string(),
        "remoteMessageId": message_id.to_string(),
        "remoteUserId": user_id.to_string()
    });
    if let Some(content) = content {
        payload["content"] = json!(content);
    }
    Ok((
        kind,
        payload,
        format!("{dedupe_prefix}:{channel_id}:{message_id}:{user_id}"),
    ))
}

fn reaction_payload(
    kind: FederationEventKind,
    dedupe_prefix: &str,
    channel_id: i64,
    message_id: i64,
    user_id: i64,
    emoji: &str,
    emoji_id: Option<i64>,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    Ok((
        kind,
        json!({
            "channelId": channel_id.to_string(),
            "remoteMessageId": message_id.to_string(),
            "remoteUserId": user_id.to_string(),
            "emoji": emoji,
            "emojiId": emoji_id.map(|value| value.to_string())
        }),
        format!("{dedupe_prefix}:{channel_id}:{message_id}:{user_id}:{emoji}"),
    ))
}

fn relationship_payload(
    kind: FederationEventKind,
    dedupe_prefix: &str,
    user_id: i64,
    local_user_id: i64,
) -> Result<(FederationEventKind, Value, String), FederationProducerError> {
    Ok((
        kind,
        json!({
            "remoteUserId": user_id.to_string(),
            "localUserId": local_user_id.to_string()
        }),
        format!("{dedupe_prefix}:{user_id}:{local_user_id}"),
    ))
}

fn stable_event_id(
    source_peer_id: &str,
    destination_peer_id: &str,
    kind: FederationEventKind,
    dedupe_key: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_peer_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(destination_peer_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(dedupe_key.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("fed:{}:{}", kind.as_str(), &digest[..32])
}

fn event_kind_is_ephemeral(kind: FederationEventKind) -> bool {
    matches!(
        kind,
        FederationEventKind::PresenceUpdate | FederationEventKind::TypingStart
    )
}

fn payload_hash(payload: &Value) -> Result<String, FederationProducerError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| FederationProducerError::InvalidPayload)?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_join_envelope_omits_raw_invite_code() {
        let produced = build_outbound_envelope(
            "host:home.example",
            "host:target.example",
            &FederationLocalEvent::MembershipJoin {
                server_id: 42,
                user_id: 7,
                invite_code: Some("InviteABC123".to_string()),
                invite_code_hash: None,
            },
            FederationProducerSource::Local,
            1_700_000_000,
        )
        .expect("membership join envelope should build");

        let payload = produced
            .body_json
            .get("payload")
            .and_then(Value::as_object)
            .expect("payload object should exist");

        assert!(!payload.contains_key("inviteCode"));
        let expected_hash = crate::services::pg::server_invites::code_hash("InviteABC123");
        assert_eq!(
            payload.get("inviteCodeHash").and_then(Value::as_str),
            Some(expected_hash.as_str())
        );
        assert!(!produced.body_json.to_string().contains("InviteABC123"));
    }
}
