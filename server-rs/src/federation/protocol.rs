use serde::Deserialize;
use serde_json::Value;

use super::identity::is_safe_public_profile_url;

const SUPPORTED_PROTOCOL_VERSION: i16 = 1;
const MAX_EVENT_ID_CHARS: usize = 256;
const MAX_PEER_ID_CHARS: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationEventKind {
    InvitePreview,
    PrincipalUpsert,
    MembershipJoin,
    MembershipLeave,
    MembershipRemove,
    MembershipBan,
    MembershipUnban,
    RoleCreate,
    RoleUpdate,
    RoleDelete,
    RoleReorder,
    CategoryCreate,
    CategoryUpdate,
    CategoryDelete,
    ChannelCreate,
    ChannelUpdate,
    ChannelDelete,
    ChannelReorder,
    ChannelOverrideSet,
    ChannelOverrideDelete,
    MemberRoleAssign,
    MemberRoleRemove,
    EmojiRename,
    EmojiDelete,
    MessageCreate,
    MessageUpdate,
    MessageDelete,
    MessagePin,
    MessageUnpin,
    ReactionAdd,
    ReactionRemove,
    RelationshipRequest,
    RelationshipAccept,
    RelationshipRemove,
    RelationshipBlock,
    PresenceUpdate,
    TypingStart,
    ReadStateUpdate,
    DmCreate,
    DmGroupCreate,
}

impl FederationEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvitePreview => "invite_preview",
            Self::PrincipalUpsert => "principal_upsert",
            Self::MembershipJoin => "membership_join",
            Self::MembershipLeave => "membership_leave",
            Self::MembershipRemove => "membership_remove",
            Self::MembershipBan => "membership_ban",
            Self::MembershipUnban => "membership_unban",
            Self::RoleCreate => "role_create",
            Self::RoleUpdate => "role_update",
            Self::RoleDelete => "role_delete",
            Self::RoleReorder => "role_reorder",
            Self::CategoryCreate => "category_create",
            Self::CategoryUpdate => "category_update",
            Self::CategoryDelete => "category_delete",
            Self::ChannelCreate => "channel_create",
            Self::ChannelUpdate => "channel_update",
            Self::ChannelDelete => "channel_delete",
            Self::ChannelReorder => "channel_reorder",
            Self::ChannelOverrideSet => "channel_override_set",
            Self::ChannelOverrideDelete => "channel_override_delete",
            Self::MemberRoleAssign => "member_role_assign",
            Self::MemberRoleRemove => "member_role_remove",
            Self::EmojiRename => "emoji_rename",
            Self::EmojiDelete => "emoji_delete",
            Self::MessageCreate => "message_create",
            Self::MessageUpdate => "message_update",
            Self::MessageDelete => "message_delete",
            Self::MessagePin => "message_pin",
            Self::MessageUnpin => "message_unpin",
            Self::ReactionAdd => "reaction_add",
            Self::ReactionRemove => "reaction_remove",
            Self::RelationshipRequest => "relationship_request",
            Self::RelationshipAccept => "relationship_accept",
            Self::RelationshipRemove => "relationship_remove",
            Self::RelationshipBlock => "relationship_block",
            Self::PresenceUpdate => "presence_update",
            Self::TypingStart => "typing_start",
            Self::ReadStateUpdate => "read_state_update",
            Self::DmCreate => "dm_create",
            Self::DmGroupCreate => "dm_group_create",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FederationProtocolError {
    #[error("malformed federation event envelope")]
    MalformedJson,
    #[error("unsupported federation protocol version")]
    UnsupportedVersion,
    #[error("unknown federation event kind")]
    UnknownEventKind,
    #[error("invalid federation event envelope")]
    InvalidEnvelope,
    #[error("invalid federation event payload")]
    InvalidPayload,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedFederationEnvelope {
    pub protocol_version: i16,
    pub event_id: String,
    pub kind: FederationEventKind,
    pub source_peer_id: String,
    pub destination_peer_id: String,
    pub sent_at_ms: i64,
    pub payload: Value,
}

impl ParsedFederationEnvelope {
    pub fn from_json(bytes: &[u8]) -> Result<Self, FederationProtocolError> {
        let raw: RawFederationEnvelope =
            serde_json::from_slice(bytes).map_err(|_| FederationProtocolError::MalformedJson)?;
        if raw.protocol_version != SUPPORTED_PROTOCOL_VERSION {
            return Err(FederationProtocolError::UnsupportedVersion);
        }
        let kind = parse_event_kind(&raw.kind)?;
        if !valid_event_id(&raw.event_id)
            || !valid_peer_id(&raw.source_peer_id)
            || !valid_peer_id(&raw.destination_peer_id)
            || raw.sent_at_ms <= 0
            || !raw.payload.is_object()
        {
            return Err(FederationProtocolError::InvalidEnvelope);
        }
        validate_payload(kind, &raw.payload)?;

        Ok(Self {
            protocol_version: raw.protocol_version,
            event_id: raw.event_id,
            kind,
            source_peer_id: raw.source_peer_id,
            destination_peer_id: raw.destination_peer_id,
            sent_at_ms: raw.sent_at_ms,
            payload: raw.payload,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawFederationEnvelope {
    protocol_version: i16,
    event_id: String,
    kind: String,
    source_peer_id: String,
    destination_peer_id: String,
    sent_at_ms: i64,
    payload: Value,
}

fn parse_event_kind(value: &str) -> Result<FederationEventKind, FederationProtocolError> {
    match value {
        "invite_preview" => Ok(FederationEventKind::InvitePreview),
        "principal_upsert" => Ok(FederationEventKind::PrincipalUpsert),
        "membership_join" => Ok(FederationEventKind::MembershipJoin),
        "membership_leave" => Ok(FederationEventKind::MembershipLeave),
        "membership_remove" => Ok(FederationEventKind::MembershipRemove),
        "membership_ban" => Ok(FederationEventKind::MembershipBan),
        "membership_unban" => Ok(FederationEventKind::MembershipUnban),
        "role_create" => Ok(FederationEventKind::RoleCreate),
        "role_update" => Ok(FederationEventKind::RoleUpdate),
        "role_delete" => Ok(FederationEventKind::RoleDelete),
        "role_reorder" => Ok(FederationEventKind::RoleReorder),
        "category_create" => Ok(FederationEventKind::CategoryCreate),
        "category_update" => Ok(FederationEventKind::CategoryUpdate),
        "category_delete" => Ok(FederationEventKind::CategoryDelete),
        "channel_create" => Ok(FederationEventKind::ChannelCreate),
        "channel_update" => Ok(FederationEventKind::ChannelUpdate),
        "channel_delete" => Ok(FederationEventKind::ChannelDelete),
        "channel_reorder" => Ok(FederationEventKind::ChannelReorder),
        "channel_override_set" => Ok(FederationEventKind::ChannelOverrideSet),
        "channel_override_delete" => Ok(FederationEventKind::ChannelOverrideDelete),
        "member_role_assign" => Ok(FederationEventKind::MemberRoleAssign),
        "member_role_remove" => Ok(FederationEventKind::MemberRoleRemove),
        "emoji_rename" => Ok(FederationEventKind::EmojiRename),
        "emoji_delete" => Ok(FederationEventKind::EmojiDelete),
        "message_create" => Ok(FederationEventKind::MessageCreate),
        "message_update" => Ok(FederationEventKind::MessageUpdate),
        "message_delete" => Ok(FederationEventKind::MessageDelete),
        "message_pin" => Ok(FederationEventKind::MessagePin),
        "message_unpin" => Ok(FederationEventKind::MessageUnpin),
        "reaction_add" => Ok(FederationEventKind::ReactionAdd),
        "reaction_remove" => Ok(FederationEventKind::ReactionRemove),
        "relationship_request" => Ok(FederationEventKind::RelationshipRequest),
        "relationship_accept" => Ok(FederationEventKind::RelationshipAccept),
        "relationship_remove" => Ok(FederationEventKind::RelationshipRemove),
        "relationship_block" => Ok(FederationEventKind::RelationshipBlock),
        "presence_update" => Ok(FederationEventKind::PresenceUpdate),
        "typing_start" => Ok(FederationEventKind::TypingStart),
        "read_state_update" => Ok(FederationEventKind::ReadStateUpdate),
        "dm_create" => Ok(FederationEventKind::DmCreate),
        "dm_group_create" => Ok(FederationEventKind::DmGroupCreate),
        _ => Err(FederationProtocolError::UnknownEventKind),
    }
}

fn validate_payload(
    kind: FederationEventKind,
    payload: &Value,
) -> Result<(), FederationProtocolError> {
    if !payload_has_only_allowed_fields(kind, payload) {
        return Err(FederationProtocolError::InvalidPayload);
    }

    let valid = match kind {
        FederationEventKind::InvitePreview => true,
        FederationEventKind::PrincipalUpsert => {
            required_payload_id(payload, "remoteUserId")
                && optional_short_string(payload, "username", 120)
                && optional_short_string(payload, "displayName", 120)
                && optional_url_string(payload, "avatarUrl")
        }
        FederationEventKind::MembershipJoin => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && optional_short_string(payload, "inviteCode", 256)
                && optional_short_string(payload, "inviteCodeHash", 256)
        }
        FederationEventKind::MembershipLeave => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && optional_short_string(payload, "reason", 128)
        }
        FederationEventKind::MembershipRemove | FederationEventKind::MembershipBan => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "targetUserId")
                && optional_short_string(payload, "reason", 512)
        }
        FederationEventKind::MembershipUnban => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "targetUserId")
        }
        FederationEventKind::RoleCreate => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteRoleId")
                && required_content(payload, "name", 100)
                && optional_color_string(payload, "color")
                && optional_integer_string(payload, "permissions")
                && optional_bool(payload, "colorOnly")
                && optional_bool(payload, "showAsSection")
                && optional_i32(payload, "colorPriority", 0, 10_000)
        }
        FederationEventKind::RoleUpdate => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteRoleId")
                && optional_short_nonempty_string(payload, "name", 100)
                && optional_color_string(payload, "color")
                && optional_integer_string(payload, "permissions")
                && optional_i32(payload, "position", 0, i32::MAX)
                && optional_bool(payload, "showAsSection")
                && optional_i32(payload, "colorPriority", 0, 10_000)
        }
        FederationEventKind::RoleDelete => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteRoleId")
        }
        FederationEventKind::RoleReorder => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && role_reorder_items(payload)
        }
        FederationEventKind::CategoryCreate => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteCategoryId")
                && required_content(payload, "name", 100)
                && optional_short_string(payload, "emoji", 32)
        }
        FederationEventKind::CategoryUpdate => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteCategoryId")
                && optional_short_nonempty_string(payload, "name", 100)
                && optional_i32(payload, "position", 0, i32::MAX)
                && optional_short_string(payload, "emoji", 32)
        }
        FederationEventKind::CategoryDelete => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteCategoryId")
        }
        FederationEventKind::ChannelCreate => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteChannelId")
                && required_content(payload, "name", 100)
                && optional_short_string(payload, "topic", 1024)
                && payload
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == "text")
                && optional_payload_id(payload, "remoteCategoryId")
                && optional_bool(payload, "readOnly")
                && optional_i32(payload, "slowmodeSeconds", 0, 21_600)
        }
        FederationEventKind::ChannelUpdate => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteChannelId")
                && optional_short_nonempty_string(payload, "name", 100)
                && optional_short_string(payload, "topic", 1024)
                && optional_i32(payload, "position", 0, i32::MAX)
                && optional_payload_id(payload, "remoteCategoryId")
                && optional_bool(payload, "readOnly")
                && optional_i32(payload, "slowmodeSeconds", 0, 21_600)
        }
        FederationEventKind::ChannelDelete => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteChannelId")
        }
        FederationEventKind::ChannelReorder => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && channel_reorder_items(payload)
        }
        FederationEventKind::ChannelOverrideSet => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteChannelId")
                && required_payload_id(payload, "roleId")
                && optional_integer_string(payload, "allow")
                && optional_integer_string(payload, "deny")
        }
        FederationEventKind::ChannelOverrideDelete => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "remoteChannelId")
                && required_payload_id(payload, "roleId")
        }
        FederationEventKind::MemberRoleAssign | FederationEventKind::MemberRoleRemove => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "targetUserId")
                && required_payload_id(payload, "roleId")
        }
        FederationEventKind::EmojiRename => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "emojiId")
                && required_content(payload, "name", 32)
        }
        FederationEventKind::EmojiDelete => {
            required_payload_id(payload, "serverId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "emojiId")
        }
        FederationEventKind::MessageCreate => {
            optional_payload_id(payload, "serverId")
                && required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteMessageId")
                && required_payload_id(payload, "remoteUserId")
                && required_content(payload, "content", 4000)
                && optional_short_string(payload, "nonce", 128)
                && optional_payload_id(payload, "replyToRemoteMessageId")
        }
        FederationEventKind::MessageUpdate => {
            required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteMessageId")
                && required_payload_id(payload, "remoteUserId")
                && required_content(payload, "content", 4000)
        }
        FederationEventKind::MessageDelete => {
            required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteMessageId")
                && required_payload_id(payload, "remoteUserId")
        }
        FederationEventKind::MessagePin | FederationEventKind::MessageUnpin => {
            required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteMessageId")
                && required_payload_id(payload, "remoteUserId")
        }
        FederationEventKind::ReactionAdd | FederationEventKind::ReactionRemove => {
            required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteMessageId")
                && required_payload_id(payload, "remoteUserId")
                && required_content(payload, "emoji", 64)
                && optional_payload_id(payload, "emojiId")
        }
        FederationEventKind::RelationshipRequest
        | FederationEventKind::RelationshipAccept
        | FederationEventKind::RelationshipRemove
        | FederationEventKind::RelationshipBlock => {
            required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "localUserId")
        }
        FederationEventKind::PresenceUpdate => {
            required_payload_id(payload, "remoteUserId")
                && payload
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| matches!(status, "online" | "idle" | "dnd" | "offline"))
        }
        FederationEventKind::TypingStart => {
            required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteUserId")
        }
        FederationEventKind::ReadStateUpdate => {
            required_payload_id(payload, "channelId")
                && required_payload_id(payload, "remoteMessageId")
                && required_payload_id(payload, "remoteUserId")
        }
        FederationEventKind::DmCreate => {
            required_payload_id(payload, "dmId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id(payload, "localUserId")
        }
        FederationEventKind::DmGroupCreate => {
            required_payload_id(payload, "dmId")
                && required_payload_id(payload, "remoteUserId")
                && required_payload_id_array(payload, "localUserIds", 2, 9)
                && optional_short_string(payload, "name", 120)
        }
    };
    valid
        .then_some(())
        .ok_or(FederationProtocolError::InvalidPayload)
}

fn required_payload_id(payload: &Value, key: &str) -> bool {
    payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(valid_payload_id)
}

fn payload_has_only_allowed_fields(kind: FederationEventKind, payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let allowed = allowed_payload_fields(kind);
    object
        .keys()
        .all(|key| allowed.iter().any(|allowed_key| key == allowed_key))
}

fn allowed_payload_fields(kind: FederationEventKind) -> &'static [&'static str] {
    match kind {
        FederationEventKind::InvitePreview => &["serverId", "inviteCode", "inviteCodeHash"],
        FederationEventKind::PrincipalUpsert => {
            &["remoteUserId", "username", "displayName", "avatarUrl"]
        }
        FederationEventKind::MembershipJoin => {
            &["serverId", "remoteUserId", "inviteCode", "inviteCodeHash"]
        }
        FederationEventKind::MembershipLeave => &["serverId", "remoteUserId", "reason"],
        FederationEventKind::MembershipRemove | FederationEventKind::MembershipBan => {
            &["serverId", "remoteUserId", "targetUserId", "reason"]
        }
        FederationEventKind::MembershipUnban => &["serverId", "remoteUserId", "targetUserId"],
        FederationEventKind::RoleCreate => &[
            "serverId",
            "remoteUserId",
            "remoteRoleId",
            "name",
            "color",
            "permissions",
            "colorOnly",
            "showAsSection",
            "colorPriority",
        ],
        FederationEventKind::RoleUpdate => &[
            "serverId",
            "remoteUserId",
            "remoteRoleId",
            "name",
            "color",
            "permissions",
            "position",
            "showAsSection",
            "colorPriority",
        ],
        FederationEventKind::RoleDelete => &["serverId", "remoteUserId", "remoteRoleId"],
        FederationEventKind::RoleReorder => &["serverId", "remoteUserId", "items"],
        FederationEventKind::CategoryCreate => &[
            "serverId",
            "remoteUserId",
            "remoteCategoryId",
            "name",
            "emoji",
        ],
        FederationEventKind::CategoryUpdate => &[
            "serverId",
            "remoteUserId",
            "remoteCategoryId",
            "name",
            "position",
            "emoji",
        ],
        FederationEventKind::CategoryDelete => &["serverId", "remoteUserId", "remoteCategoryId"],
        FederationEventKind::ChannelCreate => &[
            "serverId",
            "remoteUserId",
            "remoteChannelId",
            "name",
            "topic",
            "type",
            "remoteCategoryId",
            "readOnly",
            "slowmodeSeconds",
        ],
        FederationEventKind::ChannelUpdate => &[
            "serverId",
            "remoteUserId",
            "remoteChannelId",
            "name",
            "topic",
            "position",
            "remoteCategoryId",
            "readOnly",
            "slowmodeSeconds",
        ],
        FederationEventKind::ChannelDelete => &["serverId", "remoteUserId", "remoteChannelId"],
        FederationEventKind::ChannelReorder => {
            &["serverId", "remoteUserId", "topLevel", "categories"]
        }
        FederationEventKind::ChannelOverrideSet => &[
            "serverId",
            "remoteUserId",
            "remoteChannelId",
            "roleId",
            "allow",
            "deny",
        ],
        FederationEventKind::ChannelOverrideDelete => {
            &["serverId", "remoteUserId", "remoteChannelId", "roleId"]
        }
        FederationEventKind::MemberRoleAssign | FederationEventKind::MemberRoleRemove => {
            &["serverId", "remoteUserId", "targetUserId", "roleId"]
        }
        FederationEventKind::EmojiRename => &["serverId", "remoteUserId", "emojiId", "name"],
        FederationEventKind::EmojiDelete => &["serverId", "remoteUserId", "emojiId"],
        FederationEventKind::MessageCreate => &[
            "serverId",
            "channelId",
            "remoteMessageId",
            "remoteUserId",
            "content",
            "nonce",
            "replyToRemoteMessageId",
        ],
        FederationEventKind::MessageUpdate => {
            &["channelId", "remoteMessageId", "remoteUserId", "content"]
        }
        FederationEventKind::MessageDelete
        | FederationEventKind::MessagePin
        | FederationEventKind::MessageUnpin => &["channelId", "remoteMessageId", "remoteUserId"],
        FederationEventKind::ReactionAdd | FederationEventKind::ReactionRemove => &[
            "channelId",
            "remoteMessageId",
            "remoteUserId",
            "emoji",
            "emojiId",
        ],
        FederationEventKind::RelationshipRequest
        | FederationEventKind::RelationshipAccept
        | FederationEventKind::RelationshipRemove
        | FederationEventKind::RelationshipBlock => &["remoteUserId", "localUserId"],
        FederationEventKind::PresenceUpdate => &["remoteUserId", "status"],
        FederationEventKind::TypingStart => &["channelId", "remoteUserId"],
        FederationEventKind::ReadStateUpdate => &["channelId", "remoteMessageId", "remoteUserId"],
        FederationEventKind::DmCreate => &["dmId", "remoteUserId", "localUserId"],
        FederationEventKind::DmGroupCreate => &["dmId", "remoteUserId", "localUserIds", "name"],
    }
}

fn optional_payload_id(payload: &Value, key: &str) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value.as_str().is_some_and(valid_payload_id),
    }
}

fn required_payload_id_array(payload: &Value, key: &str, min_len: usize, max_len: usize) -> bool {
    payload
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            (min_len..=max_len).contains(&values.len())
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(valid_payload_id))
        })
}

fn channel_reorder_items(payload: &Value) -> bool {
    let top_level_valid = payload
        .get("topLevel")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.len() <= 1_000
                && items.iter().all(|item| {
                    item.as_object().is_some_and(|object| {
                        object
                            .get("remoteId")
                            .and_then(Value::as_str)
                            .is_some_and(valid_payload_id)
                            && object
                                .get("type")
                                .and_then(Value::as_str)
                                .is_some_and(|value| matches!(value, "channel" | "category"))
                    })
                })
        });
    let categories_valid = payload
        .get("categories")
        .and_then(Value::as_object)
        .is_some_and(|categories| {
            categories.len() <= 250
                && categories.iter().all(|(category_id, channel_ids)| {
                    valid_payload_id(category_id)
                        && channel_ids.as_array().is_some_and(|ids| {
                            ids.len() <= 500
                                && ids
                                    .iter()
                                    .all(|id| id.as_str().is_some_and(valid_payload_id))
                        })
                })
        });
    top_level_valid && categories_valid
}

fn role_reorder_items(payload: &Value) -> bool {
    payload
        .get("items")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            (1..=250).contains(&items.len())
                && items.iter().all(|item| {
                    item.as_object().is_some_and(|object| {
                        object
                            .get("remoteRoleId")
                            .and_then(Value::as_str)
                            .is_some_and(valid_payload_id)
                            && object
                                .get("position")
                                .is_none_or(|value| value.as_i64().is_some_and(|v| v >= 0))
                            && object.get("colorPriority").is_none_or(|value| {
                                value.as_i64().is_some_and(|v| (0..=10_000).contains(&v))
                            })
                            && (object.contains_key("position")
                                || object.contains_key("colorPriority"))
                    })
                })
        })
}

fn required_content(payload: &Value, key: &str, max_chars: usize) -> bool {
    payload
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty() && value.chars().count() <= max_chars)
}

fn optional_short_string(payload: &Value, key: &str, max_chars: usize) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value
            .as_str()
            .is_some_and(|value| value.chars().count() <= max_chars),
    }
}

fn optional_short_nonempty_string(payload: &Value, key: &str, max_chars: usize) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value
            .as_str()
            .is_some_and(|value| !value.is_empty() && value.chars().count() <= max_chars),
    }
}

fn optional_bool(payload: &Value, key: &str) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value.is_boolean(),
    }
}

fn optional_i32(payload: &Value, key: &str, min: i32, max: i32) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value
            .as_i64()
            .is_some_and(|value| (min as i64..=max as i64).contains(&value)),
    }
}

fn optional_integer_string(payload: &Value, key: &str) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value.as_str().is_some_and(|value| {
            !value.is_empty() && value.len() <= 20 && value.parse::<i64>().is_ok()
        }),
    }
}

fn optional_color_string(payload: &Value, key: &str) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value.as_str().is_some_and(|value| {
            let hex = value.strip_prefix('#').unwrap_or(value);
            hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit())
        }),
    }
}

fn optional_url_string(payload: &Value, key: &str) -> bool {
    match payload.get(key) {
        None | Some(Value::Null) => true,
        Some(value) => value.as_str().is_some_and(is_safe_public_profile_url),
    }
}

fn valid_payload_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_event_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVENT_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_peer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PEER_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}
