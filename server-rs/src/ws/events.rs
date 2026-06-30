use serde_json::{Value, json};

use crate::proto::{self, WsMessage, ws_message};
use crate::services::banner_crop::{self, BannerCrop};

// ─── Helpers ─────────────────────────────────────────────────────────

/// Build a JSON event string: `{ "op": "<op>", "d": <data> }`.
fn json_event(op: &str, data: Value) -> String {
    json!({ "op": op, "d": data }).to_string()
}

/// Build a proto WsMessage from a payload variant.
fn proto_event(payload: ws_message::Payload) -> WsMessage {
    WsMessage {
        payload: Some(payload),
    }
}

// ─── Server→Client Event Builders ────────────────────────────────────

// READY
pub fn ready_json(data: Value) -> String {
    json_event("READY", data)
}

pub fn ready_proto(ready: proto::Ready) -> WsMessage {
    proto_event(ws_message::Payload::Ready(ready))
}

// READY_DELTA
pub fn ready_delta_json(data: Value) -> String {
    json_event("READY_DELTA", data)
}

pub fn ready_delta_proto(delta: proto::ReadyDelta) -> WsMessage {
    proto_event(ws_message::Payload::ReadyDelta(delta))
}

// MESSAGE_CREATE
pub fn message_create_json(msg: &Value) -> String {
    json_event("MESSAGE_CREATE", json!({ "message": msg }))
}

pub fn message_create_proto(msg: proto::Message) -> WsMessage {
    proto_event(ws_message::Payload::MessageCreate(proto::MessageCreate {
        message: Some(msg),
    }))
}

// MESSAGE_UPDATE
pub fn message_update_json(msg: &Value) -> String {
    json_event("MESSAGE_UPDATE", json!({ "message": msg }))
}

pub fn message_update_proto(msg: proto::Message) -> WsMessage {
    proto_event(ws_message::Payload::MessageUpdate(proto::MessageUpdate {
        message: Some(msg),
    }))
}

// MESSAGE_DELETE
pub fn message_delete_json(id: &str, channel_id: &str) -> String {
    json_event(
        "MESSAGE_DELETE",
        json!({ "id": id, "channelId": channel_id }),
    )
}

pub fn message_delete_proto(id: String, channel_id: String) -> WsMessage {
    proto_event(ws_message::Payload::MessageDelete(proto::MessageDelete {
        id,
        channel_id,
    }))
}

// CHANNEL_UNREAD_SIGNAL
pub fn channel_unread_signal_json(
    channel_id: &str,
    server_id: Option<&str>,
    message_id: &str,
    author_id: &str,
    created_at: &str,
    mentions_current_user: bool,
    dm: bool,
) -> String {
    json_event(
        "CHANNEL_UNREAD_SIGNAL",
        json!({
            "channelId": channel_id,
            "serverId": server_id,
            "messageId": message_id,
            "authorId": author_id,
            "createdAt": created_at,
            "mentionsCurrentUser": mentions_current_user,
            "dm": dm,
        }),
    )
}

pub fn channel_unread_signal_proto(
    channel_id: String,
    server_id: Option<String>,
    message_id: String,
    author_id: String,
    created_at: String,
    mentions_current_user: bool,
    dm: bool,
) -> WsMessage {
    proto_event(ws_message::Payload::ChannelUnreadSignal(
        proto::ChannelUnreadSignal {
            channel_id,
            server_id,
            message_id,
            author_id,
            created_at,
            mentions_current_user,
            dm,
        },
    ))
}

// CHANNEL_ACTIVITY_UPDATE
pub fn channel_activity_update_json(
    channel_id: &str,
    user_id: &str,
    last_message_at: &str,
    username: Option<&str>,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
) -> String {
    json_event(
        "CHANNEL_ACTIVITY_UPDATE",
        json!({
            "channelId": channel_id,
            "userId": user_id,
            "lastMessageAt": last_message_at,
            "username": username,
            "displayName": display_name,
            "avatarUrl": avatar_url,
        }),
    )
}

pub fn channel_activity_update_proto(
    channel_id: String,
    user_id: String,
    last_message_at: String,
    username: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
) -> WsMessage {
    proto_event(ws_message::Payload::ChannelActivityUpdate(
        proto::ChannelActivityUpdate {
            channel_id,
            user_id,
            last_message_at,
            username,
            display_name,
            avatar_url,
        },
    ))
}

// CHANNEL_VISIBILITY_UPDATE
pub fn channel_visibility_update_json(
    server_id: &str,
    channel_id: &str,
    gained_user_ids: &[String],
    lost_user_ids: &[String],
) -> String {
    json_event(
        "CHANNEL_VISIBILITY_UPDATE",
        json!({
            "serverId": server_id,
            "channelId": channel_id,
            "gainedUserIds": gained_user_ids,
            "lostUserIds": lost_user_ids,
        }),
    )
}

// MESSAGE_SEND_ERROR
pub fn message_send_error_json(nonce: &str, error: &str, code: &str) -> String {
    json_event(
        "MESSAGE_SEND_ERROR",
        json!({ "nonce": nonce, "error": error, "code": code }),
    )
}

pub fn message_send_error_proto(nonce: String, error: String, code: String) -> WsMessage {
    proto_event(ws_message::Payload::MessageSendError(
        proto::MessageSendError { nonce, error, code },
    ))
}

// TYPING_START
pub fn typing_start_json(channel_id: &str, user_id: &str, timestamp: &str) -> String {
    json_event(
        "TYPING_START",
        json!({ "channelId": channel_id, "userId": user_id, "timestamp": timestamp }),
    )
}

pub fn typing_start_proto(channel_id: String, user_id: String, timestamp: String) -> WsMessage {
    proto_event(ws_message::Payload::TypingStart(proto::TypingStart {
        channel_id,
        user_id,
        timestamp,
    }))
}

// PRESENCE_UPDATE
pub fn presence_update_json(user_id: &str, status: i32) -> String {
    let status_str = match status {
        1 => "online",
        2 => "idle",
        3 => "dnd",
        4 => "offline",
        _ => "offline",
    };
    json_event(
        "PRESENCE_UPDATE",
        json!({ "userId": user_id, "status": status_str }),
    )
}

pub fn presence_update_proto(user_id: String, status: i32) -> WsMessage {
    proto_event(ws_message::Payload::PresenceUpdate(proto::PresenceUpdate {
        user_id,
        status,
    }))
}

// CHANNEL_CREATE
pub fn channel_create_json(ch: &Value) -> String {
    json_event("CHANNEL_CREATE", json!({ "channel": ch }))
}

pub fn channel_create_proto(channel: proto::Channel) -> WsMessage {
    proto_event(ws_message::Payload::ChannelCreate(proto::ChannelCreate {
        channel: Some(channel),
    }))
}

// CHANNEL_UPDATE
pub fn channel_update_json(ch: &Value) -> String {
    json_event("CHANNEL_UPDATE", json!({ "channel": ch }))
}

pub fn channel_update_proto(channel: proto::Channel) -> WsMessage {
    proto_event(ws_message::Payload::ChannelUpdate(proto::ChannelUpdate {
        channel: Some(channel),
    }))
}

// CHANNEL_DELETE
pub fn channel_delete_json(channel_id: &str, server_id: &str) -> String {
    json_event(
        "CHANNEL_DELETE",
        json!({ "channelId": channel_id, "serverId": server_id }),
    )
}

pub fn channel_delete_proto(channel_id: String, server_id: String) -> WsMessage {
    proto_event(ws_message::Payload::ChannelDelete(proto::ChannelDelete {
        channel_id,
        server_id,
    }))
}

// MEMBER_REMOVE
pub fn member_remove_json(server_id: &str, user_id: &str) -> String {
    json_event(
        "MEMBER_REMOVE",
        json!({ "serverId": server_id, "userId": user_id }),
    )
}

pub fn member_remove_proto(server_id: String, user_id: String) -> WsMessage {
    proto_event(ws_message::Payload::MemberRemove(proto::MemberRemove {
        server_id,
        user_id,
    }))
}

// SERVER_DELETE
pub fn server_delete_json(server_id: &str) -> String {
    json_event("SERVER_DELETE", json!({ "serverId": server_id }))
}

pub fn server_delete_proto(server_id: String) -> WsMessage {
    proto_event(ws_message::Payload::ServerDelete(proto::ServerDelete {
        server_id,
    }))
}

// SERVER_UPDATE
pub fn server_update_json(server: &Value) -> String {
    json_event("SERVER_UPDATE", server.clone())
}

pub fn server_update_proto(server: proto::Server) -> WsMessage {
    proto_event(ws_message::Payload::ServerUpdate(proto::ServerUpdate {
        server: Some(server),
    }))
}

// VOICE_STATE_UPDATE
pub fn voice_state_update_json(state: &Value) -> String {
    json_event("VOICE_STATE_UPDATE", json!({ "voiceState": state }))
}

pub fn voice_state_update_proto(voice_state: proto::VoiceState) -> WsMessage {
    proto_event(ws_message::Payload::VoiceStateUpdate(
        proto::VoiceStateUpdate {
            voice_state: Some(voice_state),
        },
    ))
}

// CATEGORY_CREATE
pub fn category_create_json(cat: &Value) -> String {
    json_event("CATEGORY_CREATE", json!({ "category": cat }))
}

pub fn category_create_proto(category: proto::Category) -> WsMessage {
    proto_event(ws_message::Payload::CategoryCreate(proto::CategoryCreate {
        category: Some(category),
    }))
}

// CATEGORY_UPDATE
pub fn category_update_json(cat: &Value) -> String {
    json_event("CATEGORY_UPDATE", json!({ "category": cat }))
}

pub fn category_update_proto(category: proto::Category) -> WsMessage {
    proto_event(ws_message::Payload::CategoryUpdate(proto::CategoryUpdate {
        category: Some(category),
    }))
}

// CATEGORY_DELETE
pub fn category_delete_json(category_id: &str, server_id: &str) -> String {
    json_event(
        "CATEGORY_DELETE",
        json!({ "categoryId": category_id, "serverId": server_id }),
    )
}

pub fn category_delete_proto(category_id: String, server_id: String) -> WsMessage {
    proto_event(ws_message::Payload::CategoryDelete(proto::CategoryDelete {
        category_id,
        server_id,
    }))
}

// REACTION_ADD
pub fn reaction_add_json(
    message_id: &str,
    channel_id: &str,
    user_id: &str,
    emoji: &str,
    emoji_id: Option<&str>,
) -> String {
    json_event(
        "REACTION_ADD",
        json!({
            "messageId": message_id,
            "channelId": channel_id,
            "userId": user_id,
            "emoji": emoji,
            "emojiId": emoji_id,
        }),
    )
}

pub fn reaction_add_proto(
    message_id: String,
    channel_id: String,
    user_id: String,
    emoji: String,
    emoji_id: Option<String>,
) -> WsMessage {
    proto_event(ws_message::Payload::ReactionAdd(proto::ReactionAdd {
        message_id,
        channel_id,
        user_id,
        emoji,
        emoji_id,
    }))
}

// REACTION_REMOVE
pub fn reaction_remove_json(
    message_id: &str,
    channel_id: &str,
    user_id: &str,
    emoji: &str,
) -> String {
    json_event(
        "REACTION_REMOVE",
        json!({
            "messageId": message_id,
            "channelId": channel_id,
            "userId": user_id,
            "emoji": emoji,
        }),
    )
}

pub fn reaction_remove_proto(
    message_id: String,
    channel_id: String,
    user_id: String,
    emoji: String,
) -> WsMessage {
    proto_event(ws_message::Payload::ReactionRemove(proto::ReactionRemove {
        message_id,
        channel_id,
        user_id,
        emoji,
    }))
}

// ROLE_CREATE
pub fn role_create_json(server_id: &str, role: &Value) -> String {
    json_event(
        "ROLE_CREATE",
        json!({ "serverId": server_id, "role": role }),
    )
}

pub fn role_create_proto(server_id: String, role: proto::Role) -> WsMessage {
    proto_event(ws_message::Payload::RoleCreate(proto::RoleCreate {
        server_id,
        role: Some(role),
    }))
}

// ROLE_UPDATE
pub fn role_update_json(server_id: &str, role: &Value) -> String {
    json_event(
        "ROLE_UPDATE",
        json!({ "serverId": server_id, "role": role }),
    )
}

pub fn role_update_proto(server_id: String, role: proto::Role) -> WsMessage {
    proto_event(ws_message::Payload::RoleUpdate(proto::RoleUpdate {
        server_id,
        role: Some(role),
    }))
}

// ROLE_DELETE
pub fn role_delete_json(server_id: &str, role_id: &str) -> String {
    json_event(
        "ROLE_DELETE",
        json!({ "serverId": server_id, "roleId": role_id }),
    )
}

pub fn role_delete_proto(server_id: String, role_id: String) -> WsMessage {
    proto_event(ws_message::Payload::RoleDelete(proto::RoleDelete {
        server_id,
        role_id,
    }))
}

// MEMBER_ROLE_UPDATE
pub fn member_role_update_json(server_id: &str, user_id: &str, role_ids: &[String]) -> String {
    json_event(
        "MEMBER_ROLE_UPDATE",
        json!({ "serverId": server_id, "userId": user_id, "roleIds": role_ids }),
    )
}

pub fn member_role_update_proto(
    server_id: String,
    user_id: String,
    role_ids: Vec<String>,
) -> WsMessage {
    proto_event(ws_message::Payload::MemberRoleUpdate(
        proto::MemberRoleUpdate {
            server_id,
            user_id,
            role_ids,
        },
    ))
}

// FORCE_UPDATE
pub fn force_update_json(min_version: &str, download_url: &str) -> String {
    json_event(
        "FORCE_UPDATE",
        json!({ "minVersion": min_version, "downloadUrl": download_url }),
    )
}

pub fn force_update_proto(min_version: String, download_url: String) -> WsMessage {
    proto_event(ws_message::Payload::ForceUpdate(proto::ForceUpdate {
        min_version,
        download_url,
    }))
}

// FEATURE_FLAGS_UPDATE
pub fn feature_flags_update_json(flags: &Value) -> String {
    json_event("FEATURE_FLAGS_UPDATE", json!({ "flags": flags }))
}

pub fn feature_flags_update_proto(flags: std::collections::HashMap<String, bool>) -> WsMessage {
    proto_event(ws_message::Payload::FeatureFlagsUpdate(
        proto::FeatureFlagsUpdate { flags },
    ))
}

// RELATIONSHIP_ADD
pub fn relationship_add_json(rel: &Value) -> String {
    json_event("RELATIONSHIP_ADD", json!({ "relationship": rel }))
}

pub fn relationship_add_proto(relationship: proto::Relationship) -> WsMessage {
    proto_event(ws_message::Payload::RelationshipAdd(
        proto::RelationshipAdd {
            relationship: Some(relationship),
        },
    ))
}

// RELATIONSHIP_REMOVE
pub fn relationship_remove_json(user_id: &str) -> String {
    json_event("RELATIONSHIP_REMOVE", json!({ "userId": user_id }))
}

pub fn relationship_remove_proto(user_id: String) -> WsMessage {
    proto_event(ws_message::Payload::RelationshipRemove(
        proto::RelationshipRemove { user_id },
    ))
}

// DM_CHANNEL_CREATE
pub fn dm_channel_create_json(ch: &Value) -> String {
    json_event("DM_CHANNEL_CREATE", json!({ "dmChannel": ch }))
}

pub fn dm_channel_create_proto(dm_channel: proto::DmChannel) -> WsMessage {
    proto_event(ws_message::Payload::DmChannelCreate(
        proto::DmChannelCreate {
            dm_channel: Some(dm_channel),
        },
    ))
}

// DM_NAME_COLOR_UPDATE
pub fn dm_name_color_update_json(data: &Value) -> String {
    json_event("DM_NAME_COLOR_UPDATE", data.clone())
}

pub fn dm_name_color_update_proto(
    channel_id: String,
    user_id: String,
    name_color: Option<String>,
) -> WsMessage {
    proto_event(ws_message::Payload::DmNameColorUpdate(
        proto::DmNameColorUpdate {
            channel_id,
            user_id,
            name_color,
        },
    ))
}

// ANNOUNCEMENT_CREATE
pub fn announcement_create_json(announcement: &Value) -> String {
    json_event("ANNOUNCEMENT_CREATE", announcement.clone())
}

pub fn announcement_create_proto(
    server_id: String,
    feed_id: String,
    announcement: proto::Announcement,
) -> WsMessage {
    proto_event(ws_message::Payload::AnnouncementCreate(
        proto::AnnouncementCreate {
            server_id,
            feed_id,
            announcement: Some(announcement),
        },
    ))
}

// ANNOUNCEMENT_UPDATE
pub fn announcement_update_json(announcement: &Value) -> String {
    json_event("ANNOUNCEMENT_UPDATE", announcement.clone())
}

pub fn announcement_update_proto(
    server_id: String,
    feed_id: String,
    announcement: proto::Announcement,
) -> WsMessage {
    proto_event(ws_message::Payload::AnnouncementUpdate(
        proto::AnnouncementUpdate {
            server_id,
            feed_id,
            announcement: Some(announcement),
        },
    ))
}

// ANNOUNCEMENT_DELETE
pub fn announcement_delete_json(server_id: &str, feed_id: &str, announcement_id: &str) -> String {
    json_event(
        "ANNOUNCEMENT_DELETE",
        json!({
            "announcementId": announcement_id,
            "id": announcement_id,
            "feedId": feed_id,
            "serverId": server_id,
        }),
    )
}

pub fn announcement_delete_proto(
    server_id: String,
    feed_id: String,
    announcement_id: String,
) -> WsMessage {
    proto_event(ws_message::Payload::AnnouncementDelete(
        proto::AnnouncementDelete {
            server_id,
            feed_id,
            announcement_id,
        },
    ))
}

// FEED_CREATE
pub fn feed_create_json(feed: &Value) -> String {
    json_event("FEED_CREATE", feed.clone())
}

pub fn feed_create_proto(server_id: String, feed: proto::Feed) -> WsMessage {
    proto_event(ws_message::Payload::FeedCreate(proto::FeedCreate {
        server_id,
        feed: Some(feed),
    }))
}

// FEED_UPDATE
pub fn feed_update_json(feed: &Value) -> String {
    json_event("FEED_UPDATE", feed.clone())
}

pub fn feed_update_proto(server_id: String, feed: proto::Feed) -> WsMessage {
    proto_event(ws_message::Payload::FeedUpdate(proto::FeedUpdate {
        server_id,
        feed: Some(feed),
    }))
}

// FEED_DELETE
pub fn feed_delete_json(server_id: &str, feed_id: &str) -> String {
    json_event(
        "FEED_DELETE",
        json!({ "id": feed_id, "feedId": feed_id, "serverId": server_id }),
    )
}

pub fn feed_delete_proto(server_id: String, feed_id: String) -> WsMessage {
    proto_event(ws_message::Payload::FeedDelete(proto::FeedDelete {
        server_id,
        feed_id,
    }))
}

// UPDATE_AVAILABLE
pub fn update_available_json(version: &str, notes: &str) -> String {
    json_event(
        "UPDATE_AVAILABLE",
        json!({ "version": version, "notes": notes }),
    )
}

pub fn update_available_proto(version: String, notes: String) -> WsMessage {
    proto_event(ws_message::Payload::UpdateAvailable(
        proto::UpdateAvailable { version, notes },
    ))
}

// MESSAGE_PIN
pub fn message_pin_json(message_id: &str, channel_id: &str, pinned_by: &str) -> String {
    json_event(
        "MESSAGE_PIN",
        json!({ "messageId": message_id, "channelId": channel_id, "pinnedBy": pinned_by }),
    )
}

pub fn message_pin_proto(message_id: String, channel_id: String, pinned_by: String) -> WsMessage {
    proto_event(ws_message::Payload::MessagePin(proto::MessagePin {
        message_id,
        channel_id,
        pinned_by,
    }))
}

// MESSAGE_UNPIN
pub fn message_unpin_json(message_id: &str, channel_id: &str) -> String {
    json_event(
        "MESSAGE_UNPIN",
        json!({ "messageId": message_id, "channelId": channel_id }),
    )
}

pub fn message_unpin_proto(message_id: String, channel_id: String) -> WsMessage {
    proto_event(ws_message::Payload::MessageUnpin(proto::MessageUnpin {
        message_id,
        channel_id,
    }))
}

// MEMBER_JOIN
pub fn member_join_json(
    server_id: &str,
    user_id: &str,
    username: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    joined_at: &str,
) -> String {
    json_event(
        "MEMBER_JOIN",
        json!({
            "serverId": server_id,
            "userId": user_id,
            "username": username,
            "displayName": display_name,
            "avatarUrl": avatar_url,
            "joinedAt": joined_at,
        }),
    )
}

pub fn member_join_proto(
    server_id: String,
    user_id: String,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    joined_at: String,
) -> WsMessage {
    proto_event(ws_message::Payload::MemberJoin(proto::MemberJoin {
        server_id,
        user_id,
        username,
        display_name,
        avatar_url,
        joined_at,
    }))
}

// USER_PROFILE_UPDATE
pub fn user_profile_update_json(
    user_id: &str,
    avatar_url: Option<&str>,
    banner_url: Option<&str>,
    display_name: Option<&str>,
    bio: Option<&str>,
    banner_base_color: Option<&str>,
    banner_crop: Option<Option<BannerCrop>>,
    member_list_banner_url: Option<&str>,
    member_list_banner_crop: Option<Option<BannerCrop>>,
) -> String {
    let mut d = json!({ "userId": user_id });
    if let Some(v) = avatar_url {
        d["avatarUrl"] = json!(v);
    }
    if let Some(v) = banner_url {
        d["bannerUrl"] = json!(v);
    }
    if let Some(v) = display_name {
        d["displayName"] = json!(v);
    }
    if let Some(v) = bio {
        d["bio"] = json!(v);
    }
    if let Some(v) = banner_base_color {
        d["bannerBaseColor"] = json!(v);
    }
    if let Some(crop) = banner_crop {
        d["bannerCrop"] = banner_crop::to_json(crop);
    }
    if let Some(v) = member_list_banner_url {
        d["memberListBannerUrl"] = json!(v);
    }
    if let Some(crop) = member_list_banner_crop {
        d["memberListBannerCrop"] = banner_crop::to_json(crop);
    }
    json_event("USER_PROFILE_UPDATE", d)
}

pub fn user_profile_update_proto(
    user_id: String,
    avatar_url: Option<String>,
    banner_url: Option<String>,
    display_name: Option<String>,
    bio: Option<String>,
    banner_base_color: Option<String>,
) -> WsMessage {
    proto_event(ws_message::Payload::UserProfileUpdate(
        proto::UserProfileUpdate {
            user_id,
            avatar_url,
            banner_url,
            display_name,
            bio,
            banner_base_color,
        },
    ))
}

// SERVER_EMOJIS_UPDATE
pub fn server_emojis_update_json(server_id: &str, emoji_version: i32, emojis: &[Value]) -> String {
    json_event(
        "SERVER_EMOJIS_UPDATE",
        json!({
            "serverId": server_id,
            "emojiVersion": emoji_version,
            "emojis": emojis,
        }),
    )
}

pub fn server_emojis_update_proto(
    server_id: String,
    emoji_version: i32,
    emojis: Vec<proto::Emoji>,
) -> WsMessage {
    proto_event(ws_message::Payload::ServerEmojisUpdate(
        proto::ServerEmojisUpdate {
            server_id,
            emoji_version,
            emojis,
        },
    ))
}

// WS_ERROR
pub fn ws_error_json(origin_op: &str, error: &str, code: &str) -> String {
    json_event(
        "WS_ERROR",
        json!({ "originOp": origin_op, "error": error, "code": code }),
    )
}

pub fn ws_error_proto(origin_op: &str, error: &str, code: &str) -> WsMessage {
    proto_event(ws_message::Payload::WsError(proto::WsError {
        origin_op: origin_op.to_string(),
        error: error.to_string(),
        code: code.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_delete_json_includes_feed_id_and_server_id() {
        let value: Value = serde_json::from_str(&feed_delete_json("server-1", "feed-1")).unwrap();

        assert_eq!(value["op"], "FEED_DELETE");
        assert_eq!(value["d"]["id"], "feed-1");
        assert_eq!(value["d"]["feedId"], "feed-1");
        assert_eq!(value["d"]["serverId"], "server-1");
    }

    #[test]
    fn announcement_delete_json_includes_canonical_and_legacy_ids() {
        let value: Value =
            serde_json::from_str(&announcement_delete_json("server-1", "feed-1", "ann-1")).unwrap();

        assert_eq!(value["op"], "ANNOUNCEMENT_DELETE");
        assert_eq!(value["d"]["announcementId"], "ann-1");
        assert_eq!(value["d"]["id"], "ann-1");
        assert_eq!(value["d"]["feedId"], "feed-1");
        assert_eq!(value["d"]["serverId"], "server-1");
    }

    #[test]
    fn user_profile_update_json_can_emit_display_name_changes() {
        let value: Value = serde_json::from_str(&user_profile_update_json(
            "user-1",
            None,
            None,
            Some("Display"),
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

        assert_eq!(value["op"], "USER_PROFILE_UPDATE");
        assert_eq!(value["d"]["userId"], "user-1");
        assert_eq!(value["d"]["displayName"], "Display");
        assert!(value["d"].get("avatarUrl").is_none());
    }

    #[test]
    fn user_profile_update_json_can_emit_bio_changes() {
        let value: Value = serde_json::from_str(&user_profile_update_json(
            "user-1",
            None,
            None,
            None,
            Some("Updated profile description"),
            None,
            None,
            None,
            None,
        ))
        .unwrap();

        assert_eq!(value["op"], "USER_PROFILE_UPDATE");
        assert_eq!(value["d"]["userId"], "user-1");
        assert_eq!(value["d"]["bio"], "Updated profile description");
        assert!(value["d"].get("displayName").is_none());
    }

    #[test]
    fn channel_unread_signal_json_excludes_message_content() {
        let value: Value = serde_json::from_str(&channel_unread_signal_json(
            "channel-1",
            Some("server-1"),
            "message-1",
            "user-1",
            "2026-05-12T00:00:00Z",
            true,
            false,
        ))
        .unwrap();

        assert_eq!(value["op"], "CHANNEL_UNREAD_SIGNAL");
        assert_eq!(value["d"]["channelId"], "channel-1");
        assert_eq!(value["d"]["serverId"], "server-1");
        assert_eq!(value["d"]["messageId"], "message-1");
        assert_eq!(value["d"]["authorId"], "user-1");
        assert_eq!(value["d"]["mentionsCurrentUser"], true);
        assert_eq!(value["d"]["dm"], false);
        assert!(value["d"].get("content").is_none());
        assert!(value["d"].get("preview").is_none());
    }

    #[test]
    fn channel_activity_update_json_uses_focused_channel_shape() {
        let value: Value = serde_json::from_str(&channel_activity_update_json(
            "channel-1",
            "user-1",
            "2026-05-12T00:00:00Z",
            Some("josh"),
            Some("Josh"),
            Some("https://cdn.verdant.chat/avatar.webp"),
        ))
        .unwrap();

        assert_eq!(value["op"], "CHANNEL_ACTIVITY_UPDATE");
        assert_eq!(value["d"]["channelId"], "channel-1");
        assert_eq!(value["d"]["userId"], "user-1");
        assert_eq!(value["d"]["username"], "josh");
        assert_eq!(value["d"]["displayName"], "Josh");
        assert_eq!(
            value["d"]["avatarUrl"],
            "https://cdn.verdant.chat/avatar.webp"
        );
    }

    #[test]
    fn channel_visibility_update_json_has_member_delta_only() {
        let gained = vec!["user-2".to_string()];
        let lost = vec!["user-3".to_string()];
        let value: Value = serde_json::from_str(&channel_visibility_update_json(
            "server-1",
            "channel-1",
            &gained,
            &lost,
        ))
        .unwrap();

        assert_eq!(value["op"], "CHANNEL_VISIBILITY_UPDATE");
        assert_eq!(value["d"]["serverId"], "server-1");
        assert_eq!(value["d"]["channelId"], "channel-1");
        assert_eq!(value["d"]["gainedUserIds"][0], "user-2");
        assert_eq!(value["d"]["lostUserIds"][0], "user-3");
        assert!(value["d"].get("content").is_none());
        assert!(value["d"].get("preview").is_none());
    }
}
