use serde_json::json;
use verdant_server::federation::protocol::{
    FederationEventKind, FederationProtocolError, ParsedFederationEnvelope,
};

#[test]
fn protocol_accepts_invite_preview_envelope() {
    let envelope = ParsedFederationEnvelope::from_json(
        br#"{
            "protocolVersion": 1,
            "eventId": "evt-0001",
            "kind": "invite_preview",
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1735689600000,
            "payload": {
                "serverId": "srv-a",
                "inviteCodeHash": "abc123"
            }
        }"#,
    )
    .expect("envelope should parse");

    assert_eq!(envelope.protocol_version, 1);
    assert_eq!(envelope.event_id.as_str(), "evt-0001");
    assert_eq!(envelope.kind, FederationEventKind::InvitePreview);
    assert_eq!(envelope.source_peer_id.as_str(), "host:a.example");
    assert_eq!(envelope.destination_peer_id.as_str(), "host:b.example");
    assert_eq!(
        envelope.payload,
        json!({
            "serverId": "srv-a",
            "inviteCodeHash": "abc123"
        })
    );
}

#[test]
fn protocol_rejects_unknown_event_kind() {
    let err = ParsedFederationEnvelope::from_json(
        br#"{
            "protocolVersion": 1,
            "eventId": "evt-0002",
            "kind": "admin_backdoor",
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1735689600000,
            "payload": {}
        }"#,
    )
    .expect_err("unknown kind should fail");

    assert_eq!(err, FederationProtocolError::UnknownEventKind);
}

#[test]
fn protocol_rejects_unsupported_version_and_blank_ids() {
    let err = ParsedFederationEnvelope::from_json(
        br#"{
            "protocolVersion": 2,
            "eventId": "evt-0003",
            "kind": "invite_preview",
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1735689600000,
            "payload": {}
        }"#,
    )
    .expect_err("unsupported version should fail");
    assert_eq!(err, FederationProtocolError::UnsupportedVersion);

    let err = ParsedFederationEnvelope::from_json(
        br#"{
            "protocolVersion": 1,
            "eventId": "",
            "kind": "invite_preview",
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1735689600000,
            "payload": {}
        }"#,
    )
    .expect_err("blank event id should fail");
    assert_eq!(err, FederationProtocolError::InvalidEnvelope);
}

#[test]
fn protocol_recognizes_full_runtime_event_surface() {
    let cases = [
        ("principal_upsert", FederationEventKind::PrincipalUpsert),
        ("membership_join", FederationEventKind::MembershipJoin),
        ("membership_leave", FederationEventKind::MembershipLeave),
        ("membership_remove", FederationEventKind::MembershipRemove),
        ("membership_ban", FederationEventKind::MembershipBan),
        ("membership_unban", FederationEventKind::MembershipUnban),
        ("role_create", FederationEventKind::RoleCreate),
        ("role_update", FederationEventKind::RoleUpdate),
        ("role_delete", FederationEventKind::RoleDelete),
        ("role_reorder", FederationEventKind::RoleReorder),
        ("category_create", FederationEventKind::CategoryCreate),
        ("category_update", FederationEventKind::CategoryUpdate),
        ("category_delete", FederationEventKind::CategoryDelete),
        ("channel_create", FederationEventKind::ChannelCreate),
        ("channel_update", FederationEventKind::ChannelUpdate),
        ("channel_delete", FederationEventKind::ChannelDelete),
        ("channel_reorder", FederationEventKind::ChannelReorder),
        (
            "channel_override_set",
            FederationEventKind::ChannelOverrideSet,
        ),
        (
            "channel_override_delete",
            FederationEventKind::ChannelOverrideDelete,
        ),
        ("member_role_assign", FederationEventKind::MemberRoleAssign),
        ("member_role_remove", FederationEventKind::MemberRoleRemove),
        ("emoji_rename", FederationEventKind::EmojiRename),
        ("emoji_delete", FederationEventKind::EmojiDelete),
        ("message_create", FederationEventKind::MessageCreate),
        ("message_update", FederationEventKind::MessageUpdate),
        ("message_delete", FederationEventKind::MessageDelete),
        ("message_pin", FederationEventKind::MessagePin),
        ("message_unpin", FederationEventKind::MessageUnpin),
        ("reaction_add", FederationEventKind::ReactionAdd),
        ("reaction_remove", FederationEventKind::ReactionRemove),
        (
            "relationship_request",
            FederationEventKind::RelationshipRequest,
        ),
        (
            "relationship_accept",
            FederationEventKind::RelationshipAccept,
        ),
        (
            "relationship_remove",
            FederationEventKind::RelationshipRemove,
        ),
        ("relationship_block", FederationEventKind::RelationshipBlock),
        ("presence_update", FederationEventKind::PresenceUpdate),
        ("typing_start", FederationEventKind::TypingStart),
        ("read_state_update", FederationEventKind::ReadStateUpdate),
        ("dm_create", FederationEventKind::DmCreate),
        ("dm_group_create", FederationEventKind::DmGroupCreate),
    ];

    for (kind, expected) in cases {
        let body = json!({
            "protocolVersion": 1,
            "eventId": format!("evt-{kind}"),
            "kind": kind,
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1735689600000_i64,
            "payload": valid_payload_for(kind)
        })
        .to_string();

        let envelope = ParsedFederationEnvelope::from_json(body.as_bytes())
            .unwrap_or_else(|err| panic!("{kind} should parse: {err:?}"));

        assert_eq!(envelope.kind, expected);
        assert_eq!(envelope.kind.as_str(), kind);
    }
}

#[test]
fn protocol_rejects_missing_required_payload_fields_for_runtime_events() {
    let body = json!({
        "protocolVersion": 1,
        "eventId": "evt-bad-message",
        "kind": "message_create",
        "sourcePeerId": "host:a.example",
        "destinationPeerId": "host:b.example",
        "sentAtMs": 1735689600000_i64,
        "payload": {
            "serverId": "100",
            "channelId": "200",
            "remoteUserId": "remote-user-1"
        }
    })
    .to_string();

    let err = ParsedFederationEnvelope::from_json(body.as_bytes())
        .expect_err("message_create without content or remoteMessageId should fail");

    assert_eq!(err, FederationProtocolError::InvalidPayload);
}

#[test]
fn protocol_rejects_unsafe_presence_status() {
    let body = json!({
        "protocolVersion": 1,
        "eventId": "evt-bad-presence",
        "kind": "presence_update",
        "sourcePeerId": "host:a.example",
        "destinationPeerId": "host:b.example",
        "sentAtMs": 1735689600000_i64,
        "payload": {
            "remoteUserId": "remote-user-1",
            "status": "invisible-admin"
        }
    })
    .to_string();

    let err = ParsedFederationEnvelope::from_json(body.as_bytes())
        .expect_err("unknown presence status should fail");

    assert_eq!(err, FederationProtocolError::InvalidPayload);
}

#[test]
fn protocol_rejects_secret_bearing_principal_avatar_urls() {
    for (idx, avatar_url) in [
        "https://user:pass@cdn.example/avatar.png",
        "https://cdn.example/avatar.png?token=secret",
        "https://127.0.0.1/avatar.png",
        "http://localhost/avatar.png",
        "https://cdn.example/attachments/private-object-key.png",
    ]
    .into_iter()
    .enumerate()
    {
        let body = json!({
            "protocolVersion": 1,
            "eventId": format!("evt-bad-avatar-{idx}"),
            "kind": "principal_upsert",
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1735689600000_i64,
            "payload": {
                "remoteUserId": "remote-user-1",
                "avatarUrl": avatar_url
            }
        })
        .to_string();

        let err = match ParsedFederationEnvelope::from_json(body.as_bytes()) {
            Ok(_) => panic!("unsafe avatar URL should fail: {avatar_url}"),
            Err(err) => err,
        };

        assert_eq!(err, FederationProtocolError::InvalidPayload);
    }
}

#[test]
fn protocol_rejects_unknown_secret_bearing_payload_fields() {
    let body = json!({
        "protocolVersion": 1,
        "eventId": "evt-secret-field",
        "kind": "message_create",
        "sourcePeerId": "host:a.example",
        "destinationPeerId": "host:b.example",
        "sentAtMs": 1735689600000_i64,
        "payload": {
            "serverId": "100",
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1",
            "content": "hello from federation",
            "accessToken": "secret-token",
            "cookie": "session=secret",
            "attachmentKey": "attachments/private-object-key"
        }
    })
    .to_string();

    let err = ParsedFederationEnvelope::from_json(body.as_bytes())
        .expect_err("payloads with unexpected secret-bearing fields should fail");

    assert_eq!(err, FederationProtocolError::InvalidPayload);
}

#[test]
fn protocol_rejects_scoped_cross_backend_ids_in_runtime_payloads() {
    let body = json!({
        "protocolVersion": 1,
        "eventId": "evt-scoped-id",
        "kind": "message_create",
        "sourcePeerId": "host:a.example",
        "destinationPeerId": "host:b.example",
        "sentAtMs": 1735689600000_i64,
        "payload": {
            "serverId": "100",
            "channelId": "origin:https%3A%2F%2Fapi.evil.example/200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1",
            "content": "hello from federation"
        }
    })
    .to_string();

    let err = ParsedFederationEnvelope::from_json(body.as_bytes())
        .expect_err("network-scoped IDs must not enter backend-local S2S payloads");

    assert_eq!(err, FederationProtocolError::InvalidPayload);
}

fn valid_payload_for(kind: &str) -> serde_json::Value {
    match kind {
        "principal_upsert" => json!({
            "remoteUserId": "remote-user-1",
            "username": "remote_user",
            "displayName": "Remote User",
            "avatarUrl": null
        }),
        "membership_join" => json!({
            "serverId": "100",
            "remoteUserId": "remote-user-1",
            "inviteCode": "InviteCode123",
            "inviteCodeHash": "hash-1"
        }),
        "membership_leave" => json!({
            "serverId": "100",
            "remoteUserId": "remote-user-1",
            "reason": "left"
        }),
        "membership_remove" | "membership_ban" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "300",
            "reason": "moderation action"
        }),
        "membership_unban" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "300"
        }),
        "role_create" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteRoleId": "remote-role-admin",
            "name": "Remote Admin",
            "color": "#33aaee",
            "permissions": "1024",
            "colorOnly": false,
            "showAsSection": true,
            "colorPriority": 10
        }),
        "role_update" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteRoleId": "remote-role-admin",
            "name": "Remote Mods",
            "color": null,
            "permissions": "512",
            "position": 3,
            "showAsSection": false,
            "colorPriority": 0
        }),
        "role_delete" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteRoleId": "remote-role-admin"
        }),
        "role_reorder" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "items": [
                {
                    "remoteRoleId": "remote-role-admin",
                    "position": 3,
                    "colorPriority": 10
                }
            ]
        }),
        "category_create" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteCategoryId": "remote-category-general",
            "name": "General",
            "emoji": "hash"
        }),
        "category_update" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteCategoryId": "remote-category-general",
            "name": "Announcements",
            "position": 2,
            "emoji": null
        }),
        "category_delete" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteCategoryId": "remote-category-general"
        }),
        "channel_create" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteChannelId": "remote-channel-general",
            "name": "General Chat",
            "topic": "Federated discussion",
            "type": "text",
            "remoteCategoryId": "remote-category-general",
            "readOnly": false,
            "slowmodeSeconds": 5
        }),
        "channel_update" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteChannelId": "remote-channel-general",
            "name": "General",
            "topic": null,
            "position": 3,
            "remoteCategoryId": null,
            "readOnly": true,
            "slowmodeSeconds": 10
        }),
        "channel_delete" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteChannelId": "remote-channel-general"
        }),
        "channel_reorder" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "topLevel": [
                {
                    "remoteId": "remote-category-general",
                    "type": "category"
                },
                {
                    "remoteId": "remote-channel-general",
                    "type": "channel"
                }
            ],
            "categories": {
                "remote-category-general": ["remote-channel-updates"]
            }
        }),
        "channel_override_set" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteChannelId": "remote-channel-general",
            "roleId": "400",
            "allow": "1024",
            "deny": "2048"
        }),
        "channel_override_delete" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "remoteChannelId": "remote-channel-general",
            "roleId": "400"
        }),
        "member_role_assign" | "member_role_remove" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "300",
            "roleId": "400"
        }),
        "emoji_rename" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "emojiId": "500",
            "name": "party_blob"
        }),
        "emoji_delete" => json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "emojiId": "500"
        }),
        "message_create" => json!({
            "serverId": "100",
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1",
            "content": "hello from federation",
            "nonce": "nonce-1",
            "replyToRemoteMessageId": null
        }),
        "message_update" => json!({
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1",
            "content": "edited from federation"
        }),
        "message_delete" => json!({
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1"
        }),
        "message_pin" | "message_unpin" => json!({
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1"
        }),
        "reaction_add" | "reaction_remove" => json!({
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1",
            "emoji": ":+1:",
            "emojiId": null
        }),
        "relationship_request"
        | "relationship_accept"
        | "relationship_remove"
        | "relationship_block" => json!({
            "remoteUserId": "remote-user-1",
            "localUserId": "300"
        }),
        "presence_update" => json!({
            "remoteUserId": "remote-user-1",
            "status": "online"
        }),
        "typing_start" => json!({
            "channelId": "200",
            "remoteUserId": "remote-user-1"
        }),
        "read_state_update" => json!({
            "channelId": "200",
            "remoteMessageId": "remote-message-1",
            "remoteUserId": "remote-user-1"
        }),
        "dm_create" => json!({
            "dmId": "dm-remote-1",
            "remoteUserId": "remote-user-1",
            "localUserId": "300"
        }),
        "dm_group_create" => json!({
            "dmId": "dm-remote-group-1",
            "remoteUserId": "remote-user-1",
            "localUserIds": ["300", "301"],
            "name": "Project chat"
        }),
        _ => unreachable!("unexpected kind {kind}"),
    }
}
