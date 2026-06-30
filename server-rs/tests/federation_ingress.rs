use serde_json::json;
use verdant_server::federation::{
    auth::VerifiedFederationRequest,
    ingress::{FederationIngressDecision, FederationIngressError, validate_ingress_envelope},
    protocol::{FederationEventKind, ParsedFederationEnvelope},
};

fn verified(source: &str, destination: &str) -> VerifiedFederationRequest {
    VerifiedFederationRequest {
        source_peer_id: source.to_string(),
        destination_peer_id: destination.to_string(),
        key_id: "ed25519:2026-01".to_string(),
        nonce: "nonce-000000000201".to_string(),
        timestamp_ms: 1_735_689_600_000,
        body_sha256: "hash".to_string(),
    }
}

fn envelope(source: &str, destination: &str) -> ParsedFederationEnvelope {
    envelope_with_kind(source, destination, FederationEventKind::InvitePreview)
}

fn envelope_with_kind(
    source: &str,
    destination: &str,
    kind: FederationEventKind,
) -> ParsedFederationEnvelope {
    ParsedFederationEnvelope {
        protocol_version: 1,
        event_id: "evt-0001".to_string(),
        kind,
        source_peer_id: source.to_string(),
        destination_peer_id: destination.to_string(),
        sent_at_ms: 1_735_689_600_000,
        payload: match kind {
            FederationEventKind::PrincipalUpsert => json!({"remoteUserId": "remote-user-1"}),
            FederationEventKind::PresenceUpdate => {
                json!({"remoteUserId": "remote-user-1", "status": "online"})
            }
            FederationEventKind::TypingStart => {
                json!({"remoteUserId": "remote-user-1", "channelId": "123"})
            }
            FederationEventKind::ReadStateUpdate => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "channelId": "123",
                    "remoteMessageId": "remote-message-1"
                })
            }
            FederationEventKind::ReactionAdd | FederationEventKind::ReactionRemove => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "remoteMessageId": "remote-message-1",
                    "channelId": "123",
                    "emoji": ":verdant:"
                })
            }
            FederationEventKind::MessageCreate | FederationEventKind::MessageUpdate => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "remoteMessageId": "remote-message-1",
                    "channelId": "123",
                    "content": "hello"
                })
            }
            FederationEventKind::MessageDelete
            | FederationEventKind::MessagePin
            | FederationEventKind::MessageUnpin => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "remoteMessageId": "remote-message-1",
                    "channelId": "123"
                })
            }
            FederationEventKind::DmCreate => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "dmId": "remote-dm-1",
                    "localUserId": "123"
                })
            }
            FederationEventKind::DmGroupCreate => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "dmId": "remote-group-dm-1",
                    "localUserIds": ["123", "124"],
                    "name": "Project chat"
                })
            }
            FederationEventKind::MembershipJoin => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "serverId": "123",
                    "inviteCode": "InviteCode123"
                })
            }
            FederationEventKind::MembershipLeave => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "serverId": "123",
                    "reason": "left"
                })
            }
            FederationEventKind::MembershipRemove | FederationEventKind::MembershipBan => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "targetUserId": "456",
                    "reason": "moderation action"
                })
            }
            FederationEventKind::MembershipUnban => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "targetUserId": "456"
                })
            }
            FederationEventKind::RoleCreate => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteRoleId": "remote-role-admin",
                    "name": "Remote Admin"
                })
            }
            FederationEventKind::RoleUpdate => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteRoleId": "remote-role-admin",
                    "name": "Remote Mods"
                })
            }
            FederationEventKind::RoleDelete => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteRoleId": "remote-role-admin"
                })
            }
            FederationEventKind::RoleReorder => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "items": [{
                        "remoteRoleId": "remote-role-admin",
                        "position": 3,
                        "colorPriority": 10
                    }]
                })
            }
            FederationEventKind::CategoryCreate => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteCategoryId": "remote-category-general",
                    "name": "General"
                })
            }
            FederationEventKind::CategoryUpdate => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteCategoryId": "remote-category-general",
                    "name": "Announcements"
                })
            }
            FederationEventKind::CategoryDelete => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteCategoryId": "remote-category-general"
                })
            }
            FederationEventKind::ChannelCreate => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteChannelId": "remote-channel-general",
                    "name": "General Chat",
                    "type": "text"
                })
            }
            FederationEventKind::ChannelUpdate => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteChannelId": "remote-channel-general",
                    "name": "General"
                })
            }
            FederationEventKind::ChannelDelete => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteChannelId": "remote-channel-general"
                })
            }
            FederationEventKind::ChannelReorder => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "topLevel": [{
                        "remoteId": "remote-channel-general",
                        "type": "channel"
                    }],
                    "categories": {}
                })
            }
            FederationEventKind::ChannelOverrideSet => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteChannelId": "remote-channel-general",
                    "roleId": "789",
                    "allow": "1024",
                    "deny": "2048"
                })
            }
            FederationEventKind::ChannelOverrideDelete => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "remoteChannelId": "remote-channel-general",
                    "roleId": "789"
                })
            }
            FederationEventKind::MemberRoleAssign | FederationEventKind::MemberRoleRemove => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "targetUserId": "456",
                    "roleId": "789"
                })
            }
            FederationEventKind::EmojiRename => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "emojiId": "789",
                    "name": "party_blob"
                })
            }
            FederationEventKind::EmojiDelete => {
                json!({
                    "remoteUserId": "remote-moderator-1",
                    "serverId": "123",
                    "emojiId": "789"
                })
            }
            FederationEventKind::RelationshipRequest
            | FederationEventKind::RelationshipAccept
            | FederationEventKind::RelationshipRemove
            | FederationEventKind::RelationshipBlock => {
                json!({
                    "remoteUserId": "remote-user-1",
                    "localUserId": "123"
                })
            }
            _ => json!({"serverId": "srv-a"}),
        },
    }
}

#[test]
fn ingress_accepts_verified_invite_preview_envelope() {
    let decision = validate_ingress_envelope(
        &verified("host:a.example", "host:b.example"),
        &envelope("host:a.example", "host:b.example"),
    )
    .expect("matching verified envelope should be accepted");

    assert_eq!(
        decision,
        FederationIngressDecision {
            source_peer_id: "host:a.example".to_string(),
            destination_peer_id: "host:b.example".to_string(),
            remote_event_id: "evt-0001".to_string(),
            event_kind: FederationEventKind::InvitePreview,
            payload_hash: "5ed3c826de265f459c2a23a63a02851ca9484560866c3dfb883dd6189adc2be2"
                .to_string(),
        }
    );
}

#[test]
fn ingress_rejects_envelope_source_that_differs_from_signature() {
    let err = validate_ingress_envelope(
        &verified("host:a.example", "host:b.example"),
        &envelope("host:evil.example", "host:b.example"),
    )
    .expect_err("mismatched source should fail");

    assert_eq!(err, FederationIngressError::SourceMismatch);
}

#[test]
fn ingress_rejects_envelope_destination_that_differs_from_signature() {
    let err = validate_ingress_envelope(
        &verified("host:a.example", "host:b.example"),
        &envelope("host:a.example", "host:c.example"),
    )
    .expect_err("mismatched destination should fail");

    assert_eq!(err, FederationIngressError::DestinationMismatch);
}

#[test]
fn ingress_rejects_runtime_events_under_server_owned_model() {
    for kind in [
        FederationEventKind::PresenceUpdate,
        FederationEventKind::TypingStart,
        FederationEventKind::ReadStateUpdate,
        FederationEventKind::ReactionAdd,
        FederationEventKind::ReactionRemove,
        FederationEventKind::RelationshipRequest,
        FederationEventKind::RelationshipAccept,
        FederationEventKind::RelationshipRemove,
        FederationEventKind::RelationshipBlock,
        FederationEventKind::MessageCreate,
        FederationEventKind::MessageUpdate,
        FederationEventKind::MessageDelete,
        FederationEventKind::MessagePin,
        FederationEventKind::MessageUnpin,
        FederationEventKind::DmCreate,
        FederationEventKind::DmGroupCreate,
        FederationEventKind::RoleCreate,
        FederationEventKind::RoleUpdate,
        FederationEventKind::RoleDelete,
        FederationEventKind::RoleReorder,
        FederationEventKind::CategoryCreate,
        FederationEventKind::CategoryUpdate,
        FederationEventKind::CategoryDelete,
        FederationEventKind::ChannelCreate,
        FederationEventKind::ChannelUpdate,
        FederationEventKind::ChannelDelete,
        FederationEventKind::ChannelReorder,
        FederationEventKind::ChannelOverrideSet,
        FederationEventKind::ChannelOverrideDelete,
        FederationEventKind::MemberRoleAssign,
        FederationEventKind::MemberRoleRemove,
        FederationEventKind::EmojiRename,
        FederationEventKind::EmojiDelete,
    ] {
        let err = validate_ingress_envelope(
            &verified("host:a.example", "host:b.example"),
            &envelope_with_kind("host:a.example", "host:b.example", kind),
        )
        .expect_err("runtime events must not be accepted by S2S ingress");

        assert_eq!(err, FederationIngressError::UnsupportedEventKind);
    }
}

#[test]
fn ingress_accepts_principal_upsert_after_runtime_path_exists() {
    let decision = validate_ingress_envelope(
        &verified("host:a.example", "host:b.example"),
        &envelope_with_kind(
            "host:a.example",
            "host:b.example",
            FederationEventKind::PrincipalUpsert,
        ),
    )
    .expect("principal upsert should be accepted");

    assert_eq!(decision.event_kind, FederationEventKind::PrincipalUpsert);
}

#[test]
fn ingress_accepts_membership_join_after_invite_scoped_runtime_path_exists() {
    let decision = validate_ingress_envelope(
        &verified("host:a.example", "host:b.example"),
        &envelope_with_kind(
            "host:a.example",
            "host:b.example",
            FederationEventKind::MembershipJoin,
        ),
    )
    .expect("membership join should be accepted once invite policy exists");

    assert_eq!(decision.event_kind, FederationEventKind::MembershipJoin);
}

#[test]
fn ingress_accepts_membership_leave_after_self_leave_path_exists() {
    let decision = validate_ingress_envelope(
        &verified("host:a.example", "host:b.example"),
        &envelope_with_kind(
            "host:a.example",
            "host:b.example",
            FederationEventKind::MembershipLeave,
        ),
    )
    .expect("membership leave should be accepted once self-leave policy exists");

    assert_eq!(decision.event_kind, FederationEventKind::MembershipLeave);
}

#[test]
fn ingress_accepts_permissioned_membership_moderation_after_runtime_path_exists() {
    for kind in [
        FederationEventKind::MembershipRemove,
        FederationEventKind::MembershipBan,
        FederationEventKind::MembershipUnban,
    ] {
        let decision = validate_ingress_envelope(
            &verified("host:a.example", "host:b.example"),
            &envelope_with_kind("host:a.example", "host:b.example", kind),
        )
        .expect("membership moderation should be accepted once local authorization path exists");

        assert_eq!(decision.event_kind, kind);
    }
}
