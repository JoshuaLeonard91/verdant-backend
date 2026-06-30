use serde_json::json;
use verdant_server::federation::{
    invite_join::federated_invite_code_hash,
    protocol::{FederationEventKind, ParsedFederationEnvelope},
    runtime::{FederationRuntimeCommand, FederationRuntimeError, command_from_envelope},
};

fn envelope(kind: FederationEventKind, payload: serde_json::Value) -> ParsedFederationEnvelope {
    ParsedFederationEnvelope {
        protocol_version: 1,
        event_id: "evt-0001".to_string(),
        kind,
        source_peer_id: "host:remote.example".to_string(),
        destination_peer_id: "host:local.example".to_string(),
        sent_at_ms: 1_735_689_600_000,
        payload,
    }
}

#[test]
fn invite_preview_is_audit_only() {
    let command = command_from_envelope(&envelope(
        FederationEventKind::InvitePreview,
        json!({
            "serverId": "100",
            "inviteCode": "InviteCode123"
        }),
    ))
    .expect("invite preview should be accepted as audit-only metadata");

    assert_eq!(command, FederationRuntimeCommand::AuditOnly);
}

#[test]
fn principal_upsert_event_becomes_remote_principal_command() {
    let command = command_from_envelope(&envelope(
        FederationEventKind::PrincipalUpsert,
        json!({
            "remoteUserId": "remote-user-1",
            "username": "remote_user",
            "displayName": "Remote User",
            "avatarUrl": "https://cdn.remote.example/avatar.png"
        }),
    ))
    .expect("principal upsert should build a metadata command");

    assert_eq!(
        command,
        FederationRuntimeCommand::UpsertRemotePrincipal {
            home_peer_id: "host:remote.example".to_string(),
            remote_user_id: "remote-user-1".to_string(),
            username: Some("remote_user".to_string()),
            display_name: Some("Remote User".to_string()),
            avatar_url: Some("https://cdn.remote.example/avatar.png".to_string()),
        }
    );
}

#[test]
fn membership_events_remain_local_server_commands() {
    let join = command_from_envelope(&envelope(
        FederationEventKind::MembershipJoin,
        json!({
            "serverId": "100",
            "remoteUserId": "remote-user-1",
            "inviteCode": "InviteCode123"
        }),
    ))
    .expect("membership join should build an invite-scoped command");
    assert_eq!(
        join,
        FederationRuntimeCommand::MembershipJoin {
            home_peer_id: "host:remote.example".to_string(),
            remote_user_id: "remote-user-1".to_string(),
            server_id: 100,
            invite_code: Some("InviteCode123".to_string()),
            invite_code_hash: Some(federated_invite_code_hash("InviteCode123")),
        }
    );

    let leave = command_from_envelope(&envelope(
        FederationEventKind::MembershipLeave,
        json!({
            "serverId": "100",
            "remoteUserId": "remote-user-1",
            "reason": "left"
        }),
    ))
    .expect("membership leave should build a self-leave command");
    assert_eq!(
        leave,
        FederationRuntimeCommand::MembershipLeave {
            home_peer_id: "host:remote.example".to_string(),
            remote_user_id: "remote-user-1".to_string(),
            server_id: 100,
        }
    );
}

#[test]
fn membership_moderation_events_remain_local_server_commands() {
    let remove = command_from_envelope(&envelope(
        FederationEventKind::MembershipRemove,
        json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "300",
            "reason": "rule violation"
        }),
    ))
    .expect("membership remove should build a moderation command");
    assert_eq!(
        remove,
        FederationRuntimeCommand::MembershipRemove {
            home_peer_id: "host:remote.example".to_string(),
            remote_user_id: "remote-moderator-1".to_string(),
            server_id: 100,
            target_user_id: 300,
            reason: Some("rule violation".to_string()),
        }
    );

    let ban = command_from_envelope(&envelope(
        FederationEventKind::MembershipBan,
        json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "300",
            "reason": "spam"
        }),
    ))
    .expect("membership ban should build a moderation command");
    assert_eq!(
        ban,
        FederationRuntimeCommand::MembershipBan {
            home_peer_id: "host:remote.example".to_string(),
            remote_user_id: "remote-moderator-1".to_string(),
            server_id: 100,
            target_user_id: 300,
            reason: Some("spam".to_string()),
        }
    );

    let unban = command_from_envelope(&envelope(
        FederationEventKind::MembershipUnban,
        json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "300"
        }),
    ))
    .expect("membership unban should build a moderation command");
    assert_eq!(
        unban,
        FederationRuntimeCommand::MembershipUnban {
            home_peer_id: "host:remote.example".to_string(),
            remote_user_id: "remote-moderator-1".to_string(),
            server_id: 100,
            target_user_id: 300,
        }
    );
}

#[test]
fn membership_events_reject_non_local_ids() {
    let join_err = command_from_envelope(&envelope(
        FederationEventKind::MembershipJoin,
        json!({
            "serverId": "remote-server",
            "remoteUserId": "remote-user-1",
            "inviteCode": "InviteCode123"
        }),
    ))
    .expect_err("membership join must target a local numeric server ID");
    assert_eq!(join_err, FederationRuntimeError::InvalidPayload);

    let moderation_err = command_from_envelope(&envelope(
        FederationEventKind::MembershipBan,
        json!({
            "serverId": "100",
            "remoteUserId": "remote-moderator-1",
            "targetUserId": "remote-user-2"
        }),
    ))
    .expect_err("membership moderation must target a local numeric user ID");
    assert_eq!(moderation_err, FederationRuntimeError::InvalidPayload);
}

#[test]
fn cross_backend_runtime_persistence_events_do_not_build_commands() {
    let rejected = [
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
        FederationEventKind::MessageCreate,
        FederationEventKind::MessageUpdate,
        FederationEventKind::MessageDelete,
        FederationEventKind::MessagePin,
        FederationEventKind::MessageUnpin,
        FederationEventKind::ReactionAdd,
        FederationEventKind::ReactionRemove,
        FederationEventKind::RelationshipRequest,
        FederationEventKind::RelationshipAccept,
        FederationEventKind::RelationshipRemove,
        FederationEventKind::RelationshipBlock,
        FederationEventKind::ReadStateUpdate,
        FederationEventKind::DmCreate,
        FederationEventKind::DmGroupCreate,
    ];

    for kind in rejected {
        let err = command_from_envelope(&envelope(kind, json!({})))
            .expect_err("server-owned model must reject cross-backend runtime persistence");
        assert_eq!(err, FederationRuntimeError::UnsupportedEventKind);
    }
}

#[test]
fn ephemeral_runtime_events_do_not_build_commands() {
    for kind in [
        FederationEventKind::PresenceUpdate,
        FederationEventKind::TypingStart,
    ] {
        let err = command_from_envelope(&envelope(kind, json!({})))
            .expect_err("server-owned model must reject ephemeral runtime signals");
        assert_eq!(err, FederationRuntimeError::UnsupportedEventKind);
    }
}
