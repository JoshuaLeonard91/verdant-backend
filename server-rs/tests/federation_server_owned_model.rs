use verdant_server::federation::{
    ownership::{
        FederationRuntimePropagationScope, runtime_propagation_allowed, runtime_propagation_scope,
    },
    protocol::FederationEventKind,
};

fn cross_backend_runtime_kinds() -> Vec<FederationEventKind> {
    vec![
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
    ]
}

fn ephemeral_runtime_kinds() -> Vec<FederationEventKind> {
    vec![
        FederationEventKind::PresenceUpdate,
        FederationEventKind::TypingStart,
    ]
}

#[test]
fn server_owned_model_keeps_runtime_persistence_default_off() {
    for kind in cross_backend_runtime_kinds() {
        assert_eq!(
            runtime_propagation_scope(kind),
            FederationRuntimePropagationScope::CrossBackendRuntimePersistence,
            "{kind:?} should be classified as cross-backend runtime persistence"
        );
        assert!(
            !runtime_propagation_allowed(kind),
            "{kind:?} must stay rejected under the server-owned model"
        );
    }
}

#[test]
fn server_owned_model_rejects_ephemeral_runtime_signals() {
    for kind in ephemeral_runtime_kinds() {
        assert_eq!(
            runtime_propagation_scope(kind),
            FederationRuntimePropagationScope::EphemeralRuntimeSignal,
            "{kind:?} should be classified as an ephemeral runtime signal"
        );
        assert!(
            !runtime_propagation_allowed(kind),
            "{kind:?} must stay rejected under the server-owned model"
        );
    }
}

#[test]
fn server_owned_model_still_allows_metadata_and_membership_handshakes() {
    for kind in [
        FederationEventKind::InvitePreview,
        FederationEventKind::PrincipalUpsert,
        FederationEventKind::MembershipJoin,
        FederationEventKind::MembershipLeave,
        FederationEventKind::MembershipRemove,
        FederationEventKind::MembershipBan,
        FederationEventKind::MembershipUnban,
    ] {
        assert_eq!(
            runtime_propagation_allowed(kind),
            true,
            "{kind:?} should remain available for signed metadata or membership handshakes"
        );
    }
}

#[test]
fn receive_event_checks_runtime_policy_before_inbound_storage_or_application() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");
    let source_path = repo
        .join("server-rs")
        .join("src")
        .join("handlers")
        .join("federation.rs");
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("{}: {error}", source_path.display()));
    let policy_idx = source
        .find("runtime_propagation_allowed(decision.event_kind)")
        .expect("receive_event should check runtime propagation policy");
    let command_idx = source
        .find("command_from_envelope(&envelope)")
        .expect("receive_event should build runtime commands");
    let insert_idx = source
        .find("federation_storage::insert_inbound_event")
        .expect("receive_event should insert inbound event rows");
    let apply_idx = source
        .find("apply_federation_runtime_command")
        .expect("receive_event should apply runtime commands");

    assert!(
        policy_idx < command_idx && policy_idx < insert_idx && policy_idx < apply_idx,
        "runtime policy must reject default-off events before command conversion, inbound event storage, or runtime persistence"
    );
}

#[test]
fn outbound_producer_checks_runtime_policy_before_peer_lookup_or_outbox_insert() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");
    let source_path = repo
        .join("server-rs")
        .join("src")
        .join("federation")
        .join("producer.rs");
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("{}: {error}", source_path.display()));
    let policy_idx = source
        .find("runtime_propagation_allowed(kind)")
        .expect("producer should check runtime propagation policy");
    let peer_lookup_idx = source
        .find("producer_peers_for_scope")
        .expect("producer should look up peer routes only after policy acceptance");
    let outbox_insert_idx = source
        .find("insert_outbound_event")
        .expect("producer should insert outbox rows only after policy acceptance");

    assert!(
        policy_idx < peer_lookup_idx && policy_idx < outbox_insert_idx,
        "runtime policy must reject default-off outbound events before peer-route lookup or outbox insert"
    );
}
