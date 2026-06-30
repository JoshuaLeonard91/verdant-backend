use verdant_server::federation::{
    invite_join::{
        build_federated_invite_join_events, federated_invite_code_hash,
        normalize_federated_invite_target_origin,
    },
    producer::FederationLocalEvent,
};

#[test]
fn federated_invite_join_target_origin_requires_a_trusted_matching_peer_host() {
    assert_eq!(
        normalize_federated_invite_target_origin(
            "host:community.example.com",
            "https://api.community.example.com/"
        )
        .unwrap(),
        "https://api.community.example.com"
    );
    assert_eq!(
        normalize_federated_invite_target_origin("host:localhost", "http://localhost:3031")
            .unwrap(),
        "http://localhost:3031"
    );

    assert!(
        normalize_federated_invite_target_origin(
            "host:verdant.chat",
            "https://verdant.chat.evil.example"
        )
        .is_err()
    );
    assert!(
        normalize_federated_invite_target_origin(
            "host:community.example.com",
            "https://api.community.example.com/invite/secret"
        )
        .is_err()
    );
    assert!(
        normalize_federated_invite_target_origin(
            "host:community.example.com",
            "http://api.community.example.com"
        )
        .is_err()
    );
}

#[test]
fn federated_invite_join_builds_principal_before_membership_without_logging_raw_code_in_hash() {
    let events = build_federated_invite_join_events(
        42,
        123,
        "InviteABC123",
        Some("Joshy".to_string()),
        Some("Josh".to_string()),
        Some("https://media.pryzmapp.com/avatars/42.webp".to_string()),
    )
    .unwrap();

    assert_eq!(events.len(), 2);
    match &events[0] {
        FederationLocalEvent::PrincipalUpsert {
            user_id,
            username,
            display_name,
            avatar_url,
        } => {
            assert_eq!(*user_id, 42);
            assert_eq!(username.as_deref(), Some("Joshy"));
            assert_eq!(display_name.as_deref(), Some("Josh"));
            assert_eq!(
                avatar_url.as_deref(),
                Some("https://media.pryzmapp.com/avatars/42.webp")
            );
        }
        other => panic!("expected principal_upsert first, got {other:?}"),
    }

    match &events[1] {
        FederationLocalEvent::MembershipJoin {
            server_id,
            user_id,
            invite_code,
            invite_code_hash,
        } => {
            assert_eq!(*server_id, 123);
            assert_eq!(*user_id, 42);
            assert_eq!(invite_code.as_deref(), None);
            let expected_hash = federated_invite_code_hash("InviteABC123");
            assert_eq!(invite_code_hash.as_deref(), Some(expected_hash.as_str()));
            assert_ne!(invite_code_hash.as_deref(), Some("InviteABC123"));
        }
        other => panic!("expected membership_join second, got {other:?}"),
    }
}
