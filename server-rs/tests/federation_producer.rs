use serde_json::json;
use verdant_server::federation::{
    producer::{
        FederationLocalEvent, FederationPeerRoute, FederationProducerError, FederationProducerPeer,
        FederationProducerSource, FederationRouteScope, FederationUnsupportedSurface,
        build_outbound_envelope, select_outbound_peers,
    },
    protocol::{FederationEventKind, ParsedFederationEnvelope},
};

fn peer(peer_id: &str, routes: Vec<FederationPeerRoute>) -> FederationProducerPeer {
    FederationProducerPeer {
        peer_id: peer_id.to_string(),
        routes,
        active: true,
    }
}

#[test]
fn producer_builds_stable_valid_membership_join_envelope() {
    let local = FederationLocalEvent::MembershipJoin {
        server_id: 100,
        user_id: 400,
        invite_code: Some("InviteCode123".to_string()),
        invite_code_hash: Some("invite-hash-1".to_string()),
    };

    let first = build_outbound_envelope(
        "host:a.example",
        "host:b.example",
        &local,
        FederationProducerSource::Local,
        1_735_689_600_000,
    )
    .expect("membership join should produce an outbound envelope");
    let second = build_outbound_envelope(
        "host:a.example",
        "host:b.example",
        &local,
        FederationProducerSource::Local,
        1_735_689_600_999,
    )
    .expect("same local action should produce a duplicate-safe event id");

    assert_eq!(first.event_id, second.event_id);
    assert_eq!(first.kind, FederationEventKind::MembershipJoin);
    assert_eq!(first.destination_peer_id, "host:b.example");
    assert_eq!(first.payload_hash.len(), 64);
    assert_eq!(
        first.body_json,
        json!({
            "protocolVersion": 1,
            "eventId": first.event_id,
            "kind": "membership_join",
            "sourcePeerId": "host:a.example",
            "destinationPeerId": "host:b.example",
            "sentAtMs": 1_735_689_600_000_i64,
            "payload": {
                "serverId": "100",
                "remoteUserId": "400",
                "inviteCode": "InviteCode123",
                "inviteCodeHash": "invite-hash-1"
            }
        })
    );

    let parsed = ParsedFederationEnvelope::from_json(first.body_json.to_string().as_bytes())
        .expect("producer body must be accepted by protocol parser");
    assert_eq!(parsed.event_id, first.event_id);
    assert_eq!(parsed.kind, FederationEventKind::MembershipJoin);
}

#[test]
fn producer_selects_only_active_peers_with_matching_route() {
    let mut inactive = peer(
        "host:c.example",
        vec![FederationPeerRoute::Server { server_id: 100 }],
    );
    inactive.active = false;
    let candidates = vec![
        peer(
            "host:b.example",
            vec![FederationPeerRoute::Server { server_id: 100 }],
        ),
        peer(
            "host:d.example",
            vec![FederationPeerRoute::Server { server_id: 999 }],
        ),
        inactive,
    ];

    let selected = select_outbound_peers(
        &candidates,
        "host:a.example",
        FederationRouteScope::Server { server_id: 100 },
        FederationProducerSource::Local,
    );

    assert_eq!(selected, vec!["host:b.example".to_string()]);
}

#[test]
fn producer_does_not_rebroadcast_inbound_federated_events() {
    let candidates = vec![peer(
        "host:c.example",
        vec![FederationPeerRoute::Server { server_id: 100 }],
    )];

    let selected = select_outbound_peers(
        &candidates,
        "host:a.example",
        FederationRouteScope::Server { server_id: 100 },
        FederationProducerSource::InboundFederation {
            source_peer_id: "host:b.example".to_string(),
            remote_event_id: "remote-evt-1".to_string(),
        },
    );

    assert!(selected.is_empty());
}

#[test]
fn producer_rejects_unsupported_surfaces_fail_closed() {
    let err = build_outbound_envelope(
        "host:a.example",
        "host:b.example",
        &FederationLocalEvent::Unsupported {
            surface: FederationUnsupportedSurface::AttachmentMedia,
        },
        FederationProducerSource::Local,
        1_735_689_600_000,
    )
    .expect_err("attachments must not federate in the MVP");

    assert_eq!(
        err,
        FederationProducerError::UnsupportedSurface(FederationUnsupportedSurface::AttachmentMedia)
    );
}

#[test]
fn producer_rejects_runtime_events_under_server_owned_model() {
    let runtime_events = [
        FederationLocalEvent::MessageCreate {
            channel_id: 200,
            server_id: Some(100),
            message_id: 300,
            author_user_id: 400,
            content: "hello federated channel".to_string(),
            nonce: None,
            reply_to_message_id: None,
        },
        FederationLocalEvent::ReactionAdd {
            channel_id: 200,
            message_id: 300,
            user_id: 400,
            emoji: ":thumbsup:".to_string(),
            emoji_id: None,
        },
        FederationLocalEvent::PresenceUpdate {
            user_id: 400,
            status: "online".to_string(),
        },
        FederationLocalEvent::TypingStart {
            channel_id: 200,
            user_id: 400,
        },
        FederationLocalEvent::ReadStateUpdate {
            channel_id: 200,
            message_id: 300,
            user_id: 400,
        },
        FederationLocalEvent::DmCreate {
            dm_id: 500,
            actor_user_id: 400,
            local_user_id: 401,
        },
    ];

    for local_event in runtime_events {
        build_outbound_envelope(
            "host:a.example",
            "host:b.example",
            &local_event,
            FederationProducerSource::Local,
            1_735_689_600_000,
        )
        .expect_err("server-owned model must not produce outbound runtime events");
    }
}

#[test]
fn producer_builds_valid_metadata_and_membership_event_payloads() {
    let cases = [
        (
            FederationEventKind::PrincipalUpsert,
            FederationLocalEvent::PrincipalUpsert {
                user_id: 400,
                username: Some("projected_user".to_string()),
                display_name: Some("Projected User".to_string()),
                avatar_url: None,
            },
        ),
        (
            FederationEventKind::MembershipLeave,
            FederationLocalEvent::MembershipLeave {
                server_id: 100,
                user_id: 400,
                reason: Some("left".to_string()),
            },
        ),
        (
            FederationEventKind::MembershipBan,
            FederationLocalEvent::MembershipBan {
                server_id: 100,
                moderator_user_id: 400,
                target_user_id: 401,
                reason: Some("moderation action".to_string()),
            },
        ),
    ];

    for (kind, local_event) in cases {
        let produced = build_outbound_envelope(
            "host:a.example",
            "host:b.example",
            &local_event,
            FederationProducerSource::Local,
            1_735_689_600_000,
        )
        .unwrap_or_else(|err| panic!("{kind:?} should build: {err:?}"));

        assert_eq!(produced.kind, kind);
        ParsedFederationEnvelope::from_json(produced.body_json.to_string().as_bytes())
            .unwrap_or_else(|err| panic!("{kind:?} should parse: {err:?}"));
    }
}
