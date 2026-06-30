use reqwest::StatusCode;
use serde_json::json;
use verdant_server::federation::{
    outbox::{
        FederationDeliveryDisposition, delivery_nonce, delivery_status_disposition,
        outbound_event_body_bytes, outbox_dispatcher_enabled,
    },
    storage::ClaimedOutboundFederationEvent,
};

fn claimed_event() -> ClaimedOutboundFederationEvent {
    ClaimedOutboundFederationEvent {
        id: 42,
        destination_peer_id: "host:b.example".to_string(),
        event_id: "evt-0001".to_string(),
        event_kind: "message_create".to_string(),
        payload_hash: "5ed3c826de265f459c2a23a63a02851ca9484560866c3dfb883dd6189adc2be2"
            .to_string(),
        event_body_json: json!({
            "v": 1,
            "eventId": "evt-0001",
            "kind": "message_create",
            "source": "host:a.example",
            "destination": "host:b.example",
            "payload": {
                "messageId": "remote-message-1",
                "channelId": "123",
                "content": "hello federated channel"
            }
        }),
        attempt_count: 0,
    }
}

#[test]
fn dispatcher_serializes_claimed_event_body_for_signing() {
    let event = claimed_event();

    let bytes = outbound_event_body_bytes(&event).expect("body should serialize");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json body");

    assert_eq!(parsed["eventId"], "evt-0001");
    assert_eq!(parsed["payload"]["content"], "hello federated channel");
    assert!(bytes.len() <= 131_072);
}

#[test]
fn dispatcher_nonce_is_valid_for_s2s_signatures() {
    let nonce = delivery_nonce();

    assert!((16..=128).contains(&nonce.len()));
    assert!(
        nonce
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    );
}

#[test]
fn dispatcher_classifies_delivery_status_without_payload_logging() {
    assert_eq!(
        delivery_status_disposition(StatusCode::OK),
        FederationDeliveryDisposition::Sent
    );
    assert_eq!(
        delivery_status_disposition(StatusCode::TOO_MANY_REQUESTS),
        FederationDeliveryDisposition::RetryableFailure("HTTP_429".to_string())
    );
    assert_eq!(
        delivery_status_disposition(StatusCode::INTERNAL_SERVER_ERROR),
        FederationDeliveryDisposition::RetryableFailure("HTTP_500".to_string())
    );
    assert_eq!(
        delivery_status_disposition(StatusCode::BAD_REQUEST),
        FederationDeliveryDisposition::PermanentFailure("HTTP_400".to_string())
    );
}

#[test]
fn dispatcher_requires_complete_s2s_signing_config() {
    let seed = [42; 32];

    assert!(outbox_dispatcher_enabled(
        Some("ed25519:2026-01"),
        Some(&seed)
    ));
    assert!(!outbox_dispatcher_enabled(None, Some(&seed)));
    assert!(!outbox_dispatcher_enabled(Some("ed25519:2026-01"), None));
}
