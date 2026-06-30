use verdant_server::federation::{
    protocol::FederationEventKind,
    storage::{
        InsertOutboundFederationEvent, OUTBOUND_EVENT_CLAIM_SQL, OutboundFailurePlan,
        PEER_ENDPOINT_FOR_PEER_SQL, PEER_ROUTE_REVOKE_SQL, PEER_ROUTE_UPSERT_SQL,
        PEER_ROUTES_FOR_SCOPE_SQL, next_outbound_failure_plan, next_retry_at_ms,
    },
};

#[test]
fn outbound_retry_backoff_is_exponential_and_capped() {
    let now_ms = 1_735_689_600_000;

    assert_eq!(next_retry_at_ms(now_ms, 0), now_ms + 1_000);
    assert_eq!(next_retry_at_ms(now_ms, 1), now_ms + 2_000);
    assert_eq!(next_retry_at_ms(now_ms, 5), now_ms + 30_000);
    assert_eq!(next_retry_at_ms(now_ms, 30), now_ms + 30_000);
}

#[test]
fn outbound_event_insert_shape_keeps_payload_hash_and_bounded_event_body() {
    let event = InsertOutboundFederationEvent {
        id: 42,
        destination_peer_id: "host:b.example",
        event_id: "evt-0001",
        event_kind: FederationEventKind::InvitePreview,
        payload_hash: "5ed3c826de265f459c2a23a63a02851ca9484560866c3dfb883dd6189adc2be2",
        event_body_json: &serde_json::json!({
            "v": 1,
            "eventId": "evt-0001",
            "kind": "invite_preview",
            "source": "host:a.example",
            "destination": "host:b.example",
            "payload": {
                "inviteCode": "local-invite-code"
            }
        }),
        now_ms: 1_735_689_600_000,
    };

    assert_eq!(event.destination_peer_id, "host:b.example");
    assert_eq!(event.event_kind, FederationEventKind::InvitePreview);
    assert_eq!(event.payload_hash.len(), 64);
    assert_eq!(event.event_body_json["eventId"], "evt-0001");
}

#[test]
fn outbound_failure_plan_retries_then_dead_letters() {
    let now_ms = 1_735_689_600_000;

    assert_eq!(
        next_outbound_failure_plan(now_ms, 0, "TEMPORARY_DELIVERY_FAILURE"),
        OutboundFailurePlan {
            status: "failed",
            attempt_count: 1,
            next_attempt_at_ms: Some(now_ms + 1_000),
            last_error_code: "TEMPORARY_DELIVERY_FAILURE".to_string(),
        }
    );

    assert_eq!(
        next_outbound_failure_plan(now_ms, 7, "HTTP_503"),
        OutboundFailurePlan {
            status: "dead",
            attempt_count: 8,
            next_attempt_at_ms: None,
            last_error_code: "HTTP_503".to_string(),
        }
    );
}

#[test]
fn outbound_failure_plan_sanitizes_error_codes() {
    let plan = next_outbound_failure_plan(
        1_735_689_600_000,
        1,
        "temporary network failure: token=secret\nbody=private",
    );

    assert_eq!(
        plan.last_error_code,
        "temporary_network_failure_token_secret_body_private"
    );
    assert!(plan.last_error_code.len() <= 96);
}

#[test]
fn outbound_claim_sql_locks_due_pending_or_failed_rows() {
    assert!(OUTBOUND_EVENT_CLAIM_SQL.contains("FOR UPDATE SKIP LOCKED"));
    assert!(OUTBOUND_EVENT_CLAIM_SQL.contains("status IN ('pending','failed')"));
    assert!(OUTBOUND_EVENT_CLAIM_SQL.contains("next_attempt_at_ms <= $1"));
    assert!(OUTBOUND_EVENT_CLAIM_SQL.contains("LIMIT $2"));
    assert!(OUTBOUND_EVENT_CLAIM_SQL.contains("status = 'sending'"));
    assert!(OUTBOUND_EVENT_CLAIM_SQL.contains("event_body_json"));
}

#[test]
fn peer_route_sql_filters_active_routes_and_active_peer_keys_by_scope() {
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("FROM federation_peer_routes routes"));
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("JOIN federation_peer_keys keys"));
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("routes.status = 'active'"));
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("keys.status = 'active'"));
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("routes.scope_type = $1"));
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("routes.scope_id = $2"));
    assert!(PEER_ROUTES_FOR_SCOPE_SQL.contains("ORDER BY routes.peer_id ASC"));
}

#[test]
fn peer_endpoint_sql_routes_by_destination_peer_active_key_origin() {
    assert!(PEER_ENDPOINT_FOR_PEER_SQL.contains("SELECT api_origin"));
    assert!(PEER_ENDPOINT_FOR_PEER_SQL.contains("FROM federation_peer_keys"));
    assert!(PEER_ENDPOINT_FOR_PEER_SQL.contains("peer_id = $1"));
    assert!(PEER_ENDPOINT_FOR_PEER_SQL.contains("status = 'active'"));
    assert!(PEER_ENDPOINT_FOR_PEER_SQL.contains("ORDER BY valid_until_ms NULLS LAST"));
    assert!(PEER_ENDPOINT_FOR_PEER_SQL.contains("LIMIT 1"));
    assert!(!PEER_ENDPOINT_FOR_PEER_SQL.contains("display_name"));
    assert!(!PEER_ENDPOINT_FOR_PEER_SQL.contains("domain"));
}

#[test]
fn peer_route_upsert_and_revoke_sql_are_idempotent_and_scoped() {
    assert!(PEER_ROUTE_UPSERT_SQL.contains("INSERT INTO federation_peer_routes"));
    assert!(
        PEER_ROUTE_UPSERT_SQL
            .contains("ON CONFLICT ON CONSTRAINT federation_peer_routes_unique_scope DO UPDATE")
    );
    assert!(PEER_ROUTE_UPSERT_SQL.contains("status = 'active'"));
    assert!(PEER_ROUTE_UPSERT_SQL.contains("scope_type"));
    assert!(PEER_ROUTE_UPSERT_SQL.contains("scope_id"));

    assert!(PEER_ROUTE_REVOKE_SQL.contains("UPDATE federation_peer_routes"));
    assert!(PEER_ROUTE_REVOKE_SQL.contains("SET status = 'revoked'"));
    assert!(PEER_ROUTE_REVOKE_SQL.contains("peer_id = $1"));
    assert!(PEER_ROUTE_REVOKE_SQL.contains("scope_type = $2"));
    assert!(PEER_ROUTE_REVOKE_SQL.contains("scope_id = $3"));
}
