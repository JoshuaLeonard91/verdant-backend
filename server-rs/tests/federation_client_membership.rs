use serde_json::json;
use verdant_server::federation::client_membership::{
    FEDERATED_MEMBERSHIP_CAPABILITY_PATH, FederatedClientMembershipRecord,
    build_federated_membership_capability_body, sanitize_capability_response_for_client,
};

#[test]
fn durable_federated_membership_migration_stores_only_home_owned_pointers() {
    let migration = include_str!("../migrations/0029_federation_client_memberships.sql");

    for required in [
        "CREATE TABLE IF NOT EXISTS federation_client_memberships",
        "home_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
        "target_peer_id text NOT NULL",
        "target_api_origin text NOT NULL",
        "target_server_id bigint NOT NULL",
        "remote_user_id text NOT NULL",
        "invite_code_hash text NOT NULL",
        "CONSTRAINT federation_client_memberships_unique_remote_server UNIQUE",
        "CREATE INDEX IF NOT EXISTS idx_federation_client_memberships_home_user",
    ] {
        assert!(
            migration.contains(required),
            "missing durable membership schema guardrail: {required}"
        );
    }

    for forbidden in [
        "message_body",
        "message_content",
        "attachment_url",
        "presence_json",
        "runtime_event",
        "channel_payload",
        "role_payload",
        "raw_grant",
        "access_token",
        "session_token",
        "bearer",
    ] {
        assert!(
            !migration.to_ascii_lowercase().contains(forbidden),
            "home-owned membership table must not store remote runtime or credential data: {forbidden}"
        );
    }
}

#[test]
fn durable_membership_record_serializes_to_safe_client_pointer() {
    let record = FederatedClientMembershipRecord {
        id: 1001,
        home_user_id: 42,
        target_peer_id: "host:remote.example.com".to_string(),
        target_api_origin: "https://api.remote.example.com".to_string(),
        target_server_id: 9001,
        remote_user_id: "42".to_string(),
        invite_code_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        status: "active".to_string(),
        server_name: Some("Remote Community".to_string()),
        server_icon_url: Some("https://cdn.remote.example.com/icons/9001.webp".to_string()),
        server_banner_url: None,
        last_capability_status: Some("ready".to_string()),
        last_error_code: None,
        last_refreshed_at_ms: Some(1_800_000_000_000),
        created_at_ms: 1_799_999_000_000,
        updated_at_ms: 1_800_000_000_000,
    };

    let value = record.to_client_json();

    assert_eq!(value["id"], "1001");
    assert_eq!(value["targetPeerId"], "host:remote.example.com");
    assert_eq!(value["targetApiOrigin"], "https://api.remote.example.com");
    assert_eq!(value["targetServerId"], "9001");
    assert_eq!(value["status"], "active");
    assert_eq!(value["server"]["name"], "Remote Community");
    assert_eq!(
        value["server"]["iconUrl"],
        "https://cdn.remote.example.com/icons/9001.webp"
    );
    assert!(value.get("inviteCodeHash").is_none());
    assert!(value.get("remoteUserId").is_none());
    assert!(value.to_string().contains("access") == false);
    assert!(value.to_string().contains("token") == false);
}

#[test]
fn capability_refresh_body_reuses_membership_pointer_without_raw_invite_code() {
    let body = build_federated_membership_capability_body(
        "42",
        9001,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("membership pointer should build a capability body");

    assert_eq!(body["remoteUserId"], "42");
    assert_eq!(body["serverId"], "9001");
    assert_eq!(
        body["inviteCodeHash"],
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(!body.to_string().contains("Invite"));
}

#[test]
fn capability_refresh_response_for_client_redacts_request_metadata() {
    let upstream = json!({
        "status": "ready",
        "tokenType": "federated_client",
        "accessToken": "remote-access-token",
        "expiresAt": "2026-07-23T00:00:00Z",
        "serverId": "9001",
        "user": {
            "id": "fed_1",
            "username": "remote_user",
            "email": "",
            "status": "online",
            "usernameSet": true
        }
    });

    let response =
        sanitize_capability_response_for_client(FEDERATED_MEMBERSHIP_CAPABILITY_PATH, upstream)
            .expect("ready response should be safe for client delivery");

    assert_eq!(response["status"], "ready");
    assert_eq!(response["tokenType"], "federated_client");
    assert_eq!(response["accessToken"], "remote-access-token");
    assert_eq!(response["serverId"], "9001");
    assert_eq!(response["user"]["id"], "fed_1");
    assert!(response.get("headers").is_none());
    assert!(response.get("bodyJson").is_none());
    assert!(response.get("inviteCodeHash").is_none());
}

#[test]
fn home_backend_exposes_protected_membership_list_and_refresh_routes() {
    let main_rs = include_str!("../src/main.rs");
    let handler = include_str!("../src/handlers/federation_memberships.rs");

    assert!(
        main_rs.contains(".nest(\"/api/federation/memberships\", federation_memberships)"),
        "protected router must mount durable federated memberships"
    );
    assert!(
        handler.contains(".route(\"/\", get(list_federated_memberships))"),
        "membership list route must be explicit"
    );
    assert!(
        handler.contains("\"/{membershipId}/capability\"")
            && handler.contains("post(refresh_federated_membership_capability)"),
        "membership refresh route must be explicit"
    );
    assert!(
        handler.contains("UserId"),
        "membership routes must be authenticated as the home user"
    );
}

#[test]
fn membership_refresh_handler_uses_backend_to_backend_signed_minting() {
    let handler = include_str!("../src/handlers/federation_memberships.rs");

    for required in [
        "client_membership_for_user",
        "peer_endpoint_by_peer_id",
        "FederationRequestSigner::from_seed",
        "send_signed_json_request",
        "FEDERATED_MEMBERSHIP_CAPABILITY_PATH",
        "sanitize_capability_response_for_client",
        "mark_client_membership_capability_status",
        "FEDERATION_EVENT_LIMIT",
    ] {
        assert!(
            handler.contains(required),
            "membership refresh handler is missing S2S guardrail: {required}"
        );
    }

    for forbidden in ["capabilityClaim", "bodyJson", "headers", "Authorization"] {
        assert!(
            !handler.contains(forbidden),
            "home refresh route should not return client-forwarded signing material: {forbidden}"
        );
    }
}

#[test]
fn membership_refresh_handler_enforces_owner_status_and_peer_binding() {
    let handler = include_str!("../src/handlers/federation_memberships.rs");

    for required in [
        "client_membership_for_user(&state.pg, membership_id, user_id.0)",
        ".ok_or(AppError::NotFound(\"federated membership\"))?",
        "!matches!(membership.status.as_str(), \"active\" | \"pending\")",
        "FEDERATED_MEMBERSHIP_INACTIVE",
        "peer_endpoint_by_peer_id(&state.pg, &membership.target_peer_id)",
        "FEDERATION_PEER_UNTRUSTED",
        "normalize_federated_invite_target_origin",
        "trusted_origin != membership.target_api_origin",
        "FEDERATION_PEER_ORIGIN_MISMATCH",
    ] {
        assert!(
            handler.contains(required),
            "membership refresh handler is missing ownership/status/peer guardrail: {required}"
        );
    }
}

#[test]
fn membership_refresh_handler_bounds_and_sanitizes_upstream_response() {
    let handler = include_str!("../src/handlers/federation_memberships.rs");

    for required in [
        "FEDERATED_MEMBERSHIP_CAPABILITY_RESPONSE_LIMIT_BYTES: usize = 128 * 1024",
        "read_limited_response(",
        "content_length()",
        "received.checked_add(chunk.len())",
        "FEDERATION_CAPABILITY_RESPONSE_TOO_LARGE",
        "upstream.status()",
        "!upstream_status.is_success()",
        "serde_json::from_slice(&response_bytes)",
        "sanitize_capability_response_for_client(",
        "mark_membership_refresh(&state, membership_id, \"failed\"",
        "mark_membership_refresh(&state, membership_id, capability_status, None)",
    ] {
        assert!(
            handler.contains(required),
            "membership refresh handler is missing upstream response guardrail: {required}"
        );
    }
}

#[test]
fn capability_body_validation_rejects_tampered_membership_pointers() {
    for (remote_user_id, server_id, invite_code_hash) in [
        (
            "../42",
            9001,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "42",
            0,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("42", 9001, "invite-code-not-a-hash"),
    ] {
        assert!(
            build_federated_membership_capability_body(remote_user_id, server_id, invite_code_hash)
                .is_err(),
            "tampered membership pointer should not build a target minting body"
        );
    }
}

#[test]
fn capability_response_sanitizer_rejects_wrong_path_and_malformed_ready_payloads() {
    let valid_ready = json!({
        "status": "ready",
        "tokenType": "federated_client",
        "accessToken": "remote-access-token",
        "expiresAt": "2026-07-23T00:00:00Z",
        "serverId": "9001",
        "user": {"id": "fed_1", "username": "remote_user"}
    });

    assert!(
        sanitize_capability_response_for_client("/api/federation/other", valid_ready.clone())
            .is_err(),
        "home refresh route must only sanitize the expected target capability endpoint"
    );

    for malformed in [
        json!({"status": "ready", "tokenType": "bearer", "accessToken": "x", "expiresAt": "2026-07-23T00:00:00Z", "serverId": "9001", "user": {}}),
        json!({"status": "ready", "tokenType": "federated_client", "accessToken": "", "expiresAt": "2026-07-23T00:00:00Z", "serverId": "9001", "user": {}}),
        json!({"status": "ready", "tokenType": "federated_client", "accessToken": "x", "expiresAt": "2026-07-23T00:00:00Z", "serverId": "9001"}),
    ] {
        assert!(
            sanitize_capability_response_for_client(
                FEDERATED_MEMBERSHIP_CAPABILITY_PATH,
                malformed
            )
            .is_err(),
            "malformed target capability response must not be forwarded to the client"
        );
    }
}

#[test]
fn federated_invite_join_persists_membership_pointer_without_client_forwarded_s2s_material() {
    let invites = include_str!("../src/handlers/invites.rs");

    for required in [
        "upsert_client_membership",
        "UpsertFederatedClientMembership",
        "federated_invite_code_hash",
        "\"membership\": membership.to_client_json()",
    ] {
        assert!(
            invites.contains(required),
            "federated invite join must persist a durable home-owned pointer: {required}"
        );
    }

    let join_start = invites
        .find("pub async fn join_federated_invite")
        .expect("join handler must exist");
    let capability_start = invites
        .find("pub async fn issue_federated_invite_capability")
        .expect("capability handler must exist");
    let join_handler = &invites[join_start..capability_start];

    for forbidden in ["capabilityClaim", "bodyJson", "headers"] {
        assert!(
            !join_handler.contains(forbidden),
            "join response must not expose client-forwarded S2S material: {forbidden}"
        );
    }
}
