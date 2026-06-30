use verdant_server::federation::auth::{
    FederationPeerKey, FederationRequestIdentity, FederationRequestSigner,
    FederationRequestVerifier, InMemoryNonceStore, StaticPeerKeyStore, VerifyError,
};

fn test_signing_seed() -> [u8; 32] {
    [42; 32]
}

fn verifier_for(
    destination: &str,
    source: &str,
    key_id: &str,
    public_key: [u8; 32],
    now_ms: i64,
) -> FederationRequestVerifier<StaticPeerKeyStore, InMemoryNonceStore> {
    let mut keys = StaticPeerKeyStore::default();
    keys.insert(FederationPeerKey {
        peer_id: source.to_string(),
        key_id: key_id.to_string(),
        public_key,
        valid_after_ms: None,
        valid_until_ms: None,
    });

    FederationRequestVerifier::new(destination.to_string(), keys, InMemoryNonceStore::default())
        .with_now_ms(now_ms)
}

#[test]
fn signed_request_round_trips_and_binds_method_path_destination_and_body() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let key_id = "ed25519:2026-01";
    let body = br#"{"eventId":"evt-1","kind":"invite.preview"}"#;
    let path_and_query = "/api/federation/v1/events?room=alpha";
    let signer = FederationRequestSigner::from_seed(source, key_id, test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            path_and_query,
            destination,
            body,
            now_ms,
            "nonce-000000000001",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        key_id,
        signer.public_key_bytes(),
        now_ms,
    );

    let verified = verifier
        .verify("POST", path_and_query, &headers, body)
        .expect("signature should verify");

    assert_eq!(verified.source_peer_id.as_str(), source);
    assert_eq!(verified.destination_peer_id.as_str(), destination);
    assert_eq!(verified.key_id.as_str(), key_id);
    assert_eq!(verified.nonce.as_str(), "nonce-000000000001");
}

#[test]
fn signature_identity_extracts_source_and_key_for_lookup() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let key_id = "ed25519:2026-01";
    let signer = FederationRequestSigner::from_seed(source, key_id, test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            "host:b.example",
            b"{}",
            now_ms,
            "nonce-000000000006",
        )
        .expect("request should sign");

    let identity = FederationRequestIdentity::from_headers(&headers)
        .expect("identity headers should parse for key lookup");

    assert_eq!(identity.source_peer_id.as_str(), source);
    assert_eq!(identity.key_id.as_str(), key_id);
}

#[test]
fn signature_verification_can_run_before_durable_nonce_reservation() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let key_id = "ed25519:2026-01";
    let signer = FederationRequestSigner::from_seed(source, key_id, test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000007",
        )
        .expect("request should sign");
    let verifier = verifier_for(
        destination,
        source,
        key_id,
        signer.public_key_bytes(),
        now_ms,
    );

    verifier
        .verify_signature("POST", "/api/federation/v1/events", &headers, b"{}")
        .expect("signature should verify before durable nonce reservation");
    verifier
        .verify_signature("POST", "/api/federation/v1/events", &headers, b"{}")
        .expect("signature-only verification should not reserve nonce");
}

#[test]
fn signed_request_rejects_destination_mismatch() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            "host:b.example",
            b"{}",
            now_ms,
            "nonce-000000000002",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        "host:c.example",
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("wrong destination should fail"),
        VerifyError::DestinationMismatch
    );
}

#[test]
fn signed_request_rejects_body_tampering() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            br#"{"ok":true}"#,
            now_ms,
            "nonce-000000000003",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify(
                "POST",
                "/api/federation/v1/events",
                &headers,
                br#"{"ok":false}"#
            )
            .expect_err("changed body should fail"),
        VerifyError::BodyHashMismatch
    );
}

#[test]
fn signed_request_rejects_method_tampering() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000010",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("GET", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("changed method should fail"),
        VerifyError::InvalidSignature
    );
}

#[test]
fn signed_request_rejects_path_tampering() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000011",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events?spoof=1", &headers, b"{}")
            .expect_err("changed path/query should fail"),
        VerifyError::InvalidSignature
    );
}

#[test]
fn signed_request_rejects_invalid_signature() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let mut headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000008",
        )
        .expect("request should sign");
    headers.insert(
        "x-verdant-federation-signature",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap(),
    );

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("invalid signature should fail"),
        VerifyError::InvalidSignature
    );
}

#[test]
fn signed_request_rejects_unknown_peer_key() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000012",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        "host:other.example",
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("unknown source peer should fail"),
        VerifyError::UnknownPeerKey
    );
}

#[test]
fn signed_request_rejects_key_fingerprint_mismatch() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let other_signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", [7; 32])
        .expect("alternate signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000013",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        other_signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("registered key mismatch should fail"),
        VerifyError::InvalidSignature
    );
}

#[test]
fn signed_request_rejects_replayed_nonce() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000004",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    verifier
        .verify("POST", "/api/federation/v1/events", &headers, b"{}")
        .expect("first request should verify");
    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("second request should be replay"),
        VerifyError::Replay
    );
}

#[test]
fn signed_request_rejects_key_outside_validity_window() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let key_id = "ed25519:2026-01";
    let signer = FederationRequestSigner::from_seed(source, key_id, test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms,
            "nonce-000000000009",
        )
        .expect("request should sign");
    let mut keys = StaticPeerKeyStore::default();
    keys.insert(FederationPeerKey {
        peer_id: source.to_string(),
        key_id: key_id.to_string(),
        public_key: signer.public_key_bytes(),
        valid_after_ms: Some(now_ms + 1),
        valid_until_ms: None,
    });
    let verifier = FederationRequestVerifier::new(
        destination.to_string(),
        keys,
        InMemoryNonceStore::default(),
    )
    .with_now_ms(now_ms);

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("not-yet-valid peer key should fail"),
        VerifyError::KeyOutsideValidityWindow
    );
}

#[test]
fn signed_request_rejects_stale_timestamp() {
    let now_ms = 1_735_689_600_000;
    let source = "host:a.example";
    let destination = "host:b.example";
    let signer = FederationRequestSigner::from_seed(source, "ed25519:2026-01", test_signing_seed())
        .expect("test signing key should be valid");
    let headers = signer
        .sign(
            "POST",
            "/api/federation/v1/events",
            destination,
            b"{}",
            now_ms - 301_000,
            "nonce-000000000005",
        )
        .expect("request should sign");

    let verifier = verifier_for(
        destination,
        source,
        "ed25519:2026-01",
        signer.public_key_bytes(),
        now_ms,
    );

    assert_eq!(
        verifier
            .verify("POST", "/api/federation/v1/events", &headers, b"{}")
            .expect_err("stale timestamp should fail"),
        VerifyError::TimestampOutsideWindow
    );
}
