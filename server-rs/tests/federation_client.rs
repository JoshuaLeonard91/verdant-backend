use axum::{
    Router,
    http::{StatusCode, header::LOCATION},
    routing::any,
};
use reqwest::Method;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use verdant_server::federation::{
    auth::{FederationRequestSigner, FederationRequestVerifier, InMemoryNonceStore},
    client::{FederationHttpClient, FederationPeerEndpoint},
};

mod support {
    use verdant_server::federation::auth::{FederationPeerKey, StaticPeerKeyStore};

    pub fn key_store(source: &str, key_id: &str, public_key: [u8; 32]) -> StaticPeerKeyStore {
        let mut keys = StaticPeerKeyStore::default();
        keys.insert(FederationPeerKey {
            peer_id: source.to_string(),
            key_id: key_id.to_string(),
            public_key,
            valid_after_ms: None,
            valid_until_ms: None,
        });
        keys
    }
}

#[test]
fn outbound_client_builds_signed_json_request_for_peer() {
    let now_ms = 1_735_689_600_000;
    let signer = FederationRequestSigner::from_seed("host:a.example", "ed25519:2026-01", [43; 32])
        .expect("test signing key should be valid");
    let public_key = signer.public_key_bytes();
    let client = FederationHttpClient::new(reqwest::Client::new(), signer);
    let peer = FederationPeerEndpoint {
        peer_id: "host:b.example".to_string(),
        api_origin: "https://b.example".to_string(),
    };
    let request = client
        .signed_json_request(
            Method::POST,
            &peer,
            "/api/federation/v1/events",
            br#"{"eventId":"evt-1"}"#.to_vec(),
            now_ms,
            "nonce-000000000101",
        )
        .expect("request should build");

    assert_eq!(request.method(), Method::POST);
    assert_eq!(
        request.url().as_str(),
        "https://b.example/api/federation/v1/events"
    );
    assert_eq!(
        request.headers().get("content-type").unwrap(),
        "application/json"
    );

    let verifier = FederationRequestVerifier::new(
        "host:b.example".to_string(),
        support::key_store("host:a.example", "ed25519:2026-01", public_key),
        InMemoryNonceStore::default(),
    )
    .with_now_ms(now_ms);
    let body = request
        .body()
        .expect("request should have a body")
        .as_bytes()
        .expect("body should be buffered");

    verifier
        .verify("POST", "/api/federation/v1/events", request.headers(), body)
        .expect("outbound request should verify");
}

#[test]
fn outbound_client_allows_peer_subdomain_api_origin() {
    let signer = FederationRequestSigner::from_seed("host:a.example", "ed25519:2026-01", [43; 32])
        .expect("test signing key should be valid");
    let client = FederationHttpClient::new(reqwest::Client::new(), signer);
    let peer = FederationPeerEndpoint {
        peer_id: "host:community.dev".to_string(),
        api_origin: "https://api.community.dev".to_string(),
    };

    let request = client
        .signed_json_request(
            Method::POST,
            &peer,
            "/api/federation/v1/events",
            b"{}".to_vec(),
            1_735_689_600_000,
            "nonce-000000000104",
        )
        .expect("peer subdomain api origin should be accepted");

    assert_eq!(
        request.url().as_str(),
        "https://api.community.dev/api/federation/v1/events"
    );
}

#[test]
fn outbound_client_rejects_lookalike_origin_for_peer_identity() {
    let signer = FederationRequestSigner::from_seed("host:a.example", "ed25519:2026-01", [43; 32])
        .expect("test signing key should be valid");
    let client = FederationHttpClient::new(reqwest::Client::new(), signer);

    for api_origin in [
        "https://api.verdant.chat.evil.com",
        "https://verdant.chat.evil.com",
        "https://api-community.dev",
    ] {
        let peer = FederationPeerEndpoint {
            peer_id: "host:verdant.chat".to_string(),
            api_origin: api_origin.to_string(),
        };

        assert!(
            client
                .signed_json_request(
                    Method::POST,
                    &peer,
                    "/api/federation/v1/events",
                    b"{}".to_vec(),
                    1_735_689_600_000,
                    "nonce-000000000105",
                )
                .is_err(),
            "lookalike origin should be rejected: {api_origin}"
        );
    }
}

#[test]
fn outbound_client_rejects_peer_origin_with_path_or_credentials() {
    let signer = FederationRequestSigner::from_seed("host:a.example", "ed25519:2026-01", [43; 32])
        .expect("test signing key should be valid");
    let client = FederationHttpClient::new(reqwest::Client::new(), signer);

    for api_origin in [
        "https://b.example/base",
        "https://user:pass@b.example",
        "file:///tmp/federation",
    ] {
        let peer = FederationPeerEndpoint {
            peer_id: "host:b.example".to_string(),
            api_origin: api_origin.to_string(),
        };

        assert!(
            client
                .signed_json_request(
                    Method::POST,
                    &peer,
                    "/api/federation/v1/events",
                    b"{}".to_vec(),
                    1_735_689_600_000,
                    "nonce-000000000102",
                )
                .is_err(),
            "unsafe origin should be rejected: {api_origin}"
        );
    }
}

#[test]
fn outbound_client_rejects_private_https_peer_origins() {
    let signer = FederationRequestSigner::from_seed("host:a.example", "ed25519:2026-01", [43; 32])
        .expect("test signing key should be valid");
    let client = FederationHttpClient::new(reqwest::Client::new(), signer);

    for api_origin in [
        "https://localhost",
        "https://127.0.0.1",
        "https://10.0.0.5",
        "https://192.168.1.10",
        "https://[::1]",
        "https://[fd00::1]",
    ] {
        let peer = FederationPeerEndpoint {
            peer_id: "host:b.example".to_string(),
            api_origin: api_origin.to_string(),
        };

        assert!(
            client
                .signed_json_request(
                    Method::POST,
                    &peer,
                    "/api/federation/v1/events",
                    b"{}".to_vec(),
                    1_735_689_600_000,
                    "nonce-000000000103",
                )
                .is_err(),
            "private HTTPS peer origin should be rejected: {api_origin}"
        );
    }
}

#[tokio::test]
async fn outbound_client_does_not_follow_peer_redirects() {
    let redirected_hits = Arc::new(AtomicUsize::new(0));

    let redirected_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("redirect target listener should bind");
    let redirected_addr = redirected_listener
        .local_addr()
        .expect("redirect target address should be available");
    let redirected_hits_for_route = redirected_hits.clone();
    let redirected_app = Router::new().route(
        "/private-metadata",
        any(move || {
            let redirected_hits = redirected_hits_for_route.clone();
            async move {
                redirected_hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );
    let redirected_server = tokio::spawn(async move {
        axum::serve(redirected_listener, redirected_app)
            .await
            .expect("redirect target server should run")
    });

    let peer_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("peer listener should bind");
    let peer_addr = peer_listener
        .local_addr()
        .expect("peer address should be available");
    let redirect_location = format!("http://{redirected_addr}/private-metadata");
    let peer_app = Router::new().route(
        "/api/federation/v1/events",
        any(move || {
            let redirect_location = redirect_location.clone();
            async move { (StatusCode::FOUND, [(LOCATION, redirect_location)]) }
        }),
    );
    let peer_server = tokio::spawn(async move {
        axum::serve(peer_listener, peer_app)
            .await
            .expect("peer server should run")
    });

    let signer = FederationRequestSigner::from_seed("host:a.example", "ed25519:2026-01", [43; 32])
        .expect("test signing key should be valid");
    let client = FederationHttpClient::with_timeout(Duration::from_secs(5), signer)
        .expect("federation client should build");
    let peer = FederationPeerEndpoint {
        peer_id: "test-peer".to_string(),
        api_origin: format!("http://{peer_addr}"),
    };

    let response = client
        .send_signed_json_request(
            Method::POST,
            &peer,
            "/api/federation/v1/events",
            b"{}".to_vec(),
            1_735_689_600_000,
            "nonce-000000000106",
        )
        .await
        .expect("redirect response should be returned to caller");

    assert_eq!(response.status(), StatusCode::FOUND);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        redirected_hits.load(Ordering::SeqCst),
        0,
        "federation S2S clients must not follow peer redirects"
    );

    peer_server.abort();
    redirected_server.abort();
}
