use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::Deserialize;
use verdant_server::services::crypto::generate_federated_client_access_token;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claims {
    user_id: String,
    iss: String,
    aud: String,
    typ: String,
    sid: Option<i64>,
    home_peer_id: String,
    remote_user_id: String,
    server_ids: Vec<String>,
}

#[test]
fn federated_client_access_token_is_not_a_normal_session_token() {
    let token = generate_federated_client_access_token(
        9001,
        "test-secret",
        "host:target.example.com",
        "host:home.example.com",
        "42",
        &[1234],
        chrono::Duration::minutes(10),
    )
    .expect("token should be generated");

    let mut validation = Validation::default();
    validation.set_issuer(&["verdant"]);
    validation.set_audience(&["host:target.example.com"]);
    let decoded = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"test-secret"),
        &validation,
    )
    .expect("token should decode");

    assert_eq!(decoded.claims.user_id, "9001");
    assert_eq!(decoded.claims.iss, "verdant");
    assert_eq!(decoded.claims.aud, "host:target.example.com");
    assert_eq!(decoded.claims.typ, "federated_client");
    assert_eq!(decoded.claims.sid, None);
    assert_eq!(decoded.claims.home_peer_id, "host:home.example.com");
    assert_eq!(decoded.claims.remote_user_id, "42");
    assert_eq!(decoded.claims.server_ids, vec!["1234".to_string()]);
}
