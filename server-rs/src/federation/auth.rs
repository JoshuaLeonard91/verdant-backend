use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const ALGORITHM: &str = "ed25519-v1";
const CANONICAL_VERSION: &str = "verdant-s2s-v1";
const DEFAULT_MAX_TIMESTAMP_SKEW_MS: i64 = 5 * 60 * 1000;
const MAX_HEADER_VALUE_CHARS: usize = 512;
const MIN_NONCE_CHARS: usize = 16;
const MAX_NONCE_CHARS: usize = 128;
const MAX_PEER_ID_CHARS: usize = 253;
const MAX_KEY_ID_CHARS: usize = 128;

const HEADER_ALGORITHM: &str = "x-verdant-federation-algorithm";
const HEADER_SOURCE: &str = "x-verdant-federation-source";
const HEADER_DESTINATION: &str = "x-verdant-federation-destination";
const HEADER_KEY_ID: &str = "x-verdant-federation-key-id";
const HEADER_TIMESTAMP: &str = "x-verdant-federation-timestamp-ms";
const HEADER_NONCE: &str = "x-verdant-federation-nonce";
const HEADER_BODY_HASH: &str = "x-verdant-federation-content-sha256";
const HEADER_SIGNATURE: &str = "x-verdant-federation-signature";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPeerKey {
    pub peer_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub valid_after_ms: Option<i64>,
    pub valid_until_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFederationRequest {
    pub source_peer_id: String,
    pub destination_peer_id: String,
    pub key_id: String,
    pub nonce: String,
    pub timestamp_ms: i64,
    pub body_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationRequestIdentity {
    pub source_peer_id: String,
    pub key_id: String,
}

impl FederationRequestIdentity {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, VerifyError> {
        let parsed = ParsedHeaders::from_headers(headers)?;
        Ok(Self {
            source_peer_id: parsed.source_peer_id,
            key_id: parsed.key_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("invalid federation signing input")]
    InvalidInput,
    #[error("invalid federation header value")]
    InvalidHeaderValue,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("missing federation signature header")]
    MissingHeader,
    #[error("malformed federation signature header")]
    MalformedHeader,
    #[error("unsupported federation signature algorithm")]
    UnsupportedAlgorithm,
    #[error("federation request destination mismatch")]
    DestinationMismatch,
    #[error("federation request body hash mismatch")]
    BodyHashMismatch,
    #[error("federation request timestamp is outside the allowed window")]
    TimestampOutsideWindow,
    #[error("federation request nonce was already used")]
    Replay,
    #[error("unknown federation peer key")]
    UnknownPeerKey,
    #[error("federation peer key is outside its validity window")]
    KeyOutsideValidityWindow,
    #[error("invalid federation request signature")]
    InvalidSignature,
    #[error("federation replay store unavailable")]
    ReplayStoreUnavailable,
}

pub trait PeerKeyStore {
    fn key_for(&self, peer_id: &str, key_id: &str) -> Option<FederationPeerKey>;
}

pub trait NonceStore {
    fn reserve(&self, peer_id: &str, nonce: &str, timestamp_ms: i64) -> Result<(), VerifyError>;
}

#[derive(Debug, Clone)]
pub struct FederationRequestSigner {
    source_peer_id: String,
    key_id: String,
    signing_key: SigningKey,
}

impl FederationRequestSigner {
    pub fn from_seed(
        source_peer_id: &str,
        key_id: &str,
        seed: [u8; 32],
    ) -> Result<Self, SignError> {
        validate_peer_id(source_peer_id).map_err(|_| SignError::InvalidInput)?;
        validate_key_id(key_id).map_err(|_| SignError::InvalidInput)?;
        Ok(Self {
            source_peer_id: source_peer_id.to_string(),
            key_id: key_id.to_string(),
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(
        &self,
        method: &str,
        path_and_query: &str,
        destination_peer_id: &str,
        body: &[u8],
        timestamp_ms: i64,
        nonce: &str,
    ) -> Result<HeaderMap, SignError> {
        validate_method(method).map_err(|_| SignError::InvalidInput)?;
        validate_path_and_query(path_and_query).map_err(|_| SignError::InvalidInput)?;
        validate_peer_id(destination_peer_id).map_err(|_| SignError::InvalidInput)?;
        validate_nonce(nonce).map_err(|_| SignError::InvalidInput)?;
        if timestamp_ms <= 0 {
            return Err(SignError::InvalidInput);
        }

        let body_sha256 = body_sha256(body);
        let canonical = canonical_request(
            method,
            path_and_query,
            &self.source_peer_id,
            destination_peer_id,
            &self.key_id,
            timestamp_ms,
            nonce,
            &body_sha256,
        );
        let signature: Signature = self.signing_key.sign(canonical.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut headers = HeaderMap::new();
        insert_header(&mut headers, HEADER_ALGORITHM, ALGORITHM)?;
        insert_header(&mut headers, HEADER_SOURCE, &self.source_peer_id)?;
        insert_header(&mut headers, HEADER_DESTINATION, destination_peer_id)?;
        insert_header(&mut headers, HEADER_KEY_ID, &self.key_id)?;
        insert_header(&mut headers, HEADER_TIMESTAMP, &timestamp_ms.to_string())?;
        insert_header(&mut headers, HEADER_NONCE, nonce)?;
        insert_header(&mut headers, HEADER_BODY_HASH, &body_sha256)?;
        insert_header(&mut headers, HEADER_SIGNATURE, &signature)?;
        Ok(headers)
    }
}

#[derive(Debug)]
pub struct FederationRequestVerifier<K, N> {
    destination_peer_id: String,
    key_store: K,
    nonce_store: N,
    now_ms: Option<i64>,
    max_timestamp_skew_ms: i64,
}

impl<K, N> FederationRequestVerifier<K, N>
where
    K: PeerKeyStore,
    N: NonceStore,
{
    pub fn new(destination_peer_id: String, key_store: K, nonce_store: N) -> Self {
        Self {
            destination_peer_id,
            key_store,
            nonce_store,
            now_ms: None,
            max_timestamp_skew_ms: DEFAULT_MAX_TIMESTAMP_SKEW_MS,
        }
    }

    pub fn with_now_ms(mut self, now_ms: i64) -> Self {
        self.now_ms = Some(now_ms);
        self
    }

    pub fn verify(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<VerifiedFederationRequest, VerifyError> {
        let verified = self.verify_signature(method, path_and_query, headers, body)?;
        self.nonce_store.reserve(
            &verified.source_peer_id,
            &verified.nonce,
            verified.timestamp_ms,
        )?;

        tracing::info!(
            source_peer_id = %verified.source_peer_id,
            destination_peer_id = %verified.destination_peer_id,
            key_id = %verified.key_id,
            timestamp_ms = verified.timestamp_ms,
            "Federation request signature accepted"
        );

        Ok(verified)
    }

    pub fn verify_signature(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<VerifiedFederationRequest, VerifyError> {
        validate_method(method).map_err(|_| VerifyError::MalformedHeader)?;
        validate_path_and_query(path_and_query).map_err(|_| VerifyError::MalformedHeader)?;

        let parsed = ParsedHeaders::from_headers(headers)?;
        if parsed.algorithm != ALGORITHM {
            tracing::warn!(
                algorithm = %parsed.algorithm,
                "Federation request rejected: unsupported signature algorithm"
            );
            return Err(VerifyError::UnsupportedAlgorithm);
        }
        if parsed.destination_peer_id != self.destination_peer_id {
            tracing::warn!(
                source_peer_id = %parsed.source_peer_id,
                destination_peer_id = %parsed.destination_peer_id,
                expected_destination_peer_id = %self.destination_peer_id,
                "Federation request rejected: destination mismatch"
            );
            return Err(VerifyError::DestinationMismatch);
        }

        let actual_body_hash = body_sha256(body);
        if parsed.body_sha256 != actual_body_hash {
            tracing::warn!(
                source_peer_id = %parsed.source_peer_id,
                key_id = %parsed.key_id,
                "Federation request rejected: body hash mismatch"
            );
            return Err(VerifyError::BodyHashMismatch);
        }

        let now_ms = self
            .now_ms
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        if (now_ms - parsed.timestamp_ms).abs() > self.max_timestamp_skew_ms {
            tracing::warn!(
                source_peer_id = %parsed.source_peer_id,
                key_id = %parsed.key_id,
                timestamp_ms = parsed.timestamp_ms,
                now_ms,
                "Federation request rejected: timestamp outside allowed window"
            );
            return Err(VerifyError::TimestampOutsideWindow);
        }

        let key = self
            .key_store
            .key_for(&parsed.source_peer_id, &parsed.key_id)
            .ok_or_else(|| {
                tracing::warn!(
                    source_peer_id = %parsed.source_peer_id,
                    key_id = %parsed.key_id,
                    "Federation request rejected: unknown peer key"
                );
                VerifyError::UnknownPeerKey
            })?;
        if key
            .valid_after_ms
            .is_some_and(|valid_after| parsed.timestamp_ms < valid_after)
            || key
                .valid_until_ms
                .is_some_and(|valid_until| parsed.timestamp_ms >= valid_until)
        {
            tracing::warn!(
                source_peer_id = %parsed.source_peer_id,
                key_id = %parsed.key_id,
                "Federation request rejected: key outside validity window"
            );
            return Err(VerifyError::KeyOutsideValidityWindow);
        }

        let canonical = canonical_request(
            method,
            path_and_query,
            &parsed.source_peer_id,
            &parsed.destination_peer_id,
            &parsed.key_id,
            parsed.timestamp_ms,
            &parsed.nonce,
            &parsed.body_sha256,
        );
        let verifying_key =
            VerifyingKey::from_bytes(&key.public_key).map_err(|_| VerifyError::UnknownPeerKey)?;
        let signature = decode_signature(&parsed.signature)?;
        verifying_key
            .verify(canonical.as_bytes(), &signature)
            .map_err(|_| {
                tracing::warn!(
                    source_peer_id = %parsed.source_peer_id,
                    key_id = %parsed.key_id,
                    "Federation request rejected: invalid signature"
                );
                VerifyError::InvalidSignature
            })?;

        Ok(VerifiedFederationRequest {
            source_peer_id: parsed.source_peer_id,
            destination_peer_id: parsed.destination_peer_id,
            key_id: parsed.key_id,
            nonce: parsed.nonce,
            timestamp_ms: parsed.timestamp_ms,
            body_sha256: parsed.body_sha256,
        })
    }
}

#[derive(Debug, Default)]
pub struct StaticPeerKeyStore {
    keys: HashMap<(String, String), FederationPeerKey>,
}

impl StaticPeerKeyStore {
    pub fn insert(&mut self, key: FederationPeerKey) {
        self.keys
            .insert((key.peer_id.clone(), key.key_id.clone()), key);
    }
}

impl PeerKeyStore for StaticPeerKeyStore {
    fn key_for(&self, peer_id: &str, key_id: &str) -> Option<FederationPeerKey> {
        self.keys
            .get(&(peer_id.to_string(), key_id.to_string()))
            .cloned()
    }
}

#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    seen: Mutex<HashSet<String>>,
}

impl NonceStore for InMemoryNonceStore {
    fn reserve(&self, peer_id: &str, nonce: &str, _timestamp_ms: i64) -> Result<(), VerifyError> {
        let key = format!("{peer_id}:{nonce}");
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| VerifyError::ReplayStoreUnavailable)?;
        if !seen.insert(key) {
            return Err(VerifyError::Replay);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ParsedHeaders {
    algorithm: String,
    source_peer_id: String,
    destination_peer_id: String,
    key_id: String,
    timestamp_ms: i64,
    nonce: String,
    body_sha256: String,
    signature: String,
}

impl ParsedHeaders {
    fn from_headers(headers: &HeaderMap) -> Result<Self, VerifyError> {
        let algorithm = required_header(headers, HEADER_ALGORITHM)?;
        let source_peer_id = required_header(headers, HEADER_SOURCE)?;
        let destination_peer_id = required_header(headers, HEADER_DESTINATION)?;
        let key_id = required_header(headers, HEADER_KEY_ID)?;
        let timestamp_ms = required_header(headers, HEADER_TIMESTAMP)?
            .parse::<i64>()
            .map_err(|_| VerifyError::MalformedHeader)?;
        let nonce = required_header(headers, HEADER_NONCE)?;
        let body_sha256 = required_header(headers, HEADER_BODY_HASH)?;
        let signature = required_header(headers, HEADER_SIGNATURE)?;

        validate_peer_id(&source_peer_id).map_err(|_| VerifyError::MalformedHeader)?;
        validate_peer_id(&destination_peer_id).map_err(|_| VerifyError::MalformedHeader)?;
        validate_key_id(&key_id).map_err(|_| VerifyError::MalformedHeader)?;
        validate_nonce(&nonce).map_err(|_| VerifyError::MalformedHeader)?;
        if timestamp_ms <= 0 || body_sha256.len() != 43 {
            return Err(VerifyError::MalformedHeader);
        }

        Ok(Self {
            algorithm,
            source_peer_id,
            destination_peer_id,
            key_id,
            timestamp_ms,
            nonce,
            body_sha256,
            signature,
        })
    }
}

fn body_sha256(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    URL_SAFE_NO_PAD.encode(digest)
}

fn canonical_request(
    method: &str,
    path_and_query: &str,
    source_peer_id: &str,
    destination_peer_id: &str,
    key_id: &str,
    timestamp_ms: i64,
    nonce: &str,
    body_sha256: &str,
) -> String {
    [
        CANONICAL_VERSION.to_string(),
        method.to_ascii_uppercase(),
        path_and_query.to_string(),
        source_peer_id.to_string(),
        destination_peer_id.to_string(),
        key_id.to_string(),
        timestamp_ms.to_string(),
        nonce.to_string(),
        body_sha256.to_string(),
    ]
    .join("\n")
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), SignError> {
    let value = HeaderValue::from_str(value).map_err(|_| SignError::InvalidHeaderValue)?;
    headers.insert(name, value);
    Ok(())
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, VerifyError> {
    let value = headers
        .get(name)
        .ok_or(VerifyError::MissingHeader)?
        .to_str()
        .map_err(|_| VerifyError::MalformedHeader)?
        .trim();
    if value.is_empty() || value.len() > MAX_HEADER_VALUE_CHARS {
        return Err(VerifyError::MalformedHeader);
    }
    Ok(value.to_string())
}

fn decode_signature(value: &str) -> Result<Signature, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VerifyError::MalformedHeader)?;
    Signature::try_from(bytes.as_slice()).map_err(|_| VerifyError::MalformedHeader)
}

fn validate_method(value: &str) -> Result<(), ()> {
    let valid = !value.is_empty()
        && value.len() <= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-');
    valid.then_some(()).ok_or(())
}

fn validate_path_and_query(value: &str) -> Result<(), ()> {
    let valid = value.starts_with('/')
        && value.len() <= 2048
        && !value.contains('\r')
        && !value.contains('\n');
    valid.then_some(()).ok_or(())
}

fn validate_peer_id(value: &str) -> Result<(), ()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_PEER_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'));
    valid.then_some(()).ok_or(())
}

fn validate_key_id(value: &str) -> Result<(), ()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_KEY_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'));
    valid.then_some(()).ok_or(())
}

fn validate_nonce(value: &str) -> Result<(), ()> {
    let valid = (MIN_NONCE_CHARS..=MAX_NONCE_CHARS).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    valid.then_some(()).ok_or(())
}
