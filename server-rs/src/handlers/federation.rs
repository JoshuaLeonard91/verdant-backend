use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
};
use fred::interfaces::{HashesInterface, KeysInterface, SetsInterface};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, str::FromStr};
use url::Url;

use super::extract_client_ip;
use crate::config::{InstanceMode, UploadPolicy};
use crate::error::{AppError, AppResult};
use crate::federation::{
    auth::{
        FederationRequestIdentity, FederationRequestVerifier, InMemoryNonceStore,
        StaticPeerKeyStore, VerifyError,
    },
    ingress::{FederationIngressError, validate_ingress_envelope},
    ownership::runtime_propagation_allowed,
    protocol::{FederationProtocolError, ParsedFederationEnvelope},
    runtime::{FederationRuntimeCommand, FederationRuntimeError, command_from_envelope},
    storage as federation_storage,
};
use crate::middleware::rate_limit;
use crate::services::{instance, pg};
use crate::state::AppState;

const MAX_DISCOVERY_LIMIT: i64 = 50;
const DEFAULT_DISCOVERY_LIMIT: i64 = 25;
const MAX_DISPLAY_NAME_CHARS: usize = 120;
const MAX_DESCRIPTION_CHARS: usize = 512;
const MAX_VERSION_CHARS: usize = 64;
const MAX_PUBLIC_KEY_CHARS: usize = 4096;
const MAX_INVITE_URL_CHARS: usize = 2048;
const FEDERATION_ADMIN_BODY_LIMIT_BYTES: usize = 64 * 1024;
const FEDERATION_RUNTIME_BODY_LIMIT_BYTES: usize = 64 * 1024;
const FEDERATION_ADMIN_NONCE_TTL_SECS: i64 = 120;
const FEDERATION_ADMIN_CREATE_PATH: &str = "/api/admin/federation/instances";
const MAX_INSTANCE_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_INSTANCE_VOICE_BITRATE: u64 = 512_000;
const MAX_FEDERATION_MEMBERS_PER_SERVER: i64 = 10_000;
const FEDERATION_CHANNEL_TYPE_SERVER_TEXT: i32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryStatus {
    Pending,
    Verified,
    Revoked,
    Rejected,
}

impl RegistryStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
        }
    }
}

impl FromStr for RegistryStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "revoked" => Ok(Self::Revoked),
            "rejected" => Ok(Self::Rejected),
            _ => Err("status must be pending, verified, revoked, or rejected".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerificationMethod {
    DnsTxt,
    HttpWellKnown,
}

impl VerificationMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::DnsTxt => "dns_txt",
            Self::HttpWellKnown => "http_well_known",
        }
    }
}

impl Default for VerificationMethod {
    fn default() -> Self {
        Self::DnsTxt
    }
}

impl FromStr for VerificationMethod {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dns_txt" => Ok(Self::DnsTxt),
            "http_well_known" => Ok(Self::HttpWellKnown),
            _ => Err("verificationMethod must be dns_txt or http_well_known".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationVerificationChallenge {
    pub dns_txt_name: String,
    pub dns_txt_value: String,
    pub http_url: String,
    pub http_body: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationDiscoveryInstance {
    pub id: String,
    pub domain: String,
    pub display_name: String,
    pub api_url: String,
    pub public_url: String,
    pub mode: String,
    pub status: String,
    pub discovery_description: Option<String>,
    pub invite_url: Option<String>,
    pub server_version: Option<String>,
    pub min_client_version: Option<String>,
    pub upload_policy: Option<String>,
    pub content_scanning: Value,
    pub capabilities: Value,
    pub public_key_fingerprint: Option<String>,
    pub verified_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationDiscoveryResponse {
    pub source: &'static str,
    pub instances: Vec<FederationDiscoveryInstance>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationManifest {
    pub instance_id: String,
    pub registry_trust: &'static str,
    pub name: String,
    pub domain: String,
    pub mode: &'static str,
    pub server_version: &'static str,
    pub min_client_version: String,
    pub public_url: String,
    pub api_url: String,
    pub ws_url: String,
    pub docs_url: String,
    pub upload_policy: &'static str,
    pub content_scanning: instance::ContentScanningMetadata,
    pub capabilities: crate::config::LocalCapabilities,
    pub public_key: Option<String>,
    pub public_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FederationRegistryAdminInstance {
    pub id: String,
    pub domain: String,
    pub display_name: String,
    pub api_url: String,
    pub public_url: String,
    pub mode: String,
    pub status: String,
    pub public_discovery: bool,
    pub discovery_description: Option<String>,
    pub invite_url: Option<String>,
    pub server_version: Option<String>,
    pub min_client_version: Option<String>,
    pub upload_policy: Option<String>,
    pub content_scanning: Value,
    pub capabilities: Value,
    pub public_key: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub verification_method: String,
    pub verified_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationRegistryAdminResponse {
    instance: FederationRegistryAdminInstance,
    verification_challenge: Option<FederationVerificationChallenge>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRegistryInstanceRequest {
    domain: String,
    display_name: String,
    api_url: String,
    public_url: String,
    #[serde(default = "default_selfhost_registry_mode")]
    mode: String,
    #[serde(default)]
    public_discovery: bool,
    discovery_description: Option<String>,
    invite_url: Option<String>,
    server_version: Option<String>,
    min_client_version: Option<String>,
    upload_policy: Option<String>,
    #[serde(default)]
    content_scanning: Option<Value>,
    #[serde(default)]
    capabilities: Option<Value>,
    public_key: Option<String>,
    #[serde(default)]
    verification_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UpdateRegistryInstanceRequest {
    domain: Option<String>,
    display_name: Option<String>,
    api_url: Option<String>,
    public_url: Option<String>,
    mode: Option<String>,
    status: Option<String>,
    public_discovery: Option<bool>,
    discovery_description: Option<Option<String>>,
    invite_url: Option<Option<String>>,
    server_version: Option<Option<String>>,
    min_client_version: Option<Option<String>>,
    upload_policy: Option<Option<String>>,
    content_scanning: Option<Value>,
    capabilities: Option<Value>,
    public_key: Option<Option<String>>,
    verification_method: Option<String>,
    #[serde(default)]
    rotate_verification_token: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryQuery {
    q: Option<String>,
    limit: Option<i64>,
}

fn default_selfhost_registry_mode() -> String {
    "standalone".to_string()
}

fn bad_request(message: impl Into<String>) -> AppError {
    AppError::Validation(message.into())
}

fn registry_not_configured() -> AppError {
    AppError::WithCode {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "FEDERATION_REGISTRY_NOT_CONFIGURED",
        message: "Federation registry admin is not configured".into(),
    }
}

fn ensure_official_registry_admin(state: &AppState) -> AppResult<&str> {
    if state.config.instance_mode != InstanceMode::Official
        || !state.config.federation_registry_admin_enabled
    {
        return Err(AppError::NotFound("federation registry"));
    }

    state
        .config
        .federation_registry_admin_secret
        .as_deref()
        .filter(|secret| !secret.trim().is_empty())
        .ok_or_else(registry_not_configured)
}

fn is_reserved_registry_tld(tld: &str) -> bool {
    matches!(tld, "example" | "invalid" | "local" | "localhost" | "test")
}

pub fn normalize_registry_domain(raw: &str) -> AppResult<String> {
    let value = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return Err(bad_request("Invalid registry domain"));
    }
    if value.contains("://")
        || value.contains('/')
        || value.contains('\\')
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.contains(':')
        || value.contains('*')
        || value.chars().any(char::is_whitespace)
        || value.chars().any(|c| !c.is_ascii())
    {
        return Err(bad_request("Registry domain must be a public hostname"));
    }
    if value == "localhost" || value.parse::<std::net::IpAddr>().is_ok() || !value.contains('.') {
        return Err(bad_request("Registry domain must be a public hostname"));
    }

    let labels: Vec<&str> = value.split('.').collect();
    let tld = labels.last().copied().unwrap_or_default();
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(bad_request("Registry domain must use a public DNS suffix"));
    }
    if is_reserved_registry_tld(tld) {
        return Err(bad_request("Registry domain must use a public DNS suffix"));
    }

    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(bad_request("Registry domain must be a public hostname"));
        }
    }

    Ok(value)
}

pub fn normalize_registry_origin(raw: &str) -> AppResult<String> {
    let parsed = Url::parse(raw.trim()).map_err(|_| bad_request("Invalid registry URL"))?;
    if parsed.scheme() != "https" {
        return Err(bad_request("Registry URL must use https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad_request("Registry URL must not include credentials"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| bad_request("Registry URL must include a host"))?;
    let _ = normalize_registry_domain(host)?;
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad_request(
            "Registry URL must be an origin without path or query",
        ));
    }

    let mut origin = format!("https://{host}");
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn normalize_registry_invite_url(raw: Option<String>, domain: &str) -> AppResult<Option<String>> {
    let Some(value) = sanitize_optional_text(raw, MAX_INVITE_URL_CHARS)? else {
        return Ok(None);
    };
    let parsed = Url::parse(&value).map_err(|_| bad_request("Invalid invite URL"))?;
    if parsed.scheme() != "https" {
        return Err(bad_request("Invite URL must use https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(bad_request(
            "Invite URL must not include credentials or fragments",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| bad_request("Invite URL must include a host"))?
        .trim()
        .to_ascii_lowercase();
    let host = normalize_registry_domain(&host)?;
    if !host_matches_domain(&host, domain) {
        return Err(bad_request("Invite URL must be on the registered domain"));
    }
    Ok(Some(value))
}

fn sanitize_optional_text(raw: Option<String>, max_chars: usize) -> AppResult<Option<String>> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let clean = crate::services::sanitize::sanitize_text(&value);
    if clean.is_empty() {
        return Ok(None);
    }
    if clean.chars().count() > max_chars {
        return Err(bad_request("Field is too long"));
    }
    Ok(Some(clean))
}

fn sanitize_required_text(raw: String, max_chars: usize, field: &str) -> AppResult<String> {
    let clean = crate::services::sanitize::sanitize_text(&raw);
    if clean.is_empty() {
        return Err(bad_request(format!("{field} is required")));
    }
    if clean.chars().count() > max_chars {
        return Err(bad_request(format!("{field} is too long")));
    }
    Ok(clean)
}

fn normalize_registry_mode(raw: &str) -> AppResult<String> {
    let mode = raw
        .parse::<InstanceMode>()
        .map_err(|_| bad_request("Invalid registry mode"))?;
    match mode {
        InstanceMode::Standalone | InstanceMode::Linked | InstanceMode::Federated => {
            Ok(mode.as_str().to_string())
        }
        InstanceMode::Official => Err(bad_request(
            "Self-host registry records cannot claim official mode",
        )),
    }
}

fn normalize_registry_upload_policy(raw: Option<String>) -> AppResult<Option<String>> {
    let Some(value) = sanitize_optional_text(raw, MAX_VERSION_CHARS)? else {
        return Ok(None);
    };
    let parsed = value
        .parse::<UploadPolicy>()
        .map_err(|_| bad_request("Invalid upload policy"))?;
    Ok(Some(parsed.as_str().to_string()))
}

fn normalize_json_object(value: Option<Value>) -> AppResult<Value> {
    let value = value.unwrap_or_else(|| json!({}));
    if !value.is_object() {
        return Err(bad_request("Federation metadata must be a JSON object"));
    }
    Ok(value)
}

fn normalize_content_scanning(value: Option<Value>) -> AppResult<Value> {
    let value = value.unwrap_or_else(|| json!({ "provider": "none", "enabled": false }));
    let Some(object) = value.as_object() else {
        return Err(bad_request("contentScanning must be a JSON object"));
    };

    let provider = object
        .get("provider")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|provider| !provider.is_empty())
        .unwrap_or("none")
        .to_ascii_lowercase();
    if provider.len() > 64
        || !provider
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
    {
        return Err(bad_request("contentScanning.provider is invalid"));
    }
    let enabled = object
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(json!({ "provider": provider, "enabled": enabled }))
}

fn normalize_capabilities(value: Option<Value>) -> AppResult<Value> {
    let value = normalize_json_object(value)?;
    let object = value
        .as_object()
        .expect("normalize_json_object returned an object");
    let mut public = Map::new();

    for key in [
        "imageUploads",
        "fileSharing",
        "messageAttachments",
        "voiceChat",
        "videoStreaming",
        "crossServerEmoji",
        "animatedAvatar",
        "animatedBanner",
        "memberListBanner",
    ] {
        if let Some(value) = object.get(key) {
            let flag = value
                .as_bool()
                .ok_or_else(|| bad_request(format!("capabilities.{key} must be a boolean")))?;
            public.insert(key.to_string(), Value::Bool(flag));
        }
    }

    for (key, max) in [
        ("maxUploadBytes", MAX_INSTANCE_UPLOAD_BYTES),
        ("maxVoiceBitrate", MAX_INSTANCE_VOICE_BITRATE),
    ] {
        if let Some(value) = object.get(key) {
            let amount = value
                .as_u64()
                .filter(|amount| *amount <= max)
                .ok_or_else(|| bad_request(format!("capabilities.{key} is invalid")))?;
            public.insert(key.to_string(), Value::from(amount));
        }
    }

    Ok(Value::Object(public))
}

fn normalize_public_key(raw: Option<String>) -> AppResult<Option<String>> {
    let Some(value) = raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if value.to_ascii_uppercase().contains("PRIVATE KEY") {
        return Err(bad_request(
            "FEDERATION_PUBLIC_KEY must contain public key material",
        ));
    }
    if value.chars().count() > MAX_PUBLIC_KEY_CHARS
        || value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(bad_request("Invalid public key"));
    }
    Ok(Some(value))
}

fn apply_registry_identity_guard(
    status: RegistryStatus,
    public_discovery: bool,
    identity_changed: bool,
) -> (RegistryStatus, bool) {
    if !identity_changed {
        return (status, public_discovery);
    }

    match status {
        RegistryStatus::Verified | RegistryStatus::Pending => (RegistryStatus::Pending, false),
        RegistryStatus::Revoked | RegistryStatus::Rejected => (status, public_discovery),
    }
}

pub fn public_key_fingerprint(public_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.trim().as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_verification_token() -> String {
    let token: [u8; 32] = rand::random();
    hex::encode(token)
}

fn federation_admin_instance_path(instance_id: &str) -> String {
    format!("{FEDERATION_ADMIN_CREATE_PATH}/{instance_id}")
}

async fn read_federation_admin_body(body: Body) -> AppResult<Bytes> {
    to_bytes(body, FEDERATION_ADMIN_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| AppError::WithCode {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "FEDERATION_ADMIN_BODY_TOO_LARGE",
            message: "Federation registry admin request body is too large".into(),
        })
}

async fn read_federation_runtime_body(body: Body) -> AppResult<Bytes> {
    to_bytes(body, FEDERATION_RUNTIME_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| AppError::WithCode {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "FEDERATION_EVENT_BODY_TOO_LARGE",
            message: "Federation event body is too large".into(),
        })
}

fn federation_verify_error(error: VerifyError) -> AppError {
    let code = match error {
        VerifyError::MissingHeader | VerifyError::MalformedHeader => {
            "FEDERATION_INVALID_SIGNATURE_HEADERS"
        }
        VerifyError::UnsupportedAlgorithm => "FEDERATION_UNSUPPORTED_SIGNATURE_ALGORITHM",
        VerifyError::DestinationMismatch => "FEDERATION_DESTINATION_MISMATCH",
        VerifyError::BodyHashMismatch => "FEDERATION_BODY_HASH_MISMATCH",
        VerifyError::TimestampOutsideWindow => "FEDERATION_TIMESTAMP_EXPIRED",
        VerifyError::Replay => "FEDERATION_REPLAY_REJECTED",
        VerifyError::UnknownPeerKey => "FEDERATION_UNKNOWN_PEER_KEY",
        VerifyError::KeyOutsideValidityWindow => "FEDERATION_KEY_NOT_VALID",
        VerifyError::InvalidSignature => "FEDERATION_INVALID_SIGNATURE",
        VerifyError::ReplayStoreUnavailable => "FEDERATION_REPLAY_STORE_UNAVAILABLE",
    };
    let status = match error {
        VerifyError::ReplayStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        VerifyError::MissingHeader
        | VerifyError::MalformedHeader
        | VerifyError::UnsupportedAlgorithm => StatusCode::BAD_REQUEST,
        _ => StatusCode::UNAUTHORIZED,
    };
    AppError::WithCode {
        status,
        code,
        message: "Federation request was rejected".into(),
    }
}

fn federation_protocol_error(error: FederationProtocolError) -> AppError {
    let code = match error {
        FederationProtocolError::MalformedJson => "FEDERATION_EVENT_MALFORMED_JSON",
        FederationProtocolError::UnsupportedVersion => "FEDERATION_UNSUPPORTED_PROTOCOL_VERSION",
        FederationProtocolError::UnknownEventKind => "FEDERATION_UNKNOWN_EVENT_KIND",
        FederationProtocolError::InvalidEnvelope => "FEDERATION_INVALID_EVENT_ENVELOPE",
        FederationProtocolError::InvalidPayload => "FEDERATION_INVALID_EVENT_PAYLOAD",
    };
    AppError::WithCode {
        status: StatusCode::BAD_REQUEST,
        code,
        message: "Federation event envelope was rejected".into(),
    }
}

fn federation_ingress_error(error: FederationIngressError) -> AppError {
    let code = match error {
        FederationIngressError::SourceMismatch => "FEDERATION_EVENT_SOURCE_MISMATCH",
        FederationIngressError::DestinationMismatch => "FEDERATION_EVENT_DESTINATION_MISMATCH",
        FederationIngressError::UnsupportedEventKind => "FEDERATION_EVENT_KIND_UNSUPPORTED",
        FederationIngressError::InvalidPayload => "FEDERATION_EVENT_INVALID_PAYLOAD",
    };
    AppError::WithCode {
        status: StatusCode::BAD_REQUEST,
        code,
        message: "Federation event was rejected".into(),
    }
}

fn federation_runtime_error(error: FederationRuntimeError) -> AppError {
    let code = match error {
        FederationRuntimeError::UnsupportedEventKind => "FEDERATION_EVENT_KIND_UNSUPPORTED",
        FederationRuntimeError::InvalidPayload => "FEDERATION_EVENT_INVALID_PAYLOAD",
    };
    AppError::WithCode {
        status: StatusCode::BAD_REQUEST,
        code,
        message: "Federation event was rejected".into(),
    }
}

fn federation_runtime_propagation_error() -> AppError {
    AppError::WithCode {
        status: StatusCode::FORBIDDEN,
        code: "FEDERATION_RUNTIME_PROPAGATION_DISABLED",
        message: "Federation runtime propagation is disabled for server-owned backends".into(),
    }
}

fn federation_admin_nonce_key(nonce: &str) -> String {
    format!("federation:admin_nonce:{}", token_hash(nonce))
}

async fn reserve_federation_admin_nonce(state: &AppState, nonce: &str) -> AppResult<()> {
    let key = federation_admin_nonce_key(nonce);
    let inserted: bool = KeysInterface::set(
        &state.redis,
        &key,
        "1",
        Some(fred::types::Expiration::EX(FEDERATION_ADMIN_NONCE_TTL_SECS)),
        Some(fred::types::SetOptions::NX),
        false,
    )
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "Federation registry admin nonce store failed");
        AppError::WithCode {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "FEDERATION_ADMIN_NONCE_STORE_UNAVAILABLE",
            message: "Federation registry admin nonce store is unavailable".into(),
        }
    })?;

    if !inserted {
        tracing::warn!("Federation registry admin replay rejected");
        return Err(AppError::WithCode {
            status: StatusCode::UNAUTHORIZED,
            code: "FEDERATION_ADMIN_REPLAY_REJECTED",
            message: "Federation registry admin request nonce was already used".into(),
        });
    }

    Ok(())
}

pub fn token_challenge(domain: &str, token: &str) -> FederationVerificationChallenge {
    let body = format!("verdant-site-verification={token}");
    FederationVerificationChallenge {
        dns_txt_name: format!("_verdant-federation.{domain}"),
        dns_txt_value: body.clone(),
        http_url: format!("https://{domain}/.well-known/verdant-federation.txt"),
        http_body: body,
    }
}

fn domain_from_origin(origin: &str) -> String {
    Url::parse(origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "unknown.invalid".to_string())
}

pub fn discovery_instance_from_row(
    row: pg::federation::FederationInstanceRow,
) -> Option<FederationDiscoveryInstance> {
    if row.status != RegistryStatus::Verified.as_str() || !row.public_discovery {
        return None;
    }
    let content_scanning = normalize_content_scanning(Some(row.content_scanning)).ok()?;
    let capabilities = normalize_capabilities(Some(row.capabilities)).ok()?;

    Some(FederationDiscoveryInstance {
        id: row.id.to_string(),
        domain: row.domain,
        display_name: row.display_name,
        api_url: row.api_url,
        public_url: row.public_url,
        mode: row.mode,
        status: row.status,
        discovery_description: row.discovery_description,
        invite_url: row.invite_url,
        server_version: row.server_version,
        min_client_version: row.min_client_version,
        upload_policy: row.upload_policy,
        content_scanning,
        capabilities,
        public_key_fingerprint: row.public_key_fingerprint,
        verified_at_ms: row.verified_at_ms,
        updated_at_ms: row.updated_at_ms,
    })
}

fn admin_instance_from_row(
    row: pg::federation::FederationInstanceRow,
) -> FederationRegistryAdminInstance {
    FederationRegistryAdminInstance {
        id: row.id.to_string(),
        domain: row.domain,
        display_name: row.display_name,
        api_url: row.api_url,
        public_url: row.public_url,
        mode: row.mode,
        status: row.status,
        public_discovery: row.public_discovery,
        discovery_description: row.discovery_description,
        invite_url: row.invite_url,
        server_version: row.server_version,
        min_client_version: row.min_client_version,
        upload_policy: row.upload_policy,
        content_scanning: row.content_scanning,
        capabilities: row.capabilities,
        public_key: row.public_key,
        public_key_fingerprint: row.public_key_fingerprint,
        verification_method: row.verification_method,
        verified_at_ms: row.verified_at_ms,
        revoked_at_ms: row.revoked_at_ms,
        created_at_ms: row.created_at_ms,
        updated_at_ms: row.updated_at_ms,
    }
}

fn map_sqlx_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &error
        && db.is_unique_violation()
    {
        return AppError::WithCode {
            status: StatusCode::CONFLICT,
            code: "FEDERATION_DOMAIN_EXISTS",
            message: "Federation registry domain already exists".into(),
        };
    }
    tracing::error!("Federation registry database error: {error}");
    AppError::Internal
}

pub async fn manifest(State(state): State<AppState>) -> AppResult<Json<FederationManifest>> {
    let metadata = instance::metadata(&state.config);
    let public_key = normalize_public_key(state.config.federation_public_key.clone())?;
    let public_key_fingerprint = public_key.as_deref().map(public_key_fingerprint);
    let domain = normalize_registry_domain(&domain_from_origin(&metadata.api_url))
        .unwrap_or_else(|_| domain_from_origin(&metadata.api_url));

    Ok(Json(FederationManifest {
        instance_id: state.config.instance_id.clone(),
        registry_trust: "self_reported",
        name: metadata.name,
        domain,
        mode: metadata.mode,
        server_version: metadata.server_version,
        min_client_version: metadata.min_client_version,
        public_url: metadata.public_url,
        api_url: metadata.api_url,
        ws_url: metadata.ws_url,
        docs_url: metadata.docs_url,
        upload_policy: metadata.upload_policy,
        content_scanning: metadata.content_scanning,
        capabilities: metadata.capabilities,
        public_key,
        public_key_fingerprint,
    }))
}

pub async fn discovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<DiscoveryQuery>,
) -> AppResult<Json<FederationDiscoveryResponse>> {
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::SEARCH_LIMIT, &ip).await?;

    if state.config.instance_mode != InstanceMode::Official {
        return Ok(Json(FederationDiscoveryResponse {
            source: "self_host",
            instances: Vec::new(),
        }));
    }

    let limit = query
        .limit
        .unwrap_or(DEFAULT_DISCOVERY_LIMIT)
        .clamp(1, MAX_DISCOVERY_LIMIT);
    let search = query.q.and_then(|q| {
        let q = q.trim();
        if q.is_empty() || q.len() > 120 {
            None
        } else {
            Some(q.to_string())
        }
    });
    let rows = pg::federation::list_public_discovery(&state.pg, search.as_deref(), limit)
        .await
        .map_err(map_sqlx_error)?;

    let instances = rows
        .into_iter()
        .filter_map(discovery_instance_from_row)
        .collect();
    Ok(Json(FederationDiscoveryResponse {
        source: "official_registry",
        instances,
    }))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationEventIngressResponse {
    pub accepted: bool,
    pub duplicate: bool,
    pub event_id: String,
}

pub async fn receive_event(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> AppResult<Json<FederationEventIngressResponse>> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::FEDERATION_EVENT_LIMIT, &ip).await?;
    let body_bytes = read_federation_runtime_body(body).await?;
    let identity =
        FederationRequestIdentity::from_headers(&headers).map_err(federation_verify_error)?;
    let Some(peer_key) = federation_storage::peer_key_by_peer_and_key(
        &state.pg,
        &identity.source_peer_id,
        &identity.key_id,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            source_peer_id = %identity.source_peer_id,
            key_id = %identity.key_id,
            error = %error,
            "Federation peer key lookup failed"
        );
        AppError::Internal
    })?
    else {
        tracing::warn!(
            source_peer_id = %identity.source_peer_id,
            key_id = %identity.key_id,
            "Federation event rejected: unknown peer key"
        );
        return Err(federation_verify_error(VerifyError::UnknownPeerKey));
    };
    let mut key_store = StaticPeerKeyStore::default();
    key_store.insert(peer_key);
    let verifier = FederationRequestVerifier::new(
        state.config.instance_id.clone(),
        key_store,
        InMemoryNonceStore::default(),
    );
    let verified = verifier
        .verify_signature("POST", "/api/federation/v1/events", &headers, &body_bytes)
        .map_err(federation_verify_error)?;

    let now_ms = pg::now_ms();
    let nonce_reserved = federation_storage::reserve_replay_nonce(
        &state.pg,
        state.snowflake.next_id(),
        &verified.source_peer_id,
        &verified.key_id,
        &verified.nonce,
        verified.timestamp_ms,
        now_ms,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            source_peer_id = %verified.source_peer_id,
            key_id = %verified.key_id,
            error = %error,
            "Federation replay nonce reservation failed"
        );
        AppError::Internal
    })?;
    if !nonce_reserved {
        tracing::warn!(
            source_peer_id = %verified.source_peer_id,
            key_id = %verified.key_id,
            "Federation event rejected: replayed nonce"
        );
        return Err(federation_verify_error(VerifyError::Replay));
    }

    let envelope =
        ParsedFederationEnvelope::from_json(&body_bytes).map_err(federation_protocol_error)?;
    let decision =
        validate_ingress_envelope(&verified, &envelope).map_err(federation_ingress_error)?;
    if !runtime_propagation_allowed(decision.event_kind) {
        tracing::warn!(
            source_peer_id = %decision.source_peer_id,
            remote_event_id = %decision.remote_event_id,
            event_kind = %decision.event_kind.as_str(),
            "Federation runtime event rejected: server-owned backend model does not accept cross-backend runtime propagation"
        );
        return Err(federation_runtime_propagation_error());
    }
    let runtime_command = command_from_envelope(&envelope).map_err(federation_runtime_error)?;
    let insert_result = federation_storage::insert_inbound_event(
        &state.pg,
        federation_storage::InsertInboundFederationEvent {
            id: state.snowflake.next_id(),
            source_peer_id: &decision.source_peer_id,
            remote_event_id: &decision.remote_event_id,
            event_kind: decision.event_kind,
            payload_hash: &decision.payload_hash,
            now_ms,
        },
    )
    .await
    .map_err(|error| {
        tracing::error!(
            source_peer_id = %decision.source_peer_id,
            remote_event_id = %decision.remote_event_id,
            event_kind = %decision.event_kind.as_str(),
            error = %error,
            "Federation inbound event record failed"
        );
        AppError::Internal
    })?;
    let duplicate = insert_result == federation_storage::EventInsertResult::Duplicate;
    if !duplicate {
        apply_federation_runtime_command(&state, &decision, runtime_command, now_ms).await?;
        federation_storage::mark_inbound_event_accepted(
            &state.pg,
            &decision.source_peer_id,
            &decision.remote_event_id,
            now_ms,
        )
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                error = %error,
                "Federation inbound event accept marker failed"
            );
            AppError::Internal
        })?;
    }
    tracing::info!(
        source_peer_id = %decision.source_peer_id,
        destination_peer_id = %decision.destination_peer_id,
        remote_event_id = %decision.remote_event_id,
        event_kind = %decision.event_kind.as_str(),
        duplicate,
        "Federation inbound event accepted"
    );

    Ok(Json(FederationEventIngressResponse {
        accepted: true,
        duplicate,
        event_id: decision.remote_event_id,
    }))
}

async fn apply_federation_runtime_command(
    state: &AppState,
    decision: &crate::federation::ingress::FederationIngressDecision,
    command: FederationRuntimeCommand,
    now_ms: i64,
) -> AppResult<()> {
    match command {
        FederationRuntimeCommand::AuditOnly => Ok(()),
        FederationRuntimeCommand::UpsertRemotePrincipal {
            home_peer_id,
            remote_user_id,
            username,
            display_name,
            avatar_url,
        } => {
            federation_storage::upsert_remote_principal(
                &state.pg,
                federation_storage::UpsertRemotePrincipal {
                    principal_id: state.snowflake.next_id(),
                    local_user_id: state.snowflake.next_id(),
                    home_peer_id: &home_peer_id,
                    remote_user_id: &remote_user_id,
                    remote_username: username.as_deref(),
                    display_name: display_name.as_deref(),
                    avatar_url: avatar_url.as_deref(),
                    now_ms,
                },
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    source_peer_id = %decision.source_peer_id,
                    remote_event_id = %decision.remote_event_id,
                    event_kind = %decision.event_kind.as_str(),
                    error = %error,
                    "Federation remote principal upsert failed"
                );
                AppError::Internal
            })?;
            Ok(())
        }
        FederationRuntimeCommand::MembershipJoin {
            home_peer_id,
            remote_user_id,
            server_id,
            invite_code,
            invite_code_hash,
        } => {
            apply_federation_membership_join(
                state,
                decision,
                &home_peer_id,
                &remote_user_id,
                server_id,
                invite_code.as_deref(),
                invite_code_hash.as_deref(),
                now_ms,
            )
            .await
        }
        FederationRuntimeCommand::MembershipLeave {
            home_peer_id,
            remote_user_id,
            server_id,
        } => {
            apply_federation_membership_leave(
                state,
                decision,
                &home_peer_id,
                &remote_user_id,
                server_id,
                now_ms,
            )
            .await
        }
        FederationRuntimeCommand::MembershipRemove {
            home_peer_id,
            remote_user_id,
            server_id,
            target_user_id,
            reason,
        } => {
            apply_federation_membership_moderation(
                state,
                decision,
                FederationMembershipModerationAction::Remove,
                &home_peer_id,
                &remote_user_id,
                server_id,
                target_user_id,
                reason.as_deref(),
                now_ms,
            )
            .await
        }
        FederationRuntimeCommand::MembershipBan {
            home_peer_id,
            remote_user_id,
            server_id,
            target_user_id,
            reason,
        } => {
            apply_federation_membership_moderation(
                state,
                decision,
                FederationMembershipModerationAction::Ban,
                &home_peer_id,
                &remote_user_id,
                server_id,
                target_user_id,
                reason.as_deref(),
                now_ms,
            )
            .await
        }
        FederationRuntimeCommand::MembershipUnban {
            home_peer_id,
            remote_user_id,
            server_id,
            target_user_id,
        } => {
            apply_federation_membership_moderation(
                state,
                decision,
                FederationMembershipModerationAction::Unban,
                &home_peer_id,
                &remote_user_id,
                server_id,
                target_user_id,
                None,
                now_ms,
            )
            .await
        }
    }
}

async fn grant_federation_peer_server_routes(
    state: &AppState,
    peer_id: &str,
    server_id: i64,
    now_ms: i64,
) {
    if let Err(error) = crate::federation::storage::upsert_peer_route(
        &state.pg,
        state.snowflake.next_id(),
        peer_id,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        now_ms,
    )
    .await
    {
        tracing::warn!(
            source_peer_id = %peer_id,
            server_id,
            error = %error,
            "Federation peer server route grant failed"
        );
        return;
    }

    match crate::services::pg::channels::list_for_server(&state.pg, server_id).await {
        Ok(channels) => {
            for channel in channels {
                if channel.r#type != FEDERATION_CHANNEL_TYPE_SERVER_TEXT {
                    continue;
                }
                if let Err(error) = crate::federation::storage::upsert_peer_route(
                    &state.pg,
                    state.snowflake.next_id(),
                    peer_id,
                    crate::federation::producer::FederationRouteScope::Channel {
                        channel_id: channel.id,
                    },
                    now_ms,
                )
                .await
                {
                    tracing::warn!(
                        source_peer_id = %peer_id,
                        server_id,
                        channel_id = channel.id,
                        error = %error,
                        "Federation peer channel route grant failed"
                    );
                }
            }
        }
        Err(error) => tracing::warn!(
            source_peer_id = %peer_id,
            server_id,
            error = %error,
            "Federation peer channel route grant lookup failed"
        ),
    }
}

async fn revoke_federation_peer_server_routes(
    state: &AppState,
    peer_id: &str,
    server_id: i64,
    now_ms: i64,
) {
    if let Err(error) = crate::federation::storage::revoke_peer_route(
        &state.pg,
        peer_id,
        crate::federation::producer::FederationRouteScope::Server { server_id },
        now_ms,
    )
    .await
    {
        tracing::warn!(
            source_peer_id = %peer_id,
            server_id,
            error = %error,
            "Federation peer server route revoke failed"
        );
    }

    match crate::services::pg::channels::list_for_server(&state.pg, server_id).await {
        Ok(channels) => {
            for channel in channels {
                if let Err(error) = crate::federation::storage::revoke_peer_route(
                    &state.pg,
                    peer_id,
                    crate::federation::producer::FederationRouteScope::Channel {
                        channel_id: channel.id,
                    },
                    now_ms,
                )
                .await
                {
                    tracing::warn!(
                        source_peer_id = %peer_id,
                        server_id,
                        channel_id = channel.id,
                        error = %error,
                        "Federation peer channel route revoke failed"
                    );
                }
            }
        }
        Err(error) => tracing::warn!(
            source_peer_id = %peer_id,
            server_id,
            error = %error,
            "Federation peer channel route revoke lookup failed"
        ),
    }
}

async fn apply_federation_membership_join(
    state: &AppState,
    decision: &crate::federation::ingress::FederationIngressDecision,
    home_peer_id: &str,
    remote_user_id: &str,
    server_id: i64,
    invite_code: Option<&str>,
    invite_code_hash: Option<&str>,
    now_ms: i64,
) -> AppResult<()> {
    if invite_code.is_none() && invite_code_hash.is_none() {
        return Err(federation_membership_rejected("FEDERATION_INVITE_REQUIRED"));
    }
    let local_user_id =
        federation_require_remote_principal(state, decision, home_peer_id, remote_user_id).await?;

    let invite = match invite_code {
        Some(code) => crate::services::pg::server_invites::by_code(&state.pg, code)
            .await
            .map_err(|error| {
                tracing::error!(
                    source_peer_id = %decision.source_peer_id,
                    remote_event_id = %decision.remote_event_id,
                    event_kind = %decision.event_kind.as_str(),
                    server_id,
                    error = %error,
                    "Federation membership invite lookup failed"
                );
                AppError::Internal
            })?,
        None => crate::services::pg::server_invites::by_code_hash_for_server(
            &state.pg,
            server_id,
            invite_code_hash.unwrap_or_default(),
        )
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                error = %error,
                "Federation membership invite hash lookup failed"
            );
            AppError::Internal
        })?,
    }
    .ok_or_else(|| federation_membership_rejected("FEDERATION_INVITE_NOT_FOUND"))?;
    if invite.server_id != server_id {
        return Err(federation_membership_rejected(
            "FEDERATION_INVITE_NOT_FOUND",
        ));
    }
    if invite
        .expires_at_ms
        .is_some_and(|expires_at_ms| expires_at_ms < now_ms)
        || (invite.max_uses != 0 && invite.uses >= invite.max_uses)
    {
        return Err(federation_membership_rejected(
            "FEDERATION_INVITE_NOT_FOUND",
        ));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                error = %error,
                "Federation membership server lookup failed"
            );
            AppError::Internal
        })?
        .ok_or_else(|| federation_membership_rejected("FEDERATION_INVITE_NOT_FOUND"))?;
    if server.deleted_at.is_some() {
        return Err(federation_membership_rejected(
            "FEDERATION_INVITE_NOT_FOUND",
        ));
    }

    use fred::interfaces::SetsInterface;
    let ban_key = format!("banned:{server_id}");
    let banned: bool = state
        .redis
        .sismember(&ban_key, local_user_id.to_string())
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                local_user_id,
                error = %error,
                "Federation membership ban lookup failed"
            );
            AppError::Internal
        })?;
    if banned {
        return Err(federation_membership_rejected(
            "FEDERATION_INVITE_NOT_FOUND",
        ));
    }

    let already_member =
        crate::services::pg::servers::is_member(&state.pg, server_id, local_user_id)
            .await
            .map_err(|error| {
                tracing::error!(
                    source_peer_id = %decision.source_peer_id,
                    remote_event_id = %decision.remote_event_id,
                    event_kind = %decision.event_kind.as_str(),
                    server_id,
                    local_user_id,
                    error = %error,
                    "Federation membership lookup failed"
                );
                AppError::Internal
            })?;
    if already_member {
        state.permissions.add_user_server(local_user_id, server_id);
        grant_federation_peer_server_routes(state, &decision.source_peer_id, server_id, now_ms)
            .await;
        return Ok(());
    }

    let member_count = crate::services::pg::servers::member_count(&state.pg, server_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                error = %error,
                "Federation membership count failed"
            );
            AppError::Internal
        })?;
    if member_count >= MAX_FEDERATION_MEMBERS_PER_SERVER {
        return Err(federation_membership_rejected("FEDERATION_SERVER_FULL"));
    }

    let consumed =
        crate::services::pg::server_invites::try_consume(&state.pg, &invite.code, now_ms)
            .await
            .map_err(|error| {
                tracing::error!(
                    source_peer_id = %decision.source_peer_id,
                    remote_event_id = %decision.remote_event_id,
                    event_kind = %decision.event_kind.as_str(),
                    server_id,
                    error = %error,
                    "Federation membership invite consume failed"
                );
                AppError::Internal
            })?;
    if !consumed {
        return Err(federation_membership_rejected(
            "FEDERATION_INVITE_NOT_FOUND",
        ));
    }

    crate::services::pg::servers::add_member(&state.pg, server_id, local_user_id, now_ms)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                local_user_id,
                error = %error,
                "Federation membership insert failed"
            );
            AppError::Internal
        })?;

    state.permissions.add_user_server(local_user_id, server_id);
    grant_federation_peer_server_routes(state, &decision.source_peer_id, server_id, now_ms).await;
    federation_publish_member_join(state, server_id, local_user_id, now_ms).await;
    federation_publish_welcome_join_message(
        state,
        &server,
        local_user_id,
        member_count + 1,
        now_ms,
    )
    .await;

    tracing::debug!(
        source_peer_id = %decision.source_peer_id,
        remote_event_id = %decision.remote_event_id,
        event_kind = %decision.event_kind.as_str(),
        server_id,
        local_user_id,
        "Federation membership join applied"
    );
    Ok(())
}

async fn apply_federation_membership_leave(
    state: &AppState,
    decision: &crate::federation::ingress::FederationIngressDecision,
    home_peer_id: &str,
    remote_user_id: &str,
    server_id: i64,
    now_ms: i64,
) -> AppResult<()> {
    let local_user_id =
        federation_require_remote_principal(state, decision, home_peer_id, remote_user_id).await?;

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                error = %error,
                "Federation membership leave server lookup failed"
            );
            AppError::Internal
        })?
        .ok_or_else(|| federation_membership_rejected("FEDERATION_SERVER_NOT_FOUND"))?;
    if server.deleted_at.is_some() {
        return Err(federation_membership_rejected(
            "FEDERATION_SERVER_NOT_FOUND",
        ));
    }
    if server.owner_id == local_user_id {
        return Err(federation_membership_rejected(
            "FEDERATION_OWNER_CANNOT_LEAVE",
        ));
    }

    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, local_user_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                local_user_id,
                error = %error,
                "Federation membership leave lookup failed"
            );
            AppError::Internal
        })?;
    if !is_member {
        return Err(federation_membership_rejected("FEDERATION_NOT_MEMBER"));
    }

    crate::services::pg::servers::remove_member(&state.pg, server_id, local_user_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                local_user_id,
                error = %error,
                "Federation membership leave remove failed"
            );
            AppError::Internal
        })?;

    if let Err(error) = crate::services::pg::roles::replace_user_roles_in_server(
        &state.pg,
        local_user_id,
        server_id,
        &[],
    )
    .await
    {
        tracing::warn!(
            source_peer_id = %decision.source_peer_id,
            remote_event_id = %decision.remote_event_id,
            event_kind = %decision.event_kind.as_str(),
            server_id,
            local_user_id,
            error = %error,
            "Federation membership leave role wipe failed"
        );
    }

    state
        .permissions
        .remove_user_server(local_user_id, server_id);
    crate::services::presence::remove(&state.redis, local_user_id).await;
    revoke_federation_peer_server_routes(state, &decision.source_peer_id, server_id, now_ms).await;

    let server_id_str = server_id.to_string();
    let user_id_str = local_user_id.to_string();
    crate::services::bot_events::enqueue(
        state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_LEAVE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(local_user_id),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str.clone(),
                "userId": user_id_str.clone(),
                "reason": "leave",
            }),
        },
    );

    let json = crate::ws::events::member_remove_json(&server_id_str, &user_id_str);
    let proto = crate::ws::events::member_remove_proto(server_id_str.clone(), user_id_str.clone());
    crate::ws::topics::publish(
        state,
        &crate::ws::topics::presence_topic(server_id),
        &json,
        &proto,
    )
    .await;

    tracing::info!(
        source_peer_id = %decision.source_peer_id,
        remote_event_id = %decision.remote_event_id,
        event_kind = %decision.event_kind.as_str(),
        server_id,
        local_user_id,
        "Federation membership leave applied"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FederationMembershipModerationAction {
    Remove,
    Ban,
    Unban,
}

impl FederationMembershipModerationAction {
    fn required_permission(self) -> i64 {
        match self {
            Self::Remove => crate::services::permissions::bits::KICK_MEMBERS,
            Self::Ban | Self::Unban => crate::services::permissions::bits::BAN_MEMBERS,
        }
    }

    fn audit_action(self) -> crate::services::audit::AuditAction {
        match self {
            Self::Remove => crate::services::audit::AuditAction::KickMember,
            Self::Ban => crate::services::audit::AuditAction::BanMember,
            Self::Unban => crate::services::audit::AuditAction::UnbanMember,
        }
    }

    fn bot_reason(self) -> &'static str {
        match self {
            Self::Remove => "kick",
            Self::Ban => "ban",
            Self::Unban => "unban",
        }
    }

    fn log_label(self) -> &'static str {
        match self {
            Self::Remove => "remove",
            Self::Ban => "ban",
            Self::Unban => "unban",
        }
    }
}

async fn apply_federation_membership_moderation(
    state: &AppState,
    decision: &crate::federation::ingress::FederationIngressDecision,
    action: FederationMembershipModerationAction,
    home_peer_id: &str,
    remote_user_id: &str,
    server_id: i64,
    target_user_id: i64,
    reason: Option<&str>,
    now_ms: i64,
) -> AppResult<()> {
    let actor_user_id =
        federation_require_remote_principal(state, decision, home_peer_id, remote_user_id).await?;

    state
        .require_permission(actor_user_id, server_id, action.required_permission())
        .await
        .map_err(|_| federation_membership_rejected("FEDERATION_MODERATION_DENIED"))?;

    if actor_user_id == target_user_id {
        return Err(federation_membership_rejected(
            "FEDERATION_CANNOT_MODERATE_SELF",
        ));
    }

    let server = crate::services::pg::servers::by_id(&state.pg, server_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                error = %error,
                "Federation membership moderation server lookup failed"
            );
            AppError::Internal
        })?
        .ok_or_else(|| federation_membership_rejected("FEDERATION_SERVER_NOT_FOUND"))?;
    if server.deleted_at.is_some() {
        return Err(federation_membership_rejected(
            "FEDERATION_SERVER_NOT_FOUND",
        ));
    }
    if matches!(
        action,
        FederationMembershipModerationAction::Remove | FederationMembershipModerationAction::Ban
    ) && target_user_id == server.owner_id
    {
        return Err(federation_membership_rejected(
            "FEDERATION_CANNOT_MODERATE_OWNER",
        ));
    }

    let target_exists = crate::services::pg::users::by_id(&state.pg, target_user_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                target_user_id,
                error = %error,
                "Federation membership moderation target lookup failed"
            );
            AppError::Internal
        })?
        .is_some();
    if !target_exists {
        return Err(federation_membership_rejected(
            "FEDERATION_TARGET_USER_NOT_FOUND",
        ));
    }

    match action {
        FederationMembershipModerationAction::Remove => {
            federation_apply_member_remove(
                state,
                decision,
                server_id,
                actor_user_id,
                target_user_id,
                action,
                true,
            )
            .await?;
        }
        FederationMembershipModerationAction::Ban => {
            let is_member =
                crate::services::pg::servers::is_member(&state.pg, server_id, target_user_id)
                    .await
                    .map_err(|error| {
                        tracing::error!(
                            source_peer_id = %decision.source_peer_id,
                            remote_event_id = %decision.remote_event_id,
                            event_kind = %decision.event_kind.as_str(),
                            server_id,
                            target_user_id,
                            error = %error,
                            "Federation ban membership lookup failed"
                        );
                        AppError::Internal
                    })?;
            if is_member {
                state
                    .permissions
                    .check_hierarchy(actor_user_id, target_user_id, server_id)
                    .await
                    .map_err(|_| {
                        federation_membership_rejected("FEDERATION_MODERATION_HIERARCHY_DENIED")
                    })?;
            }

            let banned: bool = state
                .redis
                .sismember(
                    federation_banned_set_key(server_id),
                    target_user_id.to_string(),
                )
                .await
                .map_err(|error| {
                    tracing::error!(
                        source_peer_id = %decision.source_peer_id,
                        remote_event_id = %decision.remote_event_id,
                        event_kind = %decision.event_kind.as_str(),
                        server_id,
                        target_user_id,
                        error = %error,
                        "Federation moderation ban lookup failed"
                    );
                    AppError::Internal
                })?;
            if !banned {
                let _: Result<i64, _> = state
                    .redis
                    .sadd(
                        federation_banned_set_key(server_id),
                        target_user_id.to_string(),
                    )
                    .await;
                let fields: Vec<(&str, String)> = vec![
                    ("banned_by", actor_user_id.to_string()),
                    ("reason", reason.unwrap_or_default().to_string()),
                    ("created_at_millis", now_ms.to_string()),
                ];
                let _: Result<(), _> = state
                    .redis
                    .hset(federation_ban_detail_key(server_id, target_user_id), fields)
                    .await;
            }

            if is_member {
                federation_apply_member_remove(
                    state,
                    decision,
                    server_id,
                    actor_user_id,
                    target_user_id,
                    action,
                    false,
                )
                .await?;
            }
        }
        FederationMembershipModerationAction::Unban => {
            let _: Result<i64, _> = state
                .redis
                .srem(
                    federation_banned_set_key(server_id),
                    target_user_id.to_string(),
                )
                .await;
            let _: Result<i64, _> = state
                .redis
                .del(federation_ban_detail_key(server_id, target_user_id))
                .await;
        }
    }

    crate::services::audit::log_async(
        state.redis.clone(),
        crate::services::audit::AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: actor_user_id,
            action: action.audit_action(),
            target_type: "user",
            target_id: target_user_id,
            server_id: Some(server_id),
            metadata: Some(match action {
                FederationMembershipModerationAction::Unban => json!({
                    "serverId": server_id.to_string(),
                    "federated": true,
                }),
                _ => json!({
                    "serverId": server_id.to_string(),
                    "reason": reason,
                    "federated": true,
                }),
            }),
            ip: None,
        },
        state.pg.clone(),
    );

    tracing::info!(
        source_peer_id = %decision.source_peer_id,
        remote_event_id = %decision.remote_event_id,
        event_kind = %decision.event_kind.as_str(),
        action = action.log_label(),
        server_id,
        actor_user_id,
        target_user_id,
        "Federation membership moderation applied"
    );
    Ok(())
}

async fn federation_apply_member_remove(
    state: &AppState,
    decision: &crate::federation::ingress::FederationIngressDecision,
    server_id: i64,
    actor_user_id: i64,
    target_user_id: i64,
    action: FederationMembershipModerationAction,
    require_existing_member: bool,
) -> AppResult<()> {
    let is_member = crate::services::pg::servers::is_member(&state.pg, server_id, target_user_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                target_user_id,
                error = %error,
                "Federation member removal membership lookup failed"
            );
            AppError::Internal
        })?;
    if !is_member {
        if require_existing_member {
            return Err(federation_membership_rejected("FEDERATION_NOT_MEMBER"));
        }
        return Ok(());
    }

    state
        .permissions
        .check_hierarchy(actor_user_id, target_user_id, server_id)
        .await
        .map_err(|_| federation_membership_rejected("FEDERATION_MODERATION_HIERARCHY_DENIED"))?;

    crate::services::pg::servers::remove_member(&state.pg, server_id, target_user_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                server_id,
                target_user_id,
                error = %error,
                "Federation member removal failed"
            );
            AppError::Internal
        })?;

    if let Err(error) = crate::services::pg::roles::replace_user_roles_in_server(
        &state.pg,
        target_user_id,
        server_id,
        &[],
    )
    .await
    {
        tracing::warn!(
            source_peer_id = %decision.source_peer_id,
            remote_event_id = %decision.remote_event_id,
            event_kind = %decision.event_kind.as_str(),
            server_id,
            target_user_id,
            error = %error,
            "Federation member removal role wipe failed"
        );
    }

    state
        .permissions
        .remove_user_server(target_user_id, server_id);

    let server_channels = crate::services::pg::channels::list_for_server(&state.pg, server_id)
        .await
        .unwrap_or_default();
    let channel_ids: Vec<i64> = server_channels.iter().map(|channel| channel.id).collect();
    crate::ws::topics::unsubscribe_user_from_server(state, target_user_id, server_id, &channel_ids)
        .await;

    let server_id_str = server_id.to_string();
    let target_user_id_str = target_user_id.to_string();
    crate::services::bot_events::enqueue(
        state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_LEAVE,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(actor_user_id),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str.clone(),
                "userId": target_user_id_str.clone(),
                "reason": action.bot_reason(),
            }),
        },
    );

    let member_remove_json =
        crate::ws::events::member_remove_json(&server_id_str, &target_user_id_str);
    let member_remove_proto =
        crate::ws::events::member_remove_proto(server_id_str.clone(), target_user_id_str.clone());
    crate::ws::topics::publish(
        state,
        &crate::ws::topics::presence_topic(server_id),
        &member_remove_json,
        &member_remove_proto,
    )
    .await;

    let server_delete_json = crate::ws::events::server_delete_json(&server_id_str);
    let server_delete_proto = crate::ws::events::server_delete_proto(server_id_str);
    crate::ws::topics::publish(
        state,
        &crate::ws::topics::user_topic(target_user_id),
        &server_delete_json,
        &server_delete_proto,
    )
    .await;

    Ok(())
}

fn federation_banned_set_key(server_id: i64) -> String {
    format!("banned:{server_id}")
}

fn federation_ban_detail_key(server_id: i64, target_user_id: i64) -> String {
    format!("ban:{server_id}:{target_user_id}")
}

async fn federation_publish_member_join(
    state: &AppState,
    server_id: i64,
    local_user_id: i64,
    now_ms: i64,
) {
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
        .unwrap_or_else(chrono::Utc::now);
    let (username, avatar_url, display_name) = state
        .user_profiles
        .get_or_fetch_vdb(state, local_user_id)
        .await;
    let user_id_str = local_user_id.to_string();
    let server_id_str = server_id.to_string();
    let joined_at = now.to_rfc3339();
    let join_json = crate::ws::events::member_join_json(
        &server_id_str,
        &user_id_str,
        &username,
        display_name.as_deref(),
        avatar_url.as_deref(),
        &joined_at,
    );
    let join_proto = crate::ws::events::member_join_proto(
        server_id_str.clone(),
        user_id_str.clone(),
        username.clone(),
        display_name.clone(),
        avatar_url.clone(),
        joined_at.clone(),
    );
    crate::services::bot_events::enqueue(
        state,
        crate::services::bot_events::BotEvent {
            event_type: crate::services::bot_events::EVENT_MEMBER_JOIN,
            server_id: Some(server_id),
            channel_id: None,
            feed_id: None,
            actor_user_id: Some(local_user_id),
            actor_bot_id: None,
            payload: json!({
                "serverId": server_id_str,
                "userId": user_id_str,
                "username": username,
                "displayName": display_name,
                "avatarUrl": avatar_url,
                "joinedAt": joined_at,
            }),
        },
    );
    crate::ws::topics::publish(
        state,
        &crate::ws::topics::presence_topic(server_id),
        &join_json,
        &join_proto,
    )
    .await;
}

async fn federation_publish_welcome_join_message(
    state: &AppState,
    server: &crate::repo::servers::ServerRow,
    local_user_id: i64,
    member_count: i64,
    now_ms: i64,
) {
    let Some(welcome_channel_id) = server.welcome_channel_id else {
        return;
    };
    if !federation_configured_server_text_channel_exists(
        state,
        server.id,
        welcome_channel_id,
        "welcome_channel_id",
    )
    .await
    {
        return;
    }

    let (username, avatar_url, display_name) = state
        .user_profiles
        .get_or_fetch_vdb(state, local_user_id)
        .await;
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
        .unwrap_or_else(chrono::Utc::now);
    let content = server
        .welcome_message
        .clone()
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "{user} joined the server!".to_string())
        .replace("{user}", &username)
        .replace("{server}", &server.name)
        .replace("{count}", &member_count.to_string());
    let message_id = state.snowflake.next_id();
    let row = crate::services::pg::messages::MessageRow {
        id: message_id,
        channel_id: welcome_channel_id,
        author_id: local_user_id,
        r#type: 1,
        flags: 0,
        content: content.clone(),
        reply_to: None,
        edited_at_ms: None,
        created_at_ms: now_ms,
    };
    if let Err(error) = crate::services::pg::messages::insert(&state.pg, &row).await {
        tracing::warn!(server_id = server.id, error = %error, "Federation welcome join message insert failed");
        return;
    }

    let user_id_str = local_user_id.to_string();
    let channel_id_str = welcome_channel_id.to_string();
    let server_id_str = server.id.to_string();
    let created_at = now.to_rfc3339();
    let message = json!({
        "id": message_id.to_string(),
        "channelId": channel_id_str,
        "authorId": user_id_str,
        "author": {
            "id": user_id_str,
            "username": username.clone(),
            "displayName": display_name.clone(),
            "avatarUrl": avatar_url.clone(),
        },
        "content": content.clone(),
        "type": 1,
        "edited": false,
        "editedAt": Value::Null,
        "createdAt": created_at,
        "updatedAt": created_at,
        "reactions": [],
        "attachments": [],
    });
    let json_text = crate::ws::events::message_create_json(&message);
    let proto_msg = crate::ws::events::message_create_proto(crate::proto::Message {
        id: message_id.to_string(),
        channel_id: welcome_channel_id.to_string(),
        author_id: local_user_id.to_string(),
        author: Some(crate::proto::MessageAuthor {
            id: local_user_id.to_string(),
            username,
            avatar_url,
            display_name,
        }),
        content,
        r#type: 1,
        edited: false,
        created_at: created_at.clone(),
        updated_at: created_at.clone(),
        nonce: None,
        attachments: vec![],
        reactions: vec![],
        reply_to: None,
        edited_at: None,
    });
    crate::ws::topics::publish(
        state,
        &crate::ws::topics::channel_live_topic(welcome_channel_id),
        &json_text,
        &proto_msg,
    )
    .await;

    let message_id_str = message_id.to_string();
    let unread_json = crate::ws::events::channel_unread_signal_json(
        &welcome_channel_id.to_string(),
        Some(&server_id_str),
        &message_id_str,
        &local_user_id.to_string(),
        &created_at,
        false,
        false,
    );
    let unread_proto = crate::ws::events::channel_unread_signal_proto(
        welcome_channel_id.to_string(),
        Some(server_id_str),
        message_id_str,
        local_user_id.to_string(),
        created_at,
        false,
        false,
    );
    crate::ws::topics::publish(
        state,
        &crate::ws::topics::channel_notify_topic(welcome_channel_id),
        &unread_json,
        &unread_proto,
    )
    .await;
}

async fn federation_configured_server_text_channel_exists(
    state: &AppState,
    server_id: i64,
    channel_id: i64,
    purpose: &'static str,
) -> bool {
    match crate::services::pg::channels::by_id(&state.pg, channel_id).await {
        Ok(Some(channel))
            if channel.server_id == Some(server_id)
                && channel.r#type == FEDERATION_CHANNEL_TYPE_SERVER_TEXT =>
        {
            true
        }
        Ok(Some(channel)) => {
            tracing::warn!(
                server_id,
                channel_id,
                purpose,
                channel_server_id = ?channel.server_id,
                channel_type = channel.r#type,
                "Skipping federation configured channel outside this server or non-text channel"
            );
            false
        }
        Ok(None) => {
            tracing::warn!(
                server_id,
                channel_id,
                purpose,
                "Skipping missing federation configured channel"
            );
            false
        }
        Err(error) => {
            tracing::warn!(server_id, channel_id, purpose, error = %error, "Failed to validate federation configured channel");
            false
        }
    }
}

fn federation_membership_rejected(code: &'static str) -> AppError {
    AppError::WithCode {
        status: StatusCode::BAD_REQUEST,
        code,
        message: "Federation event was rejected".into(),
    }
}

async fn federation_require_remote_principal(
    state: &AppState,
    decision: &crate::federation::ingress::FederationIngressDecision,
    home_peer_id: &str,
    remote_user_id: &str,
) -> AppResult<i64> {
    federation_storage::local_user_id_for_remote_principal(&state.pg, home_peer_id, remote_user_id)
        .await
        .map_err(|error| {
            tracing::error!(
                source_peer_id = %decision.source_peer_id,
                remote_event_id = %decision.remote_event_id,
                event_kind = %decision.event_kind.as_str(),
                error = %error,
                "Federation remote principal lookup failed"
            );
            AppError::Internal
        })?
        .ok_or_else(|| federation_membership_rejected("FEDERATION_UNKNOWN_REMOTE_PRINCIPAL"))
}

pub async fn admin_create_instance(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> AppResult<Json<FederationRegistryAdminResponse>> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::ADMIN_LIMIT, &ip).await?;
    let secret = ensure_official_registry_admin(&state)?;
    let body_bytes = read_federation_admin_body(body).await?;
    super::admin::verify_admin_signature_scoped(
        &headers,
        &body_bytes,
        secret,
        "POST",
        FEDERATION_ADMIN_CREATE_PATH,
    )?;
    reserve_federation_admin_nonce(&state, super::admin::admin_signature_nonce(&headers)?).await?;

    let body: CreateRegistryInstanceRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| AppError::Validation("Invalid request body".into()))?;
    let now_ms = pg::now_ms();
    let domain = normalize_registry_domain(&body.domain)?;
    let display_name =
        sanitize_required_text(body.display_name, MAX_DISPLAY_NAME_CHARS, "displayName")?;
    let api_url = normalize_registry_origin(&body.api_url)?;
    let public_url = normalize_registry_origin(&body.public_url)?;
    let mode = normalize_registry_mode(&body.mode)?;
    let discovery_description =
        sanitize_optional_text(body.discovery_description, MAX_DESCRIPTION_CHARS)?;
    let invite_url = normalize_registry_invite_url(body.invite_url, &domain)?;
    let server_version = sanitize_optional_text(body.server_version, MAX_VERSION_CHARS)?;
    let min_client_version = sanitize_optional_text(body.min_client_version, MAX_VERSION_CHARS)?;
    let upload_policy = normalize_registry_upload_policy(body.upload_policy)?;
    let content_scanning = normalize_content_scanning(body.content_scanning)?;
    let capabilities = normalize_capabilities(body.capabilities)?;
    let public_key = normalize_public_key(body.public_key)?;
    let public_key_fingerprint = public_key.as_deref().map(public_key_fingerprint);
    let verification_method = body
        .verification_method
        .as_deref()
        .unwrap_or(VerificationMethod::DnsTxt.as_str())
        .parse::<VerificationMethod>()
        .map_err(bad_request)?;
    let verification_token = generate_verification_token();
    let verification_token_hash = token_hash(&verification_token);

    let row = pg::federation::insert(
        &state.pg,
        pg::federation::InsertFederationInstance {
            id: state.snowflake.next_id(),
            domain: &domain,
            display_name: &display_name,
            api_url: &api_url,
            public_url: &public_url,
            mode: &mode,
            status: RegistryStatus::Pending.as_str(),
            public_discovery: body.public_discovery,
            discovery_description: discovery_description.as_deref(),
            invite_url: invite_url.as_deref(),
            server_version: server_version.as_deref(),
            min_client_version: min_client_version.as_deref(),
            upload_policy: upload_policy.as_deref(),
            content_scanning: &content_scanning,
            capabilities: &capabilities,
            public_key: public_key.as_deref(),
            public_key_fingerprint: public_key_fingerprint.as_deref(),
            verification_method: verification_method.as_str(),
            verification_token_hash: &verification_token_hash,
            verified_at_ms: None,
            revoked_at_ms: None,
            now_ms,
        },
    )
    .await
    .map_err(map_sqlx_error)?;

    tracing::info!(
        instance_id = row.id,
        domain = %row.domain,
        mode = %row.mode,
        public_discovery = row.public_discovery,
        "Federation registry instance created"
    );

    Ok(Json(FederationRegistryAdminResponse {
        instance: admin_instance_from_row(row),
        verification_challenge: Some(token_challenge(&domain, &verification_token)),
    }))
}

pub async fn admin_update_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> AppResult<Json<FederationRegistryAdminResponse>> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let ip = extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::ADMIN_LIMIT, &ip).await?;
    let secret = ensure_official_registry_admin(&state)?;
    let signed_path = federation_admin_instance_path(&instance_id);
    let body_bytes = read_federation_admin_body(body).await?;
    super::admin::verify_admin_signature_scoped(
        &headers,
        &body_bytes,
        secret,
        "PATCH",
        &signed_path,
    )?;
    reserve_federation_admin_nonce(&state, super::admin::admin_signature_nonce(&headers)?).await?;

    let id = super::parse_id(&instance_id)?;
    let existing = pg::federation::by_id(&state.pg, id)
        .await
        .map_err(map_sqlx_error)?
        .ok_or(AppError::NotFound("federation registry instance"))?;
    let body: UpdateRegistryInstanceRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| AppError::Validation("Invalid request body".into()))?;

    let now_ms = pg::now_ms();
    let existing_domain = existing.domain.clone();
    let existing_api_url = existing.api_url.clone();
    let existing_public_url = existing.public_url.clone();
    let existing_public_key = existing.public_key.clone();
    let existing_verification_method = existing.verification_method.clone();
    let domain = match body.domain {
        Some(value) => normalize_registry_domain(&value)?,
        None => existing.domain,
    };
    let display_name = match body.display_name {
        Some(value) => sanitize_required_text(value, MAX_DISPLAY_NAME_CHARS, "displayName")?,
        None => existing.display_name,
    };
    let api_url = match body.api_url {
        Some(value) => normalize_registry_origin(&value)?,
        None => existing.api_url,
    };
    let public_url = match body.public_url {
        Some(value) => normalize_registry_origin(&value)?,
        None => existing.public_url,
    };
    let mode = match body.mode {
        Some(value) => normalize_registry_mode(&value)?,
        None => existing.mode,
    };
    let status = match body.status {
        Some(value) => value.parse::<RegistryStatus>().map_err(bad_request)?,
        None => existing
            .status
            .parse::<RegistryStatus>()
            .map_err(bad_request)?,
    };
    let public_discovery = body.public_discovery.unwrap_or(existing.public_discovery);
    let discovery_description = match body.discovery_description {
        Some(value) => sanitize_optional_text(value, MAX_DESCRIPTION_CHARS)?,
        None => existing.discovery_description,
    };
    let invite_url = match body.invite_url {
        Some(value) => normalize_registry_invite_url(value, &domain)?,
        None => existing.invite_url,
    };
    let server_version = match body.server_version {
        Some(value) => sanitize_optional_text(value, MAX_VERSION_CHARS)?,
        None => existing.server_version,
    };
    let min_client_version = match body.min_client_version {
        Some(value) => sanitize_optional_text(value, MAX_VERSION_CHARS)?,
        None => existing.min_client_version,
    };
    let upload_policy = match body.upload_policy {
        Some(value) => normalize_registry_upload_policy(value)?,
        None => existing.upload_policy,
    };
    let content_scanning = match body.content_scanning {
        Some(value) => normalize_content_scanning(Some(value))?,
        None => normalize_content_scanning(Some(existing.content_scanning))?,
    };
    let capabilities = match body.capabilities {
        Some(value) => normalize_capabilities(Some(value))?,
        None => normalize_capabilities(Some(existing.capabilities))?,
    };
    let public_key = match body.public_key {
        Some(value) => normalize_public_key(value)?,
        None => existing.public_key,
    };
    let public_key_fingerprint = public_key.as_deref().map(public_key_fingerprint);
    let verification_method = match body.verification_method {
        Some(value) => value
            .parse::<VerificationMethod>()
            .map_err(bad_request)?
            .as_str()
            .to_string(),
        None => existing.verification_method,
    };
    let identity_changed = domain != existing_domain
        || api_url != existing_api_url
        || public_url != existing_public_url
        || public_key != existing_public_key
        || verification_method != existing_verification_method;
    let (status, public_discovery) =
        apply_registry_identity_guard(status, public_discovery, identity_changed);
    if identity_changed {
        tracing::warn!(
            instance_id = id,
            status = status.as_str(),
            "Federation registry identity changed; new verification challenge issued"
        );
    }

    let (verification_token_hash, verification_challenge) =
        if body.rotate_verification_token || identity_changed {
            let token = generate_verification_token();
            (token_hash(&token), Some(token_challenge(&domain, &token)))
        } else {
            (existing.verification_token_hash, None)
        };
    let (verified_at_ms, revoked_at_ms) = match status {
        RegistryStatus::Verified => (existing.verified_at_ms.or(Some(now_ms)), None),
        RegistryStatus::Revoked => (
            existing.verified_at_ms,
            existing.revoked_at_ms.or(Some(now_ms)),
        ),
        RegistryStatus::Pending | RegistryStatus::Rejected => (None, None),
    };

    let row = pg::federation::update(
        &state.pg,
        pg::federation::UpdateFederationInstance {
            id,
            domain: &domain,
            display_name: &display_name,
            api_url: &api_url,
            public_url: &public_url,
            mode: &mode,
            status: status.as_str(),
            public_discovery,
            discovery_description: discovery_description.as_deref(),
            invite_url: invite_url.as_deref(),
            server_version: server_version.as_deref(),
            min_client_version: min_client_version.as_deref(),
            upload_policy: upload_policy.as_deref(),
            content_scanning: &content_scanning,
            capabilities: &capabilities,
            public_key: public_key.as_deref(),
            public_key_fingerprint: public_key_fingerprint.as_deref(),
            verification_method: &verification_method,
            verification_token_hash: &verification_token_hash,
            verified_at_ms,
            revoked_at_ms,
            updated_at_ms: now_ms,
        },
    )
    .await
    .map_err(map_sqlx_error)?
    .ok_or(AppError::NotFound("federation registry instance"))?;

    tracing::info!(
        instance_id = row.id,
        domain = %row.domain,
        status = %row.status,
        public_discovery = row.public_discovery,
        identity_changed,
        "Federation registry instance updated"
    );

    Ok(Json(FederationRegistryAdminResponse {
        instance: admin_instance_from_row(row),
        verification_challenge,
    }))
}

#[cfg(test)]
fn federation_reaction_emoji_id_allowed(
    emoji: &str,
    local_shortcode: &str,
    emoji_server_id: i64,
    current_server_id: Option<i64>,
    shared_server_ids: &[i64],
    has_cross_server_entitlement: bool,
) -> bool {
    if !emoji.starts_with(':') || !emoji.ends_with(':') {
        return false;
    }
    let shortcode = emoji.trim_matches(':');
    if shortcode != local_shortcode {
        return false;
    }
    if current_server_id == Some(emoji_server_id) {
        return true;
    }
    has_cross_server_entitlement && shared_server_ids.contains(&emoji_server_id)
}

#[cfg(test)]
fn federation_dm_participants_match(
    expected_user_ids: &[i64],
    actual: &[crate::services::pg::dms::DmMemberRow],
) -> bool {
    if expected_user_ids.len() != actual.len() {
        return false;
    }
    let mut expected = expected_user_ids.to_vec();
    expected.sort_unstable();
    let mut actual_user_ids: Vec<i64> = actual.iter().map(|member| member.user_id).collect();
    actual_user_ids.sort_unstable();
    expected == actual_user_ids
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::StatusCode};
    use serde_json::json;

    use super::{
        RegistryStatus, apply_registry_identity_guard, discovery_instance_from_row,
        federation_admin_nonce_key, federation_dm_participants_match,
        federation_reaction_emoji_id_allowed, normalize_capabilities, normalize_content_scanning,
        normalize_public_key, normalize_registry_domain, normalize_registry_invite_url,
        normalize_registry_mode, normalize_registry_origin, public_key_fingerprint,
        read_federation_admin_body, read_federation_runtime_body, token_challenge,
    };
    use crate::error::AppError;
    use crate::services::pg::federation::FederationInstanceRow;

    const SOURCE: &str = include_str!("federation.rs");

    fn registry_row(status: &str, public_discovery: bool) -> FederationInstanceRow {
        FederationInstanceRow {
            id: 42,
            domain: "community.dev".to_string(),
            display_name: "Community".to_string(),
            api_url: "https://api.community.dev".to_string(),
            public_url: "https://community.dev".to_string(),
            mode: "standalone".to_string(),
            status: status.to_string(),
            public_discovery,
            discovery_description: Some("A public community".to_string()),
            invite_url: Some("https://community.dev/invite/abc123".to_string()),
            server_version: Some("0.1.0".to_string()),
            min_client_version: Some("0.0.329".to_string()),
            upload_policy: Some("operator_managed".to_string()),
            content_scanning: json!({
                "provider": "none",
                "enabled": false,
                "apiKey": "must-not-leak"
            }),
            capabilities: json!({
                "messageAttachments": true,
                "maxUploadBytes": 1024,
                "secretKey": "must-not-leak"
            }),
            public_key: Some(
                "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----".to_string(),
            ),
            public_key_fingerprint: Some("sha256:test".to_string()),
            verification_method: "dns_txt".to_string(),
            verification_token_hash: "secret-hash".to_string(),
            verified_at_ms: Some(1234),
            revoked_at_ms: None,
            created_at_ms: 1000,
            updated_at_ms: 1234,
        }
    }

    #[test]
    fn registry_domains_are_public_hostnames_only() {
        assert_eq!(
            normalize_registry_domain("Community.Dev.").unwrap(),
            "community.dev"
        );

        for raw in [
            "https://community.dev",
            "localhost",
            "127.0.0.1",
            "10.0.0.4",
            "*.example.com",
            "bad_host.dev",
            "example.test",
            "community",
        ] {
            assert!(normalize_registry_domain(raw).is_err(), "{raw} accepted");
        }
    }

    #[test]
    fn registry_origins_are_https_origins_without_credentials_or_paths() {
        assert_eq!(
            normalize_registry_origin("https://api.community.dev/").unwrap(),
            "https://api.community.dev"
        );

        for raw in [
            "http://api.community.dev",
            "https://user:pass@api.community.dev",
            "https://api.community.dev/path",
            "https://api.community.dev?token=secret",
            "https://127.0.0.1",
        ] {
            assert!(normalize_registry_origin(raw).is_err(), "{raw} accepted");
        }
    }

    #[test]
    fn public_discovery_response_hides_admin_verification_material() {
        let row = registry_row("verified", true);
        let public = discovery_instance_from_row(row).unwrap();
        let value = serde_json::to_value(public).unwrap();

        assert_eq!(value["id"], json!("42"));
        assert_eq!(value["domain"], json!("community.dev"));
        assert!(value.get("verificationTokenHash").is_none());
        assert!(value.get("verificationMethod").is_none());
        assert!(value.get("publicKey").is_none());
        assert_eq!(value["publicKeyFingerprint"], json!("sha256:test"));
        assert_eq!(
            value["contentScanning"],
            json!({ "provider": "none", "enabled": false })
        );
        assert_eq!(
            value["capabilities"],
            json!({ "messageAttachments": true, "maxUploadBytes": 1024 })
        );
        assert!(value["contentScanning"].get("apiKey").is_none());
        assert!(value["capabilities"].get("secretKey").is_none());
    }

    #[test]
    fn public_discovery_serialization_rejects_unverified_or_hidden_rows() {
        assert!(discovery_instance_from_row(registry_row("pending", true)).is_none());
        assert!(discovery_instance_from_row(registry_row("verified", false)).is_none());
        assert!(discovery_instance_from_row(registry_row("revoked", true)).is_none());
    }

    #[test]
    fn reaction_emoji_id_policy_requires_matching_local_shortcode() {
        assert!(federation_reaction_emoji_id_allowed(
            ":party:",
            "party",
            10,
            Some(10),
            &[],
            false,
        ));
        assert!(!federation_reaction_emoji_id_allowed(
            ":party:",
            "other",
            10,
            Some(10),
            &[],
            false,
        ));
        assert!(!federation_reaction_emoji_id_allowed(
            "\u{1f642}",
            "party",
            10,
            Some(10),
            &[],
            false,
        ));
    }

    #[test]
    fn reaction_emoji_id_policy_requires_cross_server_membership_and_entitlement() {
        assert!(!federation_reaction_emoji_id_allowed(
            ":party:",
            "party",
            20,
            Some(10),
            &[20],
            false,
        ));
        assert!(!federation_reaction_emoji_id_allowed(
            ":party:",
            "party",
            20,
            Some(10),
            &[30],
            true,
        ));
        assert!(federation_reaction_emoji_id_allowed(
            ":party:",
            "party",
            20,
            Some(10),
            &[20],
            true,
        ));
    }

    #[test]
    fn dm_participant_matching_ignores_order_but_not_members() {
        let actual = vec![
            crate::services::pg::dms::DmMemberRow {
                channel_id: 10,
                user_id: 300,
                name_color: None,
                joined_at_ms: 1,
            },
            crate::services::pg::dms::DmMemberRow {
                channel_id: 10,
                user_id: 100,
                name_color: None,
                joined_at_ms: 1,
            },
            crate::services::pg::dms::DmMemberRow {
                channel_id: 10,
                user_id: 200,
                name_color: None,
                joined_at_ms: 1,
            },
        ];

        assert!(federation_dm_participants_match(&[100, 200, 300], &actual));
        assert!(!federation_dm_participants_match(&[100, 200, 400], &actual));
    }

    #[test]
    fn public_key_fingerprint_is_hash_only() {
        let fp =
            public_key_fingerprint("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----");
        assert!(fp.starts_with("sha256:"));
        assert!(!fp.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn public_key_rejects_private_key_material() {
        assert!(
            normalize_public_key(Some(
                "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----".to_string()
            ))
            .unwrap()
            .is_some()
        );
        assert!(
            normalize_public_key(Some(
                "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_string()
            ))
            .is_err()
        );
        assert!(
            normalize_public_key(Some(
                "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----"
                    .to_string()
            ))
            .is_err()
        );
    }

    #[test]
    fn content_scanning_metadata_is_whitelisted_for_public_discovery() {
        let value = normalize_content_scanning(Some(json!({
            "provider": "Mock",
            "enabled": true,
            "apiKey": "secret",
            "mockHashes": ["secret-hash"]
        })))
        .unwrap();

        assert_eq!(value, json!({ "provider": "mock", "enabled": true }));
        assert!(value.get("apiKey").is_none());
        assert!(value.get("mockHashes").is_none());
    }

    #[test]
    fn capability_metadata_is_whitelisted_for_public_discovery() {
        let value = normalize_capabilities(Some(json!({
            "imageUploads": true,
            "messageAttachments": false,
            "maxUploadBytes": 2048,
            "bucket": "secret-bucket",
            "accountId": "secret-account"
        })))
        .unwrap();

        assert_eq!(
            value,
            json!({
                "imageUploads": true,
                "messageAttachments": false,
                "maxUploadBytes": 2048
            })
        );
        assert!(value.get("bucket").is_none());
        assert!(value.get("accountId").is_none());
    }

    #[tokio::test]
    async fn federation_admin_body_reader_rejects_oversized_bodies() {
        let oversized = vec![b'a'; super::FEDERATION_ADMIN_BODY_LIMIT_BYTES + 1];
        let err = read_federation_admin_body(Body::from(oversized))
            .await
            .unwrap_err();

        match err {
            AppError::WithCode { status, code, .. } => {
                assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(code, "FEDERATION_ADMIN_BODY_TOO_LARGE");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn federation_admin_body_reader_accepts_small_bodies() {
        let body = read_federation_admin_body(Body::from(r#"{"status":"pending"}"#))
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"status":"pending"}"#);
    }

    #[tokio::test]
    async fn federation_runtime_body_reader_rejects_oversized_bodies() {
        let oversized = vec![b'a'; super::FEDERATION_RUNTIME_BODY_LIMIT_BYTES + 1];
        let err = read_federation_runtime_body(Body::from(oversized))
            .await
            .unwrap_err();

        match err {
            AppError::WithCode { status, code, .. } => {
                assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(code, "FEDERATION_EVENT_BODY_TOO_LARGE");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn federation_runtime_body_reader_accepts_small_bodies() {
        let body = read_federation_runtime_body(Body::from(r#"{"kind":"invite_preview"}"#))
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"kind":"invite_preview"}"#);
    }

    #[test]
    fn federation_admin_nonce_key_hashes_raw_nonce() {
        let key = federation_admin_nonce_key("01HV6N6MJ2KTZ02C6RG8BN0KTE");

        assert!(key.starts_with("federation:admin_nonce:"));
        assert!(!key.contains("01HV6N6MJ2KTZ02C6RG8BN0KTE"));
    }

    #[test]
    fn identity_change_forces_verified_registry_record_pending_and_hidden() {
        let (status, public_discovery) =
            apply_registry_identity_guard(RegistryStatus::Verified, true, true);

        assert_eq!(status, RegistryStatus::Pending);
        assert!(!public_discovery);
    }

    #[test]
    fn identity_guard_preserves_non_identity_update_state() {
        let (status, public_discovery) =
            apply_registry_identity_guard(RegistryStatus::Verified, true, false);

        assert_eq!(status, RegistryStatus::Verified);
        assert!(public_discovery);
    }

    #[test]
    fn federated_membership_join_ban_lookup_does_not_fail_open() {
        let handler = SOURCE
            .split("async fn apply_federation_membership_join")
            .nth(1)
            .expect("apply_federation_membership_join source should exist")
            .split("let already_member")
            .next()
            .expect("already-member check follows ban lookup");

        assert!(
            !handler.contains(".unwrap_or(false)"),
            "federated membership join must not treat ban-store errors as not banned"
        );
        assert!(
            handler.contains("map_err") || handler.contains("?"),
            "ban lookup errors must propagate or fail closed before membership creation"
        );
    }

    #[test]
    fn federated_membership_join_accepts_hash_without_persisted_plaintext() {
        let handler = SOURCE
            .split("async fn apply_federation_membership_join")
            .nth(1)
            .expect("apply_federation_membership_join source should exist")
            .split("crate::services::pg::servers::add_member")
            .next()
            .expect("member insert follows invite validation");

        assert!(
            handler.contains("by_code_hash_for_server"),
            "federated membership join must resolve new S2S invite joins by hash"
        );
        assert!(
            handler.contains("try_consume(&state.pg, &invite.code"),
            "federated membership join should consume the target backend's local invite code after hash lookup"
        );
        assert!(
            handler.contains("invite_code.is_none() && invite_code_hash.is_none()"),
            "federated membership join must reject events missing both legacy code and hash"
        );
    }

    #[test]
    fn verification_challenge_is_domain_scoped() {
        let challenge = token_challenge("community.dev", "abc123");
        assert_eq!(challenge.dns_txt_name, "_verdant-federation.community.dev");
        assert_eq!(challenge.dns_txt_value, "verdant-site-verification=abc123");
        assert_eq!(
            challenge.http_url,
            "https://community.dev/.well-known/verdant-federation.txt"
        );
    }

    #[test]
    fn registry_status_rejects_unknown_values() {
        assert!("verified".parse::<RegistryStatus>().is_ok());
        assert!("official".parse::<RegistryStatus>().is_err());
    }

    #[test]
    fn registry_mode_cannot_claim_official() {
        assert_eq!(normalize_registry_mode("standalone").unwrap(), "standalone");
        assert_eq!(normalize_registry_mode("linked").unwrap(), "linked");
        assert_eq!(normalize_registry_mode("federated").unwrap(), "federated");
        assert!(normalize_registry_mode("official").is_err());
    }

    #[test]
    fn invite_url_must_stay_on_registered_domain() {
        assert_eq!(
            normalize_registry_invite_url(
                Some("https://join.community.dev/invite/abc".to_string()),
                "community.dev"
            )
            .unwrap()
            .as_deref(),
            Some("https://join.community.dev/invite/abc")
        );
        assert!(
            normalize_registry_invite_url(
                Some("https://attacker.dev/invite/abc".to_string()),
                "community.dev"
            )
            .is_err()
        );
        assert!(
            normalize_registry_invite_url(
                Some("https://user:pass@community.dev/invite/abc".to_string()),
                "community.dev"
            )
            .is_err()
        );
    }
}
