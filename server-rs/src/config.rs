use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::{collections::HashSet, env};
use url::Url;

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(default)
}

fn env_optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn env_optional_pem(name: &str) -> Option<String> {
    env_optional(name).map(|value| value.replace("\\n", "\n"))
}

fn env_u64_bounded(name: &str, default: u64, max: u64) -> u64 {
    let Some(raw) = env_optional(name) else {
        return default;
    };
    let parsed = raw
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("{name} must be an integer"));
    assert!(parsed <= max, "{name} must be between 0 and {max}");
    parsed
}

fn env_u32_bounded(name: &str, default: u32, max: u32) -> u32 {
    let Some(raw) = env_optional(name) else {
        return default;
    };
    let parsed = raw
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("{name} must be an integer"));
    assert!(parsed <= max, "{name} must be between 0 and {max}");
    parsed
}

fn env_bool_any(names: &[&str], default: bool) -> bool {
    for name in names {
        if let Ok(value) = env::var(name) {
            return matches!(value.trim(), "true" | "1" | "yes");
        }
    }
    default
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceMode {
    Official,
    Standalone,
    Linked,
    Federated,
}

impl InstanceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::Standalone => "standalone",
            Self::Linked => "linked",
            Self::Federated => "federated",
        }
    }

    pub fn official_network_linked(self) -> bool {
        !matches!(self, Self::Standalone)
    }
}

impl std::str::FromStr for InstanceMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "official" | "" => Ok(Self::Official),
            "standalone" => Ok(Self::Standalone),
            "linked" => Ok(Self::Linked),
            "federated" => Ok(Self::Federated),
            _ => Err("INSTANCE_MODE must be one of official, standalone, linked, federated".into()),
        }
    }
}

fn email_verification_required_for(
    instance_mode: InstanceMode,
    require_email_verification: bool,
    public_registration_enabled: bool,
) -> bool {
    require_email_verification
        || (instance_mode == InstanceMode::Official && public_registration_enabled)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingMode {
    Disabled,
    OfficialStripe,
}

impl BillingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::OfficialStripe => "official_stripe",
        }
    }
}

impl std::str::FromStr for BillingMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "official_stripe" => Ok(Self::OfficialStripe),
            _ => Err("BILLING_MODE must be one of disabled, official_stripe".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailProvider {
    Disabled,
    Console,
    Resend,
    Smtp,
}

impl EmailProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Console => "console",
            Self::Resend => "resend",
            Self::Smtp => "smtp",
        }
    }
}

impl std::str::FromStr for EmailProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "console" => Ok(Self::Console),
            "resend" => Ok(Self::Resend),
            "smtp" => Ok(Self::Smtp),
            _ => Err("EMAIL_PROVIDER must be one of disabled, console, resend, smtp".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadPolicy {
    Disabled,
    MediaValidationOnly,
    OperatorManaged,
}

impl UploadPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MediaValidationOnly => "media_validation_only",
            Self::OperatorManaged => "operator_managed",
        }
    }
}

impl std::str::FromStr for UploadPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "media_validation_only" => Ok(Self::MediaValidationOnly),
            "operator_managed" => Ok(Self::OperatorManaged),
            _ => Err(
                "UPLOAD_POLICY must be one of disabled, media_validation_only, operator_managed"
                    .into(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCapabilities {
    pub image_uploads: bool,
    pub file_sharing: bool,
    pub message_attachments: bool,
    pub voice_chat: bool,
    pub video_streaming: bool,
    pub cross_server_emoji: bool,
    pub animated_avatar: bool,
    pub animated_banner: bool,
    pub member_list_banner: bool,
    pub max_upload_bytes: u64,
    pub max_voice_bitrate: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeConfig {
    pub secret_key: Option<String>,
    pub webhook_secret: Option<String>,
    pub premium_price_id: Option<String>,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
}

pub fn resolve_billing_mode(mode: InstanceMode, raw: Option<&str>) -> BillingMode {
    let billing_mode = raw
        .unwrap_or("disabled")
        .parse::<BillingMode>()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        billing_mode != BillingMode::OfficialStripe || mode == InstanceMode::Official,
        "BILLING_MODE=official_stripe is only allowed for official instances"
    );
    billing_mode
}

pub fn resolve_stripe_config(
    billing_mode: BillingMode,
    secret_key: Option<String>,
    webhook_secret: Option<String>,
    premium_price_id: Option<String>,
    success_url: Option<String>,
    cancel_url: Option<String>,
) -> StripeConfig {
    if billing_mode == BillingMode::Disabled {
        return StripeConfig {
            secret_key: None,
            webhook_secret: None,
            premium_price_id: None,
            success_url: None,
            cancel_url: None,
        };
    }

    assert!(
        secret_key.as_deref().is_some_and(|s| !s.trim().is_empty()),
        "BILLING_MODE=official_stripe requires STRIPE_SECRET_KEY"
    );
    assert!(
        webhook_secret
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty()),
        "BILLING_MODE=official_stripe requires STRIPE_WEBHOOK_SECRET"
    );
    assert!(
        premium_price_id
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty()),
        "BILLING_MODE=official_stripe requires STRIPE_PREMIUM_PRICE_ID"
    );

    StripeConfig {
        secret_key,
        webhook_secret,
        premium_price_id,
        success_url,
        cancel_url,
    }
}

pub fn billing_routes_enabled(instance_mode: InstanceMode, billing_mode: BillingMode) -> bool {
    instance_mode == InstanceMode::Official && billing_mode == BillingMode::OfficialStripe
}

fn resolve_email_provider(raw: Option<&str>, resend_configured: bool) -> EmailProvider {
    match raw {
        Some(value) => {
            let provider = value
                .parse::<EmailProvider>()
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                provider != EmailProvider::Resend || resend_configured,
                "EMAIL_PROVIDER=resend requires RESEND_API_KEY and EMAIL_FROM"
            );
            provider
        }
        None if resend_configured => EmailProvider::Resend,
        None => EmailProvider::Disabled,
    }
}

fn resolve_upload_policy(raw: Option<&str>, storage_configured: bool) -> UploadPolicy {
    match raw {
        Some(value) => value
            .parse::<UploadPolicy>()
            .unwrap_or_else(|e| panic!("{e}")),
        None if storage_configured => UploadPolicy::OperatorManaged,
        None => UploadPolicy::Disabled,
    }
}

pub fn validate_upload_policy_requirements(upload_policy: UploadPolicy, storage_configured: bool) {
    assert!(
        upload_policy == UploadPolicy::Disabled || storage_configured,
        "UPLOAD_POLICY={} requires S3 storage configuration",
        upload_policy.as_str()
    );
}

fn default_image_upload_capability(instance_mode: InstanceMode, storage_configured: bool) -> bool {
    instance_mode != InstanceMode::Official && storage_configured
}

pub fn validate_database_app_role_split(
    mode: InstanceMode,
    database_url: &str,
    database_app_url: Option<&str>,
) {
    if mode != InstanceMode::Standalone {
        return;
    }

    let Some(app_url) = database_app_url.map(str::trim).filter(|s| !s.is_empty()) else {
        panic!("DATABASE_APP_URL is required when INSTANCE_MODE=standalone");
    };

    let owner_url = database_url.trim();
    assert!(
        owner_url != app_url,
        "DATABASE_APP_URL must use a separate database role when INSTANCE_MODE=standalone"
    );

    let owner = Url::parse(owner_url).unwrap_or_else(|_| panic!("DATABASE_URL is invalid"));
    let app = Url::parse(app_url).unwrap_or_else(|_| panic!("DATABASE_APP_URL is invalid"));
    assert!(
        owner.username().is_empty() || owner.username() != app.username(),
        "DATABASE_APP_URL must use a separate database role when INSTANCE_MODE=standalone"
    );
}

fn first_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env_optional(name))
}

pub fn normalize_cdn_base_url(raw: Option<String>) -> Option<String> {
    let mut value = raw?.trim().to_string();
    if value.is_empty() {
        return None;
    }

    if !value.contains("://") {
        value = format!("https://{value}");
    }

    let parsed = Url::parse(&value).unwrap_or_else(|_| panic!("CDN_BASE_URL must be a valid URL"));
    assert!(
        matches!(parsed.scheme(), "http" | "https"),
        "CDN_BASE_URL must use http:// or https://"
    );
    assert!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "CDN_BASE_URL must not include embedded credentials"
    );
    assert!(
        parsed.host_str().is_some(),
        "CDN_BASE_URL must include a host"
    );
    assert!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "CDN_BASE_URL must not include query strings or fragments"
    );

    Some(value.trim_end_matches('/').to_string())
}

fn derive_ws_url(api_url: &str) -> String {
    let Ok(mut parsed) = Url::parse(api_url) else {
        return "ws://localhost:3001/ws".to_string();
    };
    let scheme = match parsed.scheme() {
        "https" => "wss",
        "http" => "ws",
        "ws" | "wss" => parsed.scheme(),
        _ => "ws",
    }
    .to_string();
    let _ = parsed.set_scheme(&scheme);
    parsed.set_path("/ws");
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

pub fn parse_trusted_hosts(raw: Option<&str>, public_url: &str) -> Vec<String> {
    if let Some(raw) = raw {
        let mut hosts = Vec::new();
        for host in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            assert!(
                host.len() <= 253,
                "INSTANCE_TRUSTED_HOSTS entries must be at most 253 characters"
            );
            assert!(
                !host.contains("://")
                    && !host.contains('/')
                    && !host.contains('@')
                    && !host.contains('?')
                    && !host.contains('#'),
                "INSTANCE_TRUSTED_HOSTS entries must be host-only values"
            );
            let bracketed_ipv6 = host.starts_with('[') && host.ends_with(']');
            assert!(
                bracketed_ipv6 || !host.contains(':'),
                "INSTANCE_TRUSTED_HOSTS entries must be host-only values"
            );

            let parsed = Url::parse(&format!("http://{host}")).unwrap_or_else(|_| {
                panic!("INSTANCE_TRUSTED_HOSTS entries must be host-only values")
            });
            assert!(
                parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.host_str().is_some()
                    && parsed.port().is_none()
                    && parsed.path() == "/"
                    && parsed.query().is_none()
                    && parsed.fragment().is_none(),
                "INSTANCE_TRUSTED_HOSTS entries must be host-only values"
            );
            hosts.push(host.to_string());
        }
        assert!(
            hosts.len() <= 32,
            "INSTANCE_TRUSTED_HOSTS must contain at most 32 hosts"
        );
        hosts.sort();
        hosts.dedup();
        return hosts;
    }

    Url::parse(public_url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .into_iter()
        .collect()
}

fn trusted_hosts_from(public_url: &str) -> Vec<String> {
    let raw = env_optional("INSTANCE_TRUSTED_HOSTS");
    parse_trusted_hosts(raw.as_deref(), public_url)
}

pub fn normalize_certificate_sha256_pin(raw: &str) -> String {
    let value = raw.trim();
    let normalized = if let Some(encoded) = value.strip_prefix("sha256/") {
        let bytes = general_purpose::STANDARD
            .decode(encoded.trim())
            .unwrap_or_else(|_| panic!("certificate SHA-256 pins must be hex or sha256/base64"));
        assert!(
            bytes.len() == 32,
            "certificate SHA-256 pins must be exactly 32 bytes"
        );
        hex::encode(bytes)
    } else {
        value.replace(':', "").to_ascii_lowercase()
    };

    assert!(
        normalized.len() == 64 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()),
        "certificate SHA-256 pins must be 64-character SHA-256 hex fingerprints"
    );
    normalized
}

pub fn parse_certificate_sha256_pins(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };

    let mut pins = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_certificate_sha256_pin)
        .collect::<Vec<_>>();
    assert!(
        pins.len() <= 8,
        "certificate SHA-256 pins must contain at most 8 entries"
    );
    pins.sort();
    pins.dedup();
    pins
}

fn validate_instance_url(raw: &str, env_name: &str, allowed_schemes: &[&str]) {
    let parsed = Url::parse(raw).unwrap_or_else(|_| panic!("{env_name} must be a valid URL"));
    assert!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{env_name} must not include embedded credentials"
    );
    assert!(
        parsed.host_str().is_some(),
        "{env_name} must include a host"
    );
    assert!(
        allowed_schemes
            .iter()
            .any(|scheme| *scheme == parsed.scheme()),
        "{env_name} must use one of: {}",
        allowed_schemes.join(", ")
    );
}

fn normalize_account_link_official_api_origin(raw: Option<String>) -> String {
    let value = raw.unwrap_or_else(|| "https://api.verdant.chat".to_string());
    let parsed = Url::parse(value.trim())
        .unwrap_or_else(|_| panic!("ACCOUNT_LINK_OFFICIAL_API_ORIGIN must be a valid URL"));
    assert!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "ACCOUNT_LINK_OFFICIAL_API_ORIGIN must not include embedded credentials"
    );
    let host = parsed
        .host_str()
        .unwrap_or_else(|| panic!("ACCOUNT_LINK_OFFICIAL_API_ORIGIN must include a host"));
    match parsed.scheme() {
        "https" => {}
        "http" if is_localhost_host(host) => {}
        other => panic!(
            "ACCOUNT_LINK_OFFICIAL_API_ORIGIN must use https://, or http:// only for localhost; got {other}://"
        ),
    }
    assert!(
        parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none(),
        "ACCOUNT_LINK_OFFICIAL_API_ORIGIN must be an origin without path, query, or fragment"
    );

    let mut origin = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    origin
}

fn resolve_capabilities(
    instance_mode: InstanceMode,
    storage_configured: bool,
    livekit_configured: bool,
    upload_policy: UploadPolicy,
) -> LocalCapabilities {
    const ONE_GIB: u64 = 1024 * 1024 * 1024;
    const DEFAULT_MAX_UPLOAD_BYTES: u64 = 25 * 1024 * 1024;
    const MAX_VOICE_BITRATE: u32 = 512_000;

    let uploads_enabled = upload_policy != UploadPolicy::Disabled && storage_configured;
    let image_uploads_default = default_image_upload_capability(instance_mode, storage_configured);
    let image_uploads = uploads_enabled
        && env_bool_any(
            &["INSTANCE_CAP_IMAGE_UPLOADS", "CAP_IMAGE_UPLOADS"],
            image_uploads_default,
        );
    let file_sharing =
        uploads_enabled && env_bool_any(&["INSTANCE_CAP_FILE_SHARING", "CAP_FILE_SHARING"], false);
    let message_attachments = file_sharing
        && env_bool_any(
            &[
                "INSTANCE_CAP_MESSAGE_ATTACHMENTS",
                "CAP_MESSAGE_ATTACHMENTS",
            ],
            true,
        );

    LocalCapabilities {
        image_uploads,
        file_sharing,
        message_attachments,
        voice_chat: env_bool_any(
            &["INSTANCE_CAP_VOICE_CHAT", "CAP_VOICE_CHAT"],
            livekit_configured,
        ),
        video_streaming: env_bool_any(
            &["INSTANCE_CAP_VIDEO_STREAMING", "CAP_VIDEO_STREAMING"],
            false,
        ),
        cross_server_emoji: env_bool_any(
            &["INSTANCE_CAP_CROSS_SERVER_EMOJI", "CAP_CROSS_SERVER_EMOJI"],
            false,
        ),
        animated_avatar: env_bool_any(
            &["INSTANCE_CAP_ANIMATED_AVATAR", "CAP_ANIMATED_AVATAR"],
            true,
        ),
        animated_banner: env_bool_any(
            &["INSTANCE_CAP_ANIMATED_BANNER", "CAP_ANIMATED_BANNER"],
            true,
        ),
        member_list_banner: env_bool_any(
            &["INSTANCE_CAP_MEMBER_LIST_BANNER", "CAP_MEMBER_LIST_BANNER"],
            true,
        ),
        max_upload_bytes: env_u64_bounded(
            "INSTANCE_MAX_UPLOAD_BYTES",
            DEFAULT_MAX_UPLOAD_BYTES,
            ONE_GIB,
        ),
        max_voice_bitrate: env_u32_bounded(
            "INSTANCE_MAX_VOICE_BITRATE",
            if livekit_configured { 256_000 } else { 0 },
            MAX_VOICE_BITRATE,
        ),
    }
}

fn resolve_loadtest_secret(
    raw_secret: Option<String>,
    routes_enabled: bool,
    secure_cookies: bool,
) -> Option<String> {
    let key = raw_secret
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() >= 16);

    if !routes_enabled {
        if key.is_some() {
            tracing::info!(
                "LOADTEST_SECRET is set but LOADTEST_ROUTES_ENABLED is false; loadtest API and rate-limit bypass disabled"
            );
        }
        return None;
    }

    assert!(
        !secure_cookies,
        "LOADTEST_ROUTES_ENABLED is true but the CORS origin set contains HTTPS entries (production-shaped). \
         Refusing to boot. Unset LOADTEST_ROUTES_ENABLED outside dev/loadtest-only environments."
    );

    if key.is_some() {
        tracing::warn!(
            "LOADTEST_ROUTES_ENABLED is true — /api/admin/loadtest/* routes and loadtest rate-limit bypass are enabled"
        );
    }

    key
}

fn validate_optional_admin_secret(name: &str, secret: Option<String>) -> Option<String> {
    let secret = secret
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(ref value) = secret {
        assert!(value.len() >= 32, "{name} must be at least 32 characters");
        let lower = value.to_ascii_lowercase();
        assert!(
            ![
                "change-me",
                "change_me",
                "changeme",
                "replace-me",
                "replace_me",
                "placeholder",
                "example",
                "sample",
                "default",
                "todo",
            ]
            .iter()
            .any(|pattern| lower.contains(pattern)),
            "{name} appears to be a placeholder"
        );
    }
    secret
}

fn validate_federation_link_key_pem(
    name: &str,
    key: Option<String>,
    private: bool,
) -> Option<String> {
    let key = key.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(ref value) = key {
        if private {
            assert!(
                value.contains("BEGIN PRIVATE KEY") || value.contains("BEGIN RSA PRIVATE KEY"),
                "{name} must contain an RSA private key PEM"
            );
        } else {
            assert!(
                value.contains("BEGIN PUBLIC KEY"),
                "{name} must contain a public key PEM"
            );
            assert!(
                !value.contains("PRIVATE KEY"),
                "{name} must not contain private key material"
            );
        }
    }
    key
}

fn validate_federation_s2s_key_id(raw: Option<String>) -> Option<String> {
    let Some(value) = raw else {
        return None;
    };
    let value = value.trim().to_string();
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'));
    assert!(
        valid,
        "FEDERATION_S2S_KEY_ID must be 1-128 ASCII letters, numbers, dots, dashes, underscores, or colons"
    );
    Some(value)
}

fn validate_federation_s2s_signing_seed(raw: Option<String>) -> Option<[u8; 32]> {
    let Some(value) = raw else {
        return None;
    };
    let value = value.trim();
    let bytes = hex::decode(value)
        .unwrap_or_else(|_| panic!("FEDERATION_S2S_SIGNING_SEED must be a 32-byte hex value"));
    assert!(
        bytes.len() == 32,
        "FEDERATION_S2S_SIGNING_SEED must be a 32-byte hex value"
    );
    assert!(
        bytes.iter().any(|byte| *byte != 0),
        "FEDERATION_S2S_SIGNING_SEED must not be all zeroes"
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Some(seed)
}

const OLD_SELFHOST_JWT_SECRET_SAMPLE: &str = "replace-with-random-32-plus-character-secret";
const OLD_SELFHOST_LIVEKIT_SECRET_SAMPLE: &str = "local-voice-unsafe-demo-secret-32chars";

fn validate_jwt_secret(secret: &str) {
    let trimmed = secret.trim();
    assert!(
        trimmed.len() >= 32,
        "JWT_SECRET must be at least 32 characters"
    );

    let lower = trimmed.to_ascii_lowercase();
    let weak_patterns = [
        "change-me",
        "change_me",
        "changeme",
        "replace-me",
        "replace_me",
        "replace-with",
        "replace_with",
        "replacewith",
        "placeholder",
        "example",
        "sample",
        "default",
        "todo",
    ];

    assert!(
        lower != OLD_SELFHOST_JWT_SECRET_SAMPLE
            && !weak_patterns.iter().any(|pattern| lower.contains(pattern)),
        "JWT_SECRET appears to be a placeholder; use a cryptographically random secret"
    );
}

fn validate_livekit_api_secret(secret: &str) {
    let trimmed = secret.trim();
    assert!(
        trimmed.len() >= 32,
        "LIVEKIT_API_SECRET must be at least 32 characters"
    );

    let lower = trimmed.to_ascii_lowercase();
    let weak_patterns = [
        "devsecret",
        "dev-secret",
        "change-me",
        "change_me",
        "changeme",
        "replace-me",
        "replace_me",
        "replace-with",
        "replace_with",
        "replacewith",
        "placeholder",
        "example",
        "sample",
        "default",
        "demo",
        "unsafe",
        "local",
        "todo",
    ];

    assert!(
        lower != OLD_SELFHOST_LIVEKIT_SECRET_SAMPLE
            && !weak_patterns.iter().any(|pattern| lower.contains(pattern)),
        "LIVEKIT_API_SECRET appears to be a placeholder; use a cryptographically random secret"
    );
}

fn validate_app_field_encryption_key(secret: &str) {
    let trimmed = secret.trim();
    let lower = trimmed.to_ascii_lowercase();
    let weak_patterns = [
        "change-me",
        "change_me",
        "changeme",
        "replace-me",
        "replace_me",
        "replace-with",
        "replace_with",
        "replacewith",
        "placeholder",
        "example",
        "sample",
        "default",
        "todo",
    ];

    assert!(
        !weak_patterns.iter().any(|pattern| lower.contains(pattern)),
        "APP_FIELD_ENCRYPTION_KEY appears to be a placeholder; generate a cryptographically random 32-byte hex secret"
    );

    let bytes = hex::decode(trimmed)
        .unwrap_or_else(|_| panic!("APP_FIELD_ENCRYPTION_KEY must be a 64-character hex value"));
    assert!(
        bytes.len() == 32,
        "APP_FIELD_ENCRYPTION_KEY must be a 64-character hex value"
    );
    assert!(
        bytes.iter().any(|byte| *byte != 0)
            && !trimmed.as_bytes().windows(2).all(|pair| pair[0] == pair[1]),
        "APP_FIELD_ENCRYPTION_KEY appears to be a placeholder; generate a cryptographically random 32-byte hex secret"
    );
}

fn resolve_app_field_encryption_key(
    instance_mode: InstanceMode,
    raw_secret: Option<String>,
) -> Option<String> {
    let Some(secret) = raw_secret else {
        if instance_mode == InstanceMode::Official {
            return None;
        }
        panic!("APP_FIELD_ENCRYPTION_KEY is required for self-hosted instances");
    };
    validate_app_field_encryption_key(&secret);
    Some(secret.trim().to_string())
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub redis_url: String,
    /// Runtime Postgres connection URL.
    pub database_url: String,
    /// Optional non-owner Postgres URL for request paths that should be
    /// constrained by row-level security policies.
    pub database_app_url: Option<String>,
    /// Optional direct Postgres URL used only for sqlx migrations at boot.
    /// Runtime traffic may use a PgBouncer/pooler URL, but migrations need a
    /// direct session because sqlx migration locks are session-scoped.
    pub migration_database_url: Option<String>,
    /// Sqlx pool max connections per server-rs instance.
    pub database_pool_size: u32,
    pub jwt_secret: String,
    pub app_field_encryption_key: Option<String>,
    pub cors_origins: Vec<String>,
    pub min_client_version: String,
    /// When false, signup still requires a single-use registration key.
    /// Public soft-launch signup must be explicitly enabled in env.
    pub public_registration_enabled: bool,
    /// Optional server that verified public signups are automatically added to.
    pub registration_default_server_id: Option<i64>,
    /// Require accounts to verify email before entering protected API/WS.
    /// Public registration forces this requirement on even if the env is false.
    pub require_email_verification: bool,

    // Instance metadata / self-host surface
    pub instance_name: String,
    pub instance_mode: InstanceMode,
    pub instance_public_url: String,
    pub instance_api_url: String,
    pub instance_ws_url: String,
    pub instance_docs_url: String,
    pub instance_trusted_hosts: Vec<String>,
    pub certificate_sha256_pins: Vec<String>,
    pub instance_id: String,
    pub federation_public_key: Option<String>,
    pub federation_s2s_key_id: Option<String>,
    pub federation_s2s_signing_seed: Option<[u8; 32]>,
    pub federation_link_signing_key_pem: Option<String>,
    pub federation_link_verify_key_pem: Option<String>,
    pub account_link_official_api_origin: String,
    pub billing_mode: BillingMode,
    pub email_provider: EmailProvider,
    pub upload_policy: UploadPolicy,
    pub local_capabilities: LocalCapabilities,

    // S3-compatible storage (R2 / DO Spaces)
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub s3_region: Option<String>,
    pub storage_path_style: bool,

    // CDN (Cloudflare)
    pub cdn_base_url: Option<String>,
    pub evidence_bucket: Option<String>,

    // 2FA
    pub totp_encryption_key: Option<String>,

    // Email
    pub resend_api_key: Option<String>,
    pub email_from: Option<String>,
    pub frontend_url: Option<String>,

    // LiveKit (voice)
    pub livekit_url: Option<String>,
    pub livekit_api_url: Option<String>,
    pub livekit_nodes: Vec<LiveKitNodeConfig>,
    pub livekit_api_key: Option<String>,
    pub livekit_api_secret: Option<String>,

    // Klipy (GIF API)
    pub klipy_api_key: Option<String>,

    // Admin
    pub update_notify_secret: Option<String>,
    pub federation_registry_admin_enabled: bool,
    pub federation_registry_admin_secret: Option<String>,

    // Stripe billing
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub stripe_premium_price_id: Option<String>,
    pub billing_success_url: Option<String>,
    pub billing_cancel_url: Option<String>,

    // Content scanning
    pub content_scan_provider: String,
    pub content_scan_api_key: Option<String>,
    pub content_scan_mock_hashes: Option<String>,

    // Web app
    pub web_dist_dir: Option<String>,
    pub secure_cookies: bool,

    // Debug / Testing
    pub log_latency: bool,
    /// When set, requests with `X-Stress-Test: <this value>` skip all rate limits.
    /// NEVER set this in production. Only for local load testing.
    pub stress_test_key: Option<String>,
    /// Admin secret for dev-only loadtest setup/teardown routes.
    pub loadtest_secret: Option<String>,

    // Multi-region
    /// Region identifier for this app server instance.
    pub app_region: Option<String>,
    /// Region label for `X-Verdant-Region` and cross-region loopback filtering.
    pub verdant_region: Option<String>,

    // NATS cross-region mesh
    /// NATS client URL.
    pub nats_url: String,
    /// Shared token used to authenticate with nats-server.
    pub nats_auth_token: Option<String>,
    /// Enables cross-region fanout for whitelisted topics.
    pub nats_cross_region_enabled: bool,
    /// Comma-separated `<cluster-name>:<host>:<port>` gateway list.
    pub nats_gateways: Option<String>,
    /// NATS topology role; hub/spoke use cross-domain JetStream sources.
    pub nats_topology: NatsTopology,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveKitNodeConfig {
    pub name: String,
    pub url: String,
    pub api_url: String,
    pub region: Option<String>,
    pub weight: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveKitNodeEnv {
    name: Option<String>,
    url: String,
    #[serde(alias = "api_url")]
    api_url: String,
    region: Option<String>,
    weight: Option<u32>,
}

fn is_localhost_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn assert_no_url_credentials(parsed: &Url, env_name: &str, node_name: &str) {
    assert!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{env_name} for LiveKit node '{node_name}' must not include embedded credentials"
    );
}

fn validate_livekit_client_url(url: &str, env_name: &str, node_name: &str) {
    let parsed = Url::parse(url)
        .unwrap_or_else(|e| panic!("{env_name} for LiveKit node '{node_name}' is invalid: {e}"));
    assert_no_url_credentials(&parsed, env_name, node_name);
    let host = parsed
        .host_str()
        .unwrap_or_else(|| panic!("{env_name} for LiveKit node '{node_name}' must include a host"));
    match parsed.scheme() {
        "wss" => {}
        "ws" if is_localhost_host(host) => {}
        other => panic!(
            "{env_name} for LiveKit node '{node_name}' must use wss://, or ws:// only for localhost; got {other}://"
        ),
    }
}

fn validate_livekit_api_url(url: &str, env_name: &str, node_name: &str) {
    let parsed = Url::parse(url)
        .unwrap_or_else(|e| panic!("{env_name} for LiveKit node '{node_name}' is invalid: {e}"));
    assert_no_url_credentials(&parsed, env_name, node_name);
    assert!(
        parsed.host_str().is_some(),
        "{env_name} for LiveKit node '{node_name}' must include a host"
    );
    match parsed.scheme() {
        "http" | "https" => {}
        other => panic!(
            "{env_name} for LiveKit node '{node_name}' must use http:// or https://; got {other}://"
        ),
    }
}

fn validate_livekit_node_name(name: &str) {
    assert!(
        !name.is_empty() && name.len() <= 64,
        "LiveKit node names must be 1-64 characters"
    );
    assert!(
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "LiveKit node names may only contain ASCII letters, numbers, dash, underscore, and dot"
    );
}

fn normalize_livekit_node(raw: LiveKitNodeEnv, index: usize) -> LiveKitNodeConfig {
    let name = raw
        .name
        .unwrap_or_else(|| format!("node-{}", index + 1))
        .trim()
        .to_string();
    validate_livekit_node_name(&name);

    let url = raw.url.trim().trim_end_matches('/').to_string();
    let api_url = raw.api_url.trim().trim_end_matches('/').to_string();
    validate_livekit_client_url(&url, "LIVEKIT_NODES.url", &name);
    validate_livekit_api_url(&api_url, "LIVEKIT_NODES.apiUrl", &name);

    let weight = raw.weight.unwrap_or(1);
    assert!(
        (1..=1000).contains(&weight),
        "LIVEKIT_NODES weight for LiveKit node '{name}' must be between 1 and 1000"
    );

    LiveKitNodeConfig {
        name,
        url,
        api_url,
        region: raw.region.and_then(|r| {
            let r = r.trim().to_string();
            if r.is_empty() { None } else { Some(r) }
        }),
        weight,
    }
}

fn livekit_env_from_value<T: DeserializeOwned>(value: serde_json::Value, context: &str) -> T {
    serde_json::from_value(value)
        .unwrap_or_else(|e| panic!("LIVEKIT_NODES {context} is not a valid LiveKit node: {e}"))
}

fn livekit_json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn parse_livekit_nodes_array(value: serde_json::Value, context: &str) -> Vec<LiveKitNodeEnv> {
    let parsed: Vec<LiveKitNodeEnv> = livekit_env_from_value(value, context);
    assert!(
        !parsed.is_empty(),
        "LIVEKIT_NODES must contain at least one node when set"
    );
    parsed
}

fn parse_livekit_nodes_map(
    map: serde_json::Map<String, serde_json::Value>,
    context: &str,
) -> Vec<LiveKitNodeEnv> {
    let mut parsed = Vec::new();
    for (key, value) in map {
        match value {
            serde_json::Value::Object(_) => {
                parsed.push(livekit_env_from_value(value, &format!("{context}.{key}")));
            }
            serde_json::Value::String(raw) => {
                let value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
                    panic!("LIVEKIT_NODES {context}.{key} must be node JSON: {e}")
                });
                parsed.push(livekit_env_from_value(value, &format!("{context}.{key}")));
            }
            other => panic!(
                "LIVEKIT_NODES {context}.{key} must be a node object or node JSON string; got {}",
                livekit_json_type(&other)
            ),
        }
    }
    assert!(
        !parsed.is_empty(),
        "LIVEKIT_NODES must contain at least one node when set"
    );
    parsed
}

fn livekit_node_object_like(map: &serde_json::Map<String, serde_json::Value>) -> bool {
    map.contains_key("url") && (map.contains_key("apiUrl") || map.contains_key("api_url"))
}

fn parse_livekit_nodes_value(value: serde_json::Value, context: &str) -> Vec<LiveKitNodeEnv> {
    match value {
        serde_json::Value::Array(_) => parse_livekit_nodes_array(value, context),
        serde_json::Value::Object(mut map) => {
            if livekit_node_object_like(&map) {
                return vec![livekit_env_from_value(
                    serde_json::Value::Object(map),
                    context,
                )];
            }
            if let Some(nodes) = map.remove("nodes") {
                return match nodes {
                    serde_json::Value::Array(_) => parse_livekit_nodes_array(nodes, "nodes"),
                    serde_json::Value::Object(node_map) => {
                        parse_livekit_nodes_map(node_map, "nodes")
                    }
                    other => panic!(
                        "LIVEKIT_NODES nodes must be an array or node map; got {}",
                        livekit_json_type(&other)
                    ),
                };
            }
            if let Some(value) = map.remove("value") {
                let raw = value.as_str().unwrap_or_else(|| {
                    panic!(
                        "LIVEKIT_NODES value must be a JSON string; got {}",
                        livekit_json_type(&value)
                    )
                });
                let value: serde_json::Value = serde_json::from_str(raw)
                    .unwrap_or_else(|e| panic!("LIVEKIT_NODES value must contain JSON: {e}"));
                return parse_livekit_nodes_value(value, "value");
            }
            parse_livekit_nodes_map(map, context)
        }
        other => panic!(
            "LIVEKIT_NODES must be a JSON array or compatible node object; got {}",
            livekit_json_type(&other)
        ),
    }
}

fn parse_livekit_nodes(
    raw_nodes: Option<String>,
    legacy_url: Option<&str>,
    legacy_api_url: Option<&str>,
) -> Vec<LiveKitNodeConfig> {
    let nodes = if let Some(raw) = raw_nodes {
        let value: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("LIVEKIT_NODES must be valid JSON: {e}"));
        let parsed = parse_livekit_nodes_value(value, "root");
        parsed
            .into_iter()
            .enumerate()
            .map(|(idx, node)| normalize_livekit_node(node, idx))
            .collect()
    } else if let (Some(url), Some(api_url)) = (legacy_url, legacy_api_url) {
        vec![normalize_livekit_node(
            LiveKitNodeEnv {
                name: Some("default".to_string()),
                url: url.to_string(),
                api_url: api_url.to_string(),
                region: None,
                weight: Some(1),
            },
            0,
        )]
    } else {
        Vec::new()
    };

    let mut names = HashSet::new();
    for node in &nodes {
        assert!(
            names.insert(node.name.clone()),
            "LIVEKIT_NODES contains duplicate node name '{}'",
            node.name
        );
    }

    nodes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsTopology {
    Standalone,
    Hub,
    Spoke,
    Gateway,
}

impl NatsTopology {
    /// True when cross-region JetStream sources need `$JS.<peer>.API`.
    pub fn needs_cross_domain_sources(self) -> bool {
        matches!(self, NatsTopology::Hub | NatsTopology::Spoke)
    }
}

impl std::str::FromStr for NatsTopology {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "standalone" | "" => Ok(NatsTopology::Standalone),
            "hub" => Ok(NatsTopology::Hub),
            "spoke" | "leaf" => Ok(NatsTopology::Spoke),
            "gateway" => Ok(NatsTopology::Gateway),
            other => Err(format!("unknown NATS_TOPOLOGY: {other}")),
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var("RS_PORT")
            .or_else(|_| env::var("PORT"))
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3001);
        let redis_url = env::var("REDIS_URL").expect("REDIS_URL is required");
        let database_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL is required (postgres://user:pass@host:5432/db)");
        let database_app_url = env::var("DATABASE_APP_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let migration_database_url = env::var("MIGRATION_DATABASE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let database_pool_size: u32 = env::var("DATABASE_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET is required");
        validate_jwt_secret(&jwt_secret);
        let cors_origin = env::var("CORS_ORIGIN").expect("CORS_ORIGIN is required");
        let cors_origins: Vec<String> = cors_origin
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        for origin in &cors_origins {
            assert!(
                origin.starts_with("http://")
                    || origin.starts_with("https://")
                    || origin.starts_with("tauri://"),
                "CORS_ORIGIN entries must be valid URLs: {origin}"
            );
            if origin.starts_with("http://")
                && !origin.contains("localhost")
                && !origin.contains("127.0.0.1")
            {
                tracing::warn!(
                    "CORS_ORIGIN contains non-localhost HTTP origin: {origin} — use HTTPS in production"
                );
            }
        }

        let secure_cookies = cors_origins.iter().any(|o| o.starts_with("https://"));
        let livekit_url = env::var("LIVEKIT_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let livekit_api_url = env::var("LIVEKIT_API_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let livekit_nodes = parse_livekit_nodes(
            env::var("LIVEKIT_NODES")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            livekit_url.as_deref(),
            livekit_api_url.as_deref(),
        );

        let instance_mode = env_optional("INSTANCE_MODE")
            .unwrap_or_else(|| "official".to_string())
            .parse::<InstanceMode>()
            .unwrap_or_else(|e| panic!("{e}"));
        let app_field_encryption_key = resolve_app_field_encryption_key(
            instance_mode,
            env_optional("APP_FIELD_ENCRYPTION_KEY"),
        );
        validate_database_app_role_split(instance_mode, &database_url, database_app_url.as_deref());

        let instance_public_url = first_env(&["INSTANCE_PUBLIC_URL", "PUBLIC_URL", "FRONTEND_URL"])
            .or_else(|| {
                cors_origins
                    .iter()
                    .find(|origin| origin.starts_with("http"))
                    .cloned()
            })
            .unwrap_or_else(|| "http://localhost:3000".to_string());
        let instance_api_url = first_env(&["INSTANCE_API_URL", "API_URL"])
            .unwrap_or_else(|| format!("http://localhost:{port}"));
        let instance_ws_url = first_env(&["INSTANCE_WS_URL", "WS_URL"])
            .unwrap_or_else(|| derive_ws_url(&instance_api_url));
        let instance_docs_url = env_optional("INSTANCE_DOCS_URL")
            .unwrap_or_else(|| format!("{}/docs", instance_public_url.trim_end_matches('/')));
        validate_instance_url(
            &instance_public_url,
            "INSTANCE_PUBLIC_URL",
            &["http", "https"],
        );
        validate_instance_url(&instance_api_url, "INSTANCE_API_URL", &["http", "https"]);
        validate_instance_url(&instance_ws_url, "INSTANCE_WS_URL", &["ws", "wss"]);
        validate_instance_url(&instance_docs_url, "INSTANCE_DOCS_URL", &["http", "https"]);
        let instance_trusted_hosts = trusted_hosts_from(&instance_public_url);
        let certificate_sha256_pins = parse_certificate_sha256_pins(
            first_env(&[
                "INSTANCE_CERT_SHA256_PINS",
                "VERDANT_CERT_SHA256_PINS",
                "VERDANT_OFFICIAL_CERT_SHA256_PINS",
            ])
            .as_deref(),
        );
        let instance_id = env_optional("INSTANCE_ID").unwrap_or_else(|| {
            let host = Url::parse(&instance_api_url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .unwrap_or_else(|| "localhost".to_string());
            format!("host:{host}")
        });

        let s3_endpoint = env::var("S3_ENDPOINT")
            .or_else(|_| env::var("DO_SPACES_ENDPOINT"))
            .ok();
        let s3_bucket = env::var("S3_BUCKET")
            .or_else(|_| env::var("DO_SPACES_BUCKET"))
            .ok();
        let s3_access_key = env::var("S3_ACCESS_KEY")
            .or_else(|_| env::var("DO_SPACES_KEY"))
            .ok();
        let s3_secret_key = env::var("S3_SECRET_KEY")
            .or_else(|_| env::var("DO_SPACES_SECRET"))
            .ok();
        let s3_region = env_optional("S3_REGION");
        let storage_configured = s3_endpoint.is_some()
            && s3_bucket.is_some()
            && s3_access_key.is_some()
            && s3_secret_key.is_some();
        let resend_api_key = env::var("RESEND_API_KEY").ok();
        let email_from = env::var("EMAIL_FROM").ok();
        let frontend_url = env::var("FRONTEND_URL").ok();
        let resend_configured = resend_api_key.is_some() && email_from.is_some();
        let email_provider =
            resolve_email_provider(env_optional("EMAIL_PROVIDER").as_deref(), resend_configured);
        let upload_policy =
            resolve_upload_policy(env_optional("UPLOAD_POLICY").as_deref(), storage_configured);
        validate_upload_policy_requirements(upload_policy, storage_configured);
        let billing_mode =
            resolve_billing_mode(instance_mode, env_optional("BILLING_MODE").as_deref());
        let local_capabilities = resolve_capabilities(
            instance_mode,
            storage_configured,
            !livekit_nodes.is_empty(),
            upload_policy,
        );
        let cdn_base_url = normalize_cdn_base_url(env::var("CDN_BASE_URL").ok());
        let stripe_config = resolve_stripe_config(
            billing_mode,
            env::var("STRIPE_SECRET_KEY").ok(),
            env::var("STRIPE_WEBHOOK_SECRET").ok(),
            env::var("STRIPE_PREMIUM_PRICE_ID").ok(),
            env::var("BILLING_SUCCESS_URL").ok(),
            env::var("BILLING_CANCEL_URL").ok(),
        );
        let (resend_api_key, email_from, frontend_url) = if email_provider == EmailProvider::Resend
        {
            (resend_api_key, email_from, frontend_url)
        } else {
            (None, None, frontend_url)
        };
        let federation_registry_admin_enabled =
            env_bool("FEDERATION_REGISTRY_ADMIN_ENABLED", false);
        let federation_registry_admin_secret = validate_optional_admin_secret(
            "FEDERATION_REGISTRY_ADMIN_SECRET",
            env_optional("FEDERATION_REGISTRY_ADMIN_SECRET"),
        );
        assert!(
            !federation_registry_admin_enabled || federation_registry_admin_secret.is_some(),
            "FEDERATION_REGISTRY_ADMIN_ENABLED=true requires FEDERATION_REGISTRY_ADMIN_SECRET"
        );
        let federation_s2s_key_id =
            validate_federation_s2s_key_id(env_optional("FEDERATION_S2S_KEY_ID"));
        let federation_s2s_signing_seed =
            validate_federation_s2s_signing_seed(env_optional("FEDERATION_S2S_SIGNING_SEED"));
        assert!(
            federation_s2s_signing_seed.is_none() || federation_s2s_key_id.is_some(),
            "FEDERATION_S2S_SIGNING_SEED requires FEDERATION_S2S_KEY_ID"
        );
        Self {
            port,
            redis_url,
            database_url,
            database_app_url,
            migration_database_url,
            database_pool_size,
            jwt_secret,
            app_field_encryption_key,
            cors_origins,
            min_client_version: env::var("MIN_CLIENT_VERSION")
                .unwrap_or_else(|_| "0.0.293".to_string()),
            public_registration_enabled: env_bool("PUBLIC_REGISTRATION_ENABLED", false),
            registration_default_server_id: env::var("REGISTRATION_DEFAULT_SERVER_ID")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse::<i64>().ok()),
            require_email_verification: env_bool("REQUIRE_EMAIL_VERIFICATION", false),
            instance_name: env_optional("INSTANCE_NAME").unwrap_or_else(|| "Verdant".to_string()),
            instance_mode,
            instance_public_url,
            instance_api_url,
            instance_ws_url,
            instance_docs_url,
            instance_trusted_hosts,
            certificate_sha256_pins,
            instance_id,
            federation_public_key: env_optional("FEDERATION_PUBLIC_KEY"),
            federation_s2s_key_id,
            federation_s2s_signing_seed,
            federation_link_signing_key_pem: validate_federation_link_key_pem(
                "FEDERATION_LINK_SIGNING_KEY_PEM",
                env_optional_pem("FEDERATION_LINK_SIGNING_KEY_PEM"),
                true,
            ),
            federation_link_verify_key_pem: validate_federation_link_key_pem(
                "FEDERATION_LINK_VERIFY_KEY_PEM",
                env_optional_pem("FEDERATION_LINK_VERIFY_KEY_PEM"),
                false,
            ),
            account_link_official_api_origin: normalize_account_link_official_api_origin(
                env_optional("ACCOUNT_LINK_OFFICIAL_API_ORIGIN"),
            ),
            billing_mode,
            email_provider,
            upload_policy,
            local_capabilities,
            s3_endpoint,
            s3_bucket,
            s3_access_key,
            s3_secret_key,
            s3_region,
            storage_path_style: env::var("STORAGE_PATH_STYLE")
                .map(|v| v == "true")
                .unwrap_or(false),
            cdn_base_url,
            evidence_bucket: env::var("EVIDENCE_BUCKET").ok(),
            totp_encryption_key: env::var("TOTP_ENCRYPTION_KEY").ok(),
            resend_api_key,
            email_from,
            frontend_url,
            livekit_url,
            livekit_api_url,
            livekit_nodes,
            livekit_api_key: env::var("LIVEKIT_API_KEY").ok(),
            livekit_api_secret: {
                let secret = env::var("LIVEKIT_API_SECRET").ok();
                if let Some(ref s) = secret {
                    validate_livekit_api_secret(s);
                }
                secret
            },
            klipy_api_key: env::var("KLIPY_API_KEY")
                .or_else(|_| env::var("VITE_KLIPY_API_KEY"))
                .ok(),
            update_notify_secret: env::var("UPDATE_NOTIFY_SECRET").ok(),
            federation_registry_admin_enabled,
            federation_registry_admin_secret,
            stripe_secret_key: stripe_config.secret_key,
            stripe_webhook_secret: stripe_config.webhook_secret,
            stripe_premium_price_id: stripe_config.premium_price_id,
            billing_success_url: stripe_config.success_url,
            billing_cancel_url: stripe_config.cancel_url,
            content_scan_provider: env::var("CONTENT_SCAN_PROVIDER")
                .unwrap_or_else(|_| "none".to_string()),
            content_scan_api_key: env::var("CONTENT_SCAN_API_KEY").ok(),
            content_scan_mock_hashes: env::var("CONTENT_SCAN_MOCK_HASHES").ok(),
            web_dist_dir: env::var("WEB_DIST_DIR").ok(),
            secure_cookies,
            log_latency: env_bool("LOG_LATENCY", false),
            stress_test_key: {
                let key = env::var("STRESS_TEST_KEY").ok().filter(|s| !s.is_empty());
                if key.is_some() {
                    // Refuse to boot with STRESS_TEST_KEY in a production-shaped
                    // config. We infer "production" from the CORS origin set
                    // containing any HTTPS entry (same signal that drives
                    // secure_cookies above). This stops a stale .env from
                    // silently weakening rate limits on live infra.
                    assert!(
                        !secure_cookies,
                        "STRESS_TEST_KEY is set but the CORS origin set contains HTTPS entries (production-shaped). \
                         Refusing to boot. Unset STRESS_TEST_KEY or use a dev-only config."
                    );
                    tracing::warn!(
                        "⚠️  STRESS_TEST_KEY is set — rate limits can be bypassed via X-Stress-Test header! NEVER use in production."
                    );
                }
                key
            },
            loadtest_secret: {
                let routes_enabled = env_bool("LOADTEST_ROUTES_ENABLED", false);
                resolve_loadtest_secret(
                    env::var("LOADTEST_SECRET").ok(),
                    routes_enabled,
                    secure_cookies,
                )
            },
            app_region: {
                let region = env::var("APP_REGION").ok().filter(|s| !s.is_empty());
                if let Some(ref r) = region {
                    tracing::info!(region = %r, "APP_REGION set — region-aware routing enabled");
                }
                region
            },
            verdant_region: env::var("VERDANT_REGION")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| env::var("APP_REGION").ok().filter(|s| !s.is_empty())),
            nats_url: env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string()),
            nats_auth_token: env::var("NATS_AUTH_TOKEN").ok().filter(|s| !s.is_empty()),
            nats_cross_region_enabled: env_bool("NATS_CROSS_REGION_ENABLED", false),
            nats_gateways: env::var("NATS_GATEWAYS").ok().filter(|s| !s.is_empty()),
            nats_topology: env::var("NATS_TOPOLOGY")
                .ok()
                .and_then(|v| v.parse::<NatsTopology>().ok())
                .unwrap_or(NatsTopology::Standalone),
        }
    }

    pub fn livekit_enabled(&self) -> bool {
        !self.livekit_nodes.is_empty()
            && self.livekit_api_key.is_some()
            && self.livekit_api_secret.is_some()
    }

    pub fn storage_enabled(&self) -> bool {
        self.upload_policy != UploadPolicy::Disabled
            && self.s3_endpoint.is_some()
            && self.s3_bucket.is_some()
            && self.s3_access_key.is_some()
            && self.s3_secret_key.is_some()
    }

    pub fn cdn_enabled(&self) -> bool {
        self.cdn_base_url.is_some()
    }

    pub fn totp_enabled(&self) -> bool {
        self.totp_encryption_key.is_some()
    }

    pub fn email_enabled(&self) -> bool {
        self.email_provider == EmailProvider::Resend
            && self.resend_api_key.is_some()
            && self.email_from.is_some()
    }

    pub fn email_verification_required(&self) -> bool {
        email_verification_required_for(
            self.instance_mode,
            self.require_email_verification,
            self.public_registration_enabled,
        )
    }

    pub fn email_delivery_configured(&self) -> bool {
        match self.email_provider {
            EmailProvider::Disabled => false,
            EmailProvider::Resend => self.email_enabled(),
            EmailProvider::Console | EmailProvider::Smtp => false,
        }
    }

    pub fn content_scan_enabled(&self) -> bool {
        !matches!(
            self.content_scan_provider
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "none" | ""
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BillingMode, EmailProvider, InstanceMode, UploadPolicy, billing_routes_enabled,
        default_image_upload_capability, email_verification_required_for,
        normalize_account_link_official_api_origin, normalize_cdn_base_url,
        normalize_certificate_sha256_pin, parse_certificate_sha256_pins, parse_livekit_nodes,
        parse_trusted_hosts, resolve_app_field_encryption_key, resolve_billing_mode,
        resolve_capabilities, resolve_email_provider, resolve_loadtest_secret,
        resolve_stripe_config, validate_app_field_encryption_key, validate_database_app_role_split,
        validate_federation_link_key_pem, validate_federation_s2s_key_id,
        validate_federation_s2s_signing_seed, validate_jwt_secret, validate_livekit_api_secret,
        validate_optional_admin_secret, validate_upload_policy_requirements,
    };

    #[test]
    fn jwt_secret_accepts_random_32_plus_character_value() {
        validate_jwt_secret("a9Zk82nQp4Rw7Ty1Lm6Vc3Bf0Hs5Xd2P");
    }

    #[test]
    #[should_panic(expected = "JWT_SECRET appears to be a placeholder")]
    fn jwt_secret_rejects_old_selfhost_example_value() {
        validate_jwt_secret("replace-with-random-32-plus-character-secret");
    }

    #[test]
    #[should_panic(expected = "JWT_SECRET appears to be a placeholder")]
    fn jwt_secret_rejects_obvious_selfhost_placeholder() {
        validate_jwt_secret("CHANGE_ME_RANDOM_JWT_SECRET_32_CHARS_MIN");
    }

    #[test]
    #[should_panic(expected = "JWT_SECRET must be at least 32 characters")]
    fn jwt_secret_rejects_short_value() {
        validate_jwt_secret("short-random-secret");
    }

    #[test]
    fn livekit_api_secret_accepts_random_32_plus_character_value() {
        validate_livekit_api_secret("Lk8vX2pR6nQ9sW3mT7yB4cF0hJ5dN1zA");
    }

    #[test]
    #[should_panic(expected = "LIVEKIT_API_SECRET appears to be a placeholder")]
    fn livekit_api_secret_rejects_old_selfhost_example_value() {
        validate_livekit_api_secret("local-voice-unsafe-demo-secret-32chars");
    }

    #[test]
    #[should_panic(expected = "LIVEKIT_API_SECRET appears to be a placeholder")]
    fn livekit_api_secret_rejects_local_demo_unsafe_text() {
        validate_livekit_api_secret("local-demo-unsafe-livekit-secret-32chars");
    }

    #[test]
    #[should_panic(expected = "LIVEKIT_API_SECRET appears to be a placeholder")]
    fn livekit_api_secret_rejects_obvious_selfhost_placeholder() {
        validate_livekit_api_secret("CHANGE_ME_RANDOM_LIVEKIT_SECRET_32_CHARS_MIN");
    }

    #[test]
    #[should_panic(expected = "LIVEKIT_API_SECRET must be at least 32 characters")]
    fn livekit_api_secret_rejects_short_value() {
        validate_livekit_api_secret("short-livekit-secret");
    }

    #[test]
    fn app_field_encryption_key_accepts_random_32_byte_hex_value() {
        validate_app_field_encryption_key(
            "b55f7f6657f90b0771c71f56ab29a70fd23c9e247a57de9532a53bc55790d251",
        );
    }

    #[test]
    #[should_panic(expected = "APP_FIELD_ENCRYPTION_KEY must be a 64-character hex value")]
    fn app_field_encryption_key_rejects_short_value() {
        validate_app_field_encryption_key("short-field-key");
    }

    #[test]
    #[should_panic(expected = "APP_FIELD_ENCRYPTION_KEY must be a 64-character hex value")]
    fn app_field_encryption_key_rejects_non_hex_value() {
        validate_app_field_encryption_key(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        );
    }

    #[test]
    #[should_panic(expected = "APP_FIELD_ENCRYPTION_KEY appears to be a placeholder")]
    fn app_field_encryption_key_rejects_placeholder_value() {
        validate_app_field_encryption_key(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn official_instance_allows_missing_app_field_encryption_key() {
        assert!(resolve_app_field_encryption_key(InstanceMode::Official, None).is_none());
    }

    #[test]
    #[should_panic(expected = "APP_FIELD_ENCRYPTION_KEY is required for self-hosted instances")]
    fn self_host_instance_requires_app_field_encryption_key() {
        let _ = resolve_app_field_encryption_key(InstanceMode::Federated, None);
    }

    #[test]
    fn loadtest_secret_alone_does_not_enable_loadtest_surface() {
        let resolved = resolve_loadtest_secret(Some("x".repeat(32)), false, false);
        assert!(resolved.is_none());
    }

    #[test]
    fn loadtest_secret_requires_explicit_dev_opt_in() {
        let resolved = resolve_loadtest_secret(Some("x".repeat(32)), true, false);
        assert_eq!(
            resolved.as_deref(),
            Some("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );
    }

    #[test]
    #[should_panic(expected = "LOADTEST_ROUTES_ENABLED")]
    fn loadtest_routes_cannot_be_enabled_for_production_shaped_config() {
        let _ = resolve_loadtest_secret(Some("x".repeat(32)), true, true);
    }

    #[test]
    fn optional_admin_secret_accepts_random_32_plus_character_value() {
        let resolved = validate_optional_admin_secret(
            "TEST_ADMIN_SECRET",
            Some("a9Zk82nQp4Rw7Ty1Lm6Vc3Bf0Hs5Xd2P".to_string()),
        );
        assert!(resolved.is_some());
    }

    #[test]
    #[should_panic(expected = "TEST_ADMIN_SECRET must be at least 32 characters")]
    fn optional_admin_secret_rejects_short_value() {
        let _ = validate_optional_admin_secret("TEST_ADMIN_SECRET", Some("short".to_string()));
    }

    #[test]
    #[should_panic(expected = "TEST_ADMIN_SECRET appears to be a placeholder")]
    fn optional_admin_secret_rejects_placeholder_value() {
        let _ = validate_optional_admin_secret(
            "TEST_ADMIN_SECRET",
            Some("change-me-federation-admin-secret-32".to_string()),
        );
    }

    #[test]
    fn federation_link_verify_key_rejects_private_key_material() {
        let public = validate_federation_link_key_pem(
            "FEDERATION_LINK_VERIFY_KEY_PEM",
            Some("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----".to_string()),
            false,
        );
        assert!(public.is_some());

        let private = std::panic::catch_unwind(|| {
            validate_federation_link_key_pem(
                "FEDERATION_LINK_VERIFY_KEY_PEM",
                Some("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".to_string()),
                false,
            )
        });
        assert!(private.is_err());
    }

    #[test]
    #[should_panic(
        expected = "FEDERATION_LINK_SIGNING_KEY_PEM must contain an RSA private key PEM"
    )]
    fn federation_link_signing_key_requires_private_key_material() {
        let _ = validate_federation_link_key_pem(
            "FEDERATION_LINK_SIGNING_KEY_PEM",
            Some("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----".to_string()),
            true,
        );
    }

    #[test]
    fn federation_s2s_key_id_accepts_scoped_rotation_name() {
        assert_eq!(
            validate_federation_s2s_key_id(Some("ed25519:2026-01".to_string())).as_deref(),
            Some("ed25519:2026-01")
        );
    }

    #[test]
    #[should_panic(expected = "FEDERATION_S2S_KEY_ID must be 1-128")]
    fn federation_s2s_key_id_rejects_blank_value() {
        let _ = validate_federation_s2s_key_id(Some("   ".to_string()));
    }

    #[test]
    fn federation_s2s_signing_seed_accepts_32_byte_hex() {
        let seed = validate_federation_s2s_signing_seed(Some(
            "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a".to_string(),
        ))
        .expect("seed should parse");

        assert_eq!(seed, [42; 32]);
    }

    #[test]
    #[should_panic(expected = "FEDERATION_S2S_SIGNING_SEED must be a 32-byte hex value")]
    fn federation_s2s_signing_seed_rejects_short_hex() {
        let _ = validate_federation_s2s_signing_seed(Some("2a2a".to_string()));
    }

    #[test]
    #[should_panic(expected = "DATABASE_APP_URL is required when INSTANCE_MODE=standalone")]
    fn standalone_requires_database_app_url() {
        validate_database_app_role_split(
            InstanceMode::Standalone,
            "postgres://owner:secret@db.internal/verdant",
            None,
        );
    }

    #[test]
    #[should_panic(expected = "DATABASE_APP_URL must use a separate database role")]
    fn standalone_rejects_database_app_url_equal_to_database_url() {
        validate_database_app_role_split(
            InstanceMode::Standalone,
            "postgres://owner:secret@db.internal/verdant",
            Some("postgres://owner:secret@db.internal/verdant"),
        );
    }

    #[test]
    fn standalone_accepts_separate_app_role_url() {
        validate_database_app_role_split(
            InstanceMode::Standalone,
            "postgres://owner:secret@db.internal/verdant",
            Some("postgres://app:secret@db.internal/verdant"),
        );
    }

    #[test]
    fn account_link_official_api_origin_normalizes_origins() {
        assert_eq!(
            normalize_account_link_official_api_origin(Some("https://api.verdant.chat/".into())),
            "https://api.verdant.chat"
        );
        assert_eq!(
            normalize_account_link_official_api_origin(Some("http://localhost:3000".into())),
            "http://localhost:3000"
        );
    }

    #[test]
    #[should_panic(expected = "ACCOUNT_LINK_OFFICIAL_API_ORIGIN must be an origin")]
    fn account_link_official_api_origin_rejects_paths() {
        let _ = normalize_account_link_official_api_origin(Some(
            "https://api.verdant.chat/path".into(),
        ));
    }

    #[test]
    #[should_panic(expected = "ACCOUNT_LINK_OFFICIAL_API_ORIGIN must use https://")]
    fn account_link_official_api_origin_rejects_non_https_public_hosts() {
        let _ = normalize_account_link_official_api_origin(Some("http://api.verdant.chat".into()));
    }

    #[test]
    fn standalone_defaults_billing_to_disabled() {
        assert_eq!(
            resolve_billing_mode(InstanceMode::Standalone, None),
            BillingMode::Disabled
        );
    }

    #[test]
    #[should_panic(
        expected = "BILLING_MODE=official_stripe is only allowed for official instances"
    )]
    fn standalone_rejects_official_stripe_billing() {
        let _ = resolve_billing_mode(InstanceMode::Standalone, Some("official_stripe"));
    }

    #[test]
    #[should_panic(
        expected = "BILLING_MODE=official_stripe is only allowed for official instances"
    )]
    fn linked_rejects_official_stripe_billing() {
        let _ = resolve_billing_mode(InstanceMode::Linked, Some("official_stripe"));
    }

    #[test]
    #[should_panic(
        expected = "BILLING_MODE=official_stripe is only allowed for official instances"
    )]
    fn federated_rejects_official_stripe_billing() {
        let _ = resolve_billing_mode(InstanceMode::Federated, Some("official_stripe"));
    }

    #[test]
    fn billing_disabled_ignores_legacy_stripe_secrets() {
        let stripe = resolve_stripe_config(
            BillingMode::Disabled,
            Some("sk_live_should_not_be_used".to_string()),
            Some("whsec_should_not_be_used".to_string()),
            Some("price_should_not_be_used".to_string()),
            Some("https://app.example/success".to_string()),
            Some("https://app.example/cancel".to_string()),
        );

        assert!(stripe.secret_key.is_none());
        assert!(stripe.webhook_secret.is_none());
        assert!(stripe.premium_price_id.is_none());
        assert!(stripe.success_url.is_none());
        assert!(stripe.cancel_url.is_none());
    }

    #[test]
    fn billing_routes_mount_only_for_official_stripe() {
        assert!(!billing_routes_enabled(
            InstanceMode::Official,
            BillingMode::Disabled
        ));
        assert!(billing_routes_enabled(
            InstanceMode::Official,
            BillingMode::OfficialStripe
        ));
        assert!(!billing_routes_enabled(
            InstanceMode::Standalone,
            BillingMode::OfficialStripe
        ));
        assert!(!billing_routes_enabled(
            InstanceMode::Linked,
            BillingMode::OfficialStripe
        ));
        assert!(!billing_routes_enabled(
            InstanceMode::Federated,
            BillingMode::OfficialStripe
        ));
    }

    #[test]
    fn missing_email_provider_defaults_to_disabled() {
        assert_eq!(resolve_email_provider(None, false), EmailProvider::Disabled);
    }

    #[test]
    fn official_public_registration_requires_email_verification() {
        assert!(email_verification_required_for(
            InstanceMode::Official,
            false,
            true
        ));
    }

    #[test]
    fn standalone_public_registration_can_disable_email_verification() {
        assert!(!email_verification_required_for(
            InstanceMode::Standalone,
            false,
            true
        ));
        assert!(email_verification_required_for(
            InstanceMode::Standalone,
            true,
            true
        ));
    }

    #[test]
    fn cdn_base_url_normalizes_bare_host() {
        assert_eq!(
            normalize_cdn_base_url(Some("cdn.example.com/assets/".to_string())).as_deref(),
            Some("https://cdn.example.com/assets")
        );
    }

    #[test]
    #[should_panic(expected = "CDN_BASE_URL must not include embedded credentials")]
    fn cdn_base_url_rejects_embedded_credentials() {
        let _ = normalize_cdn_base_url(Some("https://user:pass@cdn.example.com".to_string()));
    }

    #[test]
    #[should_panic(expected = "CDN_BASE_URL must not include query strings or fragments")]
    fn cdn_base_url_rejects_query_strings() {
        let _ = normalize_cdn_base_url(Some("https://cdn.example.com?token=secret".to_string()));
    }

    #[test]
    fn disabled_upload_policy_forces_upload_capabilities_off() {
        let capabilities =
            resolve_capabilities(InstanceMode::Standalone, true, true, UploadPolicy::Disabled);

        assert!(!capabilities.image_uploads);
        assert!(!capabilities.file_sharing);
        assert!(!capabilities.message_attachments);
    }

    #[test]
    fn official_image_upload_capability_defaults_to_off() {
        assert!(!default_image_upload_capability(
            InstanceMode::Official,
            true
        ));
        assert!(default_image_upload_capability(
            InstanceMode::Standalone,
            true
        ));
        assert!(default_image_upload_capability(InstanceMode::Linked, true));
        assert!(default_image_upload_capability(
            InstanceMode::Federated,
            true
        ));
        assert!(!default_image_upload_capability(
            InstanceMode::Standalone,
            false
        ));
    }

    #[test]
    #[should_panic(expected = "UPLOAD_POLICY=operator_managed requires S3 storage configuration")]
    fn operator_managed_upload_policy_requires_storage() {
        validate_upload_policy_requirements(UploadPolicy::OperatorManaged, false);
    }

    #[test]
    #[should_panic(expected = "INSTANCE_TRUSTED_HOSTS must contain at most 32 hosts")]
    fn trusted_hosts_rejects_too_many_entries() {
        let hosts = (0..33)
            .map(|i| format!("host{i}.example.com"))
            .collect::<Vec<_>>()
            .join(",");
        let _ = parse_trusted_hosts(Some(&hosts), "https://fallback.example.com");
    }

    #[test]
    #[should_panic(expected = "INSTANCE_TRUSTED_HOSTS entries must be host-only values")]
    fn trusted_hosts_rejects_urls_and_credentials() {
        let _ = parse_trusted_hosts(
            Some("safe.example.com,https://user:pass@evil.example.com"),
            "https://fallback.example.com",
        );
    }

    #[test]
    fn certificate_sha256_pins_accept_hex_colon_and_base64_formats() {
        let hex_pin = "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA";
        assert_eq!(
            normalize_certificate_sha256_pin(hex_pin),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let base64_pin = "sha256/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
        assert_eq!(
            normalize_certificate_sha256_pin(base64_pin),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn certificate_sha256_pins_are_deduplicated_and_sorted() {
        let pins = parse_certificate_sha256_pins(Some(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,\
             bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ));

        assert_eq!(
            pins,
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ]
        );
    }

    #[test]
    #[should_panic(
        expected = "certificate SHA-256 pins must be 64-character SHA-256 hex fingerprints"
    )]
    fn certificate_sha256_pins_reject_non_fingerprints() {
        let _ = parse_certificate_sha256_pins(Some("not-a-pin"));
    }

    #[test]
    #[should_panic(expected = "certificate SHA-256 pins must contain at most 8 entries")]
    fn certificate_sha256_pins_reject_too_many_entries() {
        let pins = (0..9)
            .map(|i| format!("{i:064x}"))
            .collect::<Vec<_>>()
            .join(",");
        let _ = parse_certificate_sha256_pins(Some(&pins));
    }

    #[test]
    fn livekit_nodes_fall_back_to_legacy_single_node_env() {
        let nodes = parse_livekit_nodes(
            None,
            Some("wss://voice.verdant.chat/"),
            Some("http://10.116.0.2:7880/"),
        );
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "default");
        assert_eq!(nodes[0].url, "wss://voice.verdant.chat");
        assert_eq!(nodes[0].api_url, "http://10.116.0.2:7880");
        assert_eq!(nodes[0].weight, 1);
    }

    #[test]
    fn livekit_nodes_parse_cluster_json() {
        let raw = r#"[
            {
                "name": "nyc1-1",
                "url": "wss://voice-nyc1-1.verdant.chat",
                "apiUrl": "http://10.116.0.10:7880",
                "region": "nyc1",
                "weight": 2
            },
            {
                "name": "nyc1-2",
                "url": "wss://voice-nyc1-2.verdant.chat",
                "api_url": "http://10.116.0.11:7880"
            }
        ]"#;
        let nodes = parse_livekit_nodes(Some(raw.to_string()), None, None);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "nyc1-1");
        assert_eq!(nodes[0].region.as_deref(), Some("nyc1"));
        assert_eq!(nodes[0].weight, 2);
        assert_eq!(nodes[1].name, "nyc1-2");
        assert_eq!(nodes[1].weight, 1);
    }

    #[test]
    fn livekit_nodes_parse_orchestrator_result_object() {
        let raw = r#"{
            "project": "verdant",
            "config": "prd",
            "nodeCount": 1,
            "nodes": [
                {
                    "name": "livekit-nyc1-01",
                    "url": "wss://voice-nyc1-01.verdant.chat",
                    "apiUrl": "http://10.116.0.6:7880",
                    "region": "nyc1",
                    "weight": 1
                }
            ],
            "value": "[]"
        }"#;

        let nodes = parse_livekit_nodes(Some(raw.to_string()), None, None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "livekit-nyc1-01");
        assert_eq!(nodes[0].api_url, "http://10.116.0.6:7880");
    }

    #[test]
    fn livekit_nodes_parse_single_node_object() {
        let raw = r#"{
            "name": "livekit-nyc1-01",
            "url": "wss://voice-nyc1-01.verdant.chat",
            "apiUrl": "http://10.116.0.6:7880",
            "region": "nyc1",
            "weight": 1
        }"#;

        let nodes = parse_livekit_nodes(Some(raw.to_string()), None, None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "livekit-nyc1-01");
        assert_eq!(nodes[0].url, "wss://voice-nyc1-01.verdant.chat");
        assert_eq!(nodes[0].api_url, "http://10.116.0.6:7880");
    }

    #[test]
    fn livekit_nodes_parse_value_wrapped_array() {
        let raw = r#"{
            "value": "[{\"name\":\"livekit-nyc1-01\",\"url\":\"wss://voice-nyc1-01.verdant.chat\",\"apiUrl\":\"http://10.116.0.6:7880\"}]"
        }"#;

        let nodes = parse_livekit_nodes(Some(raw.to_string()), None, None);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "livekit-nyc1-01");
    }

    #[test]
    fn livekit_nodes_parse_redis_style_node_map() {
        let raw = r#"{
            "livekit-nyc1-01": "{\"name\":\"livekit-nyc1-01\",\"url\":\"wss://voice-nyc1-01.verdant.chat\",\"apiUrl\":\"http://10.116.0.6:7880\",\"region\":\"nyc1\",\"weight\":1}",
            "livekit-nyc1-02": {
                "name": "livekit-nyc1-02",
                "url": "wss://voice-nyc1-02.verdant.chat",
                "apiUrl": "http://10.116.0.7:7880",
                "region": "nyc1",
                "weight": 1
            }
        }"#;

        let nodes = parse_livekit_nodes(Some(raw.to_string()), None, None);

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "livekit-nyc1-01");
        assert_eq!(nodes[1].name, "livekit-nyc1-02");
    }

    #[test]
    #[should_panic(expected = "duplicate node name")]
    fn livekit_nodes_reject_duplicate_names() {
        let raw = r#"[
            {"name":"nyc1","url":"wss://voice-1.verdant.chat","apiUrl":"http://10.0.0.1:7880"},
            {"name":"nyc1","url":"wss://voice-2.verdant.chat","apiUrl":"http://10.0.0.2:7880"}
        ]"#;
        let _ = parse_livekit_nodes(Some(raw.to_string()), None, None);
    }

    #[test]
    #[should_panic(expected = "must use wss://")]
    fn livekit_nodes_reject_insecure_public_client_url() {
        let raw = r#"[
            {"name":"nyc1","url":"ws://voice.verdant.chat","apiUrl":"http://10.0.0.1:7880"}
        ]"#;
        let _ = parse_livekit_nodes(Some(raw.to_string()), None, None);
    }
}
